//! The A2A (Agent2Agent) door — a hand-rolled, dependency-free JSON-RPC 2.0
//! over HTTP/1.1 server (CONTRACTS.md §6, Phase B: server MVP, now with
//! `message/send` execution — Phase B2).
//!
//! Zero new crates: a blocking `TcpListener` accept loop (thread-per-
//! connection), a minimal HTTP/1.1 request/response layer hand-parsed off
//! `BufRead`/`Write` (the same "no clap/no tokio, offline cargo lock stays
//! pure" discipline `cli.rs` and `graph/conduct.rs` already follow), and
//! `serde_json::Value` for the JSON-RPC envelope (mirroring `mcp.rs`'s stdio
//! JSON-RPC server — this is that same shape over a socket instead of stdio).
//!
//! Routes (CONTRACTS.md §6 MVP surface):
//!   - `GET  /.well-known/agent-card.json` — the AgentCard, derived from the
//!     command registry (`schema --json`), filtered to `implemented: true`.
//!   - `POST /` — JSON-RPC 2.0: `tasks/get` (real), `message/send` (real —
//!     inject into a known conductable session, or spawn a freshly conducted
//!     one; [`decide_send_action`] below), anything else → `-32601 method
//!     not found`.
//!
//! A forwarded A2A message's TEXT is untrusted DATA, never executed as a
//! command — `message/send`'s inject path types it into a target session
//! exactly like `graph send` (in fact it reuses [`crate::graph::session_send`]
//! for that), and its spawn path never runs a client-supplied command: it
//! only ever launches the operator-configured `aoide.a2a.spawnAgent`
//! executable (a rebuild-gated nix option — the user's admission), with the
//! client-supplied prompt injected as its first turn. See
//! [`decide_send_action`]'s doc comment for the full security model.

use crate::daemon::{self, Door};
use crate::dispatch::Invocation;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

// ── Hostile-input hardening limits (security review, pre-commit) ────────────
//
// Every one of these exists because the client on the other end of the
// socket is untrusted network input, not a cooperating peer — CONTRACTS.md
// §6 draws no new trust tier for the A2A door, but that only covers the
// JSON-RPC *payload*; the HTTP framing around it still needs the same
// paranoia any Internet-facing parser needs, even bound to loopback by
// default.

/// Hard cap on a single request's body, in bytes. Without this, an untrusted
/// `Content-Length: 999999999999` would drive a ~1 TB `Vec` allocation —
/// which aborts the whole process (not just the connection) on failure.
const MAX_BODY: usize = 1 << 20; // 1 MiB

/// Hard cap on a single request-line or header-line's length, in bytes. A
/// newline-less byte stream must never grow a line buffer without bound.
const MAX_LINE: usize = 8 << 10; // 8 KiB

/// Hard cap on the number of header lines parsed before giving up.
const MAX_HEADERS: usize = 100;

/// Absolute per-connection budget. The per-read timeout below only guards
/// against a fully-idle client; a client that dribbles one byte just inside
/// that timeout, forever, would otherwise hold a handler thread indefinitely.
const MAX_REQUEST: Duration = Duration::from_secs(15);

/// Max in-flight connections. Past this, new connections get a fast `503`
/// instead of a spawned handler thread, so a connection flood can't spawn
/// unbounded threads.
const MAX_CONN: usize = 64;

/// Absolute cap on one SSE stream's lifetime (`message/stream` /
/// `tasks/resubscribe`). A never-terminal session — an idle agent that never
/// reaches `done` — must NOT hold a handler thread (and thus a [`MAX_CONN`]
/// slot) forever; on timeout the loop emits one final event and closes. The
/// [`MAX_CONN`] + [`ConnGuard`] cap already bounds CONCURRENT streams, since
/// `stream_task` runs inside the same guarded handler thread — this cap bounds
/// each individual stream's DURATION on top of that.
const MAX_STREAM: Duration = Duration::from_secs(600); // 10 minutes

/// Poll interval between task-status reads inside an SSE stream loop.
const STREAM_POLL: Duration = Duration::from_millis(750);

/// Count of currently in-flight (spawned) connection-handler threads —
/// paired with [`ConnGuard`] so the count is accurate even across a panic.
static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);

// ── Bind/port resolution (CONTRACTS.md §6 security posture) ─────────────────

/// Resolve the bind address + port for `a2a serve`: `--bind`/`--port` flags →
/// `AOIDE_A2A_BIND`/`AOIDE_A2A_PORT` env (set by the `aoide-a2a` systemd unit,
/// `modules/nucleus/aoided.nix`) → the loopback defaults
/// (`aoide.a2a.bindAddress`/`aoide.a2a.port`, `127.0.0.1`/`8710`).
pub fn resolve_bind_port(inv: &Invocation) -> (String, u16) {
    let bind = inv
        .flags
        .get("bind")
        .cloned()
        .or_else(|| std::env::var("AOIDE_A2A_BIND").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let port = inv
        .flags
        .get("port")
        .and_then(|p| p.parse::<u16>().ok())
        .or_else(|| {
            std::env::var("AOIDE_A2A_PORT")
                .ok()
                .and_then(|p| p.parse::<u16>().ok())
        })
        .unwrap_or(8710);
    (bind, port)
}

/// Resolve `aoide.a2a.spawnAgent`: the command `message/send`'s SPAWN path
/// conducts for a client that names no known session (or explicitly asks to
/// spawn). `--spawn-agent` flag → `AOIDE_A2A_SPAWN_AGENT` env (set by the
/// `aoide-a2a` systemd unit, `modules/nucleus/aoided.nix`) → default `""`
/// (empty = spawning disabled — [`decide_send_action`] returns a structured
/// error rather than launching anything). The client NEVER supplies this
/// command — only the operator, via the rebuild-gated nix option
/// (CONTRACTS.md §6, security model).
pub fn resolve_spawn_agent(inv: &Invocation) -> String {
    inv.flags
        .get("spawn-agent")
        .cloned()
        .or_else(|| std::env::var("AOIDE_A2A_SPAWN_AGENT").ok())
        .unwrap_or_default()
}

// ── AgentCard (derived from the command registry, CONTRACTS.md §6) ──────────

/// Build the AgentCard from any iterator of registry commands — factored out
/// of [`agent_card`] so tests can feed a small fake schema instead of the
/// real process-wide registry.
pub fn agent_card_from_commands<'a>(
    commands: impl Iterator<Item = &'a crate::registry::Command>,
    bind: &str,
    port: u16,
) -> Value {
    let skills: Vec<Value> = commands
        .filter(|c| c.implemented)
        .map(|c| {
            let dotted = c.dotted();
            let top_level = c.path.first().copied().unwrap_or("");
            json!({
                "id": dotted,
                "name": dotted,
                "description": c.summary,
                "tags": [top_level],
            })
        })
        .collect();

    json!({
        "name": "aoide",
        "description": "aoide — a headless conductor for agent sessions, rice \
            generation, and the song/stage state tree, exposed as a \
            discoverable A2A remote agent (CONTRACTS.md §6).",
        "version": crate::registry::AOIDE_VERSION,
        // Pinned explicitly to the A2A v0.3.x JSON-RPC binding (CONTRACTS.md
        // §6 "Version"): flat "url" below, message/send + tasks/get,
        // lowercase-kebab TaskStates. v1.0's `interfaces`-array + top-level
        // `id` card form is a later, additive follow-on — not this.
        "protocolVersion": "0.3.0",
        "url": format!("http://{bind}:{port}/"),
        // Phase C: the server now serves `message/stream` + `tasks/resubscribe`
        // over Server-Sent Events, so streaming is advertised true.
        "capabilities": { "streaming": true },
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": skills,
    })
}

/// The real AgentCard, derived from the process-wide command registry.
fn agent_card(bind: &str, port: u16) -> Value {
    agent_card_from_commands(crate::dispatch::registry().commands(), bind, port)
}

// ── Client-side registry: external A2A agents (CONTRACTS.md §4/§6) ───────────
//
// `state/a2a-agents.json` (v0): the set of EXTERNAL A2A agents this aoide has
// registered by AgentCard URL (`aoide a2a agent add`). Each entry folds into
// the session DAG as a `kind:"a2a"` node (`graph/doc.rs::build_graph`) and is
// the outbound peer `aoide a2a agent send` drives. Tolerate-missing → empty
// (an absent file is simply "no agents registered"); keyed by the card `name`,
// dedupe/replace on re-add. This is the CLIENT half of §6 — the outbound,
// aoide-drives-a-remote-agent direction — mirroring the inbound server above.
//
// Moved to `aoide-storage` (Phase 3a restructure,
// docs/architecture/PACKAGE-LAYOUT.md); re-exported here so every existing
// `crate::a2a::{A2aAgent, load_agents, …}` caller is untouched.
pub use aoide_storage::a2a_store::{
    agents_path, load_agents, remove_agent, save_agents, upsert_agent, A2aAgent, A2aAgentRegistry,
    A2A_AGENTS_VERSION,
};

// ── AgentCard parsing (client side — the shape a REMOTE card presents) ───────

/// Resolve the AgentCard URL to GET from a user-supplied `url`: if it already
/// points at a card (`…/agent-card.json`) use it verbatim, otherwise treat it
/// as an origin and append the well-known path. Pure.
pub fn resolve_card_url(url: &str) -> String {
    let trimmed = url.trim();
    if trimmed.ends_with("agent-card.json") {
        trimmed.to_string()
    } else {
        format!("{}/.well-known/agent-card.json", trimmed.trim_end_matches('/'))
    }
}

/// The `scheme://host[:port]/` origin of a URL (drops path/query) — the
/// fallback `message/send` endpoint when a card names no `url`. Pure.
fn origin_of(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (s, r),
        None => return url.to_string(),
    };
    let host = rest.split('/').next().unwrap_or(rest);
    format!("{scheme}://{host}/")
}

/// The `message/send` endpoint a card advertises: its flat `url` (the A2A
/// v0.3.x JSON-RPC binding — the shape aoide's own card emits), else the first
/// `interfaces[].url` (the v1.0 form), filtered to a non-empty string. Pure.
fn card_endpoint(card: &Value) -> Option<String> {
    if let Some(u) = card
        .get("url")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        return Some(u.to_string());
    }
    card.get("interfaces")
        .and_then(Value::as_array)
        .and_then(|xs| xs.first())
        .and_then(|i| i.get("url"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Parse a fetched AgentCard into a registry entry. Requires at least a
/// non-empty `name`; keeps `description`; resolves the POST endpoint via
/// [`card_endpoint`], falling back to the origin of `fetch_url` (the URL the
/// card was GET'd from). Pure — the fetch itself is the handler's job.
pub fn parse_agent_card(
    card: &Value,
    fetch_url: &str,
    registered_at: &str,
) -> Result<A2aAgent, String> {
    let name = card
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "AgentCard has no `name`".to_string())?;
    let description = card
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let url = card_endpoint(card).unwrap_or_else(|| origin_of(fetch_url));
    Ok(A2aAgent {
        name: name.to_string(),
        url,
        description,
        registered_at: registered_at.to_string(),
    })
}

/// Build the JSON-RPC `message/send` request body aoide POSTs when DRIVING a
/// registered external agent (the outbound half of the bidirectional link).
/// Mirrors the inbound shape [`parse_message_send_params`] reads. Pure — the
/// caller generates `message_id`, so the body stays deterministic in tests.
pub fn build_message_send_body(text: &str, message_id: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "message/send",
        "params": {
            "message": {
                "role": "user",
                "parts": [{ "kind": "text", "text": text }],
                "messageId": message_id,
            }
        }
    })
}

// ── canonical_state → A2A TaskState mapping (CONTRACTS.md §6) ───────────────

/// `canonical_state` (`graph/model.rs`) → A2A `TaskState`, JSON-RPC/HTTP
/// binding spelling (lowercase-kebab):
///
/// | canonical_state       | TaskState         |
/// | ---------------------- | ----------------- |
/// | `working`              | `working`         |
/// | `stopped`               | `completed` (the TURN ended, not the session — CONTRACTS.md §6) |
/// | `awaiting` (no needsSudo) | `input-required` |
/// | `awaiting` + `needsSudo`  | `auth-required` (precedence: needsSudo is a signal alongside state, not a state of its own) |
/// | `idle`                  | `submitted` (aoide's at-rest/cold state — acknowledged but not actively processing; NOT `working`, which is reserved for the active-turn case above) |
/// | `done`                  | `completed` (MVP simplification — CONTRACTS.md §6 flags the richer terminal vocabulary, FAILED/CANCELED/REJECTED, as unresolved in v0) |
pub fn a2a_task_state(canonical: &str, needs_sudo: bool) -> &'static str {
    match canonical {
        "working" => "working",
        "stopped" => "completed",
        "awaiting" => {
            if needs_sudo {
                "auth-required"
            } else {
                "input-required"
            }
        }
        "idle" => "submitted",
        "done" => "completed",
        // canonical_state's own vocabulary is closed to the five states
        // above; a sensible default rather than a panic if it ever grows.
        _ => "working",
    }
}

// ── JSON-RPC 2.0 method routing ──────────────────────────────────────────────

/// `tasks/get id:<sessionId>` — CONTRACTS.md §6 MVP simplification: the A2A
/// Task id and its contextId are BOTH the aoide sessionId (Task=turn vs
/// contextId=session is the real shape; this phase has no multi-task-per-
/// session tracking yet — `tasks/get` always reports the session's CURRENT
/// state, not a specific past turn). TODO(a2a-b3+): splitting Task id from
/// contextId for real per-turn tracking (so a session with several
/// in-flight/completed turns exposes each as its own Task) is still future
/// work — `message/send` (Phase B2) landed the inject/spawn execution
/// semantics but kept this MVP id-collapse.
fn task_from_sessions(
    sessions: &[crate::graph::SessionRecord],
    id: &str,
) -> Result<Value, (i64, String)> {
    let rec = sessions
        .iter()
        .find(|s| s.session_id == id)
        .ok_or_else(|| (-32001_i64, "task not found".to_string()))?;
    let canonical = crate::graph::canonical_state(&rec.state);
    let needs_sudo = rec.needs_sudo.unwrap_or(false);
    let state = a2a_task_state(canonical, needs_sudo);
    Ok(json!({
        "id": rec.session_id,
        // MVP simplification: task id == sessionId, contextId == sessionId —
        // see the doc comment above.
        "contextId": rec.session_id,
        "status": { "state": state, "timestamp": crate::graph::now_iso_utc() },
        "kind": "task",
    }))
}

/// Load `sessions.json` off the stage and resolve one task by id.
fn task_get(task_id: &str) -> Result<Value, (i64, String)> {
    let path = crate::graph::sessions_path();
    let sf: crate::graph::SessionsFile = crate::graph::load_stage(&path)
        .map_err(|e| (-32603_i64, format!("internal error: {e}")))?;
    task_from_sessions(&sf.sessions, task_id)
}

// ── `message/send`: the inject-or-spawn execution door (Phase B2) ───────────
//
// SECURITY MODEL (CONTRACTS.md §6): a `message/send` SPAWN never runs a
// client-supplied command. The executable comes ONLY from
// `aoide.a2a.spawnAgent` — a nix option, resolved once at `a2a serve` launch
// ([`resolve_spawn_agent`]) — which is rebuild-gated: setting it is the
// user's admission, made once at rebuild time, not per-request. This bounds
// what an external A2A client can do to: (1) task the ALREADY-configured
// agent with a prompt (never a command), or (2) steer an EXISTING conductable
// session the same way `graph send` would. If `spawnAgent` is unset (the
// default), spawning is simply unavailable — a structured error, not a
// silent no-op. There is deliberately no interactive per-request gate (unlike
// `graph send`'s pending/--yes/autogate dance): a JSON-RPC request/response
// cannot block on a human clicking "approve" mid-request, so the gate is
// moved entirely to rebuild time, plus the standing loopback bind + the
// Door::A2a audit trail on every inject/spawn/error.

/// What [`decide_send_action`] needs to know about a session named by a
/// `contextId`, decoupled from [`crate::graph::SessionRecord`] so the pure
/// decision stays testable without a stage file on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionRef {
    pub conductable: bool,
    pub has_socket: bool,
}

/// The routing decision `message/send` resolves to — inject into a known
/// session, spawn a fresh conducted one, or a structured JSON-RPC error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendAction {
    Inject { session_id: String },
    Spawn { agent_cmd: String },
    Error { code: i64, msg: String },
}

/// The pure spawn-vs-inject-vs-error decision (CONTRACTS.md §6, "the decided
/// semantics"). No I/O — `session_lookup` is injected so this is unit-testable
/// without a stage file, a socket, or a process.
///
/// - `spawn_asked` (the client set `metadata["aoide/spawn"] == true`) OR a
///   missing `context_id` → **Spawn** the configured agent, or **Error**
///   (`-32004`, "A2A spawn not configured") if `spawn_agent` is empty.
/// - A `context_id` naming a KNOWN, conductable(+socketed) session →
///   **Inject** into it.
/// - A `context_id` naming a known but NOT conductable session → **Error**
///   (`-32004`, "session not conductable").
/// - A `context_id` naming nothing → **Error** (`-32001`, "task not found").
pub fn decide_send_action(
    context_id: Option<&str>,
    spawn_asked: bool,
    spawn_agent: &str,
    session_lookup: impl Fn(&str) -> Option<SessionRef>,
) -> SendAction {
    if spawn_asked || context_id.is_none() {
        return if spawn_agent.is_empty() {
            SendAction::Error {
                code: -32004,
                msg: "A2A spawn not configured".to_string(),
            }
        } else {
            SendAction::Spawn {
                agent_cmd: spawn_agent.to_string(),
            }
        };
    }
    // context_id is Some past this point (the None arm returned above).
    let id = context_id.expect("context_id is Some (checked above)");
    match session_lookup(id) {
        Some(sref) if sref.conductable && sref.has_socket => SendAction::Inject {
            session_id: id.to_string(),
        },
        Some(_) => SendAction::Error {
            code: -32004,
            msg: "session not conductable".to_string(),
        },
        None => SendAction::Error {
            code: -32001,
            msg: "task not found".to_string(),
        },
    }
}

/// Concatenate every text `part`'s `text` field into one prompt — A2A's
/// `Part` union carries `text`/`file`/`data` variants; non-text parts are
/// ignored for this MVP (a richer multi-modal prompt is a later phase). Pure.
fn extract_prompt_text(message: &Value) -> String {
    message
        .get("parts")
        .and_then(Value::as_array)
        .map(|parts| {
            parts
                .iter()
                .filter_map(|p| p.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

/// Resolve `contextId`: prefer `message.contextId`, fall back to the
/// top-level `params.contextId` (both are valid per the A2A JSON-RPC binding;
/// aoide accepts either spot). An empty string is treated as absent. Pure.
fn extract_context_id(message: &Value, params: &Value) -> Option<String> {
    message
        .get("contextId")
        .and_then(Value::as_str)
        .or_else(|| params.get("contextId").and_then(Value::as_str))
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// The explicit-spawn signal: `metadata["aoide/spawn"] == true`, checked on
/// `message.metadata` first, then top-level `params.metadata` (CONTRACTS.md
/// §6 documents this key). Pure.
fn spawn_requested(message: &Value, params: &Value) -> bool {
    let flagged = |v: &Value| {
        v.get("metadata")
            .and_then(|m| m.get("aoide/spawn"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    };
    flagged(message) || flagged(params)
}

/// Parse one `message/send` `params` object into (prompt text, contextId,
/// spawn_asked) — pure, so the parsing itself is unit-testable independent of
/// [`decide_send_action`] and the I/O that follows it.
fn parse_message_send_params(params: &Value) -> (String, Option<String>, bool) {
    let message = params.get("message").cloned().unwrap_or(Value::Null);
    let prompt = extract_prompt_text(&message);
    let context_id = extract_context_id(&message, params);
    let spawn_asked = spawn_requested(&message, params);
    (prompt, context_id, spawn_asked)
}

fn unix_ts_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `session_lookup` for [`decide_send_action`]: read `sessions.json` off the
/// stage and resolve one [`SessionRef`] by id.
fn session_ref_lookup(id: &str) -> Option<SessionRef> {
    let sf: crate::graph::SessionsFile = crate::graph::load_stage(&crate::graph::sessions_path()).ok()?;
    sf.sessions.iter().find(|s| s.session_id == id).map(|s| SessionRef {
        conductable: s.conductable == Some(true),
        has_socket: s.socket.as_deref().map(|v| !v.is_empty()).unwrap_or(false),
    })
}

/// Deliver into a KNOWN, conductable session: reuse
/// [`crate::graph::session_send`] (the same gated injection door `graph send`
/// uses) rather than reimplementing the socket write. Built with `--yes`
/// (message/send's whole point is to deliver now, not queue a pending
/// approval — the A2A door's own admission, rebuild-gating +
/// loopback + audit, already stands in for that gate) and `--submit` (the
/// prompt is a full turn, not a keystroke). Returns the freshly-reloaded Task
/// so the caller sees the state the injection actually produced.
fn do_inject(session_id: &str, prompt: &str, audit_log: &Path) -> Result<Value, (i64, String)> {
    let mut flags = std::collections::BTreeMap::new();
    flags.insert("id".to_string(), session_id.to_string());
    flags.insert("submit".to_string(), "true".to_string());
    flags.insert("yes".to_string(), "true".to_string());
    flags.insert("audit-log".to_string(), audit_log.to_string_lossy().into_owned());
    let inv = Invocation {
        path: vec!["graph".to_string(), "send".to_string()],
        args: vec![prompt.to_string()],
        flags,
        door: Door::A2a,
    };
    let outcome = crate::graph::session_send(&inv);
    if outcome.status != crate::output::Status::Ok {
        return Err((-32603, outcome.message));
    }
    task_get(session_id)
}

/// Best-effort: connect to a just-spawned conducted session's control socket
/// and type `prompt` as its first turn, retrying while the child hasn't
/// bound it yet — the same connect-and-retry shape
/// `graph/conduct.rs`'s own PTY-injection test uses (there, proving the
/// production socket-write path; here, actually driving it). A missed
/// connect after the retry budget is tolerated: the session still exists and
/// is `conductable`, just without its opening turn typed in — a client can
/// always follow up with a plain `graph send`/another `message/send`.
fn spawn_inject_prompt(id: &str, prompt: &str) {
    if prompt.is_empty() {
        return;
    }
    let socket = crate::graph::conduct_socket_path(id);
    let payload = format!("{prompt}\n");
    for _ in 0..300 {
        if socket.exists() {
            if let Ok(mut s) = UnixStream::connect(&socket) {
                let _ = s.write_all(payload.as_bytes());
                let _ = s.flush();
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Spawn a NEW conducted session running the CONFIGURED agent (never a
/// client-supplied command — see the security-model note above `SessionRef`).
/// Detached: launched via the aoide binary's own `conduct` subcommand
/// (`std::env::current_exe()`), `setsid`'d so it survives this handler
/// thread, stdio nulled, and NOT waited on — it is parented to the
/// long-lived `a2a serve` daemon (acceptable for MVP; TODO(a2a-b3+): reap
/// finished A2A-spawned children instead of leaking zombies under a
/// long-lived daemon).
fn do_spawn(agent_cmd: &str, prompt: &str, audit_log: &Path) -> Result<Value, (i64, String)> {
    let id = format!("a2a-{}-{}", std::process::id(), unix_ts_now());
    let aoide_bin = std::env::current_exe()
        .map_err(|e| (-32603_i64, format!("resolving the aoide binary: {e}")))?;

    let mut argv: Vec<String> = vec![
        "conduct".to_string(),
        "--agent".to_string(),
        "a2a".to_string(),
        "--id".to_string(),
        id.clone(),
        "--".to_string(),
    ];
    argv.extend(agent_cmd.split_whitespace().map(str::to_string));

    let mut cmd = std::process::Command::new(&aoide_bin);
    cmd.args(&argv)
        .env("AOIDE_AUDIT_LOG", audit_log)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: `setsid()` is async-signal-safe and is the only call made in
    // this pre_exec hook (same discipline as `graph/conduct.rs::spawn_on_pty`'s
    // pre_exec) — it detaches the child into its own session so it survives
    // this HTTP handler thread's lifetime. A failure here (already a session
    // leader — vanishingly unlikely for a freshly-forked child) is not fatal
    // to the spawn; the child would just inherit our process group instead.
    unsafe {
        cmd.pre_exec(|| {
            let _ = libc::setsid();
            Ok(())
        });
    }

    match cmd.spawn() {
        Ok(_child) => {
            // Best-effort first-turn injection — see the doc comment above.
            spawn_inject_prompt(&id, prompt);
            let _ = daemon::audit(
                audit_log,
                Door::A2a,
                daemon::EventClass::Audit,
                "a2a.message/send",
                "ok",
                &format!("spawned conducted session `{id}` (configured agent)"),
            );
            Ok(json!({
                "id": id,
                "contextId": id,
                "status": { "state": "submitted", "timestamp": crate::graph::now_iso_utc() },
                "kind": "task",
            }))
        }
        Err(e) => {
            let msg = format!("failed to spawn A2A agent: {e}");
            let _ = daemon::audit(
                audit_log,
                Door::A2a,
                daemon::EventClass::Audit,
                "a2a.message/send",
                "error",
                &msg,
            );
            Err((-32603, msg))
        }
    }
}

/// `message/send`: parse params, resolve [`decide_send_action`], execute.
fn message_send(params: &Value, audit_log: &Path, spawn_agent: &str) -> Result<Value, (i64, String)> {
    let (prompt, context_id, spawn_asked) = parse_message_send_params(params);
    match decide_send_action(context_id.as_deref(), spawn_asked, spawn_agent, session_ref_lookup) {
        SendAction::Inject { session_id } => do_inject(&session_id, &prompt, audit_log),
        SendAction::Spawn { agent_cmd } => do_spawn(&agent_cmd, &prompt, audit_log),
        SendAction::Error { code, msg } => Err((code, msg)),
    }
}

/// Handle one parsed JSON-RPC 2.0 request `Value`, returning the response
/// `Value` (always — unlike `mcp.rs`'s stdio notifications, an HTTP POST
/// always gets a reply body). `audit_log`/`spawn_agent` are only consulted by
/// `message/send`.
fn handle_jsonrpc(req: &Value, audit_log: &Path, spawn_agent: &str) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or(Value::Null);

    let result: Result<Value, (i64, String)> = match method {
        "tasks/get" => {
            let task_id = params.get("id").and_then(Value::as_str).unwrap_or("");
            task_get(task_id)
        }
        "message/send" => message_send(&params, audit_log, spawn_agent),
        "" => Err((-32600, "invalid request: missing method".to_string())),
        other => Err((-32601, format!("method not found: {other}"))),
    };

    match result {
        Ok(value) => json!({ "jsonrpc": "2.0", "id": id, "result": value }),
        Err((code, message)) => {
            json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
        }
    }
}

fn jsonrpc_error_value(code: i64, message: impl Into<String>) -> Value {
    json!({ "jsonrpc": "2.0", "id": Value::Null, "error": { "code": code, "message": message.into() } })
}

fn handle_jsonrpc_bytes(body: &[u8], audit_log: &Path, spawn_agent: &str) -> Value {
    match serde_json::from_slice::<Value>(body) {
        Ok(req) => handle_jsonrpc(&req, audit_log, spawn_agent),
        Err(e) => jsonrpc_error_value(-32700, format!("parse error: {e}")),
    }
}

// ── SSE streaming: `message/stream` + `tasks/resubscribe` (Phase C) ──────────
//
// These two methods do NOT take the one-shot `route()`→`write_http_response`
// path: they keep the socket open, write `text/event-stream` headers ONCE,
// and emit a `data:` event whenever the target task's status changes, until
// it reaches a TERMINAL state, the client disconnects, or [`MAX_STREAM`]
// elapses. `message/stream` FIRST runs the send (inject/spawn, reusing
// [`message_send`]) and then streams the resulting task; `tasks/resubscribe`
// streams an already-existing task named by `params.id`.

/// Format one Server-Sent-Events data frame: `data: <json>\n\n`. Pure.
fn sse_event(value: &Value) -> String {
    format!("data: {}\n\n", serde_json::to_string(value).unwrap_or_default())
}

/// A2A terminal `TaskState`s (JSON-RPC binding spelling): once a task reaches
/// one of these it will not change again, so the stream emits its final event
/// and closes. For aoide today only `completed` is actually reachable
/// (canonical `done`/`stopped` → `completed`); `failed`/`canceled`/`rejected`
/// have no canonical_state producer yet (CONTRACTS.md §6) but are recognised
/// as terminal here so a future producer streams correctly with no change. Pure.
fn is_terminal_state(state: &str) -> bool {
    matches!(state, "completed" | "failed" | "canceled" | "rejected")
}

/// Emit-on-change: emit only when this is the first observation (`last` is
/// `None`) or the state differs from the last emitted one. Pure. (The stream
/// loop additionally forces the FINAL event even when the state is unchanged,
/// so a terminal/timeout close is never swallowed.)
fn should_emit(last: Option<&str>, current: &str) -> bool {
    last != Some(current)
}

/// Build the JSON-RPC result envelope for one SSE stream event. A non-final
/// event carries the Task itself as `result`; the FINAL event's `result` is
/// shaped as A2A's `TaskStatusUpdateEvent` (`{taskId, contextId, status,
/// final:true, kind:"status-update"}`) so the client knows it is the last one.
/// Pure — the `task` argument is whatever [`task_get`] produced.
fn build_stream_event(rpc_id: &Value, task: &Value, is_final: bool) -> Value {
    let result = if is_final {
        json!({
            "taskId": task.get("id").cloned().unwrap_or(Value::Null),
            "contextId": task.get("contextId").cloned().unwrap_or(Value::Null),
            "status": task.get("status").cloned().unwrap_or(Value::Null),
            "final": true,
            "kind": "status-update",
        })
    } else {
        task.clone()
    };
    json!({ "jsonrpc": "2.0", "id": rpc_id, "result": result })
}

/// Peek a parsed request: if it's a `POST /` whose JSON-RPC body names a
/// streaming method (`message/stream` / `tasks/resubscribe`), return that
/// method so [`handle_connection`] can hand the socket to [`stream_task`].
/// Everything else (GET card, `tasks/get`, `message/send`, errors) returns
/// `None` and keeps the existing one-shot path. Pure.
fn streaming_method(req: &HttpRequest) -> Option<String> {
    if req.method != "POST" || req.path != "/" {
        return None;
    }
    let v: Value = serde_json::from_slice(&req.body).ok()?;
    match v.get("method").and_then(Value::as_str)? {
        m @ ("message/stream" | "tasks/resubscribe") => Some(m.to_string()),
        _ => None,
    }
}

/// Read the `status.state` string out of a Task JSON (`task_get`'s shape).
fn task_state_of(task: &Value) -> String {
    task.get("status")
        .and_then(|s| s.get("state"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// Take over the socket and stream the target task's status as SSE, until it
/// reaches a terminal state, the client disconnects, or [`MAX_STREAM`] elapses.
/// The request was already fully parsed by [`handle_connection`], so this only
/// ever WRITES the socket (never reads it again) — the 10s read-timeout set on
/// the stream by `handle_connection` therefore cannot interrupt this loop.
fn stream_task<W: Write>(
    writer: &mut W,
    req: &HttpRequest,
    method: &str,
    audit_log: &Path,
    spawn_agent: &str,
) -> std::io::Result<()> {
    let rpc: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
    let rpc_id = rpc.get("id").cloned().unwrap_or(Value::Null);
    let params = rpc.get("params").cloned().unwrap_or(Value::Null);

    // Resolve the target task + its initial state. `message/stream` runs the
    // send FIRST (inject/spawn) and streams the task it produced;
    // `tasks/resubscribe` streams an existing task by id.
    let resolved: Result<Value, (i64, String)> = match method {
        "message/stream" => message_send(&params, audit_log, spawn_agent),
        _ /* tasks/resubscribe */ => {
            match params.get("id").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                Some(id) => task_get(id),
                None => Err((-32001, "task not found".to_string())),
            }
        }
    };

    // SSE response headers — written exactly once, before any event.
    write!(
        writer,
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
    )?;
    writer.flush()?;

    // A resolution error (bad send, unknown resubscribe id) → one SSE event
    // carrying the JSON-RPC error, then close.
    let mut task = match resolved {
        Ok(task) => task,
        Err((code, message)) => {
            let err = json!({
                "jsonrpc": "2.0", "id": rpc_id,
                "error": { "code": code, "message": message },
            });
            let _ = writer.write_all(sse_event(&err).as_bytes());
            let _ = writer.flush();
            let _ = daemon::audit(
                audit_log,
                Door::A2a,
                daemon::EventClass::Audit,
                &format!("a2a.{method}"),
                "error",
                &format!("stream open error {code}"),
            );
            return Ok(());
        }
    };
    // The task id we re-poll each tick — the sessionId (Task id == contextId,
    // MVP id-collapse — see `task_from_sessions`).
    let task_id = task.get("id").and_then(Value::as_str).unwrap_or("").to_string();

    let stream_start = Instant::now();
    let mut last_state: Option<String> = None;
    loop {
        let state = task_state_of(&task);
        // Terminal state OR the absolute duration cap → this is the final event.
        let is_final = is_terminal_state(&state) || stream_start.elapsed() >= MAX_STREAM;

        if should_emit(last_state.as_deref(), &state) || is_final {
            let event = build_stream_event(&rpc_id, &task, is_final);
            // A write/flush failure means the client hung up — best-effort,
            // just stop.
            if writer.write_all(sse_event(&event).as_bytes()).is_err() || writer.flush().is_err() {
                break;
            }
            last_state = Some(state);
        }

        if is_final {
            break;
        }
        std::thread::sleep(STREAM_POLL);

        // Refresh the task off the stage for the next tick. A transient
        // not-found (e.g. a just-spawned session not yet written to
        // sessions.json) keeps the last-known task rather than aborting — the
        // MAX_STREAM cap still bounds the wait, and a real terminal state will
        // be observed as soon as the record settles.
        if let Ok(fresh) = task_get(&task_id) {
            task = fresh;
        }
    }

    let _ = daemon::audit(
        audit_log,
        Door::A2a,
        daemon::EventClass::Audit,
        &format!("a2a.{method}"),
        "ok",
        "stream closed",
    );
    Ok(())
}

// ── Minimal HTTP/1.1 layer (hand-rolled, zero deps) ──────────────────────────

/// One parsed HTTP request: the request line + the body (read exactly
/// `Content-Length` bytes). Headers beyond `Content-Length` are read and
/// discarded — this door doesn't need cookies/auth headers for the MVP.
#[derive(Debug, PartialEq, Eq)]
struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

/// A parse failure, carrying the HTTP status it should become — a plain
/// `String` error can't distinguish "malformed" (400) from "you asked for
/// too much" (413), and `handle_connection` needs that distinction to
/// respond correctly instead of hardcoding 400 for everything.
#[derive(Debug)]
struct ParseError {
    status: u16,
    message: String,
}

impl ParseError {
    fn new(status: u16, message: impl Into<String>) -> Self {
        Self { status, message: message.into() }
    }
}

/// Read one line (the request line, or one header line), bounded to
/// `MAX_LINE` bytes so a newline-less hostile stream can't grow the buffer
/// without limit. `what` names the line for error messages.
///
/// Returns `Ok(None)` on a clean EOF before any bytes of this line arrived
/// (an idle/closed connection — tolerated, same as upstream HTTP servers).
/// Returns `Err` if `MAX_LINE` bytes were read without finding `\n`, or if
/// the connection closed mid-line.
fn read_bounded_line<R: BufRead>(r: &mut R, what: &str) -> Result<Option<String>, ParseError> {
    let mut buf = Vec::new();
    r.by_ref()
        .take(MAX_LINE as u64)
        .read_until(b'\n', &mut buf)
        .map_err(|e| ParseError::new(400, format!("reading {what}: {e}")))?;
    if buf.is_empty() {
        return Ok(None);
    }
    if !buf.ends_with(b"\n") {
        return Err(if buf.len() >= MAX_LINE {
            ParseError::new(400, format!("{what} too long (max {MAX_LINE} bytes)"))
        } else {
            ParseError::new(400, format!("connection closed while reading {what}"))
        });
    }
    Ok(Some(
        String::from_utf8_lossy(&buf).trim_end_matches(['\r', '\n']).to_string(),
    ))
}

/// Parse one HTTP/1.1 request off a `BufRead` — the request line, headers up
/// to the blank line (only `Content-Length` is consulted), then exactly that
/// many body bytes. Pure enough to unit-test against an in-memory buffer
/// (`Cursor`) as well as a real `TcpStream`.
///
/// Every untrusted-length quantity here (request line, each header line,
/// header count, body length) is capped BEFORE it drives an allocation or an
/// unbounded read — see the `MAX_*` constants above — and `start` (the
/// connection's accept time) enforces an absolute wall-clock budget
/// (`MAX_REQUEST`) across the whole parse, on top of the per-read socket
/// timeout `handle_connection` sets.
fn parse_http_request<R: BufRead>(r: &mut R, start: Instant) -> Result<HttpRequest, ParseError> {
    let check_deadline = |what: &str| -> Result<(), ParseError> {
        if start.elapsed() > MAX_REQUEST {
            Err(ParseError::new(400, format!("request deadline exceeded ({what})")))
        } else {
            Ok(())
        }
    };

    let request_line = match read_bounded_line(r, "request line")? {
        Some(l) => l,
        None => {
            return Err(ParseError::new(
                400,
                "connection closed before a request line arrived",
            ))
        }
    };
    check_deadline("after request line")?;

    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| ParseError::new(400, "missing HTTP method"))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| ParseError::new(400, "missing HTTP request-target"))?
        .to_string();
    // The HTTP-version token (3rd word) is read but not otherwise checked —
    // this door only ever needs to understand HTTP/1.1 requests to itself.

    let mut content_length: usize = 0;
    let mut header_count: usize = 0;
    loop {
        if header_count >= MAX_HEADERS {
            return Err(ParseError::new(400, format!("too many headers (max {MAX_HEADERS})")));
        }
        let header_line = match read_bounded_line(r, "header line")? {
            Some(l) => l,
            None => break, // connection closed mid-headers; tolerate (no body to read)
        };
        header_count += 1;
        check_deadline("reading headers")?;
        if header_line.is_empty() {
            break; // the blank line ending the header block
        }
        if let Some((name, value)) = header_line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
    }

    // Reject an oversize body BEFORE allocating anything for it — an
    // untrusted `Content-Length: 999999999999` must never reach a `Vec`
    // allocation (that aborts the whole process on failure, not just this
    // connection).
    if content_length > MAX_BODY {
        return Err(ParseError::new(
            413,
            format!("request body too large: {content_length} bytes (max {MAX_BODY})"),
        ));
    }
    check_deadline("before reading body")?;

    let mut body = Vec::new();
    if content_length > 0 {
        r.by_ref()
            .take(content_length as u64)
            .read_to_end(&mut body)
            .map_err(|e| ParseError::new(400, format!("reading body ({content_length} bytes): {e}")))?;
        if body.len() != content_length {
            return Err(ParseError::new(
                400,
                format!(
                    "connection closed before full body arrived ({} of {content_length} bytes)",
                    body.len()
                ),
            ));
        }
    }

    Ok(HttpRequest { method, path, body })
}

fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    }
}

/// Write one HTTP/1.1 response with a JSON body.
fn write_http_response<W: Write>(w: &mut W, status: u16, body: &[u8]) -> std::io::Result<()> {
    write!(
        w,
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status_reason(status),
        body.len(),
    )?;
    w.write_all(body)?;
    w.flush()
}

// ── Routing ──────────────────────────────────────────────────────────────────

fn not_found(method: &str, path: &str) -> (u16, Vec<u8>, String) {
    let body = jsonrpc_error_value(-32601, format!("not found: {method} {path}"));
    (
        404,
        serde_json::to_vec(&body).unwrap_or_default(),
        "a2a.not-found".to_string(),
    )
}

fn method_not_allowed(method: &str, path: &str) -> (u16, Vec<u8>, String) {
    let body = jsonrpc_error_value(-32600, format!("method not allowed: {method} {path}"));
    (
        405,
        serde_json::to_vec(&body).unwrap_or_default(),
        "a2a.method-not-allowed".to_string(),
    )
}

/// Route one parsed request to (HTTP status, response body, audit-log
/// command label). `audit_log`/`spawn_agent` are only consulted by a POST `/`
/// whose body parses as `message/send` — every other route is pure I/O-free
/// routing over what's already in `req`, so it still unit-tests without a
/// real socket, spawn, or audit-log write.
fn route(
    req: &HttpRequest,
    bind: &str,
    port: u16,
    audit_log: &Path,
    spawn_agent: &str,
) -> (u16, Vec<u8>, String) {
    match req.path.as_str() {
        "/.well-known/agent-card.json" => {
            if req.method == "GET" {
                let card = agent_card(bind, port);
                (
                    200,
                    serde_json::to_vec(&card).unwrap_or_default(),
                    "a2a.agent-card".to_string(),
                )
            } else {
                method_not_allowed(&req.method, &req.path)
            }
        }
        "/" => {
            if req.method == "POST" {
                // Label the audit record with the JSON-RPC method when we can
                // parse enough of the body to see it, even if `handle_jsonrpc`
                // later rejects the request. `method` is attacker-controlled
                // (an unparsed string straight out of the untrusted body) —
                // whitelist it against the known method set rather than
                // interpolating it verbatim, so a hostile body can't bloat
                // the audit log or plant a misleading label (e.g.
                // `a2a.graph.session delete`, or a multi-KB string).
                let parsed_method = serde_json::from_slice::<Value>(&req.body)
                    .ok()
                    .and_then(|v| v.get("method").and_then(Value::as_str).map(str::to_string));
                let label = match parsed_method.as_deref() {
                    Some("tasks/get") => "tasks/get",
                    Some("message/send") => "message/send",
                    _ => "rpc",
                };
                let resp = handle_jsonrpc_bytes(&req.body, audit_log, spawn_agent);
                let body = serde_json::to_vec(&resp).unwrap_or_default();
                (200, body, format!("a2a.{label}"))
            } else {
                method_not_allowed(&req.method, &req.path)
            }
        }
        _ => not_found(&req.method, &req.path),
    }
}

// ── The blocking accept loop ─────────────────────────────────────────────────

/// RAII in-flight-connection-slot guard: decrements [`IN_FLIGHT`] on drop,
/// including on a handler-thread panic, so a slot is always released — a
/// plain `fetch_add`/`fetch_sub` pair around the handler body would leak a
/// slot forever if the handler ever panicked instead of returning `Err`.
struct ConnGuard;

impl Drop for ConnGuard {
    fn drop(&mut self) {
        IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Serve the A2A door: bind `bind:port` and block, handling connections
/// thread-per-connection. Returns on a bind failure (a clean `Err`, never a
/// panic) — the caller (`lib.rs::run_cli`) renders that as the process exit
/// code, same as `mcp serve --stdio`'s failure path.
///
/// A connection flood is bounded by [`MAX_CONN`]: past that many in-flight
/// handler threads, a new connection gets a fast `503` written directly
/// (no handler thread spawned, no `BufReader`/parse work done) rather than
/// growing the thread count without limit.
//
// TODO(a2a-hardening): chunked Transfer-Encoding and extra systemd
// sandboxing (aoide-a2a.service) are deliberately out of scope for this
// pass — see the security-review notes that produced this hardening.
pub fn serve(bind: &str, port: u16, audit_log: &Path, spawn_agent: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind((bind, port))?;
    eprintln!("aoide a2a: listening on http://{bind}:{port}/");
    for incoming in listener.incoming() {
        let mut stream = match incoming {
            Ok(s) => s,
            Err(e) => {
                eprintln!("aoide a2a: accept error: {e}");
                continue;
            }
        };

        let prior = IN_FLIGHT.fetch_add(1, Ordering::SeqCst);
        if prior >= MAX_CONN {
            IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
            let body = jsonrpc_error_value(
                -32000,
                "server busy: too many in-flight connections, try again shortly",
            );
            let body = serde_json::to_vec(&body).unwrap_or_default();
            if let Err(e) = write_http_response(&mut stream, 503, &body) {
                eprintln!("aoide a2a: writing 503 (busy) response: {e}");
            }
            continue;
        }

        let bind = bind.to_string();
        let audit_log = audit_log.to_path_buf();
        let spawn_agent = spawn_agent.to_string();
        std::thread::spawn(move || {
            let _guard = ConnGuard; // released on every exit path, incl. panic
            if let Err(e) = handle_connection(stream, &bind, port, &audit_log, &spawn_agent) {
                eprintln!("aoide a2a: connection error: {e}");
            }
        });
    }
    Ok(())
}

/// Handle one connection: parse exactly one request, route it, audit it,
/// write the response. A malformed request never panics — it becomes a 4xx
/// with a JSON-RPC-style error body, same as every other routing failure.
fn handle_connection(
    stream: TcpStream,
    bind: &str,
    port: u16,
    audit_log: &Path,
    spawn_agent: &str,
) -> std::io::Result<()> {
    // Never let one slow/hostile client wedge a server thread forever: the
    // per-read timeout catches a fully-idle client, and the absolute
    // `MAX_REQUEST` deadline (checked inside `parse_http_request`) catches
    // one that dribbles a byte at a time just inside that timeout.
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;

    let start = Instant::now();
    let req = match parse_http_request(&mut reader, start) {
        Ok(req) => req,
        Err(e) => {
            let b = jsonrpc_error_value(-32700, format!("bad request: {}", e.message));
            let body = serde_json::to_vec(&b).unwrap_or_default();
            let _ = daemon::audit(
                audit_log,
                Door::A2a,
                daemon::EventClass::Audit,
                "a2a.bad-request",
                "error",
                &format!("HTTP {}", e.status),
            );
            return write_http_response(&mut writer, e.status, &body);
        }
    };

    // Phase C: a `message/stream` / `tasks/resubscribe` POST takes over the
    // socket — headers-once + an SSE event loop in `stream_task` — instead of
    // the one-shot `route()`→`write_http_response` path below (which every
    // other request, incl. `tasks/get`/`message/send`, keeps unchanged). The
    // stream open is audited as `Door::A2a` at start; `stream_task` audits its
    // close. (The 10s read-timeout set above is harmless here: `stream_task`
    // only writes the socket, never reads it again.)
    if let Some(method) = streaming_method(&req) {
        let _ = daemon::audit(
            audit_log,
            Door::A2a,
            daemon::EventClass::Audit,
            &format!("a2a.{method}"),
            "open",
            "SSE stream open",
        );
        return stream_task(&mut writer, &req, &method, audit_log, spawn_agent);
    }

    let (status, body, audit_cmd) = route(&req, bind, port, audit_log, spawn_agent);

    // Security/audit (CONTRACTS.md §6): every handled request routes through
    // the single audit log, same discipline as the CLI/MCP doors. The
    // forwarded JSON-RPC body is DATA — it is never executed, only routed
    // through `handle_jsonrpc`'s method dispatch above and logged here.
    // "error" reflects the LOGICAL outcome (an HTTP-200 JSON-RPC error, e.g.
    // `tasks/get` on an unknown id, still audits as an error), not just the
    // HTTP status line — same as `dispatch::dispatch`'s audit, which keys off
    // `Outcome::status` rather than the exit code.
    let is_error = status >= 400
        || serde_json::from_slice::<Value>(&body)
            .ok()
            .is_some_and(|v| v.get("error").is_some());
    let status_word = if is_error { "error" } else { "ok" };
    let _ = daemon::audit(
        audit_log,
        Door::A2a,
        daemon::EventClass::Audit,
        &audit_cmd,
        status_word,
        &format!("HTTP {status}"),
    );

    write_http_response(&mut writer, status, &body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{cmd, Registry};

    fn fake_handler(_inv: &Invocation) -> crate::output::Outcome {
        crate::output::Outcome::ok("fake", "fake")
    }

    // (a) AgentCard generation from a small fake schema.
    #[test]
    fn agent_card_only_advertises_implemented_commands_as_skills() {
        let mut r = Registry::new();
        r.insert(cmd!(
            path: ["foo", "bar"],
            summary: "does a thing",
            args: [],
            flags: [],
            gated: false,
            implemented: true,
            handler: fake_handler,
        ));
        r.insert(cmd!(
            path: ["foo", "stub"],
            summary: "not yet",
            args: [],
            flags: [],
            gated: false,
            implemented: false,
            handler: fake_handler,
        ));

        let card = agent_card_from_commands(r.commands(), "127.0.0.1", 8710);
        assert_eq!(card["name"], "aoide");
        assert_eq!(card["version"], crate::registry::AOIDE_VERSION);
        assert_eq!(card["url"], "http://127.0.0.1:8710/");
        assert_eq!(card["capabilities"]["streaming"], true);

        let skills = card["skills"].as_array().unwrap();
        assert_eq!(skills.len(), 1, "only the implemented command becomes a skill");
        assert_eq!(skills[0]["id"], "foo.bar");
        assert_eq!(skills[0]["name"], "foo.bar");
        assert_eq!(skills[0]["description"], "does a thing");
        assert_eq!(skills[0]["tags"][0], "foo");
    }

    // (b) canonical_state -> TaskState mapping, incl. needs_sudo precedence.
    #[test]
    fn task_state_mapping_matches_contracts_section_6() {
        assert_eq!(a2a_task_state("working", false), "working");
        assert_eq!(a2a_task_state("stopped", false), "completed");
        assert_eq!(a2a_task_state("awaiting", false), "input-required");
        // needsSudo takes precedence over the plain awaiting->input-required.
        assert_eq!(a2a_task_state("awaiting", true), "auth-required");
        assert_eq!(a2a_task_state("idle", false), "submitted");
        assert_eq!(a2a_task_state("done", false), "completed");
    }

    fn fixture_session(id: &str, state: &str, needs_sudo: Option<bool>) -> crate::graph::SessionRecord {
        crate::graph::SessionRecord {
            session_id: id.to_string(),
            state: state.to_string(),
            needs_sudo,
            ..Default::default()
        }
    }

    // (c) JSON-RPC request parse + method routing.
    #[test]
    fn tasks_get_resolves_a_known_session_and_maps_its_state() {
        let sessions = vec![fixture_session("sess-1", "awaiting", Some(true))];
        let task = task_from_sessions(&sessions, "sess-1").unwrap();
        assert_eq!(task["id"], "sess-1");
        assert_eq!(task["contextId"], "sess-1");
        assert_eq!(task["status"]["state"], "auth-required");
        assert_eq!(task["kind"], "task");
        assert!(task["status"]["timestamp"].as_str().unwrap().ends_with('Z'));
    }

    #[test]
    fn tasks_get_unknown_id_is_a_structured_error() {
        let sessions = vec![fixture_session("sess-1", "working", None)];
        let err = task_from_sessions(&sessions, "nope").unwrap_err();
        assert_eq!(err.0, -32001);
        assert_eq!(err.1, "task not found");
    }

    // ── `decide_send_action` — every branch (pure, no I/O) ───────────────────

    #[test]
    fn decide_send_action_spawn_asked_wins_even_with_a_valid_contextid() {
        // spawn_asked == true short-circuits the contextId lookup entirely —
        // the closure below panics if it's ever consulted.
        let action = decide_send_action(Some("sess-1"), true, "claude", |_| {
            panic!("session_lookup must not be consulted when spawn is explicitly asked")
        });
        assert_eq!(action, SendAction::Spawn { agent_cmd: "claude".to_string() });
    }

    #[test]
    fn decide_send_action_no_context_id_spawns() {
        let action = decide_send_action(None, false, "claude", |_| {
            panic!("session_lookup must not be consulted with no contextId")
        });
        assert_eq!(action, SendAction::Spawn { agent_cmd: "claude".to_string() });
    }

    #[test]
    fn decide_send_action_spawn_disabled_is_a_structured_error() {
        // No contextId AND an empty spawn_agent (the default,
        // `aoide.a2a.spawnAgent = ""`) → a structured error, not a silent
        // no-op and not a fallback to something else.
        let action = decide_send_action(None, false, "", |_| {
            panic!("session_lookup must not be consulted with no contextId")
        });
        assert_eq!(
            action,
            SendAction::Error { code: -32004, msg: "A2A spawn not configured".to_string() }
        );
        // Same error when spawn IS explicitly asked but nothing is configured.
        let action2 = decide_send_action(Some("sess-1"), true, "", |_| None);
        assert_eq!(
            action2,
            SendAction::Error { code: -32004, msg: "A2A spawn not configured".to_string() }
        );
    }

    #[test]
    fn decide_send_action_known_conductable_session_injects() {
        let action = decide_send_action(Some("sess-1"), false, "claude", |id| {
            assert_eq!(id, "sess-1");
            Some(SessionRef { conductable: true, has_socket: true })
        });
        assert_eq!(action, SendAction::Inject { session_id: "sess-1".to_string() });
    }

    #[test]
    fn decide_send_action_known_but_not_conductable_is_an_error() {
        // Registered but not conductable (no control socket) — same shape as
        // `graph send`'s own `not-conductable` rejection.
        let action = decide_send_action(Some("plain"), false, "claude", |_| {
            Some(SessionRef { conductable: false, has_socket: false })
        });
        assert_eq!(
            action,
            SendAction::Error { code: -32004, msg: "session not conductable".to_string() }
        );
        // Conductable but socket-less (a bind failure at conduct time) is the
        // same rejection — `has_socket` gates it too.
        let action2 = decide_send_action(Some("nosock"), false, "claude", |_| {
            Some(SessionRef { conductable: true, has_socket: false })
        });
        assert_eq!(
            action2,
            SendAction::Error { code: -32004, msg: "session not conductable".to_string() }
        );
    }

    #[test]
    fn decide_send_action_unknown_context_id_is_task_not_found() {
        let action = decide_send_action(Some("ghost"), false, "claude", |_| None);
        assert_eq!(
            action,
            SendAction::Error { code: -32001, msg: "task not found".to_string() }
        );
    }

    // ── `message/send` param parsing (pure, no I/O) ──────────────────────────

    #[test]
    fn extract_prompt_text_concatenates_text_parts_and_ignores_others() {
        let message = json!({
            "parts": [
                { "kind": "text", "text": "hello" },
                { "kind": "file", "uri": "ignored://non-text-part" },
                { "kind": "text", "text": "world" },
            ]
        });
        assert_eq!(extract_prompt_text(&message), "hello\nworld");
        // No parts at all → empty prompt, not a panic.
        assert_eq!(extract_prompt_text(&json!({})), "");
    }

    #[test]
    fn extract_context_id_prefers_message_then_falls_back_to_params() {
        // message.contextId wins over params.contextId when both are present.
        let message = json!({ "contextId": "from-message" });
        let params = json!({ "contextId": "from-params" });
        assert_eq!(extract_context_id(&message, &params), Some("from-message".to_string()));
        // Falls back to params.contextId when the message carries none.
        assert_eq!(
            extract_context_id(&json!({}), &params),
            Some("from-params".to_string())
        );
        // Neither present, or an empty string, is treated as absent.
        assert_eq!(extract_context_id(&json!({}), &json!({})), None);
        assert_eq!(
            extract_context_id(&json!({ "contextId": "" }), &json!({})),
            None
        );
    }

    #[test]
    fn spawn_requested_reads_the_aoide_spawn_metadata_key() {
        // The documented key, on the message object.
        let message = json!({ "metadata": { "aoide/spawn": true } });
        assert!(spawn_requested(&message, &json!({})));
        // Or on the top-level params object.
        let params = json!({ "metadata": { "aoide/spawn": true } });
        assert!(spawn_requested(&json!({}), &params));
        // Absent, false, or a non-boolean value → not requested.
        assert!(!spawn_requested(&json!({}), &json!({})));
        assert!(!spawn_requested(
            &json!({ "metadata": { "aoide/spawn": false } }),
            &json!({})
        ));
        assert!(!spawn_requested(
            &json!({ "metadata": { "aoide/spawn": "true" } }),
            &json!({})
        ));
    }

    #[test]
    fn parse_message_send_params_extracts_all_three_fields_together() {
        let params = json!({
            "message": {
                "role": "user",
                "parts": [{ "kind": "text", "text": "do the thing" }],
                "contextId": "sess-9",
                "metadata": { "aoide/spawn": true },
            }
        });
        let (prompt, context_id, spawn_asked) = parse_message_send_params(&params);
        assert_eq!(prompt, "do the thing");
        assert_eq!(context_id.as_deref(), Some("sess-9"));
        assert!(spawn_asked);

        // A minimal params with no `message` at all is tolerated, not a panic.
        let (prompt2, context_id2, spawn_asked2) = parse_message_send_params(&json!({}));
        assert_eq!(prompt2, "");
        assert_eq!(context_id2, None);
        assert!(!spawn_asked2);
    }

    // ── `message/send` end-to-end via `handle_jsonrpc` — ERROR branches only.
    // Every one of these resolves to `SendAction::Error` before touching a
    // socket or a process, so none of them spawn or bind (house rule: no
    // real spawn/socket/bind in this suite).

    #[test]
    fn message_send_with_no_context_and_spawning_disabled_is_a2a_dash_32004() {
        let req = json!({
            "jsonrpc": "2.0", "id": 1, "method": "message/send",
            "params": { "message": { "parts": [{ "kind": "text", "text": "hi" }] } }
        });
        // spawn_agent == "" (the default) → decide_send_action errors out
        // before any process would be spawned.
        let resp = handle_jsonrpc(&req, Path::new("/dev/null"), "");
        assert_eq!(resp["error"]["code"], -32004);
        assert_eq!(resp["error"]["message"], "A2A spawn not configured");
        assert_eq!(resp["id"], 1);
    }

    #[test]
    fn message_send_end_to_end_unknown_and_unconductable_contexts_are_clean_errors() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = std::env::temp_dir().join(format!(
            "aoide-a2a-send-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // A registered session with no control socket (not conductable).
        let sf = crate::graph::SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![fixture_session("plain", "working", None)],
        };
        crate::graph::write_stage(&crate::graph::sessions_path(), &sf).unwrap();

        // Unknown contextId → -32001 (never reaches the socket/spawn layer).
        let req = json!({
            "jsonrpc": "2.0", "id": 1, "method": "message/send",
            "params": { "message": {
                "parts": [{ "kind": "text", "text": "hi" }],
                "contextId": "ghost",
            } }
        });
        let resp = handle_jsonrpc(&req, Path::new("/dev/null"), "claude");
        assert_eq!(resp["error"]["code"], -32001);

        // Known but not conductable → -32004 "session not conductable".
        let req2 = json!({
            "jsonrpc": "2.0", "id": 2, "method": "message/send",
            "params": { "message": {
                "parts": [{ "kind": "text", "text": "hi" }],
                "contextId": "plain",
            } }
        });
        let resp2 = handle_jsonrpc(&req2, Path::new("/dev/null"), "claude");
        assert_eq!(resp2["error"]["code"], -32004);
        assert_eq!(resp2["error"]["message"], "session not conductable");

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn unknown_method_is_minus_32601() {
        let req = json!({ "jsonrpc": "2.0", "id": 2, "method": "bogus/verb", "params": {} });
        let resp = handle_jsonrpc(&req, Path::new("/dev/null"), "");
        assert_eq!(resp["error"]["code"], -32601);
    }

    #[test]
    fn tasks_get_end_to_end_reads_the_stage_sessions_file() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = std::env::temp_dir().join(format!(
            "aoide-a2a-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let sf = crate::graph::SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![fixture_session("s1", "stopped", None)],
        };
        crate::graph::write_stage(&crate::graph::sessions_path(), &sf).unwrap();

        let req = json!({ "jsonrpc": "2.0", "id": 7, "method": "tasks/get", "params": { "id": "s1" } });
        let resp = handle_jsonrpc(&req, Path::new("/dev/null"), "");
        assert_eq!(resp["result"]["status"]["state"], "completed");

        let req = json!({ "jsonrpc": "2.0", "id": 8, "method": "tasks/get", "params": { "id": "ghost" } });
        let resp = handle_jsonrpc(&req, Path::new("/dev/null"), "");
        assert_eq!(resp["error"]["code"], -32001);

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    // (d) the HTTP request parse (request line + Content-Length body).
    #[test]
    fn parse_http_request_reads_request_line_and_body() {
        let raw = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 12\r\n\r\n{\"a\":\"body\"}";
        let mut r = BufReader::new(std::io::Cursor::new(&raw[..]));
        let req = parse_http_request(&mut r, Instant::now()).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/");
        assert_eq!(req.body, b"{\"a\":\"body\"}");
    }

    #[test]
    fn parse_http_request_handles_a_get_with_no_body() {
        let raw = b"GET /.well-known/agent-card.json HTTP/1.1\r\nHost: x\r\n\r\n";
        let mut r = BufReader::new(std::io::Cursor::new(&raw[..]));
        let req = parse_http_request(&mut r, Instant::now()).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/.well-known/agent-card.json");
        assert!(req.body.is_empty());
    }

    // ── Hostile-input regressions (security review, pre-commit) ─────────────
    //
    // All of these feed crafted bytes straight to `parse_http_request` via an
    // in-memory `Cursor` — no real socket, no sleeping, so they can't hang or
    // flake. Each one exercises a cap that, before this pass, was either
    // absent (unbounded alloc/read) or untested.

    #[test]
    fn content_length_over_max_body_is_rejected_before_any_large_allocation() {
        // A `Content-Length` far past MAX_BODY must error out of the header
        // loop WITHOUT ever reaching the body-allocation step below it — if
        // this test hangs or OOMs instead of returning quickly, the cap
        // isn't being enforced before the allocation.
        let raw = format!(
            "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        let mut r = BufReader::new(std::io::Cursor::new(raw.as_bytes()));
        let err = parse_http_request(&mut r, Instant::now()).unwrap_err();
        assert_eq!(err.status, 413);
        assert!(err.message.contains("too large"), "message: {}", err.message);
    }

    #[test]
    fn a_content_length_of_exactly_max_body_is_not_rejected_by_the_cap() {
        // Boundary check: MAX_BODY itself is still allowed by the cap (it's
        // an inclusive limit) — it should fail later, on the short read
        // (Cursor has no body bytes), not on the size check.
        let raw = format!("POST / HTTP/1.1\r\nContent-Length: {MAX_BODY}\r\n\r\n");
        let mut r = BufReader::new(std::io::Cursor::new(raw.as_bytes()));
        let err = parse_http_request(&mut r, Instant::now()).unwrap_err();
        assert!(!err.message.contains("too large"), "message: {}", err.message);
    }

    #[test]
    fn a_request_line_with_no_newline_past_max_line_is_rejected() {
        // No `\n` anywhere — a hostile stream that would otherwise grow the
        // line buffer without bound. Longer than MAX_LINE so the cap (not
        // Cursor EOF) is what triggers the error.
        let raw = vec![b'A'; MAX_LINE + 1];
        let mut r = BufReader::new(std::io::Cursor::new(raw));
        let err = parse_http_request(&mut r, Instant::now()).unwrap_err();
        assert_eq!(err.status, 400);
        assert!(err.message.contains("too long"), "message: {}", err.message);
    }

    #[test]
    fn a_header_line_with_no_newline_past_max_line_is_rejected() {
        let mut raw = b"GET / HTTP/1.1\r\n".to_vec();
        raw.extend(std::iter::repeat(b'A').take(MAX_LINE + 1));
        let mut r = BufReader::new(std::io::Cursor::new(raw));
        let err = parse_http_request(&mut r, Instant::now()).unwrap_err();
        assert_eq!(err.status, 400);
        assert!(err.message.contains("too long"), "message: {}", err.message);
    }

    #[test]
    fn more_than_max_headers_is_rejected() {
        let mut raw = b"GET / HTTP/1.1\r\n".to_vec();
        for i in 0..=MAX_HEADERS {
            raw.extend_from_slice(format!("X-Filler-{i}: x\r\n").as_bytes());
        }
        raw.extend_from_slice(b"\r\n");
        let mut r = BufReader::new(std::io::Cursor::new(raw));
        let err = parse_http_request(&mut r, Instant::now()).unwrap_err();
        assert_eq!(err.status, 400);
        assert!(err.message.contains("too many headers"), "message: {}", err.message);
    }

    #[test]
    fn a_valid_small_request_still_parses_under_the_new_caps() {
        // Regression: none of the new caps should reject an ordinary,
        // well-formed request.
        let raw = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}";
        let mut r = BufReader::new(std::io::Cursor::new(&raw[..]));
        let req = parse_http_request(&mut r, Instant::now()).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/");
        assert_eq!(req.body, b"{}");
    }

    // ── SSE streaming helpers (Phase C — pure, no socket, no sleep) ─────────

    #[test]
    fn sse_event_frames_json_as_a_data_line() {
        let v = json!({ "a": 1 });
        assert_eq!(sse_event(&v), "data: {\"a\":1}\n\n");
    }

    #[test]
    fn is_terminal_state_covers_the_four_a2a_terminal_states_only() {
        for terminal in ["completed", "failed", "canceled", "rejected"] {
            assert!(is_terminal_state(terminal), "{terminal} should be terminal");
        }
        for live in ["working", "submitted", "input-required", "auth-required", ""] {
            assert!(!is_terminal_state(live), "{live} should NOT be terminal");
        }
    }

    #[test]
    fn should_emit_fires_on_first_observation_and_on_change_but_not_on_repeat() {
        // First observation (nothing emitted yet) always emits.
        assert!(should_emit(None, "working"));
        // A changed state emits.
        assert!(should_emit(Some("working"), "completed"));
        // The same state again does NOT emit (the loop's `|| is_final` still
        // forces the terminal/timeout event separately).
        assert!(!should_emit(Some("working"), "working"));
    }

    #[test]
    fn build_stream_event_non_final_carries_the_task_and_final_is_a_status_update() {
        let task = json!({
            "id": "sess-1",
            "contextId": "sess-1",
            "status": { "state": "working", "timestamp": "2026-01-01T00:00:00Z" },
            "kind": "task",
        });
        // Non-final: the result IS the task, no `final` marker.
        let ev = build_stream_event(&json!(7), &task, false);
        assert_eq!(ev["jsonrpc"], "2.0");
        assert_eq!(ev["id"], 7);
        assert_eq!(ev["result"]["kind"], "task");
        assert_eq!(ev["result"]["status"]["state"], "working");
        assert!(ev["result"].get("final").is_none());

        // Final: a TaskStatusUpdateEvent with `final: true`.
        let done = json!({
            "id": "sess-1",
            "contextId": "sess-1",
            "status": { "state": "completed", "timestamp": "2026-01-01T00:00:01Z" },
            "kind": "task",
        });
        let fev = build_stream_event(&json!(7), &done, true);
        assert_eq!(fev["result"]["kind"], "status-update");
        assert_eq!(fev["result"]["final"], true);
        assert_eq!(fev["result"]["taskId"], "sess-1");
        assert_eq!(fev["result"]["contextId"], "sess-1");
        assert_eq!(fev["result"]["status"]["state"], "completed");
    }

    #[test]
    fn streaming_method_only_matches_the_two_sse_methods_on_post_root() {
        let mk = |method: &str, path: &str, body: &str| HttpRequest {
            method: method.into(),
            path: path.into(),
            body: body.as_bytes().to_vec(),
        };
        assert_eq!(
            streaming_method(&mk("POST", "/", r#"{"method":"message/stream"}"#)).as_deref(),
            Some("message/stream")
        );
        assert_eq!(
            streaming_method(&mk("POST", "/", r#"{"method":"tasks/resubscribe"}"#)).as_deref(),
            Some("tasks/resubscribe")
        );
        // A one-shot method is NOT a streaming method.
        assert_eq!(streaming_method(&mk("POST", "/", r#"{"method":"message/send"}"#)), None);
        assert_eq!(streaming_method(&mk("POST", "/", r#"{"method":"tasks/get"}"#)), None);
        // Wrong verb / path / unparseable body → not a stream.
        assert_eq!(streaming_method(&mk("GET", "/", r#"{"method":"message/stream"}"#)), None);
        assert_eq!(streaming_method(&mk("POST", "/other", r#"{"method":"message/stream"}"#)), None);
        assert_eq!(streaming_method(&mk("POST", "/", "not json")), None);
    }

    // Routing: non-matching path/method -> 404/405 with a JSON-RPC-style body.
    #[test]
    fn unknown_path_is_404_and_wrong_method_on_a_known_path_is_405() {
        let (status, body, _) = route(
            &HttpRequest { method: "GET".into(), path: "/nope".into(), body: vec![] },
            "127.0.0.1",
            8710,
            Path::new("/dev/null"),
            "",
        );
        assert_eq!(status, 404);
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert!(v["error"]["code"].is_i64());

        let (status, body, _) = route(
            &HttpRequest {
                method: "GET".into(),
                path: "/".into(),
                body: vec![],
            },
            "127.0.0.1",
            8710,
            Path::new("/dev/null"),
            "",
        );
        assert_eq!(status, 405);
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert!(v["error"]["code"].is_i64());
    }

    // ── Client-side registry: CRUD (pure, in-memory) ─────────────────────────

    fn fixture_agent(name: &str, url: &str) -> A2aAgent {
        A2aAgent {
            name: name.to_string(),
            url: url.to_string(),
            description: format!("{name} desc"),
            registered_at: "2026-08-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn upsert_agent_appends_then_dedupes_by_name() {
        let mut agents: Vec<A2aAgent> = Vec::new();
        upsert_agent(&mut agents, fixture_agent("alpha", "http://a/"));
        upsert_agent(&mut agents, fixture_agent("beta", "http://b/"));
        assert_eq!(agents.len(), 2);

        // Re-add `alpha` with a new endpoint → REPLACE in place (dedupe by name),
        // preserving order, not a second entry.
        let mut updated = fixture_agent("alpha", "http://a-new/");
        updated.description = "updated".into();
        upsert_agent(&mut agents, updated);
        assert_eq!(agents.len(), 2, "re-add replaces, never duplicates");
        assert_eq!(agents[0].name, "alpha");
        assert_eq!(agents[0].url, "http://a-new/");
        assert_eq!(agents[0].description, "updated");
    }

    #[test]
    fn remove_agent_is_idempotent() {
        let mut agents = vec![fixture_agent("alpha", "http://a/"), fixture_agent("beta", "http://b/")];
        assert!(remove_agent(&mut agents, "alpha"));
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].name, "beta");
        // Removing an absent name is a no-op that reports `false`.
        assert!(!remove_agent(&mut agents, "alpha"));
        assert_eq!(agents.len(), 1);
    }

    // `load_save_agents_round_trip_through_a_temp_state_dir` moved to
    // `aoide-storage`'s `a2a_store::tests` alongside `load_agents`/
    // `save_agents`/`agents_path` (Phase 3a restructure) — those are no
    // longer defined in this crate, only re-exported, so a real-I/O test of
    // them belongs where they're actually implemented.

    // ── AgentCard parsing (client side) ──────────────────────────────────────

    #[test]
    fn parse_agent_card_reads_name_description_and_card_url_endpoint() {
        // A card that names its own flat `url` (aoide's own v0.3.x shape): the
        // endpoint is that url, not the fetch origin.
        let card = json!({
            "name": "peer",
            "description": "a friendly agent",
            "url": "http://10.0.0.5:8710/",
            "skills": [],
        });
        let agent = parse_agent_card(&card, "http://10.0.0.5:8710/.well-known/agent-card.json", "NOW").unwrap();
        assert_eq!(agent.name, "peer");
        assert_eq!(agent.description, "a friendly agent");
        assert_eq!(agent.url, "http://10.0.0.5:8710/");
        assert_eq!(agent.registered_at, "NOW");
    }

    #[test]
    fn parse_agent_card_falls_back_to_fetch_origin_and_v1_interfaces() {
        // No flat `url` → fall back to the origin of the fetch URL.
        let card = json!({ "name": "originless" });
        let agent = parse_agent_card(&card, "http://host:9000/.well-known/agent-card.json", "T").unwrap();
        assert_eq!(agent.url, "http://host:9000/");
        assert_eq!(agent.description, "");

        // v1.0 `interfaces` array form → first interface url wins.
        let card = json!({
            "name": "v1",
            "interfaces": [{ "transport": "JSONRPC", "url": "http://host:9000/rpc" }],
        });
        let agent = parse_agent_card(&card, "http://host:9000/x", "T").unwrap();
        assert_eq!(agent.url, "http://host:9000/rpc");
    }

    #[test]
    fn parse_agent_card_missing_name_is_an_error() {
        assert!(parse_agent_card(&json!({ "description": "no name here" }), "http://x/", "T").is_err());
        // A present-but-empty name is also rejected.
        assert!(parse_agent_card(&json!({ "name": "  " }), "http://x/", "T").is_err());
    }

    #[test]
    fn resolve_card_url_appends_well_known_unless_already_a_card() {
        assert_eq!(
            resolve_card_url("http://127.0.0.1:8710"),
            "http://127.0.0.1:8710/.well-known/agent-card.json"
        );
        // Trailing slash is not doubled.
        assert_eq!(
            resolve_card_url("http://127.0.0.1:8710/"),
            "http://127.0.0.1:8710/.well-known/agent-card.json"
        );
        // An explicit card URL is used verbatim.
        assert_eq!(
            resolve_card_url("http://h/.well-known/agent-card.json"),
            "http://h/.well-known/agent-card.json"
        );
    }

    // ── The outbound message/send request-body builder (pure) ────────────────

    #[test]
    fn build_message_send_body_matches_the_jsonrpc_shape() {
        let body = build_message_send_body("hello there", "mid-123");
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["id"], 1);
        assert_eq!(body["method"], "message/send");
        let msg = &body["params"]["message"];
        assert_eq!(msg["role"], "user");
        assert_eq!(msg["messageId"], "mid-123");
        let parts = msg["parts"].as_array().unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0]["kind"], "text");
        assert_eq!(parts[0]["text"], "hello there");

        // The body this builds is exactly what the server's inbound parser reads
        // back out (round-trip through `parse_message_send_params`).
        let (prompt, ctx, spawn) = parse_message_send_params(&body["params"]);
        assert_eq!(prompt, "hello there");
        assert_eq!(ctx, None);
        assert!(!spawn);
    }
}
