//! The A2A (Agent2Agent) door — a hand-rolled, dependency-free JSON-RPC 2.0
//! over HTTP/1.1 server (CONTRACTS.md §6, Phase B: server MVP, now with
//! `message/send` execution — Phase B2).
//!
//! Zero new crates: a blocking `TcpListener` accept loop (thread-per-
//! connection), a minimal HTTP/1.1 request/response layer hand-parsed off
//! `BufRead`/`Write` (the same "no clap/no tokio, offline cargo lock stays
//! pure" discipline root's `cli.rs` and `aoide-conduct`'s `graph/conduct.rs`
//! already follow), and `serde_json::Value` for the JSON-RPC envelope
//! (mirroring `mcp.rs`'s stdio JSON-RPC server — this is that same shape over
//! a socket instead of stdio).
//!
//! Routes (CONTRACTS.md §6 MVP surface, plus §7's peer federation):
//!   - `GET  /.well-known/agent-card.json` — the AgentCard, derived from the
//!     command registry, filtered to `implemented: true`.
//!   - `POST /` — JSON-RPC 2.0: `tasks/get` (real), `message/send` (real —
//!     inject into a known conductable session, or spawn a freshly conducted
//!     one; [`decide_send_action`] below — a non-loopback Inject queues
//!     pending unless the caller matches an `autogate` peer, CONTRACTS.md §6
//!     amendment 2026-08-14; see [`PeerOrigin`]/[`should_deliver_now`]),
//!     `aoide/graphSummary` (real — CONTRACTS.md §7: wraps
//!     [`resolve_graph_document`] in the federation envelope; see
//!     [`graph_summary`]), anything else → `-32601 method not found`.
//!
//! A forwarded A2A message's TEXT is untrusted DATA, never executed as a
//! command — `message/send`'s inject path types it into a target session
//! exactly like `graph send` (in fact it reuses
//! [`aoide_conduct::graph::session_send`] for that), and its spawn path never
//! runs a client-supplied command: it only ever launches the
//! operator-configured `aoide.a2a.spawnAgent` executable (a rebuild-gated nix
//! option — the user's admission), with the client-supplied prompt injected
//! as its first turn. See [`decide_send_action`]'s doc comment for the full
//! security model.
//!
//! Extracted from root `src/a2a.rs` (Phase 4c restructure,
//! docs/architecture/PACKAGE-LAYOUT.md) — this is the SERVER half only. The
//! CLIENT half (the external-agent registry, AgentCard parsing, the outbound
//! request builder) stays in root/`aoide-client`/`aoide-storage`, unchanged
//! from Phase 4a/4b.
//!
//! **DI seam (the one non-mechanical part of this phase):** [`agent_card`],
//! [`route`], [`handle_connection`], and [`serve`] used to reach the
//! crate-global `dispatch::registry()`. That registry is the fully-assembled
//! command set (`commands::all()`, root-only, not moving until Phase 6
//! `cli`) — a `server` crate can't depend on it without becoming
//! `server → root`. So the registry is a parameter here instead; root
//! `lib.rs`'s `a2a serve` launch site passes `dispatch::registry()` in.
//! `handle_jsonrpc`/`message_send`/`tasks/get` etc. never needed the registry
//! (they only ever touched session state), so they're untouched.

use aoide_conduct::graph::{
    canonical_state, load_stage, now_iso_utc, resolve_graph_document, session_send,
    sessions_path, SessionRecord, SessionsFile,
};
use aoide_protocol::output::Status;
use aoide_protocol::registry::{Command, Registry};
use aoide_protocol::wire::{
    AgentCapabilities, AgentCard, AgentSkill, JsonRpcResponse, Task, TaskStatus,
    TaskStatusUpdateEvent,
};
use aoide_protocol::{audit, Door, EventClass, Invocation};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

#[cfg(test)]
use aoide_conduct::graph::write_stage;
#[cfg(test)]
use std::os::unix::net::UnixListener;

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

/// Resolve `aoide.a2a.tokenFile`: the path to a file holding the shared
/// secret a caller must present (`Authorization: Bearer <token>`) to be
/// trusted as an authenticated caller (CONTRACTS.md §6 amendment,
/// 2026-08-18) — required before Spawn runs at all, and the switch that
/// decouples loopback's free pass once it's set (see [`effective_origin`]).
/// `--token-file` flag → `AOIDE_A2A_TOKEN_FILE` env (set by the `aoide-a2a`
/// systemd unit) → default `""` (empty = no token required — today's fully
/// open behavior, unchanged). Mirrors [`resolve_spawn_agent`]'s exact
/// precedence shape. Only a FILE PATH ever crosses a flag/env var — the
/// secret itself is read off disk once, at `a2a serve` launch
/// ([`read_expected_token`]), never passed as a flag value directly (argv is
/// world-readable via `/proc/*/cmdline`) and never logged.
pub fn resolve_token_file(inv: &Invocation) -> String {
    inv.flags
        .get("token-file")
        .cloned()
        .or_else(|| std::env::var("AOIDE_A2A_TOKEN_FILE").ok())
        .unwrap_or_default()
}

/// Read the expected A2A token off [`resolve_token_file`]'s resolved path.
/// An empty path resolves to `None` outright (feature off, no disk read at
/// all). A missing/unreadable file, or one that's empty/whitespace-only,
/// ALSO resolves to `None` rather than a hard launch failure — MVP
/// tolerance, matching the other `resolve_*` functions' soft-fallback
/// stance. Trimmed once so a trailing newline from `echo >file`/an editor
/// doesn't become part of the secret.
pub fn read_expected_token(token_file: &str) -> Option<String> {
    if token_file.is_empty() {
        return None;
    }
    std::fs::read_to_string(token_file)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Resolve this instance's `aoide/graphSummary` `instance.name` (CONTRACTS.md
/// §7): `--peer-name` flag → `AOIDE_A2A_PEER_NAME` env (set by the
/// `aoide-a2a` systemd unit, mirroring `resolve_bind_port`/
/// `resolve_spawn_agent`'s precedence) → the OS hostname → the literal
/// `"aoide"` if even that fails. The env/hostname tail is
/// `aoide_storage::display::local_host_name` (petnames plan, P2): storage
/// has no `Invocation` to read the flag off, so this crate still resolves
/// the flag itself and only delegates the rest. Resolved once at `a2a serve`
/// launch, same as bind/port/spawn-agent.
pub fn resolve_peer_name(inv: &Invocation) -> String {
    // The env/hostname tail (env var -> OS hostname -> "aoide") is delegated
    // to `aoide_storage::display::local_host_name` — the storage crate's copy
    // is byte-identical (conduct/conductor renderers need the same fallback
    // chain and cannot depend on this crate), so this resolves it once
    // instead of keeping a second copy in sync. The `--peer-name` flag stays
    // here: storage has no `Invocation` to read a flag off.
    inv.flags
        .get("peer-name")
        .cloned()
        .unwrap_or_else(aoide_storage::display::local_host_name)
}

// ── Where a `message/send`/`message/stream` connection originated ───────────
//
// CONTRACTS.md §6 amendment (2026-08-14): the non-loopback pending-gate fix.
// A connection's ORIGIN (not any client-supplied field — TCP `peer_addr()`,
// which a hostile client cannot spoof from off-box) decides whether an
// Inject auto-delivers or queues pending, exactly the same shape `graph
// send`'s own gate already resolves (`conduct::graph::send::send_gate`).

/// Where one `message/send` (or `message/stream`) request's TCP connection
/// came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerOrigin {
    /// The connection's peer IP is loopback (127.0.0.0/8, `::1`) — today's
    /// trusted-by-bind-address default. UNCHANGED behavior: auto-delivers,
    /// exactly as before this amendment (hard regression requirement).
    Loopback,
    /// A non-loopback peer IP — gated UNLESS it matches an `autogate`-marked
    /// entry in `state/peers.json`.
    Remote(IpAddr),
    /// The peer address could not be determined (e.g. `peer_addr()` failed).
    /// Fails SAFE: treated exactly like an unmatched [`Self::Remote`] — never
    /// auto-delivered, never autogate-matched.
    Unknown,
}

/// Classify a raw `peer_addr()` result into a [`PeerOrigin`]. Pure.
pub fn classify_origin(peer_ip: Option<IpAddr>) -> PeerOrigin {
    match peer_ip {
        Some(ip) if ip.is_loopback() => PeerOrigin::Loopback,
        Some(ip) => PeerOrigin::Remote(ip),
        None => PeerOrigin::Unknown,
    }
}

/// Should an Inject auto-deliver (`--yes`) rather than queue pending? Pure —
/// unit-tested directly; the one place I/O (`autogate_match`, a
/// `state/peers.json` lookup) enters is the caller. Loopback is
/// unconditionally trusted (today's behavior, unchanged); a non-loopback or
/// unknown-origin peer only bypasses the queue when it matches an
/// `autogate`-marked registry entry.
fn should_deliver_now(origin: PeerOrigin, autogate_match: bool) -> bool {
    match origin {
        PeerOrigin::Loopback => true,
        PeerOrigin::Remote(_) => autogate_match,
        PeerOrigin::Unknown => false,
    }
}

// ── Bearer-token authentication (CONTRACTS.md §6 amendment, 2026-08-18) ─────
//
// The prior amendment (2026-08-14, above) trusted `PeerOrigin::Loopback`
// unconditionally, on the assumption that only a genuinely local caller
// could present it. Behind any reverse proxy or tunnel (`ssh -R`, a
// tailscale funnel, cloudflared, nginx) that assumption is false: the
// SERVER's end of the TCP connection sees the proxy's own loopback address
// for every caller, so `classify_origin` can no longer distinguish "the
// operator, locally" from "anyone who can reach the proxy". A token is the
// signal that survives a proxy hop; ORIGIN alone no longer can, once one is
// configured.
//
// [`resolve_token_file`]/[`read_expected_token`] resolve the SERVER's own
// expected token ONCE at `a2a serve` launch, exactly like `spawn_agent`. Two
// separate things then key off it:
//   - Whether the SPAWN arm may run at all ([`token_authorized`]) — the
//     actual must-fix gap: `message/send`'s Spawn path was origin-blind
//     entirely, gated only by `aoide.a2a.spawnAgent` being non-empty
//     (rebuild-time only, no per-request gate whatsoever).
//   - Whether ORIGIN still confers loopback's automatic trust for Inject
//     ([`effective_origin`]) — once a token is configured, loopback stops
//     being a trust signal, full stop: no separate opt-out, no
//     `trustLoopback` bool to leave mis-set. A caller — local or not — must
//     present the valid token to keep loopback's old free pass.
//
// Separately, [`aoide_storage::peer_store::is_autogated_peer_token`] restores
// PER-PEER identification for the non-loopback autogate match (replacing the
// now-frequently-dead address match behind a proxy) — that one is keyed on
// each registered peer's OWN token, not this single server-wide expected
// token, and works independently of whether this server-wide token is
// configured at all (see `message_send` below).

/// The outcome of comparing a presented `Authorization: Bearer <token>`
/// against the server's configured expected token. Pure — no I/O; the token
/// VALUES are already resolved by the time this runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenState {
    /// No `Authorization: Bearer` header was presented at all.
    Absent,
    /// A token was presented and matches the expected token exactly.
    Valid,
    /// A token was presented but does not match.
    Invalid,
}

/// Classify a presented token against the expected one. Only meaningful when
/// a token IS configured (`expected` non-empty) — callers gate on that
/// separately ([`resolve_token_file`]'s empty-means-off convention) rather
/// than folding "not configured" into this enum, so `TokenState` stays a
/// three-way fact about ONE comparison, not a second copy of the
/// feature-on/off switch. Uses [`aoide_storage::peer_store::token_bytes_eq`]
/// (length-independent byte compare) rather than `==` on a secret. Pure.
fn classify_token(expected: &str, presented: Option<&str>) -> TokenState {
    match presented {
        None => TokenState::Absent,
        Some(p) if aoide_storage::peer_store::token_bytes_eq(expected, p) => TokenState::Valid,
        Some(_) => TokenState::Invalid,
    }
}

/// Is a token-gated action allowed to run? When no token is configured,
/// ALWAYS yes — the off-path is byte-identical to before the token amendment
/// (admission stays rebuild-time-only, exactly CONTRACTS.md §6's original
/// security model). When a token IS configured, only a [`TokenState::Valid`]
/// bearer unlocks it — an absent or wrong token is a clean [`unauthorized`]
/// `-32005` error, not a silent fallback to the old open behavior. Pure —
/// directly testable without a socket or a spawned process.
///
/// One predicate guards two things (CONTRACTS.md §6 amendment, Phase G,
/// 2026-08-20): the SPAWN arm of `message/send`, and the READ verbs
/// (`tasks/get`, `aoide/graphSummary`, `tasks/resubscribe`, `message/stream`).
/// Before Phase G the reads were ungated even with a token set — harmless on
/// loopback, but a whole-session-graph leak the moment the door faced a
/// network. The gate is identical for both because the question is identical:
/// does the caller hold a valid token when one is required?
fn token_authorized(token_configured: bool, token_state: TokenState) -> bool {
    !token_configured || token_state == TokenState::Valid
}

/// The `-32005` unauthorized error every token-gated arm returns, so the code
/// and message never drift between the spawn gate and the read gates.
fn unauthorized() -> (i64, String) {
    (-32005, "unauthorized: a valid A2A token is required".to_string())
}

/// The origin [`should_deliver_now`] actually sees. When no token is
/// configured this is the IDENTITY function — `origin` passes through
/// unchanged, so `should_deliver_now`'s own byte-identical-when-off
/// regression pin holds by construction, not just by inspection. When a
/// token IS configured, an origin that did NOT present a [`TokenState::Valid`]
/// bearer is coerced to [`PeerOrigin::Unknown`] — deliberately reusing that
/// variant's existing "never trusted, fails safe" arm in `should_deliver_now`
/// rather than adding a fourth origin kind, since the resulting trust
/// decision (never auto-deliver) is exactly the same either way. This is the
/// "loopback stops being a trust signal" coupling: there is no code path
/// where a token is required AND loopback still auto-delivers unauthenticated
/// — the same `token_configured` bool drives both. Pure.
fn effective_origin(origin: PeerOrigin, token_configured: bool, token_state: TokenState) -> PeerOrigin {
    if token_configured && token_state != TokenState::Valid {
        PeerOrigin::Unknown
    } else {
        origin
    }
}

// ── AgentCard (derived from the command registry, CONTRACTS.md §6) ──────────

/// Build the AgentCard from any iterator of registry commands — factored out
/// of [`agent_card`] so tests can feed a small fake schema instead of a real
/// registry.
pub fn agent_card_from_commands<'a>(
    commands: impl Iterator<Item = &'a Command>,
    bind: &str,
    port: u16,
) -> Value {
    let skills: Vec<AgentSkill> = commands
        .filter(|c| c.implemented)
        .map(|c| {
            let dotted = c.dotted();
            let top_level = c.path.first().copied().unwrap_or("");
            AgentSkill {
                id: dotted.clone(),
                name: dotted,
                description: c.summary.to_string(),
                tags: vec![top_level.to_string()],
            }
        })
        .collect();

    let card = AgentCard {
        name: Some("aoide".to_string()),
        description: "aoide — a headless conductor for agent sessions, rice \
            generation, and the song/stage state tree, exposed as a \
            discoverable A2A remote agent (CONTRACTS.md §6)."
            .to_string(),
        version: Some(aoide_protocol::registry::AOIDE_VERSION.to_string()),
        // Pinned explicitly to the A2A v0.3.x JSON-RPC binding (CONTRACTS.md
        // §6 "Version"): flat "url" below, message/send + tasks/get,
        // lowercase-kebab TaskStates. v1.0's `interfaces`-array + top-level
        // `id` card form is a later, additive follow-on — not this.
        protocol_version: Some("0.3.0".to_string()),
        url: Some(format!("http://{bind}:{port}/")),
        // Phase C: the server now serves `message/stream` + `tasks/resubscribe`
        // over Server-Sent Events, so streaming is advertised true.
        capabilities: Some(AgentCapabilities { streaming: true }),
        default_input_modes: Some(vec!["text/plain".to_string()]),
        default_output_modes: Some(vec!["text/plain".to_string()]),
        skills: Some(skills),
        interfaces: None,
    };
    serde_json::to_value(&card).expect("AgentCard always serializes")
}

/// The real AgentCard, derived from an INJECTED registry rather than a
/// crate-global singleton — see the module doc comment's "DI seam" note.
pub fn agent_card(registry: &Registry, bind: &str, port: u16) -> Value {
    agent_card_from_commands(registry.commands(), bind, port)
}

/// The stripped AgentCard served to an unauthenticated GET once a server
/// token is configured (CONTRACTS.md §6, 2026-08-20 amendment): just enough
/// for a caller to identify and register the agent — `name`,
/// `protocolVersion`, `url` — with no skills inventory, `version`, or
/// `capabilities`. Each field is PICKED OFF the full card `Value` rather than
/// re-derived, so the stripped shape can never drift from what
/// [`agent_card_from_commands`] actually emits. Pure.
fn stripped_card(full: &Value) -> Value {
    let mut out = serde_json::Map::new();
    for key in ["name", "protocolVersion", "url"] {
        if let Some(v) = full.get(key) {
            out.insert(key.to_string(), v.clone());
        }
    }
    Value::Object(out)
}

// ── canonical_state → A2A TaskState mapping (CONTRACTS.md §6) ───────────────

/// `canonical_state` (`aoide_conduct::graph`) → A2A `TaskState`, JSON-RPC/HTTP
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
fn task_from_sessions(sessions: &[SessionRecord], id: &str) -> Result<Value, (i64, String)> {
    let rec = sessions
        .iter()
        .find(|s| s.session_id == id)
        .ok_or_else(|| (-32001_i64, "task not found".to_string()))?;
    let canonical = canonical_state(&rec.state);
    let needs_sudo = rec.needs_sudo.unwrap_or(false);
    let state = a2a_task_state(canonical, needs_sudo);
    let task = Task {
        id: rec.session_id.clone(),
        // MVP simplification: task id == sessionId, contextId == sessionId —
        // see the doc comment above.
        context_id: rec.session_id.clone(),
        status: TaskStatus { state: state.to_string(), timestamp: now_iso_utc() },
        kind: "task".to_string(),
    };
    Ok(serde_json::to_value(&task).expect("Task always serializes"))
}

/// Load `sessions.json` off the stage and resolve one task by id.
fn task_get(task_id: &str) -> Result<Value, (i64, String)> {
    let path = sessions_path();
    let sf: SessionsFile =
        load_stage(&path).map_err(|e| (-32603_i64, format!("internal error: {e}")))?;
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
/// `contextId`, decoupled from [`SessionRecord`] so the pure decision stays
/// testable without a stage file on disk.
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
    let sf: SessionsFile = load_stage(&sessions_path()).ok()?;
    sf.sessions.iter().find(|s| s.session_id == id).map(|s| SessionRef {
        conductable: s.conductable == Some(true),
        has_socket: s.socket.as_deref().map(|v| !v.is_empty()).unwrap_or(false),
    })
}

/// Deliver into a KNOWN, conductable session: reuse
/// [`aoide_conduct::graph::session_send`] (the same gated injection door
/// `graph send` uses) rather than reimplementing the socket write or its
/// pending-queue.
///
/// `deliver_now` decides whether `--yes` is forced:
/// - `true` (a loopback connection, or a non-loopback one from an
///   `autogate`-marked peer — [`should_deliver_now`]) forces delivery, same
///   as this door's original behavior: `--submit` (the prompt is a full
///   turn, not a keystroke), `--yes` (deliver now, don't queue).
/// - `false` (a non-loopback, non-autogated connection — CONTRACTS.md §6
///   amendment, 2026-08-14) OMITS `--yes` entirely: `session_send`'s own
///   gate then does exactly what a local ungated `graph send` does — writes
///   `pending.json` and reports `delivered:false`, never touching the
///   socket. No pending-queue logic is reimplemented here.
///
/// Build a `submitted`-state Task keyed on `session_id`/`contextId`
/// (NOT `task_get`, which would report the SESSION's current phase — an
/// unrelated prior turn's state — rather than "this particular message is
/// queued"). Shared by [`do_inject`]'s held-pending arm and `message_send`'s
/// uniform-response guard (CONTRACTS.md §6 amendment, 2026-08-20, #50) so
/// the two "the caller gets an honest immediate `submitted` receipt, the
/// real state shows up later via `tasks/get`/SSE" shapes cannot drift apart.
fn submitted_task(session_id: &str) -> Value {
    let task = Task {
        id: session_id.to_string(),
        context_id: session_id.to_string(),
        status: TaskStatus { state: "submitted".to_string(), timestamp: now_iso_utc() },
        kind: "task".to_string(),
    };
    serde_json::to_value(&task).expect("Task always serializes")
}

/// A delivered send returns the freshly-reloaded Task (unchanged from
/// before). A held-pending send returns [`submitted_task`]'s Task so the
/// synchronous JSON-RPC caller gets an honest immediate response;
/// `tasks/get`/the SSE stream reflect the real session state once/if a
/// human approves and delivers it.
fn do_inject(
    session_id: &str,
    prompt: &str,
    audit_log: &Path,
    deliver_now: bool,
) -> Result<Value, (i64, String)> {
    let mut flags = std::collections::BTreeMap::new();
    flags.insert("id".to_string(), session_id.to_string());
    flags.insert("submit".to_string(), "true".to_string());
    if deliver_now {
        flags.insert("yes".to_string(), "true".to_string());
    }
    flags.insert("audit-log".to_string(), audit_log.to_string_lossy().into_owned());
    let inv = Invocation {
        path: vec!["graph".to_string(), "send".to_string()],
        args: vec![prompt.to_string()],
        flags,
        door: Door::A2a,
    };
    let outcome = session_send(&inv);
    if outcome.status != Status::Ok {
        return Err((-32603, outcome.message));
    }
    let delivered = outcome
        .data
        .as_ref()
        .and_then(|d| d.get("delivered"))
        .and_then(Value::as_bool)
        .unwrap_or(deliver_now);
    if delivered {
        task_get(session_id)
    } else {
        Ok(submitted_task(session_id))
    }
}

/// Best-effort: connect to a just-spawned conducted session's control socket
/// and type `prompt` as its first turn, retrying while the child hasn't
/// bound it yet — the same connect-and-retry shape
/// `aoide_conduct::graph::conduct`'s own PTY-injection test uses (there,
/// proving the production socket-write path; here, actually driving it). A
/// missed connect after the retry budget is tolerated: the session still
/// exists and is `conductable`, just without its opening turn typed in — a
/// client can always follow up with a plain `graph send`/another
/// `message/send`.
fn spawn_inject_prompt(id: &str, prompt: &str) {
    if prompt.is_empty() {
        return;
    }
    let socket = aoide_conduct::graph::conduct_socket_path(id);
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
/// thread, stdio nulled, and reaped on a parked thread (see below) — it
/// stays parented to the long-lived `a2a serve` daemon for its whole life.
/// `aoide-conduct`'s `graph spawn` (P2 of the conducted-agents plan) now
/// generalizes exactly this detach/register/reap shape as its own verb; a
/// later phase can have this handler ride on it instead of hand-rolling the
/// same mechanics here.
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
        Ok(mut child) => {
            // `setsid()` above detaches the child into its own session so it
            // survives this handler thread, but a new session does NOT
            // reparent the child — this process is still its parent and
            // still owes it a `wait()`. Skip that and the kernel keeps the
            // exit status around forever once the child dies: a zombie
            // entry in the process table, uncollected for as long as
            // `a2a serve` runs. Park a thread whose only job is to collect
            // it; nothing else here depends on when that happens.
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            // Best-effort first-turn injection — see the doc comment above.
            spawn_inject_prompt(&id, prompt);
            let _ = audit(
                audit_log,
                Door::A2a,
                EventClass::Audit,
                "a2a.message/send",
                "ok",
                &format!("spawned conducted session `{id}` (configured agent)"),
            );
            let task = Task {
                id: id.clone(),
                context_id: id.clone(),
                status: TaskStatus {
                    state: "submitted".to_string(),
                    timestamp: now_iso_utc(),
                },
                kind: "task".to_string(),
            };
            Ok(serde_json::to_value(&task).expect("Task always serializes"))
        }
        Err(e) => {
            let msg = format!("failed to spawn A2A agent: {e}");
            let _ = audit(
                audit_log,
                Door::A2a,
                EventClass::Audit,
                "a2a.message/send",
                "error",
                &msg,
            );
            Err((-32603, msg))
        }
    }
}

/// `message/send`: parse params, resolve [`decide_send_action`], execute.
///
/// `origin` (CONTRACTS.md §6 amendment, 2026-08-14) affects the Inject
/// branch. `expected_token`/`presented_token` (amendment, 2026-08-18) affect
/// BOTH branches: an empty `expected_token` (no token configured) is a pure
/// no-op on every decision below — [`effective_origin`] is the identity
/// function and [`token_authorized`] always allows — so this whole amendment
/// is byte-identical-when-off by construction, not merely by testing.
///
/// - Inject's autogate match now folds TWO independent signals: the
///   original address match ([`aoide_storage::peer_store::is_autogated_peer_addr`],
///   dead behind any proxy) OR a per-peer token match
///   ([`aoide_storage::peer_store::is_autogated_peer_token`], survives one) —
///   either is sufficient, so an operator who has never set a peer
///   `token_file` sees the exact original address-only behavior.
/// - Inject's ORIGIN is [`effective_origin`]'d before reaching
///   [`should_deliver_now`]: once a token is configured, an unauthenticated
///   loopback caller no longer gets the automatic pass — see that function's
///   doc comment for why this is one switch, not two.
/// - Spawn gained a gate it never had at all: [`token_authorized`] must pass
///   before [`do_spawn`] runs. This is the actual must-fix gap this
///   amendment closes — Spawn was origin-blind AND token-blind before it.
///
/// **Amendment (2026-08-20, #50): a context-id send answers UNIFORMLY, not
/// with a hard gate, once a token is configured and the caller holds
/// neither a valid one nor an autogate match.** `message/send`'s Inject arm
/// used to run [`session_ref_lookup`] regardless of auth — an
/// unauthenticated caller could tell a real `contextId` from a bogus one by
/// the response shape (`-32001` vs an injected/queued Task), and a REAL id
/// got queued into `pending.json` with no credential at all. A hard `-32005`
/// here (mirroring Spawn) would be wrong instead: enrolled peers authenticate
/// via their OWN per-peer token
/// ([`aoide_storage::peer_store::is_autogated_peer_token`]), never the
/// server-wide one, and outbound clients send no bearer whatsoever — see the
/// grounding above. So the guard below fires only when NEITHER credential
/// matches, and answers with the exact same synthetic `submitted` Task
/// [`do_inject`]'s own held-pending arm returns ([`submitted_task`]) —
/// without ever resolving whether the id names a real session, so it never
/// reads `sessions.json` and never touches `pending.json`. Spawn (no
/// `contextId`, or `spawn_asked`) is untouched and keeps its own `-32005`.
fn message_send(
    params: &Value,
    audit_log: &Path,
    spawn_agent: &str,
    origin: PeerOrigin,
    expected_token: &str,
    presented_token: Option<&str>,
) -> Result<Value, (i64, String)> {
    let (prompt, context_id, spawn_asked) = parse_message_send_params(params);
    let token_configured = !expected_token.is_empty();
    let token_state = classify_token(expected_token, presented_token);

    // Autogate signals hoisted ABOVE the send-action decision: the uniform-
    // response guard below needs them BEFORE `decide_send_action` even runs,
    // and the Inject arm further down still needs them AFTER — one
    // `load_peers()` per `message_send` call, not two. Values and their
    // meaning are unchanged from before this amendment; only WHEN they're
    // computed moved.
    let peers = aoide_storage::peer_store::load_peers();
    let ip_autogate = match origin {
        PeerOrigin::Remote(ip) => aoide_storage::peer_store::is_autogated_peer_addr(&peers, ip),
        PeerOrigin::Loopback | PeerOrigin::Unknown => false,
    };
    let token_autogate = presented_token
        .map(|t| aoide_storage::peer_store::is_autogated_peer_token(&peers, t))
        .unwrap_or(false);
    let autogate_match = ip_autogate || token_autogate;

    // Uniform-response guard (see the amendment above) — mirrors
    // `decide_send_action`'s OWN `spawn_asked`/`context_id` split exactly
    // (`context_id.is_some() && !spawn_asked` is that function's "past this
    // point it's a lookup, not a spawn" condition, negated the same way), so
    // a request can never classify "spawn" for this gate and "send" for the
    // decision or vice versa.
    if token_configured && token_state != TokenState::Valid && !autogate_match && context_id.is_some() && !spawn_asked {
        let id = context_id.as_deref().expect("context_id.is_some() checked above");
        let _ = audit(
            audit_log,
            Door::A2a,
            EventClass::Audit,
            "a2a.message/send",
            "unauthorized",
            &format!("uniform submitted Task for context `{id}` — no valid token, no autogate match (#50)"),
        );
        return Ok(submitted_task(id));
    }

    match decide_send_action(context_id.as_deref(), spawn_asked, spawn_agent, session_ref_lookup) {
        SendAction::Inject { session_id } => {
            let eff_origin = effective_origin(origin, token_configured, token_state);
            let deliver_now = should_deliver_now(eff_origin, autogate_match);
            do_inject(&session_id, &prompt, audit_log, deliver_now)
        }
        SendAction::Spawn { agent_cmd } => {
            if !token_authorized(token_configured, token_state) {
                return Err(unauthorized());
            }
            do_spawn(&agent_cmd, &prompt, audit_log)
        }
        SendAction::Error { code, msg } => Err((code, msg)),
    }
}

/// `aoide/graphSummary` (CONTRACTS.md §7): wrap the EXISTING resolved
/// `graph.json` v0 document ([`resolve_graph_document`], the exact same
/// function `graph view`/`graph emit` build their document with) in the
/// federation envelope. No new graph vocabulary — `graph` below is that
/// document verbatim.
fn graph_summary(peer_name: &str, self_url: &str) -> Result<Value, (i64, String)> {
    let graph = resolve_graph_document().map_err(|e| (-32603_i64, format!("internal error: {e}")))?;
    Ok(json!({
        "schemaVersion": "0",
        "instance": {
            "name": peer_name,
            "url": self_url,
            "emittedAt": now_iso_utc(),
        },
        "graph": graph,
    }))
}

/// Per-request context [`handle_jsonrpc`]/[`handle_jsonrpc_bytes`] thread
/// through to whichever method needs it: `message/send` needs
/// `audit_log`/`spawn_agent`/`origin`; `aoide/graphSummary` (CONTRACTS.md §7)
/// needs `peer_name`/`self_url`. Bundled into one struct once a second method
/// needed request-scoped dependencies, rather than growing `handle_jsonrpc`'s
/// positional-arg list again.
struct RequestCtx<'a> {
    audit_log: &'a Path,
    spawn_agent: &'a str,
    origin: PeerOrigin,
    peer_name: &'a str,
    self_url: &'a str,
    /// The server's own expected A2A token (CONTRACTS.md §6 amendment,
    /// 2026-08-18) — empty means none configured (feature off). Resolved
    /// once at `a2a serve` launch, same as `spawn_agent`.
    expected_token: &'a str,
    /// This request's `Authorization: Bearer <token>`, if any.
    presented_token: Option<&'a str>,
}

/// Handle one parsed JSON-RPC 2.0 request `Value`, returning the response
/// `Value` (always — unlike `mcp.rs`'s stdio notifications, an HTTP POST
/// always gets a reply body).
fn handle_jsonrpc(req: &Value, ctx: &RequestCtx) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or(Value::Null);

    // Phase G (CONTRACTS.md §6 amendment, 2026-08-20): the read verbs are
    // token-gated by the SAME rule as spawn. Computed once; only bites when a
    // token is configured (off-path unchanged). `message/send` runs its own
    // classify internally (it needs the full TokenState for effective_origin),
    // so it is not re-gated here.
    let read_ok = token_authorized(
        !ctx.expected_token.is_empty(),
        classify_token(ctx.expected_token, ctx.presented_token),
    );

    let result: Result<Value, (i64, String)> = match method {
        "tasks/get" if !read_ok => Err(unauthorized()),
        "tasks/get" => {
            let task_id = params.get("id").and_then(Value::as_str).unwrap_or("");
            task_get(task_id)
        }
        "message/send" => message_send(
            &params,
            ctx.audit_log,
            ctx.spawn_agent,
            ctx.origin,
            ctx.expected_token,
            ctx.presented_token,
        ),
        "aoide/graphSummary" if !read_ok => Err(unauthorized()),
        "aoide/graphSummary" => graph_summary(ctx.peer_name, ctx.self_url),
        "" => Err((-32600, "invalid request: missing method".to_string())),
        other => Err((-32601, format!("method not found: {other}"))),
    };

    let resp = match result {
        Ok(value) => JsonRpcResponse::ok(id, value),
        Err((code, message)) => JsonRpcResponse::err(id, code, message),
    };
    serde_json::to_value(&resp).expect("JsonRpcResponse always serializes")
}

fn jsonrpc_error_value(code: i64, message: impl Into<String>) -> Value {
    serde_json::to_value(JsonRpcResponse::err(Value::Null, code, message))
        .expect("JsonRpcResponse always serializes")
}

fn handle_jsonrpc_bytes(body: &[u8], ctx: &RequestCtx) -> Value {
    match serde_json::from_slice::<Value>(body) {
        Ok(req) => handle_jsonrpc(&req, ctx),
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
        let event = TaskStatusUpdateEvent {
            task_id: task.get("id").cloned().unwrap_or(Value::Null),
            context_id: task.get("contextId").cloned().unwrap_or(Value::Null),
            status: task.get("status").cloned().unwrap_or(Value::Null),
            is_final: true,
            kind: "status-update".to_string(),
        };
        serde_json::to_value(&event).expect("TaskStatusUpdateEvent always serializes")
    } else {
        task.clone()
    };
    serde_json::to_value(JsonRpcResponse::ok(rpc_id.clone(), result))
        .expect("JsonRpcResponse always serializes")
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
    origin: PeerOrigin,
    expected_token: &str,
    presented_token: Option<&str>,
) -> std::io::Result<()> {
    let rpc: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
    let rpc_id = rpc.get("id").cloned().unwrap_or(Value::Null);
    let params = rpc.get("params").cloned().unwrap_or(Value::Null);

    // Resolve the target task + its initial state. `message/stream` runs the
    // send FIRST (inject/spawn) and streams the task it produced;
    // `tasks/resubscribe` streams an existing task by id.
    //
    // Phase G (CONTRACTS.md §6 amendment, 2026-08-20): gate BOTH streaming
    // reads by the same token rule as the one-shot verbs. When a token is
    // configured and the caller lacks a valid one, resolution short-circuits
    // to `unauthorized()` BEFORE `message_send` runs — so an unauthenticated
    // `message/stream` neither injects nor spawns, it only receives the
    // `-32005` SSE error event below. `tasks/resubscribe`'s own `task_get`
    // would otherwise be an ungated session-state read (the SSE sibling of
    // `tasks/get`). Off-path (no token) is byte-identical to before.
    let stream_ok = token_authorized(
        !expected_token.is_empty(),
        classify_token(expected_token, presented_token),
    );
    let resolved: Result<Value, (i64, String)> = if !stream_ok {
        Err(unauthorized())
    } else {
        match method {
            "message/stream" => {
                message_send(&params, audit_log, spawn_agent, origin, expected_token, presented_token)
            }
            _ /* tasks/resubscribe */ => {
                match params.get("id").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                    Some(id) => task_get(id),
                    None => Err((-32001, "task not found".to_string())),
                }
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
            let err = serde_json::to_value(JsonRpcResponse::err(rpc_id, code, message))
                .expect("JsonRpcResponse always serializes");
            let _ = writer.write_all(sse_event(&err).as_bytes());
            let _ = writer.flush();
            let _ = audit(
                audit_log,
                Door::A2a,
                EventClass::Audit,
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

    let _ = audit(
        audit_log,
        Door::A2a,
        EventClass::Audit,
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
    /// The `Authorization` header's bearer token, if present and well-formed
    /// (CONTRACTS.md §6 amendment, 2026-08-18) — `Some(<token>)` for
    /// `Authorization: Bearer <token>`, `None` for a missing header or any
    /// other scheme. Every other header this door doesn't need is still read
    /// and discarded, same as before this field existed.
    bearer: Option<String>,
}

/// Extract the bearer token from a raw `Authorization` header VALUE (the
/// part after `Authorization:`), case-insensitive on the `Bearer` scheme
/// name (RFC 7235 §2.1 treats auth-scheme as case-insensitive), trimmed.
/// `None` for any other scheme, an empty token, or a malformed header. Pure.
fn extract_bearer(header_value: &str) -> Option<String> {
    let rest = header_value.trim();
    let (scheme, token) = rest.split_once(char::is_whitespace)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then(|| token.to_string())
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
    let mut bearer: Option<String> = None;
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
            let name = name.trim();
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            } else if name.eq_ignore_ascii_case("authorization") {
                bearer = extract_bearer(value);
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

    Ok(HttpRequest { method, path, body, bearer })
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
/// command label). `audit_log`/`spawn_agent`/`origin` are only consulted by a
/// POST `/` whose body parses as `message/send`; `peer_name` (plus the
/// `self_url` this function derives from `bind`/`port`, the same way
/// [`agent_card`]'s own `url` field does) is only consulted by
/// `aoide/graphSummary`; `registry` and `expected_token` (compared against
/// `req.bearer`, CONTRACTS.md §6 2026-08-20 amendment) are only consulted by
/// the AgentCard GET, which strips the card down to `name`/`protocolVersion`/
/// `url` when a token is configured and the bearer doesn't classify `Valid` —
/// every other route is pure I/O-free routing over what's already in `req`,
/// so it still unit-tests without a real socket, spawn, or audit-log write.
fn route(
    req: &HttpRequest,
    bind: &str,
    port: u16,
    audit_log: &Path,
    spawn_agent: &str,
    peer_name: &str,
    origin: PeerOrigin,
    expected_token: &str,
    registry: &Registry,
) -> (u16, Vec<u8>, String) {
    match req.path.as_str() {
        "/.well-known/agent-card.json" => {
            if req.method == "GET" {
                let full = agent_card(registry, bind, port);
                let token_configured = !expected_token.is_empty();
                let token_state = classify_token(expected_token, req.bearer.as_deref());
                // A GET here returns a card, never JSON-RPC — no -32005 on
                // this path (CONTRACTS.md §6, 2026-08-20 amendment): an
                // unauthorized caller still gets 200 and a card, just the
                // stripped one, so discovery keeps working without leaking
                // the skills inventory/version/capabilities.
                let card = if token_authorized(token_configured, token_state) {
                    full
                } else {
                    stripped_card(&full)
                };
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
                    Some("aoide/graphSummary") => "aoide/graphSummary",
                    _ => "rpc",
                };
                let self_url = format!("http://{bind}:{port}/");
                let ctx = RequestCtx {
                    audit_log,
                    spawn_agent,
                    origin,
                    peer_name,
                    self_url: &self_url,
                    expected_token,
                    presented_token: req.bearer.as_deref(),
                };
                let resp = handle_jsonrpc_bytes(&req.body, &ctx);
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
/// panic) — the caller (root `lib.rs::run_cli`) renders that as the process
/// exit code, same as `mcp serve --stdio`'s failure path.
///
/// `registry` is injected (see the module doc comment's "DI seam" note) and
/// must be `'static` — it is moved into each spawned connection-handler
/// thread, same as every other per-connection state below. Root `lib.rs`
/// passes `dispatch::registry()`, whose `&'static Registry` already satisfies
/// this.
///
/// A connection flood is bounded by [`MAX_CONN`]: past that many in-flight
/// handler threads, a new connection gets a fast `503` written directly
/// (no handler thread spawned, no `BufReader`/parse work done) rather than
/// growing the thread count without limit.
//
// TODO(a2a-hardening): chunked Transfer-Encoding and extra systemd
// sandboxing (aoide-a2a.service) are deliberately out of scope for this
// pass — see the security-review notes that produced this hardening.
pub fn serve(
    bind: &str,
    port: u16,
    audit_log: &Path,
    spawn_agent: &str,
    peer_name: &str,
    expected_token: &str,
    registry: &'static Registry,
) -> std::io::Result<()> {
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
        let peer_name = peer_name.to_string();
        let expected_token = expected_token.to_string();
        std::thread::spawn(move || {
            let _guard = ConnGuard; // released on every exit path, incl. panic
            if let Err(e) = handle_connection(
                stream,
                &bind,
                port,
                &audit_log,
                &spawn_agent,
                &peer_name,
                &expected_token,
                registry,
            ) {
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
    peer_name: &str,
    expected_token: &str,
    registry: &Registry,
) -> std::io::Result<()> {
    // The connection's ORIGIN (CONTRACTS.md §6 amendment, 2026-08-14): TCP
    // `peer_addr()`, not any client-supplied field — a hostile client cannot
    // spoof this. Resolved once, BEFORE the read-timeout/BufReader wrapping
    // below (which only affect reading, not this), and threaded to every
    // path that can reach `message/send` (the one-shot route below AND the
    // `message/stream` SSE path).
    let origin = classify_origin(stream.peer_addr().ok().map(|sa| sa.ip()));

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
            let _ = audit(
                audit_log,
                Door::A2a,
                EventClass::Audit,
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
        let _ = audit(
            audit_log,
            Door::A2a,
            EventClass::Audit,
            &format!("a2a.{method}"),
            "open",
            "SSE stream open",
        );
        return stream_task(
            &mut writer,
            &req,
            &method,
            audit_log,
            spawn_agent,
            origin,
            expected_token,
            req.bearer.as_deref(),
        );
    }

    let (status, body, audit_cmd) = route(
        &req,
        bind,
        port,
        audit_log,
        spawn_agent,
        peer_name,
        origin,
        expected_token,
        registry,
    );

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
    let _ = audit(
        audit_log,
        Door::A2a,
        EventClass::Audit,
        &audit_cmd,
        status_word,
        &format!("HTTP {status}"),
    );

    write_http_response(&mut writer, status, &body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fake_handler(_inv: &Invocation) -> aoide_protocol::output::Outcome {
        aoide_protocol::output::Outcome::ok("fake", "fake")
    }

    /// A loopback `RequestCtx` — every pre-existing test below predates the
    /// non-loopback pending-gate amendment and exercises the historical
    /// "trusted, loopback caller" behavior, so this preserves that intent
    /// exactly (none of them touch the Inject-delivery branch anyway — they
    /// all resolve to `SendAction::Error`/`tasks/get`, which never consult
    /// `origin`).
    fn test_ctx<'a>(audit_log: &'a Path, spawn_agent: &'a str) -> RequestCtx<'a> {
        RequestCtx {
            audit_log,
            spawn_agent,
            origin: PeerOrigin::Loopback,
            peer_name: "aoide",
            self_url: "http://127.0.0.1:8710/",
            expected_token: "",
            presented_token: None,
        }
    }

    // (a) AgentCard generation from a small fake schema.
    #[test]
    fn agent_card_only_advertises_implemented_commands_as_skills() {
        let mut r = Registry::new();
        r.insert(Command {
            path: &["foo", "bar"],
            summary: "does a thing",
            args: &[],
            flags: &[],
            gated: false,
            implemented: true,
            exit_codes: (),
            examples: &[],
            handler: fake_handler,
            available: || true,
        });
        r.insert(Command {
            path: &["foo", "stub"],
            summary: "not yet",
            args: &[],
            flags: &[],
            gated: false,
            implemented: false,
            exit_codes: (),
            examples: &[],
            handler: fake_handler,
            available: || true,
        });

        let card = agent_card_from_commands(r.commands(), "127.0.0.1", 8710);
        assert_eq!(card["name"], "aoide");
        assert_eq!(card["version"], aoide_protocol::registry::AOIDE_VERSION);
        assert_eq!(card["url"], "http://127.0.0.1:8710/");
        assert_eq!(card["capabilities"]["streaming"], true);

        let skills = card["skills"].as_array().unwrap();
        assert_eq!(skills.len(), 1, "only the implemented command becomes a skill");
        assert_eq!(skills[0]["id"], "foo.bar");
        assert_eq!(skills[0]["name"], "foo.bar");
        assert_eq!(skills[0]["description"], "does a thing");
        assert_eq!(skills[0]["tags"][0], "foo");

        // `agent_card` (the injected-registry wrapper) produces the same
        // shape as the pure `agent_card_from_commands` it wraps.
        let card2 = agent_card(&r, "127.0.0.1", 8710);
        assert_eq!(card2, card);
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

    fn fixture_session(id: &str, state: &str, needs_sudo: Option<bool>) -> SessionRecord {
        SessionRecord {
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

    /// The outbound builder (`aoide-client`) round-tripped through the
    /// inbound parser here — a dev-dependency-only edge (see `Cargo.toml`):
    /// production code never lets `aoide-server` reach `aoide-client`.
    #[test]
    fn build_message_send_body_round_trips_through_the_inbound_parser() {
        let body = aoide_client::wire::build_message_send_body("hello there", "mid-123", None);
        let (prompt, ctx, spawn) = parse_message_send_params(&body["params"]);
        assert_eq!(prompt, "hello there");
        assert_eq!(ctx, None);
        assert!(!spawn);
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
        let resp = handle_jsonrpc(&req, &test_ctx(Path::new("/dev/null"), ""));
        assert_eq!(resp["error"]["code"], -32004);
        assert_eq!(resp["error"]["message"], "A2A spawn not configured");
        assert_eq!(resp["id"], 1);
    }

    #[test]
    fn message_send_end_to_end_unknown_and_unconductable_contexts_are_clean_errors() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = std::env::temp_dir().join(format!(
            "aoide-server-a2a-send-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // A registered session with no control socket (not conductable).
        let sf = SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![fixture_session("plain", "working", None)],
        };
        write_stage(&sessions_path(), &sf).unwrap();

        // Unknown contextId → -32001 (never reaches the socket/spawn layer).
        let req = json!({
            "jsonrpc": "2.0", "id": 1, "method": "message/send",
            "params": { "message": {
                "parts": [{ "kind": "text", "text": "hi" }],
                "contextId": "ghost",
            } }
        });
        let resp = handle_jsonrpc(&req, &test_ctx(Path::new("/dev/null"), "claude"));
        assert_eq!(resp["error"]["code"], -32001);

        // Known but not conductable → -32004 "session not conductable".
        let req2 = json!({
            "jsonrpc": "2.0", "id": 2, "method": "message/send",
            "params": { "message": {
                "parts": [{ "kind": "text", "text": "hi" }],
                "contextId": "plain",
            } }
        });
        let resp2 = handle_jsonrpc(&req2, &test_ctx(Path::new("/dev/null"), "claude"));
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
        let resp = handle_jsonrpc(&req, &test_ctx(Path::new("/dev/null"), ""));
        assert_eq!(resp["error"]["code"], -32601);
    }

    #[test]
    fn tasks_get_end_to_end_reads_the_stage_sessions_file() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = std::env::temp_dir().join(format!(
            "aoide-server-a2a-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let sf = SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![fixture_session("s1", "stopped", None)],
        };
        write_stage(&sessions_path(), &sf).unwrap();

        let req = json!({ "jsonrpc": "2.0", "id": 7, "method": "tasks/get", "params": { "id": "s1" } });
        let resp = handle_jsonrpc(&req, &test_ctx(Path::new("/dev/null"), ""));
        assert_eq!(resp["result"]["status"]["state"], "completed");

        let req = json!({ "jsonrpc": "2.0", "id": 8, "method": "tasks/get", "params": { "id": "ghost" } });
        let resp = handle_jsonrpc(&req, &test_ctx(Path::new("/dev/null"), ""));
        assert_eq!(resp["error"]["code"], -32001);

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    /// Phase G: the read verbs (`tasks/get`, `aoide/graphSummary`) are
    /// token-gated by the same rule as spawn. When a token IS configured, an
    /// absent or wrong bearer is a clean `-32005` BEFORE the read runs; a
    /// valid bearer passes through to the normal handler.
    #[test]
    fn read_verbs_are_token_gated_when_a_token_is_configured() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = std::env::temp_dir().join(format!(
            "aoide-server-a2a-gate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let sf = SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![fixture_session("s1", "stopped", None)],
        };
        write_stage(&sessions_path(), &sf).unwrap();

        let ctx = |presented: Option<&'static str>| RequestCtx {
            audit_log: Path::new("/dev/null"),
            spawn_agent: "",
            origin: PeerOrigin::Loopback,
            peer_name: "aoide",
            self_url: "http://127.0.0.1:8710/",
            expected_token: "s3cr3t",
            presented_token: presented,
        };
        let get = json!({ "jsonrpc": "2.0", "id": 1, "method": "tasks/get", "params": { "id": "s1" } });
        let sum = json!({ "jsonrpc": "2.0", "id": 2, "method": "aoide/graphSummary" });

        // Absent bearer — both reads denied, and denied BEFORE the read runs
        // (a real session id still returns -32005, never its state).
        assert_eq!(handle_jsonrpc(&get, &ctx(None))["error"]["code"], -32005);
        assert_eq!(handle_jsonrpc(&sum, &ctx(None))["error"]["code"], -32005);
        // Wrong bearer — same.
        assert_eq!(handle_jsonrpc(&get, &ctx(Some("wrong")))["error"]["code"], -32005);
        assert_eq!(handle_jsonrpc(&sum, &ctx(Some("wrong")))["error"]["code"], -32005);
        // Valid bearer — passes the gate; tasks/get reaches its real handler
        // and resolves the known session's state (never -32005).
        let ok = handle_jsonrpc(&get, &ctx(Some("s3cr3t")));
        assert_eq!(ok["result"]["status"]["state"], "completed");
        // graphSummary with a valid bearer is past the gate too — and it
        // must be a REAL read, not just "any non-auth response" (a bare
        // `assert_ne!` here would still pass if the read arm silently broke
        // and started returning some other error): the wrapped graph
        // document and the instance envelope both come through.
        let sum_ok = handle_jsonrpc(&sum, &ctx(Some("s3cr3t")));
        assert_eq!(sum_ok["result"]["schemaVersion"], "0");
        assert_eq!(sum_ok["result"]["instance"]["name"], "aoide");
        assert!(sum_ok["result"]["graph"]["nodes"].is_array());

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    /// Phase G off-path: with NO token configured (today's default), the read
    /// verbs stay open exactly as before — the gate only bites when armed.
    #[test]
    fn read_verbs_stay_open_when_no_token_is_configured() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = std::env::temp_dir().join(format!(
            "aoide-server-a2a-nogate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let sf = SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![fixture_session("s1", "stopped", None)],
        };
        write_stage(&sessions_path(), &sf).unwrap();

        let req = json!({ "jsonrpc": "2.0", "id": 1, "method": "tasks/get", "params": { "id": "s1" } });
        // Empty expected_token = feature off; no bearer presented; still works.
        let resp = handle_jsonrpc(&req, &test_ctx(Path::new("/dev/null"), ""));
        assert_eq!(resp["result"]["status"]["state"], "completed");

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    /// Pull the JSON payload out of the FIRST `data: <json>\n\n` SSE frame in
    /// `stream_task`'s written output (`sse_event`'s exact format). Every
    /// `stream_task` test below writes at most one event before returning
    /// (a denial closes immediately; a terminal initial state closes on its
    /// first tick), so "first" is also "only" in practice.
    fn first_sse_data_json(out: &[u8]) -> Value {
        let text = String::from_utf8_lossy(out);
        let frame = text.split("data: ").nth(1).expect("at least one SSE data event was written");
        let line = frame.split('\n').next().unwrap();
        serde_json::from_str(line).expect("SSE data line is valid JSON")
    }

    /// Phase G, SSE half: `tasks/resubscribe` is gated by the SAME rule as
    /// the one-shot `tasks/get` — proven here at the `stream_task` level
    /// (not just `handle_jsonrpc`), driving the function with a real
    /// `Vec<u8>` writer exactly as `handle_connection` would. A REAL staged
    /// session id is used so a passing gate would leak real state; instead
    /// the SSE headers open (the socket contract doesn't change) and the
    /// stream's one and only event is the `-32005` denial — the session's
    /// state is never read.
    #[test]
    fn stream_task_tasks_resubscribe_denies_before_reading_a_real_session_when_a_token_is_configured() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = std::env::temp_dir().join(format!(
            "aoide-server-a2a-sse-gate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let sf = SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![fixture_session("s1", "working", None)],
        };
        write_stage(&sessions_path(), &sf).unwrap();

        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tasks/resubscribe", "params": { "id": "s1" }
        }))
        .unwrap();
        let req = HttpRequest { method: "POST".to_string(), path: "/".to_string(), body, bearer: None };

        let mut out: Vec<u8> = Vec::new();
        let result = stream_task(
            &mut out,
            &req,
            "tasks/resubscribe",
            Path::new("/dev/null"),
            "",
            PeerOrigin::Loopback,
            "s3cr3t",
            None,
        );
        assert!(result.is_ok(), "a denied stream still returns Ok — it closed cleanly, not by erroring out");

        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("text/event-stream"), "SSE headers are written before the gate is even consulted: {text}");
        let event = first_sse_data_json(&out);
        assert_eq!(event["error"]["code"], -32005);

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    /// Phase G, SSE half: `message/stream` is gated BEFORE `message_send`
    /// runs, so an unauthenticated caller can neither inject into nor spawn
    /// off an existing session through the streaming path. The
    /// security-load-bearing assertion isn't the `-32005` alone (a broken
    /// gate that still happened to error out some OTHER way would pass
    /// that) — it's that `message_send` never ran at ALL: a conductable
    /// session's control socket is stood in with a real `UnixListener` (a
    /// wrongly-attempted Inject would connect to it) AND the pending-queue
    /// file (`do_inject`'s fallback when delivery isn't immediate) never
    /// gets created, proving `do_inject`/`session_send` were never reached
    /// rather than merely "delivery was skipped".
    #[test]
    fn stream_task_message_stream_denies_before_message_send_runs_when_a_token_is_configured() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-sse-msend-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_STATE_DIR", root.join("state"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        std::env::remove_var("AOIDE_SESSION_ID");

        let id = "sse-tgt";
        let socket = aoide_conduct::graph::conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        // If message_send WRONGLY ran (the gate failed to short-circuit
        // before it), a successful Inject would connect here.
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();

        let sf = SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![conductable_session(id, &socket)],
        };
        write_stage(&sessions_path(), &sf).unwrap();

        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "message/stream",
            "params": { "message": { "parts": [{ "kind": "text", "text": "hi" }], "contextId": id } }
        }))
        .unwrap();
        let req = HttpRequest { method: "POST".to_string(), path: "/".to_string(), body, bearer: None };

        let audit_log = root.join("log");
        let mut out: Vec<u8> = Vec::new();
        let result = stream_task(
            &mut out,
            &req,
            "message/stream",
            &audit_log,
            "",
            PeerOrigin::Loopback,
            "s3cr3t",
            None,
        );
        assert!(result.is_ok());

        let event = first_sse_data_json(&out);
        assert_eq!(event["error"]["code"], -32005);

        assert!(
            !stage.join("pending.json").exists(),
            "message_send must never run once the SSE gate denies — a held-pending send would still \
             have written pending.json, so its absence proves do_inject was never reached at all"
        );
        assert!(
            listener.accept().is_err(),
            "the conducted session's socket must never be touched by a denied message/stream"
        );

        let _ = std::fs::remove_dir_all(&root);
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    /// Phase G off-path, SSE half: with NO token configured, `stream_task`
    /// is byte-identical to before — `tasks/resubscribe` reaches the real
    /// session and streams its actual terminal state, proving the gate
    /// doesn't bite when off (not just that it returns SOME non-error
    /// event). The fixture session's canonical state ("stopped" ->
    /// "completed", `a2a_task_state`) is already terminal, so
    /// `stream_task`'s loop emits the final event on its very first tick
    /// and returns — no `STREAM_POLL` sleep, nowhere near `MAX_STREAM`.
    #[test]
    fn stream_task_tasks_resubscribe_reaches_the_real_terminal_state_when_no_token_is_configured() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = std::env::temp_dir().join(format!(
            "aoide-server-a2a-sse-nogate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let sf = SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![fixture_session("s1", "stopped", None)],
        };
        write_stage(&sessions_path(), &sf).unwrap();

        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": 9, "method": "tasks/resubscribe", "params": { "id": "s1" }
        }))
        .unwrap();
        let req = HttpRequest { method: "POST".to_string(), path: "/".to_string(), body, bearer: None };

        let mut out: Vec<u8> = Vec::new();
        let result = stream_task(
            &mut out,
            &req,
            "tasks/resubscribe",
            Path::new("/dev/null"),
            "",
            PeerOrigin::Loopback,
            "",
            None,
        );
        assert!(result.is_ok());

        let event = first_sse_data_json(&out);
        assert_eq!(event["result"]["status"]["state"], "completed");
        assert_eq!(event["result"]["final"], true, "the terminal state closes the stream on its first tick");

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    // ── The non-loopback pending-gate amendment (CONTRACTS.md §6, 2026-08-14) ──
    //
    // The one must-fix security gap: `do_inject` used to force `--yes`
    // UNCONDITIONALLY, so any reachable peer could inject text into any
    // local conductable session with zero approval the moment the door binds
    // somewhere other than loopback. These tests drive `message_send`
    // directly (the same function `handle_jsonrpc`'s `message/send` arm
    // calls) with a real `UnixListener` standing in for the target session's
    // control socket, exactly like `conduct::graph::send`'s own gate tests.

    fn conductable_session(id: &str, socket: &std::path::Path) -> SessionRecord {
        let mut rec = fixture_session(id, "working", None);
        rec.conductable = Some(true);
        rec.socket = Some(socket.to_string_lossy().into_owned());
        rec
    }

    #[test]
    fn classify_origin_maps_loopback_remote_and_unknown() {
        assert_eq!(classify_origin(Some("127.0.0.1".parse().unwrap())), PeerOrigin::Loopback);
        assert_eq!(classify_origin(Some("::1".parse().unwrap())), PeerOrigin::Loopback);
        assert_eq!(
            classify_origin(Some("10.0.0.5".parse().unwrap())),
            PeerOrigin::Remote("10.0.0.5".parse().unwrap())
        );
        assert_eq!(classify_origin(None), PeerOrigin::Unknown);
    }

    #[test]
    fn should_deliver_now_covers_every_origin_autogate_combination() {
        // Loopback is unconditionally trusted — unchanged from before this
        // amendment, regardless of any autogate match.
        assert!(should_deliver_now(PeerOrigin::Loopback, false));
        assert!(should_deliver_now(PeerOrigin::Loopback, true));
        // A remote origin only delivers when it matched an autogate peer.
        let remote = PeerOrigin::Remote("10.0.0.5".parse().unwrap());
        assert!(!should_deliver_now(remote, false));
        assert!(should_deliver_now(remote, true));
        // An unresolvable origin never delivers, even if (hypothetically) an
        // autogate match were somehow claimed for it — fail-safe.
        assert!(!should_deliver_now(PeerOrigin::Unknown, false));
        assert!(!should_deliver_now(PeerOrigin::Unknown, true));
    }

    // ── Bearer-token authentication (CONTRACTS.md §6 amendment, 2026-08-18) ──
    //
    // THE REGRESSION PIN this amendment must not violate: with no token
    // configured, every origin/autogate combination `should_deliver_now`
    // resolves TODAY must resolve identically — the test just above this one
    // (untouched by this amendment, still exercising the bare function) is
    // that pin at the `should_deliver_now` level. The two tests below prove
    // the pin holds at the INTEGRATION point too: `effective_origin` (what
    // actually feeds `should_deliver_now` now) is the identity function when
    // `token_configured` is false, and `token_authorized` always allows —
    // so composing them in front of the untouched functions changes nothing
    // on the off-path, by construction rather than by inspection alone.

    #[test]
    fn effective_origin_is_the_identity_function_when_no_token_is_configured() {
        for origin in [
            PeerOrigin::Loopback,
            PeerOrigin::Remote("10.0.0.5".parse().unwrap()),
            PeerOrigin::Unknown,
        ] {
            for token_state in [TokenState::Absent, TokenState::Invalid, TokenState::Valid] {
                assert_eq!(
                    effective_origin(origin, false, token_state),
                    origin,
                    "token_configured=false must pass {origin:?} through unchanged regardless of token_state"
                );
            }
        }
    }

    #[test]
    fn effective_origin_denies_loopback_once_a_token_is_configured_and_not_valid() {
        // The "coupled loopback trust" amendment: once ANY token is
        // configured, loopback keeps its old free pass ONLY with a valid
        // bearer — an absent or wrong one is coerced to Unknown, which
        // `should_deliver_now` already treats as never-trusted.
        assert_eq!(
            effective_origin(PeerOrigin::Loopback, true, TokenState::Absent),
            PeerOrigin::Unknown
        );
        assert_eq!(
            effective_origin(PeerOrigin::Loopback, true, TokenState::Invalid),
            PeerOrigin::Unknown
        );
        // A VALID token restores loopback's original standing exactly.
        assert_eq!(
            effective_origin(PeerOrigin::Loopback, true, TokenState::Valid),
            PeerOrigin::Loopback
        );
        // A remote origin without a valid token is ALSO coerced — it was
        // already untrusted by default, but this proves the coercion isn't
        // loopback-specific plumbing that happens to skip Remote.
        assert_eq!(
            effective_origin(PeerOrigin::Remote("10.0.0.5".parse().unwrap()), true, TokenState::Absent),
            PeerOrigin::Unknown
        );
    }

    #[test]
    fn classify_token_is_absent_valid_or_invalid() {
        assert_eq!(classify_token("s3cr3t", None), TokenState::Absent);
        assert_eq!(classify_token("s3cr3t", Some("s3cr3t")), TokenState::Valid);
        assert_eq!(classify_token("s3cr3t", Some("wrong")), TokenState::Invalid);
        // A presented token of a DIFFERENT length than expected is still a
        // clean Invalid, not a panic or an early-return short-circuit.
        assert_eq!(classify_token("s3cr3t", Some("s3cr3tt")), TokenState::Invalid);
        assert_eq!(classify_token("s3cr3t", Some("")), TokenState::Invalid);
    }

    #[test]
    fn token_authorized_always_allows_when_no_token_is_configured() {
        // THE regression pin: `spawn_agent` alone (rebuild-time admission)
        // still fully gates spawn, and the read verbs stay open, when no
        // token is set — Phase G adds a gate, it doesn't tighten the existing
        // off-path.
        for token_state in [TokenState::Absent, TokenState::Invalid, TokenState::Valid] {
            assert!(token_authorized(false, token_state), "token_configured=false must always allow, got {token_state:?}");
        }
    }

    #[test]
    fn token_authorized_requires_a_valid_token_once_one_is_configured() {
        assert!(!token_authorized(true, TokenState::Absent));
        assert!(!token_authorized(true, TokenState::Invalid));
        assert!(token_authorized(true, TokenState::Valid));
    }

    #[test]
    fn extract_bearer_parses_the_authorization_header_value() {
        assert_eq!(extract_bearer("Bearer abc123").as_deref(), Some("abc123"));
        // The scheme name is case-insensitive (RFC 7235 §2.1); extra
        // whitespace around the token is trimmed.
        assert_eq!(extract_bearer("bearer   abc123  ").as_deref(), Some("abc123"));
        assert_eq!(extract_bearer("BEARER abc123").as_deref(), Some("abc123"));
        // Any other scheme, a missing token, or a malformed header → None.
        assert_eq!(extract_bearer("Basic dXNlcjpwYXNz"), None);
        assert_eq!(extract_bearer("Bearer"), None);
        assert_eq!(extract_bearer("Bearer   "), None);
        assert_eq!(extract_bearer(""), None);
    }

    #[test]
    fn parse_http_request_captures_the_authorization_bearer_header() {
        let raw = b"POST / HTTP/1.1\r\nAuthorization: Bearer my-token\r\nContent-Length: 2\r\n\r\n{}";
        let mut r = BufReader::new(std::io::Cursor::new(&raw[..]));
        let req = parse_http_request(&mut r, Instant::now()).unwrap();
        assert_eq!(req.bearer.as_deref(), Some("my-token"));

        // No Authorization header at all → None, same as before this field
        // existed.
        let raw2 = b"POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}";
        let mut r2 = BufReader::new(std::io::Cursor::new(&raw2[..]));
        let req2 = parse_http_request(&mut r2, Instant::now()).unwrap();
        assert_eq!(req2.bearer, None);
    }

    #[test]
    fn resolve_token_file_prefers_flag_then_env_then_defaults_empty() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_A2A_TOKEN_FILE").ok();

        let mut flags = std::collections::BTreeMap::new();
        flags.insert("token-file".to_string(), "/flag/path".to_string());
        let inv = Invocation { path: vec![], args: vec![], flags, door: Door::Cli };
        std::env::set_var("AOIDE_A2A_TOKEN_FILE", "/env/path");
        assert_eq!(resolve_token_file(&inv), "/flag/path", "an explicit flag wins outright");

        let inv_no_flag = Invocation {
            path: vec![],
            args: vec![],
            flags: std::collections::BTreeMap::new(),
            door: Door::Cli,
        };
        assert_eq!(resolve_token_file(&inv_no_flag), "/env/path", "falls back to the env var");

        std::env::remove_var("AOIDE_A2A_TOKEN_FILE");
        assert_eq!(resolve_token_file(&inv_no_flag), "", "defaults to empty (no token required)");

        match saved {
            Some(v) => std::env::set_var("AOIDE_A2A_TOKEN_FILE", v),
            None => std::env::remove_var("AOIDE_A2A_TOKEN_FILE"),
        }
    }

    #[test]
    fn read_expected_token_trims_and_tolerates_absence() {
        assert_eq!(read_expected_token(""), None, "an empty path is feature-off — no disk read");
        assert_eq!(
            read_expected_token("/nonexistent/aoide-a2a-token-file-does-not-exist"),
            None,
            "an unreadable path is tolerated as unconfigured, not a hard failure"
        );

        let dir = std::env::temp_dir().join(format!("aoide-a2a-token-file-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("token");
        std::fs::write(&path, "  s3cr3t-value\n").unwrap();
        assert_eq!(
            read_expected_token(path.to_str().unwrap()),
            Some("s3cr3t-value".to_string()),
            "trims surrounding whitespace/newline"
        );

        std::fs::write(&path, "   \n").unwrap();
        assert_eq!(
            read_expected_token(path.to_str().unwrap()),
            None,
            "a whitespace-only file is treated as unconfigured"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn message_send_spawn_rejects_without_a_valid_token_once_one_is_configured() {
        // No contextId → the Spawn arm — spawn_agent is non-empty so
        // `decide_send_action` resolves to Spawn, and the NEW token gate must
        // reject it BEFORE `do_spawn` ever runs (so this never actually
        // spawns a process — the house rule every other error-branch test in
        // this suite already follows).
        let params = json!({
            "message": { "parts": [{ "kind": "text", "text": "hi" }] }
        });
        let err = message_send(
            &params,
            Path::new("/dev/null"),
            "claude",
            PeerOrigin::Loopback,
            "expected-secret",
            None,
        )
        .unwrap_err();
        assert_eq!(err.0, -32005);

        let err2 = message_send(
            &params,
            Path::new("/dev/null"),
            "claude",
            PeerOrigin::Loopback,
            "expected-secret",
            Some("wrong-secret"),
        )
        .unwrap_err();
        assert_eq!(err2.0, -32005);
    }

    #[test]
    fn non_loopback_message_send_is_held_pending_not_delivered() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-nonloopback-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_STATE_DIR", root.join("state"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        std::env::remove_var("AOIDE_SESSION_ID");

        let id = "remote-target";
        let socket = aoide_conduct::graph::conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        // A listener stands in for the conducted process — if a delivery
        // were WRONGLY attempted, connecting to it would succeed; the
        // assertions below prove the connect never happens at all.
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();

        let sf = SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![conductable_session(id, &socket)],
        };
        write_stage(&sessions_path(), &sf).unwrap();

        let audit_log = root.join("log");
        let params = serde_json::json!({
            "message": { "parts": [{ "kind": "text", "text": "inject me" }], "contextId": id }
        });
        let remote_origin = PeerOrigin::Remote("10.0.0.9".parse().unwrap());
        let result = message_send(&params, &audit_log, "", remote_origin, "", None);
        let task = result.expect("a pending send is still an Ok Task, not a JSON-RPC error");
        assert_eq!(task["id"], id);
        assert_eq!(
            task["status"]["state"], "submitted",
            "the synchronous response reports `submitted`, not the session's unrelated state"
        );

        // Nothing connected to the socket — no delivery was attempted.
        assert!(listener.accept().is_err(), "a non-loopback, non-autogated send must never touch the socket");

        // `pending.json` carries the queued entry.
        let pending: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(stage.join("pending.json")).unwrap(),
        )
        .unwrap();
        let entries = pending["pending"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["sessionId"], id);
        assert_eq!(entries[0]["text"], "inject me");

        // Audited through the single Door::A2a log, "pending" status — every
        // outcome (queued/auto-delivered/error) routes through the SAME
        // audit path `graph send` already uses (`conduct::graph::send::
        // audit_send`), never a second logging path.
        let log = std::fs::read_to_string(&audit_log).unwrap_or_default();
        assert!(log.contains("\"door\":\"a2a\""), "audited through Door::A2a: {log}");
        assert!(log.contains("\"status\":\"pending\""), "audited as pending: {log}");
        assert!(log.contains("graph.send"), "reuses graph send's own audit command label: {log}");

        let _ = std::fs::remove_dir_all(&root);
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    #[test]
    fn loopback_message_send_still_auto_delivers_exactly_as_before() {
        // Regression test (hard requirement): this amendment must NOT change
        // loopback semantics at all — a loopback origin still auto-delivers,
        // byte-for-byte the same as `do_inject`'s pre-amendment unconditional
        // `--yes` behavior.
        let _guard = crate::env_lock().lock().unwrap();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-loopback-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_STATE_DIR", root.join("state"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        std::env::remove_var("AOIDE_SESSION_ID");

        let id = "local-target";
        let socket = aoide_conduct::graph::conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();

        let sf = SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![conductable_session(id, &socket)],
        };
        write_stage(&sessions_path(), &sf).unwrap();

        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });

        let audit_log = root.join("log");
        let params = serde_json::json!({
            "message": { "parts": [{ "kind": "text", "text": "hello loopback" }], "contextId": id }
        });
        let result = message_send(&params, &audit_log, "", PeerOrigin::Loopback, "", None);
        let got = acc.join().unwrap();
        assert_eq!(String::from_utf8(got).unwrap(), "hello loopback\n");

        let task = result.unwrap();
        assert_eq!(task["id"], id);

        let log = std::fs::read_to_string(&audit_log).unwrap_or_default();
        assert!(log.contains("\"status\":\"delivered\""), "audited as delivered: {log}");

        let _ = std::fs::remove_dir_all(&root);
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    #[test]
    fn loopback_message_send_gets_the_uniform_answer_once_a_token_is_configured_and_absent() {
        // The actual gap the 2026-08-19 amendment closed: a proxy/tunnel
        // makes an outside caller LOOK loopback to `peer_addr()`. Once the
        // operator configures a token, an unauthenticated "loopback" caller
        // must no longer get the automatic pass it used to.
        //
        // Superseded by the 2026-08-20 (#50) uniform-response amendment: this
        // scenario now hits the uniform guard BEFORE `decide_send_action`
        // even runs, so it no longer queues into `pending.json` at all — it
        // used to (a hold-pending Task, one queued entry); now it's a
        // synthetic submitted Task and the queue stays untouched, closing
        // the unauthenticated-queue-write half of #50.
        let _guard = crate::env_lock().lock().unwrap();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            // Kept SHORT deliberately: XDG_RUNTIME_DIR is set to this root, so
            // conduct_socket_path() hangs `/aoide/session-<id>.sock` off it and
            // the whole thing must fit SUN_LEN (107 bytes + NUL).
            "aoide-a2a-tok-abs-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_STATE_DIR", root.join("state"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        std::env::remove_var("AOIDE_SESSION_ID");

        let id = "tok-abs-tgt";
        let socket = aoide_conduct::graph::conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        // If a delivery were WRONGLY attempted, connecting would succeed;
        // the assertions below prove it never happens.
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();

        let sf = SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![conductable_session(id, &socket)],
        };
        write_stage(&sessions_path(), &sf).unwrap();

        let audit_log = root.join("log");
        let params = serde_json::json!({
            "message": { "parts": [{ "kind": "text", "text": "spoofed loopback" }], "contextId": id }
        });
        let result = message_send(&params, &audit_log, "", PeerOrigin::Loopback, "the-real-token", None);
        let task = result.expect("the uniform arm always answers Ok, never a JSON-RPC error");
        assert_eq!(
            task["status"]["state"], "submitted",
            "the uniform synthetic Task, not the session's unrelated state"
        );
        assert!(listener.accept().is_err(), "an unauthenticated 'loopback' send must never touch the socket once a token is configured");

        // #50: the uniform arm never resolves the id, so it never queues —
        // no `pending.json` entry, unlike this scenario's pre-#50 behavior.
        let pending_path = stage.join("pending.json");
        if pending_path.exists() {
            let pending: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&pending_path).unwrap()).unwrap();
            assert!(
                pending["pending"].as_array().map(Vec::is_empty).unwrap_or(true),
                "an unauthenticated 'loopback' send must never feed the approval queue"
            );
        }

        let _ = std::fs::remove_dir_all(&root);
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    #[test]
    fn loopback_message_send_with_a_valid_token_still_auto_delivers() {
        // The other half of the same coupling: presenting the CORRECT token
        // restores exactly the original loopback behavior — this amendment
        // narrows trust, it doesn't remove the ability to be trusted.
        let _guard = crate::env_lock().lock().unwrap();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            // Kept SHORT deliberately — see the sibling test above for why.
            "aoide-a2a-tok-ok-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_STATE_DIR", root.join("state"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        std::env::remove_var("AOIDE_SESSION_ID");

        let id = "tok-ok-tgt";
        let socket = aoide_conduct::graph::conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();

        let sf = SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![conductable_session(id, &socket)],
        };
        write_stage(&sessions_path(), &sf).unwrap();

        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });

        let audit_log = root.join("log");
        let params = serde_json::json!({
            "message": { "parts": [{ "kind": "text", "text": "authenticated loopback" }], "contextId": id }
        });
        let result = message_send(
            &params,
            &audit_log,
            "",
            PeerOrigin::Loopback,
            "the-real-token",
            Some("the-real-token"),
        );
        let got = acc.join().unwrap();
        assert_eq!(String::from_utf8(got).unwrap(), "authenticated loopback\n");
        assert_eq!(result.unwrap()["id"], id);

        let _ = std::fs::remove_dir_all(&root);
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    #[test]
    fn autogated_peer_delivers_despite_being_non_loopback() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-autogate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        std::env::remove_var("AOIDE_SESSION_ID");

        // A peer explicitly marked `autogate: true`, whose url resolves (as
        // an IP literal — no real DNS) to the connecting address.
        aoide_storage::peer_store::save_peers(&[aoide_storage::peer_store::Peer {
            name: "trusted-peer".into(),
            url: "http://10.0.0.9:8710/".into(),
            autogate: true,
            token_file: None,
            added_at: "2026-08-14T00:00:00Z".into(),
        }])
        .unwrap();

        let id = "autogate-target";
        let socket = aoide_conduct::graph::conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();

        let sf = SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![conductable_session(id, &socket)],
        };
        write_stage(&sessions_path(), &sf).unwrap();

        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });

        let audit_log = root.join("log");
        let params = serde_json::json!({
            "message": { "parts": [{ "kind": "text", "text": "trusted send" }], "contextId": id }
        });
        let remote_origin = PeerOrigin::Remote("10.0.0.9".parse().unwrap());
        let result = message_send(&params, &audit_log, "", remote_origin, "", None);
        let got = acc.join().unwrap();
        assert_eq!(
            String::from_utf8(got).unwrap(),
            "trusted send\n",
            "an autogate-marked peer's non-loopback send still auto-delivers"
        );
        assert!(result.is_ok());

        // No pending.json entry was ever queued for this delivered send.
        let pending_path = stage.join("pending.json");
        if pending_path.exists() {
            let pending: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&pending_path).unwrap()).unwrap();
            assert!(pending["pending"].as_array().map(Vec::is_empty).unwrap_or(true));
        }

        let _ = std::fs::remove_dir_all(&root);
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    #[test]
    fn autogated_peer_delivers_via_a_matching_token_even_when_ip_does_not_match() {
        // The actual replacement for the dead IP match: behind a proxy the
        // caller's real address is unknowable, but a per-peer TOKEN survives
        // the hop. No global A2A token is configured here at all — this is
        // entirely the peer_store-level identification, independent of the
        // `message_send` expected_token/presented_token plumbing.
        let _guard = crate::env_lock().lock().unwrap();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            // Kept SHORT deliberately: XDG_RUNTIME_DIR is set to this root, so
            // conduct_socket_path() hangs `/aoide/session-<id>.sock` off it and
            // the whole thing must fit SUN_LEN (107 bytes + NUL). The verbose
            // form of this name plus a verbose session id came to exactly 108.
            "aoide-a2a-ptok-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        std::env::remove_var("AOIDE_SESSION_ID");

        let token_path = root.join("peer.token");
        std::fs::write(&token_path, "peer-secret\n").unwrap();
        aoide_storage::peer_store::save_peers(&[aoide_storage::peer_store::Peer {
            name: "proxied-peer".into(),
            // A URL that resolves to an address the caller is NOT actually
            // connecting from — proving delivery here comes from the TOKEN
            // match, not a coincidental IP match.
            url: "http://192.0.2.99:8710/".into(),
            autogate: true,
            token_file: Some(token_path.to_string_lossy().into_owned()),
            added_at: "2026-08-18T00:00:00Z".into(),
        }])
        .unwrap();

        let id = "ptok-target";
        let socket = aoide_conduct::graph::conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();

        let sf = SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![conductable_session(id, &socket)],
        };
        write_stage(&sessions_path(), &sf).unwrap();

        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });

        let audit_log = root.join("log");
        let params = serde_json::json!({
            "message": { "parts": [{ "kind": "text", "text": "token-identified send" }], "contextId": id }
        });
        let remote_origin = PeerOrigin::Remote("10.0.0.9".parse().unwrap());
        let result = message_send(&params, &audit_log, "", remote_origin, "", Some("peer-secret"));
        let got = acc.join().unwrap();
        assert_eq!(String::from_utf8(got).unwrap(), "token-identified send\n");
        assert!(result.is_ok());

        let _ = std::fs::remove_dir_all(&root);
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    // ── Uniform-response guard, #50 (CONTRACTS.md §6 amendment, 2026-08-20) ──
    //
    // Once a token is configured, an unauthenticated `message/send` naming a
    // contextId must be impossible to distinguish from the outside whether
    // that id names a real conductable session, a known-but-not-conductable
    // one, or nothing at all — and must never touch `pending.json`. These
    // tests drive `message_send` directly, same house style as the
    // non-loopback pending-gate tests above.

    fn non_conductable_session(id: &str) -> SessionRecord {
        fixture_session(id, "working", None)
    }

    #[test]
    fn uniform_response_hides_existence_and_never_queues_when_unauthenticated() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-uniform-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_STATE_DIR", root.join("state"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        std::env::remove_var("AOIDE_SESSION_ID");

        let real_id = "real-target";
        let noncond_id = "noncond-target";
        let bogus_id = "bogus-target"; // never written to sessions.json at all

        let real_socket = aoide_conduct::graph::conduct_socket_path(real_id);
        std::fs::create_dir_all(real_socket.parent().unwrap()).unwrap();
        // If the guard wrongly fell through to do_inject, connecting here
        // would succeed — proving it never happens is the point.
        let real_listener = UnixListener::bind(&real_socket).unwrap();
        real_listener.set_nonblocking(true).unwrap();

        let sf = SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![conductable_session(real_id, &real_socket), non_conductable_session(noncond_id)],
        };
        write_stage(&sessions_path(), &sf).unwrap();

        let audit_log = root.join("log");

        // Both "no bearer at all" and "a wrong bearer" must land on the same
        // uniform answer — this is TokenState::Absent vs TokenState::Invalid,
        // both non-Valid.
        for presented in [None, Some("wrong-tok")] {
            let mut shapes = Vec::new();
            for id in [real_id, bogus_id, noncond_id] {
                let params = serde_json::json!({
                    "message": { "parts": [{ "kind": "text", "text": "probe" }], "contextId": id }
                });
                // Loopback origin too — the uniform answer holds even for the
                // origin that would otherwise get the automatic trust pass.
                let result = message_send(&params, &audit_log, "", PeerOrigin::Loopback, "s3cr3t", presented);
                let task = result.expect("uniform arm always answers Ok, never a JSON-RPC error");
                assert_eq!(task["id"], id);
                assert_eq!(task["contextId"], id);
                assert_eq!(task["status"]["state"], "submitted");
                assert_eq!(task["kind"], "task");
                assert!(task["status"]["timestamp"].as_str().unwrap().ends_with('Z'));

                let mut normalized = task.clone();
                normalized["id"] = serde_json::Value::Null;
                normalized["contextId"] = serde_json::Value::Null;
                normalized["status"]["timestamp"] = serde_json::Value::Null;
                shapes.push(normalized);
            }
            assert_eq!(shapes[0], shapes[1], "real vs bogus id: byte-identical shape modulo id/timestamp");
            assert_eq!(shapes[0], shapes[2], "real vs non-conductable id: byte-identical shape modulo id/timestamp");
        }

        // Never touched the real session's control socket.
        assert!(real_listener.accept().is_err(), "the uniform arm must never attempt delivery");

        // Never wrote pending.json — no queue write for any of the three.
        let pending_path = stage.join("pending.json");
        if pending_path.exists() {
            let pending: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&pending_path).unwrap()).unwrap();
            assert!(
                pending["pending"].as_array().map(Vec::is_empty).unwrap_or(true),
                "unauthenticated sends must never feed the approval queue"
            );
        }

        let log = std::fs::read_to_string(&audit_log).unwrap_or_default();
        assert!(log.contains("\"door\":\"a2a\""), "audited through Door::A2a: {log}");
        assert!(log.contains("\"status\":\"unauthorized\""), "audited as unauthorized: {log}");
        assert!(log.contains("a2a.message/send"), "reuses message/send's own audit label: {log}");

        let _ = std::fs::remove_dir_all(&root);
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    #[test]
    fn uniform_response_guard_lets_a_valid_bearer_reach_the_real_decision() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-uniform-valid-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_STATE_DIR", root.join("state"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        std::env::remove_var("AOIDE_SESSION_ID");

        let real_id = "valid-real-target";
        let noncond_id = "valid-noncond-target";
        let bogus_id = "valid-bogus-target";

        let real_socket = aoide_conduct::graph::conduct_socket_path(real_id);
        std::fs::create_dir_all(real_socket.parent().unwrap()).unwrap();
        let real_listener = UnixListener::bind(&real_socket).unwrap();
        real_listener.set_nonblocking(true).unwrap();

        let sf = SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![conductable_session(real_id, &real_socket), non_conductable_session(noncond_id)],
        };
        write_stage(&sessions_path(), &sf).unwrap();

        let audit_log = root.join("log");
        // Remote + no registered autogate peer, so a real send is held
        // pending rather than delivered — same as the pre-#50 Inject arm,
        // and it proves `do_inject` (not the uniform guard) ran: only that
        // path writes `pending.json`.
        let remote_origin = PeerOrigin::Remote("10.0.0.9".parse().unwrap());

        let params = serde_json::json!({
            "message": { "parts": [{ "kind": "text", "text": "authed send" }], "contextId": real_id }
        });
        let result = message_send(&params, &audit_log, "", remote_origin, "s3cr3t", Some("s3cr3t"));
        let task = result.expect("a valid bearer still resolves the real Inject decision");
        assert_eq!(task["id"], real_id);
        assert_eq!(task["status"]["state"], "submitted");
        assert!(real_listener.accept().is_err(), "not auto-delivered — held pending, same as before #50");

        let pending: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(stage.join("pending.json")).unwrap()).unwrap();
        let entries = pending["pending"].as_array().unwrap();
        assert_eq!(entries.len(), 1, "a valid bearer's Inject still queues, unlike the uniform guard");
        assert_eq!(entries[0]["sessionId"], real_id);

        let bogus_params = serde_json::json!({
            "message": { "parts": [{ "kind": "text", "text": "x" }], "contextId": bogus_id }
        });
        let bogus_err =
            message_send(&bogus_params, &audit_log, "", remote_origin, "s3cr3t", Some("s3cr3t")).unwrap_err();
        assert_eq!(bogus_err.0, -32001);

        let noncond_params = serde_json::json!({
            "message": { "parts": [{ "kind": "text", "text": "x" }], "contextId": noncond_id }
        });
        let noncond_err =
            message_send(&noncond_params, &audit_log, "", remote_origin, "s3cr3t", Some("s3cr3t")).unwrap_err();
        assert_eq!(noncond_err.0, -32004);

        let _ = std::fs::remove_dir_all(&root);
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    #[test]
    fn uniform_response_guard_is_a_no_op_when_no_token_is_configured() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-uniform-off-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_STATE_DIR", root.join("state"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        std::env::remove_var("AOIDE_SESSION_ID");

        let real_id = "off-real-target";
        let noncond_id = "off-noncond-target";
        let bogus_id = "off-bogus-target";

        let real_socket = aoide_conduct::graph::conduct_socket_path(real_id);
        std::fs::create_dir_all(real_socket.parent().unwrap()).unwrap();
        let real_listener = UnixListener::bind(&real_socket).unwrap();

        let sf = SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![conductable_session(real_id, &real_socket), non_conductable_session(noncond_id)],
        };
        write_stage(&sessions_path(), &sf).unwrap();

        let acc = std::thread::spawn(move || {
            let (mut conn, _) = real_listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });

        let audit_log = root.join("log");
        // Loopback + no token configured: off-path, must auto-deliver exactly
        // as it did before the #50 amendment.
        let params = serde_json::json!({
            "message": { "parts": [{ "kind": "text", "text": "off-path send" }], "contextId": real_id }
        });
        let result = message_send(&params, &audit_log, "", PeerOrigin::Loopback, "", None);
        let got = acc.join().unwrap();
        assert_eq!(String::from_utf8(got).unwrap(), "off-path send\n", "no token configured: loopback still auto-delivers");
        assert!(result.is_ok());

        let bogus_params = serde_json::json!({
            "message": { "parts": [{ "kind": "text", "text": "x" }], "contextId": bogus_id }
        });
        let bogus_err = message_send(&bogus_params, &audit_log, "", PeerOrigin::Loopback, "", None).unwrap_err();
        assert_eq!(bogus_err.0, -32001);

        let noncond_params = serde_json::json!({
            "message": { "parts": [{ "kind": "text", "text": "x" }], "contextId": noncond_id }
        });
        let noncond_err = message_send(&noncond_params, &audit_log, "", PeerOrigin::Loopback, "", None).unwrap_err();
        assert_eq!(noncond_err.0, -32004);

        let _ = std::fs::remove_dir_all(&root);
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    #[test]
    fn uniform_response_guard_never_fires_for_a_per_peer_autogated_token() {
        // A server-wide token IS configured (and the presented bearer does
        // NOT match it), but the presented token DOES match an enrolled
        // peer's own `token_file` — the exact scenario the amendment's
        // grounding names: enrolled peers authenticate per-peer, never
        // against the server-wide token, so the uniform guard must not
        // swallow this send.
        //
        // What "not swallowed" means here is REACHING `do_inject`, not
        // necessarily instant delivery: a non-Valid server-wide bearer still
        // coerces `effective_origin` to `Unknown` (the pre-existing,
        // 2026-08-19 amendment — unrelated to #50), and `should_deliver_now`
        // never auto-delivers on `Unknown` regardless of autogate (fail-safe
        // pin: `should_deliver_now_covers_every_origin_autogate_combination`).
        // So this send is correctly held PENDING — the proof that autogate
        // exempted it from the #50 guard is that it reaches the real
        // `session_ref_lookup`/`do_inject` machinery and queues into
        // `pending.json` at all, which the #50 guard's own synthetic path
        // never does.
        let _guard = crate::env_lock().lock().unwrap();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-uniform-ptok-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        std::env::remove_var("AOIDE_SESSION_ID");

        let token_path = root.join("peer.token");
        std::fs::write(&token_path, "peer-secret\n").unwrap();
        aoide_storage::peer_store::save_peers(&[aoide_storage::peer_store::Peer {
            name: "enrolled-peer".into(),
            url: "http://192.0.2.99:8710/".into(),
            autogate: true,
            token_file: Some(token_path.to_string_lossy().into_owned()),
            added_at: "2026-08-20T00:00:00Z".into(),
        }])
        .unwrap();

        let id = "ptok-still-injects";
        let socket = aoide_conduct::graph::conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        // Nonblocking + no acceptor thread: this send is held pending (see
        // above), so a connection must never actually land here — a blocking
        // `accept()` would hang forever waiting for a delivery that never
        // comes, exactly the trap the ORIGINAL (wrong) version of this test
        // fell into.
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();

        let sf = SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![conductable_session(id, &socket)],
        };
        write_stage(&sessions_path(), &sf).unwrap();

        let audit_log = root.join("log");
        let params = serde_json::json!({
            "message": { "parts": [{ "kind": "text", "text": "per-peer authed" }], "contextId": id }
        });
        let remote_origin = PeerOrigin::Remote("10.0.0.9".parse().unwrap());
        // "server-secret" is configured server-wide; "peer-secret" (what's
        // presented) does NOT match it — only the per-peer autogate match
        // saves this from the #50 uniform guard.
        let result = message_send(&params, &audit_log, "", remote_origin, "server-secret", Some("peer-secret"));
        let task = result.expect("autogate exempts this send from the #50 guard, so it's still an Ok Task");
        assert_eq!(task["id"], id);
        assert_eq!(task["status"]["state"], "submitted");
        assert!(listener.accept().is_err(), "held pending, not delivered — the non-Valid server bearer still coerces Unknown");

        // The proof this reached REAL Inject machinery (not the #50 guard):
        // `pending.json` carries the queued entry, exactly like an
        // authenticated-but-not-auto-delivered send does.
        let pending: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(stage.join("pending.json")).unwrap()).unwrap();
        let entries = pending["pending"].as_array().unwrap();
        assert_eq!(entries.len(), 1, "autogate exemption reaches do_inject/session_ref_lookup, unlike the #50 guard");
        assert_eq!(entries[0]["sessionId"], id);

        let _ = std::fs::remove_dir_all(&root);
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    // ── `resolve_peer_name` precedence (flag → env → hostname → default) ────

    #[test]
    fn resolve_peer_name_prefers_flag_then_env_then_falls_back() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_A2A_PEER_NAME").ok();

        let mut flags = std::collections::BTreeMap::new();
        flags.insert("peer-name".to_string(), "flag-name".to_string());
        let inv = Invocation { path: vec![], args: vec![], flags, door: Door::Cli };
        std::env::set_var("AOIDE_A2A_PEER_NAME", "env-name");
        assert_eq!(resolve_peer_name(&inv), "flag-name", "an explicit flag wins outright");

        let inv_no_flag = Invocation {
            path: vec![],
            args: vec![],
            flags: std::collections::BTreeMap::new(),
            door: Door::Cli,
        };
        assert_eq!(resolve_peer_name(&inv_no_flag), "env-name", "falls back to the env var");

        std::env::remove_var("AOIDE_A2A_PEER_NAME");
        // Falls back to the OS hostname (or, failing that, "aoide") — either
        // way, never empty.
        assert!(!resolve_peer_name(&inv_no_flag).is_empty());

        match saved {
            Some(v) => std::env::set_var("AOIDE_A2A_PEER_NAME", v),
            None => std::env::remove_var("AOIDE_A2A_PEER_NAME"),
        }
    }

    // ── `aoide/graphSummary` (CONTRACTS.md §7) ───────────────────────────────

    #[test]
    fn graph_summary_wraps_the_resolved_graph_document_verbatim() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = std::env::temp_dir().join(format!(
            "aoide-a2a-graphsummary-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let resp = graph_summary("test-instance", "http://127.0.0.1:8710/").unwrap();
        assert_eq!(resp["schemaVersion"], "0");
        assert_eq!(resp["instance"]["name"], "test-instance");
        assert_eq!(resp["instance"]["url"], "http://127.0.0.1:8710/");
        assert!(resp["instance"]["emittedAt"].as_str().unwrap().ends_with('Z'));
        // `graph` is EXACTLY what `resolve_graph_document` (the same function
        // `graph view`/`graph emit` use) produces — no second vocabulary.
        assert_eq!(resp["graph"], resolve_graph_document().unwrap());
        assert_eq!(resp["graph"]["schemaVersion"], "0");
        assert!(resp["graph"]["nodes"].is_array());
        assert!(resp["graph"]["edges"].is_array());

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn handle_jsonrpc_routes_aoide_graph_summary_and_still_32601s_everything_else() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = std::env::temp_dir().join(format!(
            "aoide-a2a-graphsummary-rpc-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let req = json!({ "jsonrpc": "2.0", "id": 1, "method": "aoide/graphSummary", "params": {} });
        let resp = handle_jsonrpc(&req, &test_ctx(Path::new("/dev/null"), ""));
        assert_eq!(resp["result"]["schemaVersion"], "0");
        assert_eq!(resp["result"]["instance"]["name"], "aoide");
        assert!(resp["result"]["graph"]["nodes"].is_array());

        // An unrelated unknown method is still a clean -32601, unaffected by
        // the new method joining the dispatch table (JSON-RPC spec).
        let req2 = json!({ "jsonrpc": "2.0", "id": 2, "method": "aoide/notARealMethod", "params": {} });
        let resp2 = handle_jsonrpc(&req2, &test_ctx(Path::new("/dev/null"), ""));
        assert_eq!(resp2["error"]["code"], -32601);

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
            bearer: None,
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
        let registry = Registry::new();
        let (status, body, _) = route(
            &HttpRequest { method: "GET".into(), path: "/nope".into(), body: vec![], bearer: None },
            "127.0.0.1",
            8710,
            Path::new("/dev/null"),
            "",
            "aoide",
            PeerOrigin::Loopback,
            "",
            &registry,
        );
        assert_eq!(status, 404);
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert!(v["error"]["code"].is_i64());

        let (status, body, _) = route(
            &HttpRequest {
                method: "GET".into(),
                path: "/".into(),
                body: vec![],
                bearer: None,
            },
            "127.0.0.1",
            8710,
            Path::new("/dev/null"),
            "",
            "aoide",
            PeerOrigin::Loopback,
            "",
            &registry,
        );
        assert_eq!(status, 405);
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert!(v["error"]["code"].is_i64());
    }

    // ── P4: unauthenticated AgentCard GET is stripped, not gated ────────────
    // (CONTRACTS.md §6, 2026-08-20 amendment)

    /// Off-path pin: with NO token configured, the served card is
    /// byte-identical to the pre-amendment behavior — the FULL card,
    /// field-for-field against `agent_card_from_commands` directly — with or
    /// without a bearer presented (there's nothing configured to compare it
    /// against).
    #[test]
    fn agent_card_get_with_no_token_configured_serves_the_full_card_unchanged() {
        let registry = Registry::new();
        let expected = agent_card_from_commands(registry.commands(), "127.0.0.1", 8710);

        for bearer in [None, Some("anything".to_string())] {
            let req = HttpRequest {
                method: "GET".into(),
                path: "/.well-known/agent-card.json".into(),
                body: vec![],
                bearer,
            };
            let (status, body, label) = route(
                &req,
                "127.0.0.1",
                8710,
                Path::new("/dev/null"),
                "",
                "aoide",
                PeerOrigin::Loopback,
                "",
                &registry,
            );
            assert_eq!(status, 200);
            assert_eq!(label, "a2a.agent-card");
            let served: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(served, expected);
        }
    }

    /// Token configured, no bearer presented: the served card is stripped to
    /// EXACTLY three keys — assert the key COUNT, not just presence, so a
    /// future field added to the full card can't silently leak through the
    /// strip. Status stays 200 (a card GET never becomes `-32005`).
    #[test]
    fn agent_card_get_with_token_and_no_bearer_is_stripped_to_exactly_three_keys() {
        let registry = Registry::new();
        let req = HttpRequest {
            method: "GET".into(),
            path: "/.well-known/agent-card.json".into(),
            body: vec![],
            bearer: None,
        };
        let (status, body, label) = route(
            &req,
            "127.0.0.1",
            8710,
            Path::new("/dev/null"),
            "",
            "aoide",
            PeerOrigin::Loopback,
            "s3cr3t",
            &registry,
        );
        assert_eq!(status, 200, "a card GET never becomes -32005, even unauthorized");
        assert_eq!(label, "a2a.agent-card");
        let served: Value = serde_json::from_slice(&body).unwrap();
        let obj = served.as_object().expect("stripped card is still a JSON object");
        assert_eq!(obj.len(), 3, "stripped card must carry exactly name/protocolVersion/url, got {obj:?}");
        assert_eq!(served["name"], "aoide");
        assert_eq!(served["protocolVersion"], "0.3.0");
        assert_eq!(served["url"], "http://127.0.0.1:8710/");
        assert!(!obj.contains_key("skills"), "skills inventory must not leak unauthenticated");
        assert!(!obj.contains_key("version"), "version must not leak unauthenticated");
        assert!(!obj.contains_key("capabilities"), "capabilities must not leak unauthenticated");
        assert!(!obj.contains_key("defaultInputModes"));
        assert!(!obj.contains_key("defaultOutputModes"));
    }

    /// Token configured, WRONG bearer presented: the same stripped card as
    /// no bearer at all — `token_authorized` treats `TokenState::Invalid`
    /// identically to `Absent`.
    #[test]
    fn agent_card_get_with_wrong_bearer_is_the_same_stripped_card() {
        let registry = Registry::new();
        let req = HttpRequest {
            method: "GET".into(),
            path: "/.well-known/agent-card.json".into(),
            body: vec![],
            bearer: Some("nope".to_string()),
        };
        let (status, body, _) = route(
            &req,
            "127.0.0.1",
            8710,
            Path::new("/dev/null"),
            "",
            "aoide",
            PeerOrigin::Loopback,
            "s3cr3t",
            &registry,
        );
        assert_eq!(status, 200);
        let served: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(served.as_object().unwrap().len(), 3);
        assert_eq!(served["name"], "aoide");
    }

    /// Token configured, VALID bearer presented: the full card, unchanged.
    #[test]
    fn agent_card_get_with_valid_bearer_serves_the_full_card() {
        let registry = Registry::new();
        let expected = agent_card_from_commands(registry.commands(), "127.0.0.1", 8710);
        let req = HttpRequest {
            method: "GET".into(),
            path: "/.well-known/agent-card.json".into(),
            body: vec![],
            bearer: Some("s3cr3t".to_string()),
        };
        let (status, body, _) = route(
            &req,
            "127.0.0.1",
            8710,
            Path::new("/dev/null"),
            "",
            "aoide",
            PeerOrigin::Loopback,
            "s3cr3t",
            &registry,
        );
        assert_eq!(status, 200);
        let served: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(served, expected);
    }

    /// The client's own `parse_agent_card` still accepts the stripped shape
    /// — enrollment (`aoide a2a agent add`) survives against a
    /// token-protected server, it just gets an empty `description` (the
    /// known accepted consequence, CONTRACTS.md §6 2026-08-20 amendment;
    /// closing it is #47 Phase H, not this one).
    #[test]
    fn parse_agent_card_accepts_the_stripped_card() {
        let full = agent_card_from_commands(Registry::new().commands(), "127.0.0.1", 8710);
        let stripped = stripped_card(&full);
        let agent = aoide_client::wire::parse_agent_card(
            &stripped,
            "http://127.0.0.1:8710/.well-known/agent-card.json",
            "NOW",
        )
        .expect("stripped card still has a name; enrollment must not fail");
        assert_eq!(agent.name, "aoide");
        assert_eq!(agent.url, "http://127.0.0.1:8710/");
        assert_eq!(agent.description, "", "stripped card carries no description field to read");
    }
}
