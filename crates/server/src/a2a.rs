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
//! Routes (CONTRACTS.md §6 MVP surface, plus §7's node federation):
//!   - `GET  /.well-known/agent-card.json` — the AgentCard, derived from the
//!     command registry, filtered to `implemented: true`.
//!   - `POST /` — JSON-RPC 2.0: `tasks/get` (real), `message/send` (real —
//!     inject into a known conductable session, or spawn a freshly conducted
//!     one; [`decide_send_action`] below — a non-loopback Inject queues
//!     pending unless the caller matches an `autogate` node, CONTRACTS.md §6
//!     amendment 2026-08-14; see [`ConnOrigin`]/[`should_deliver_now`]),
//!     `aoide/graphSummary` (real — CONTRACTS.md §7: wraps
//!     [`resolve_graph_document`] in the federation envelope; see
//!     [`graph_summary`]), anything else → `-32601 method not found`.
//!
//! A forwarded A2A message's TEXT is untrusted DATA, never executed as a
//! command — `message/send`'s inject path types it into a target session
//! exactly like `send` (in fact it reuses
//! [`aoide_conduct::graph::session_send`] for that), and its spawn path never
//! runs a client-supplied command: it only ever launches the
//! operator-configured `aoide.a2a.spawnAgent` executable (a rebuild-gated nix
//! option — the user's admission), with the client-supplied prompt injected
//! as its first turn. See [`decide_send_action`]'s doc comment for the full
//! security model.
//!
//! Extracted from root `src/a2a.rs` (Phase 4c restructure,
//! docs/architecture/PACKAGE-LAYOUT.md) — this is the SERVER half only. The
//! CLIENT half (the node registry, AgentCard URL resolution, the outbound
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
    canonical_state, load_stage, now_iso_utc, resolve_graph_document, session_send, sessions_path,
    Project, ProjectsFile, SessionRecord, SessionsFile,
};
use aoide_protocol::output::Status;
use aoide_protocol::registry::{Command, Registry};
use aoide_protocol::wire::{
    AgentCapabilities, AgentCard, AgentSkill, JsonRpcResponse, Task, TaskStatus,
    TaskStatusUpdateEvent,
};
use aoide_protocol::{audit, Door, EventClass, Invocation};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
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

/// Resolve `aoide.a2a.spawnCwd`: the working directory `do_spawn`'s spawned
/// child is launched in, when set. `--spawn-cwd` flag → `AOIDE_A2A_SPAWN_CWD`
/// env (set by the `aoide-a2a` systemd unit) → default `""` (empty = inherit
/// the daemon's own cwd, today's behavior). Mirrors [`resolve_spawn_agent`]'s
/// exact precedence shape. The client NEVER supplies this — only the
/// operator. Unbounded by itself: [`do_spawn`] applies the value only when it
/// names a REGISTERED project root (see its own doc comment) — this function
/// just resolves the configured string, the same way [`resolve_spawn_agent`]
/// resolves a command line without validating it.
pub fn resolve_spawn_cwd(inv: &Invocation) -> String {
    inv.flags
        .get("spawn-cwd")
        .cloned()
        .or_else(|| std::env::var("AOIDE_A2A_SPAWN_CWD").ok())
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

/// Resolve `aoide.a2a.bearerSecret`: the NAME of a secret this door resolves
/// through the LOCAL secrets broker, fresh on every request, as its own
/// expected inbound bearer (task #84) — the first real machine consumer of
/// the secrets broker's unix-socket wire (`CONTRACTS.md`'s "Secrets wire"
/// section). `--bearer-secret` flag → `AOIDE_A2A_BEARER_SECRET` env →
/// default `""` (empty = not configured), mirroring
/// [`resolve_token_file`]'s exact precedence shape. When set, it TAKES
/// PRECEDENCE over the token-file mechanism above — see
/// [`resolve_inbound_bearer`] for the exact precedence and the fail-closed
/// behavior on a broker resolve failure.
pub fn resolve_bearer_secret(inv: &Invocation) -> String {
    inv.flags
        .get("bearer-secret")
        .cloned()
        .or_else(|| std::env::var("AOIDE_A2A_BEARER_SECRET").ok())
        .unwrap_or_default()
}

/// Resolve whether THIS `a2a serve` process is FORCED to advertise for
/// its whole lifetime (P-P6, `docs/architecture/PAIRING.md`'s "Discovery
/// (advertise-but-locked)" section): `--discovery-advertise` flag (bare
/// presence, no value — the same shape `--stdio`/`--all`/`--windowed`
/// already hold elsewhere in this tree) → `AOIDE_DISCOVERY_ADVERTISE` env,
/// truthy in `{1,true,yes,all}` (the exact vocabulary
/// `aoide-conduct::graph::send`'s own `AOIDE_CONDUCT_AUTOGATE` already
/// established — one truthy-env convention, not a second one invented
/// here) → **OFF by default** (PAIRING.md: "off by default" — no
/// advertisement, ever, until an operator opts in explicitly). Mirrors
/// [`resolve_spawn_agent`]/[`resolve_token_file`]'s exact
/// flag-then-env-then-default precedence shape, the idiomatic knob home
/// this door already established for every other operator-facing toggle.
/// This is the nix-declarative half of the switch; the runtime half is
/// `aoide node advertise on|off` (`aoide_storage::advertise::enabled`),
/// OR'd in per tick by the advertise thread
/// (`discovery::spawn_advertiser`), so `false` here still leaves the
/// operator one command away from advertising, no restart.
pub fn resolve_discovery_advertise(inv: &Invocation) -> bool {
    if inv.flag_present("discovery-advertise") {
        return true;
    }
    matches!(
        std::env::var("AOIDE_DISCOVERY_ADVERTISE").ok().as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("all")
    )
}

/// Resolve this instance's `aoide/graphSummary` `instance.name` (CONTRACTS.md
/// §7): `--node-name` flag → `AOIDE_A2A_NODE_NAME` env (set by the
/// `aoide-a2a` systemd unit, mirroring `resolve_bind_port`/
/// `resolve_spawn_agent`'s precedence) → the OS hostname → the literal
/// `"aoide"` if even that fails. The env/hostname tail is
/// `aoide_storage::display::local_host_name` (petnames plan, P2): storage
/// has no `Invocation` to read the flag off, so this crate still resolves
/// the flag itself and only delegates the rest. Resolved once at `a2a serve`
/// launch, same as bind/port/spawn-agent.
pub fn resolve_node_name(inv: &Invocation) -> String {
    // The env/hostname tail (env var -> OS hostname -> "aoide") is delegated
    // to `aoide_storage::display::local_host_name` — the storage crate's copy
    // is byte-identical (conduct/conductor renderers need the same fallback
    // chain and cannot depend on this crate), so this resolves it once
    // instead of keeping a second copy in sync. The `--node-name` flag stays
    // here: storage has no `Invocation` to read a flag off.
    inv.flags
        .get("node-name")
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
pub enum ConnOrigin {
    /// The connection's peer IP is loopback (127.0.0.0/8, `::1`) — today's
    /// trusted-by-bind-address default. UNCHANGED behavior: auto-delivers,
    /// exactly as before this amendment (hard regression requirement).
    Loopback,
    /// A non-loopback peer IP — gated UNLESS it matches an `autogate`-marked
    /// entry in `state/nodes.json`.
    Remote(IpAddr),
    /// The peer address could not be determined (e.g. `peer_addr()` failed).
    /// Fails SAFE: treated exactly like an unmatched [`Self::Remote`] — never
    /// auto-delivered, never autogate-matched.
    Unknown,
}

/// Classify a raw `peer_addr()` result into a [`ConnOrigin`]. Pure.
pub fn classify_origin(node_ip: Option<IpAddr>) -> ConnOrigin {
    match node_ip {
        Some(ip) if ip.is_loopback() => ConnOrigin::Loopback,
        Some(ip) => ConnOrigin::Remote(ip),
        None => ConnOrigin::Unknown,
    }
}

/// Should an Inject auto-deliver (`--yes`) rather than queue pending? Pure —
/// unit-tested directly; the one place I/O (`autogate_match`, a
/// `state/nodes.json` lookup) enters is the caller. Loopback is
/// unconditionally trusted (today's behavior, unchanged); a non-loopback or
/// unknown-origin node only bypasses the queue when it matches an
/// `autogate`-marked registry entry.
fn should_deliver_now(origin: ConnOrigin, autogate_match: bool) -> bool {
    match origin {
        ConnOrigin::Loopback => true,
        ConnOrigin::Remote(_) => autogate_match,
        ConnOrigin::Unknown => false,
    }
}

// ── Bearer-token authentication (CONTRACTS.md §6 amendment, 2026-08-18) ─────
//
// The prior amendment (2026-08-14, above) trusted `ConnOrigin::Loopback`
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
// Separately, [`aoide_storage::node_store::is_autogated_node_token`] restores
// PER-NODE identification for the non-loopback autogate match (replacing the
// now-frequently-dead address match behind a proxy) — that one is keyed on
// each registered node's OWN token, not this single server-wide expected
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
/// feature-on/off switch. Uses [`aoide_storage::node_store::token_bytes_eq`]
/// (length-independent byte compare) rather than `==` on a secret. Pure.
fn classify_token(expected: &str, presented: Option<&str>) -> TokenState {
    match presented {
        None => TokenState::Absent,
        Some(p) if aoide_storage::node_store::token_bytes_eq(expected, p) => TokenState::Valid,
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
/// 2026-08-20): the SPAWN arm of `message/send`, and the READ commands
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
/// bearer is coerced to [`ConnOrigin::Unknown`] — deliberately reusing that
/// variant's existing "never trusted, fails safe" arm in `should_deliver_now`
/// rather than adding a fourth origin kind, since the resulting trust
/// decision (never auto-deliver) is exactly the same either way. This is the
/// "loopback stops being a trust signal" coupling: there is no code path
/// where a token is required AND loopback still auto-delivers unauthenticated
/// — the same `token_configured` bool drives both. Pure.
fn effective_origin(origin: ConnOrigin, token_configured: bool, token_state: TokenState) -> ConnOrigin {
    if token_configured && token_state != TokenState::Valid {
        ConnOrigin::Unknown
    } else {
        origin
    }
}

// ── Signed requests outrank loopback (CONTRACTS.md §6 amendment, 2026-08-26) ─
//
// An ssh `-L` port-forward delivers a tunneled node's packets from the FAR
// box's own sshd, so `classify_origin` sees loopback for every tunneled
// request regardless of who is really on the other end — the same proxy
// ambiguity `effective_origin` above already resolves for a door-wide
// token, now reachable without any token configured at all. A request
// carrying a per-request signature that [`verify_signed_request`] already
// verified is, by construction, a REMOTE node: [`origin_for_inject`] below
// strips `ConnOrigin::Loopback`'s free pass from it before `should_deliver_
// now` ever runs.

/// The origin [`should_deliver_now`]'s Inject decision actually sees, once a
/// verified per-request signature is factored in. Pure.
///
/// `signed_non_autogate` is `true` only when the caller both ran the request
/// through [`verify_signed_request`] AND resolved it to a node the operator
/// has NOT marked auto-deliver (`message_send` computes exactly
/// `signed_node_name.is_some() && !sig_autogate`). Such a caller is a remote
/// node by construction, so it loses `ConnOrigin::Loopback`'s free pass:
/// coerced to [`ConnOrigin::Unknown`], reusing that variant's existing
/// fail-safe arm rather than inventing a fourth origin kind — exactly the
/// move [`effective_origin`] already makes for an invalid door-wide token.
///
/// The exemption is load-bearing, not a convenience:
/// `should_deliver_now(ConnOrigin::Unknown, _)` ignores `autogate_match`
/// entirely, so coercing a signature-rung autogate node would leave it
/// permanently undeliverable. It keeps riding the ordinary Loopback/Remote
/// arms, which do consult `autogate_match`.
///
/// `false` therefore covers two callers: an unsigned request (`origin`
/// passes through unchanged, so the unsigned path stays byte-identical) and
/// an autogate-marked signed node.
fn origin_for_inject(origin: ConnOrigin, signed_non_autogate: bool) -> ConnOrigin {
    if signed_non_autogate {
        ConnOrigin::Unknown
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
            generation, and the state/stage tree, exposed as a \
            discoverable A2A remote agent (CONTRACTS.md §6)."
            .to_string(),
        version: Some(aoide_protocol::registry::AOIDE_VERSION.to_string()),
        // Pinned explicitly to the A2A v0.3.x JSON-RPC binding (CONTRACTS.md
        // §6 "Version"): flat "url" below, message/send + tasks/get,
        // lowercase-kebab TaskStates. v1.0's `interfaces`-array + top-level
        // `id` card form is a later, additive follow-on — not this.
        protocol_version: Some("0.3.0".to_string()),
        url: Some(self_url(bind, port)),
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
/// | `done`                  | `completed` (MVP simplification — CONTRACTS.md §6 flags the richer terminal vocabulary, CANCELED/REJECTED, as unresolved in v0; FAILED is now produced — see the dead-session row below) |
/// | *(dead session, any of the above)* | `failed` — read-time override (task #33): `aoide_conduct::reap::is_session_dead` resolving true for the session overrides whatever the row above would have said, regardless of its last WRITTEN state; see [`a2a_task_state_checked`] |
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

/// The read-time override task #33 adds beside [`a2a_task_state`]: a session
/// `is_session_dead` (`aoide_conduct::reap` — the reaper's own, sole liveness
/// authority) resolves DEAD reads `failed` regardless of its last WRITTEN
/// state. A session that dies between two polls is not still `submitted`
/// just because nothing has swept a `done` over it yet — the reaper stays
/// the only record MUTATOR; this only changes what a read reports.
///
/// Pure: `dead` is the caller's already-resolved verdict (`task_from_sessions`
/// probes `is_session_dead` at the edge and feeds the bool in here), so this
/// stays a fold, never a second liveness predicate. `dead == false` is
/// BYTE-IDENTICAL to [`a2a_task_state`] alone — this can only override that
/// function's answer, never narrow it.
///
/// Applies uniformly to every resolved session, spawned or not: a human
/// terminal SUPER+Q'd mid-poll is exactly as dead as an A2A-spawned agent
/// whose process died after its ack, and `exempt`/`undying` (which veto
/// REAPING, not truth-telling) never enter into `is_session_dead`'s window-
/// or pid-gone signals, so a dead exempt session reads `failed` too.
pub fn a2a_task_state_checked(dead: bool, canonical: &str, needs_sudo: bool) -> &'static str {
    if dead {
        "failed"
    } else {
        a2a_task_state(canonical, needs_sudo)
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
    // Read-time liveness probe (task #33) — the SAME predicate `reap.rs`
    // sweeps the roster with, fed live here rather than waiting for the
    // next sweep pass to write `done` over a session that already died.
    // No hyprctl round trip on this read path: `live_addresses`/
    // `window_owners` pass `None` (`is_session_dead`'s own "compositor
    // unqueried" degrade — the window signal never fires, never a false
    // dead) and `last_seen` returns `None` for the same reason (absence of
    // staleness evidence is never staleness). That leaves exactly the
    // pid-gone signal live here off a REAL `/proc` probe — which is the one
    // that fires for the case #33 exists to catch: a spawned process that
    // died after its fast ack.
    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let dead = aoide_conduct::reap::is_session_dead(
        rec,
        None,
        None,
        aoide_conduct::reap::proc_exists,
        now_epoch,
        |_| None,
    );
    let state = a2a_task_state_checked(dead, canonical, needs_sudo);
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
// session the same way `send` would. If `spawnAgent` is unset (the
// default), spawning is simply unavailable — a structured error, not a
// silent no-op. There is deliberately no interactive per-request gate (unlike
// `send`'s pending/--yes/autogate dance): a JSON-RPC request/response
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
/// stage and resolve one [`SessionRef`] by id. `has_socket` means the socket
/// path exists ON DISK right now, not merely that the stored string is
/// non-empty — the impure check lives here so `SessionRef`/`decide_send_action`
/// stay disk-free, the same split `conduct::graph::doc`'s `is_conductable_now`
/// draws for the identical bug shape on the `graph` door.
fn session_ref_lookup(id: &str) -> Option<SessionRef> {
    let sf: SessionsFile = load_stage(&sessions_path()).ok()?;
    sf.sessions.iter().find(|s| s.session_id == id).map(|s| SessionRef {
        conductable: s.conductable == Some(true),
        has_socket: s
            .socket
            .as_deref()
            .filter(|p| !p.is_empty())
            .is_some_and(|p| std::path::Path::new(p).exists()),
    })
}

/// Deliver into a KNOWN, conductable session: reuse
/// [`aoide_conduct::graph::session_send`] (the same gated injection door
/// `send` uses) rather than reimplementing the socket write or its
/// pending-queue.
///
/// `deliver_now` decides whether `--yes` is forced:
/// - `true` (a loopback connection, or a non-loopback one from an
///   `autogate`-marked node — [`should_deliver_now`]) forces delivery, same
///   as this door's original behavior: `--submit` (the prompt is a full
///   turn, not a keystroke), `--yes` (deliver now, don't queue).
/// - `false` (a non-loopback, non-autogated connection — CONTRACTS.md §6
///   amendment, 2026-08-14) OMITS `--yes` entirely: `session_send`'s own
///   gate then does exactly what a local ungated `send` does — writes
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
/// **Messaging plan P-M1, `state/mail/base.jsonl`**: this function files NO
/// mailbase entry of its own. It builds a `send --id` [`Invocation`] and
/// calls [`session_send`] just like `send` itself does — and since this
/// invocation never carries a `--to` flag, `session_send` can only ever
/// reach its LOCAL branch (`deliver_local`), which is one of the two places
/// a delivered message gets filed (`aoide_conduct::graph::send::deliver_local`
/// — see `aoide_storage::mail`'s module doc, and [`spawn_inject_prompt`]
/// for the OTHER site: a brand-new spawned session's first turn, which
/// cannot go through `deliver_local` at all — this function only ever
/// injects into an ALREADY-REGISTERED session). So a remote node's message
/// into an existing session lands in the mailbase through the exact same
/// call `do_inject` already makes below; adding a second append here would
/// double-file every A2A-delivered message. See
/// `a_successfully_delivered_message_send_files_into_the_mailbase` below for
/// the end-to-end proof.
fn do_inject(
    session_id: &str,
    prompt: &str,
    audit_log: &Path,
    deliver_now: bool,
    from: Option<&str>,
) -> Result<Value, (i64, String)> {
    let mut flags = std::collections::BTreeMap::new();
    flags.insert("id".to_string(), session_id.to_string());
    flags.insert("submit".to_string(), "true".to_string());
    if deliver_now {
        flags.insert("yes".to_string(), "true".to_string());
    }
    flags.insert("audit-log".to_string(), audit_log.to_string_lossy().into_owned());
    // The resolved node's identity (P-P3, PAIRING.md decision 7), when the
    // caller resolved to one (`aoide_storage::node_store::resolve_node` —
    // ATTRIBUTION, not a gate, same posture `send --from` already
    // documents): rides straight into `send`'s own EXISTING `--from`
    // flag, so a node-driven send that lands in `pending.json` carries
    // `"from": "node:<name>"` through the exact same field a local
    // `--from`/`AOIDE_SESSION_ID` attribution already populates — no second
    // attribution field invented.
    // LANE IDENTITY P-ID3 (G9): when the caller resolved to NO attributable
    // identity (`from` is `None` — an unpaired/unsigned node, or a resolved
    // node this door chose not to attribute), the flag is stamped
    // EXPLICITLY EMPTY rather than left absent. `session_send`'s own
    // `resolve_sender` falls back to `AOIDE_SESSION_ID` off the calling
    // process's env whenever `--from` is absent — and the "calling process"
    // for an inbound A2A message is `aoide a2a serve` ITSELF, a long-lived
    // process whose own ambient env has nothing to do with the remote node
    // that just sent this message. Left alone, a remote inject could
    // misattribute to whatever session id `a2a serve` happened to inherit
    // at launch. `--from ""` is `resolve_sender`'s own documented
    // "explicit no attribution" form (the same mechanism `session pending
    // approve`'s re-drive already relies on) — it skips the env fallback
    // outright rather than merely overwriting it, so this holds regardless
    // of what `a2a serve`'s own env carries.
    flags.insert("from".to_string(), from.unwrap_or_default().to_string());
    let inv = Invocation {
        path: vec!["send".to_string()],
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
/// client can always follow up with a plain `send`/another
/// `message/send`.
///
/// **Deliberately a RAW socket write, not `session_send`/`deliver_local`.**
/// `session_send` requires a `SessionRecord` already present in
/// `sessions.json` with `conductable:true` and a socket path — and that
/// record is written by the SPAWNED CHILD ITSELF, once its own `aoide
/// conduct` process starts up and registers. At the moment `do_spawn` wants
/// to type the opening turn, that registration may not have happened yet —
/// exactly the race this function's own retry loop exists to survive (the
/// socket file itself may not even exist). Routing through the session
/// registry here would just trade the socket race for a registration race,
/// so this stays on the raw socket path it already computed.
///
/// **Messaging plan P-M1, `state/mail/base.jsonl`**: because of the above,
/// this is the SECOND (and last) mailbase-filing site in the tree, alongside
/// `deliver_local`'s (see `aoide_storage::mail`'s module doc) — a spawned
/// session's first turn can never reach `deliver_local`, so it has to file
/// itself. `from` is empty: the a2a door has no caller identity to offer
/// today (#51's scope), same reasoning [`do_inject`]'s callers rely on.
/// Best-effort, same tolerance as the rest of this function — a write error
/// above is already swallowed (the retry loop only confirms a bound socket,
/// never delivery), so a failed mailbase write is no less tolerated.
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
                let _ = aoide_storage::mail::file_receipt("", id, prompt);
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Stamp `origin=node:<name>` directly on the just-spawned session's own
/// record — LANE IDENTITY P-ID0 (G16/G5): this DOOR is the record-layer
/// authority for a `node:*` origin, because it is the one place the node
/// name is actually authenticated (`message_send`'s signature/token
/// resolution, above `do_spawn`'s call site). Threading the value through
/// the child's own env (the pre-P-ID0 shape) was unauthenticated — any
/// same-uid process can set `AOIDE_SESSION_ORIGIN=node:X` on itself before
/// invoking `aoide conduct` directly — so `graph/conduct.rs::session_conduct`
/// now REFUSES that shape from its env read entirely, and this function is
/// the only remaining writer of a `node:*` value.
///
/// Retries on the session record landing in `sessions.json`, the identical
/// registration race [`spawn_inject_prompt`] above already tolerates
/// (best-effort, same 300×10ms budget — ~3s): a spawn whose child never
/// registers within that window simply never gets stamped, same as it never
/// gets its opening turn typed. Disclosed behavior change from the pre-P-ID0
/// shape (a synchronous env write that could never "miss"): a genuinely
/// slow-to-register child can now lose its origin stamp. Never silent about
/// it, though — poll exhaustion with no registration found is eprintln'd by
/// name, so a dropped stamp shows up rather than vanishing quietly. No
/// unbounded retry: a spawn that never registers at all (a failed exec, a
/// missing agent binary) must not spin this thread forever.
fn stamp_spawn_origin(id: &str, origin: &str) {
    for _ in 0..300 {
        let registered = load_stage(&sessions_path())
            .map(|f: SessionsFile| f.sessions.iter().any(|s| s.session_id == id))
            .unwrap_or(false);
        if registered {
            aoide_conduct::graph::stamp_origin(id, origin);
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    eprintln!(
        "aoide a2a: could not stamp node origin for `{id}` within 3s — session registered late or spawn failed"
    );
}

/// How long [`do_spawn`]'s bounded liveness check (task #103) gives the
/// just-launched wrapper process to prove it's still alive before acking
/// `submitted` — 40 × 10ms = 400ms, inside the ~300-500ms window the fix
/// targets. Every legitimate spawn now pays this as fixed RPC latency (an
/// agent meant to run for minutes never notices 400ms); a wrapper that never
/// got past its own exec no longer earns a "submitted" ack for a session id
/// that will never appear in `sessions.json`.
const SPAWN_LIVENESS_ATTEMPTS: u32 = 40;
const SPAWN_LIVENESS_INTERVAL: Duration = Duration::from_millis(10);

/// Poll `try_wait` up to `attempts` times, `interval` apart, returning the
/// exit status the instant one is reported, or `None` once the budget runs
/// out with the child still alive. Pure over an injected poll closure —
/// never a real [`std::process::Child`] — so the bounded-wait SHAPE is
/// unit-testable without spawning a process, the same IO/decision split
/// `daemon::epoch_already_fired` already uses elsewhere in this crate.
fn poll_bounded_exit(
    mut try_wait: impl FnMut() -> std::io::Result<Option<std::process::ExitStatus>>,
    attempts: u32,
    interval: Duration,
) -> Option<std::process::ExitStatus> {
    for i in 0..attempts {
        if let Ok(Some(status)) = try_wait() {
            return Some(status);
        }
        if i + 1 < attempts {
            std::thread::sleep(interval);
        }
    }
    None
}

/// A taught, no-secrets message for [`poll_bounded_exit`]'s failure arm: the
/// WRAPPER process (`aoide conduct`, launched by [`do_spawn`]'s own
/// `cmd.spawn()`) exited before the liveness window closed — virtually
/// always because ITS OWN attempt to exec the configured agent
/// (`aoide-conduct::graph::conduct::spawn_on_pty`) failed, since that
/// function's own "spawn FIRST" discipline means a failed exec there returns
/// almost instantly with no session ever registered. Names the configured
/// program (never the full command line — no flag values, no env, no
/// secrets) and the observed exit status only.
fn spawn_died_immediately_message(agent_cmd: &str, status: std::process::ExitStatus) -> String {
    let program = agent_cmd.split_whitespace().next().unwrap_or(agent_cmd);
    format!(
        "the configured agent (`{program}`) exited immediately after launch ({status}) — \
         it is likely missing from this unit's PATH, or the configured spawnAgent command line is wrong"
    )
}

/// Build the spawned child's `Command`, env-sanitized, cwd-bound (when
/// `spawn_cwd` resolves), and detached — everything up to but NOT including
/// `.spawn()`. Split out of [`do_spawn`] so the env-clearing shape here is
/// directly unit-testable via `Command::get_envs()`/`Command::get_current_dir()`
/// without an OS-level process spawn (`do_spawn` always launches
/// `std::env::current_exe()`, which under `cargo test` is the TEST binary —
/// see `spawn_inject_prompts_success_branch_files_the_opening_turn_into_the_
/// mailbase`'s doc comment for why no test here drives that spawn).
fn spawn_child_command(
    aoide_bin: &Path,
    argv: &[String],
    audit_log: &Path,
    cwd: Option<&str>,
) -> std::process::Command {
    let mut cmd = std::process::Command::new(aoide_bin);
    cmd.args(argv)
        .env("AOIDE_AUDIT_LOG", audit_log)
        // No `AOIDE_SESSION_ORIGIN` on the child (LANE IDENTITY P-ID0,
        // G16/G5 — reversed from the pre-P-ID0 shape): threading a `node:*`
        // origin through inherited env was unauthenticated, since any
        // same-uid process can set that same var on itself before invoking
        // `aoide conduct` directly. `stamp_spawn_origin` below stamps the
        // record from THIS door instead, once the child registers. Cleared
        // explicitly in case `a2a serve`'s own env ever carried one.
        .env_remove("AOIDE_SESSION_ORIGIN")
        // No `AOIDE_SESSION_ID` on the child either (S-B, the Osaka
        // wrong-ancestry fix): the `aoide-a2a` systemd unit's own environment
        // can carry the OPERATOR's live terminal session id (set by that
        // terminal's own `aoide conduct` wrap, inherited by every process the
        // unit's shell forks), and a spawned child's tier-3 ambient-parent
        // fallback (`window.rs::resolve_registration_parent`) would otherwise
        // adopt it as `parentSessionId` — a spawned agent parented under a
        // human's unrelated terminal. A real `aoide conduct` launched from an
        // agent's own shell still inherits the id ITS OWN wrap exported
        // (`conduct.rs::session_conduct`'s ordinary local-inheritance path) —
        // only this door, the one place a daemon's ambient env reaches an
        // unrelated freshly-spawned session, clears it.
        .env_remove("AOIDE_SESSION_ID")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
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
    cmd
}

/// Bound `spawn_cwd` (resolved by [`resolve_spawn_cwd`]) against the
/// currently REGISTERED project roots and, on acceptance, return the exact
/// string to hand to `Command::current_dir`. Refuses (returns `None`, having
/// audited exactly once) anything that is not byte-identical to some
/// project's own root — unregistered, a relative path, or a root that no
/// longer exists on disk — since the client never supplies this value and an
/// operator typo must degrade to "inherit", never to an arbitrary directory.
/// An empty `spawn_cwd` (the default — no override configured) is the quiet
/// no-op, not an audited reject.
fn resolve_bounded_spawn_cwd(
    spawn_cwd: &str,
    projects: &[Project],
    audit_log: &Path,
) -> Option<String> {
    if spawn_cwd.is_empty() {
        return None;
    }
    let path = std::path::Path::new(spawn_cwd);
    let registered = projects.iter().any(|p| p.roots().contains(&spawn_cwd));
    if registered && path.is_absolute() && path.is_dir() {
        return Some(spawn_cwd.to_string());
    }
    let reason = if registered {
        "registered project root is not an absolute directory"
    } else {
        "not a registered project root"
    };
    let _ = audit(
        audit_log,
        Door::A2a,
        EventClass::Audit,
        "a2a.message/send",
        "skipped",
        &format!(
            "ignoring configured spawn cwd `{spawn_cwd}` for the spawned child — {reason} — \
             inheriting the daemon's own cwd instead"
        ),
    );
    None
}

/// Spawn a NEW conducted session running the CONFIGURED agent (never a
/// client-supplied command — see the security-model note above `SessionRef`).
/// Detached: launched via the aoide binary's own `conduct` subcommand
/// (`std::env::current_exe()`), `setsid`'d so it survives this handler
/// thread, stdio nulled, and reaped on a parked thread (see below) — it
/// stays parented to the long-lived `a2a serve` daemon for its whole life.
/// `aoide-conduct`'s `spawn` (P2 of the conducted-agents plan) now
/// generalizes exactly this detach/register/reap shape as its own command; a
/// later phase can have this handler ride on it instead of hand-rolling the
/// same mechanics here.
///
/// `node_name` is the resolved, PAIRED, spawn-allowed node `message_send`'s
/// gate already proved before calling this (P-P3, PAIRING.md decision 6) —
/// never optional at this call site, since the gate refuses outright
/// otherwise. Stamped directly onto the spawned record as `origin =
/// "node:<name>"` by [`stamp_spawn_origin`] below (LANE IDENTITY P-ID0,
/// G16/G5 — this door is the authenticated writer, not the child's env; see
/// that function's doc) and folded into this call's own audit line, so the
/// spawned session's provenance is visible both in the audit log and on the
/// record itself, end to end.
///
/// **Bounded liveness check (task #103).** `cmd.spawn()` below only proves
/// the wrapper process itself launched — a caller was previously handed a
/// `submitted` Task the instant that call returned, with no confirmation the
/// wrapper's OWN exec of the configured agent ever succeeded (a missing
/// `spawnAgent` binary on this unit's PATH is the exact defect this closes).
/// [`poll_bounded_exit`] gives the wrapper `SPAWN_LIVENESS_ATTEMPTS ×
/// SPAWN_LIVENESS_INTERVAL` to prove it's still running before the ack goes
/// out; a wrapper that exits inside that window gets
/// [`spawn_died_immediately_message`]'s taught refusal instead of a phantom
/// session id.
fn do_spawn(
    agent_cmd: &str,
    prompt: &str,
    audit_log: &Path,
    node_name: &str,
    spawn_cwd: &str,
) -> Result<Value, (i64, String)> {
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

    let origin = format!("node:{node_name}");
    // Project roots are already loaded the same way `session_ref_lookup`
    // loads `sessions.json` off the stage — a missing/corrupt file degrades
    // to an empty registry, so a misconfigured `spawn_cwd` never blocks a
    // spawn, only its cwd bound.
    let pf: ProjectsFile = load_stage(&aoide_storage::stage::projects_path()).unwrap_or_default();
    let bounded_cwd = resolve_bounded_spawn_cwd(spawn_cwd, &pf.projects, audit_log);
    let mut cmd = spawn_child_command(&aoide_bin, &argv, audit_log, bounded_cwd.as_deref());

    match cmd.spawn() {
        Ok(mut child) => {
            // Bounded liveness confirmation (task #103): `cmd.spawn()` above
            // only proves the WRAPPER `aoide conduct` process itself
            // launched — it says nothing about whether ITS OWN attempt to
            // exec the configured agent succeeded. That failure is
            // synchronous INSIDE the wrapper (`session_conduct`'s "spawn
            // FIRST" discipline registers no session and the wrapper exits
            // almost instantly), but this door is a separate, detached
            // process with no synchronous view into it — acking
            // unconditionally here is exactly how a caller was handed a
            // `submitted` Task naming a session that had already failed to
            // spawn (the defect this fix closes). Give the wrapper a short
            // window to prove it's still running before acking success.
            if let Some(status) = poll_bounded_exit(
                || child.try_wait(),
                SPAWN_LIVENESS_ATTEMPTS,
                SPAWN_LIVENESS_INTERVAL,
            ) {
                let msg = spawn_died_immediately_message(agent_cmd, status);
                let _ = audit(
                    audit_log,
                    Door::A2a,
                    EventClass::Audit,
                    "a2a.message/send",
                    "error",
                    &msg,
                );
                return Err((-32603, msg));
            }

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
            // Stamp the record's origin from THIS door, off the handler
            // thread so a slow-to-register child never adds latency to the
            // RPC response — see `stamp_spawn_origin`'s doc comment.
            {
                let id = id.clone();
                let origin = origin.clone();
                std::thread::spawn(move || stamp_spawn_origin(&id, &origin));
            }
            // Best-effort first-turn injection — see the doc comment above.
            spawn_inject_prompt(&id, prompt);
            let _ = audit(
                audit_log,
                Door::A2a,
                EventClass::Audit,
                "a2a.message/send",
                "ok",
                &format!("spawned conducted session `{id}` (configured agent, {origin})"),
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
            let msg = format!("failed to spawn A2A agent: {e} ({origin})");
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
///   original address match ([`aoide_storage::node_store::is_autogated_node_addr`],
///   dead behind any proxy) OR a per-node token match
///   ([`aoide_storage::node_store::is_autogated_node_token`], survives one) —
///   either is sufficient, so an operator who has never set a node
///   `token_file` sees the exact original address-only behavior.
/// - Inject's ORIGIN is [`effective_origin`]'d before reaching
///   [`should_deliver_now`]: once a token is configured, an unauthenticated
///   loopback caller no longer gets the automatic pass — see that function's
///   doc comment for why this is one switch, not two.
/// - Spawn gained a gate it never had at all: [`token_authorized`] must pass
///   before [`do_spawn`] runs. This is the actual must-fix gap this
///   amendment closes — Spawn was origin-blind AND token-blind before it.
///
/// **Amendment (2026-08-25, P-P3): the Spawn arm is regated a SECOND time —
/// from the door-wide bearer to a named, paired node resolved via its OWN
/// token.** PAIRING.md decision 6: spawning requires the caller to resolve
/// to a specific, `verified` `aoide_storage::node_store::Node` whose
/// `allows` contains `"spawn"` — [`token_authorized`] (the 2026-08-19
/// amendment above) is no longer consulted at all for Spawn; holding the
/// plain door-wide bearer, with no node identity behind it, no longer
/// reaches [`do_spawn`]. [`spawn_admitted`] is the full check, and it is
/// narrower than "resolved to *some* node": [`aoide_storage::node_store::
/// resolve_node`] answers via one of two rungs — a presented bearer that
/// matches a node's own `token_file` (survives a reverse proxy) or, failing
/// that, the TCP-observed `origin` address against that node's registered
/// `url` (the exact same two signals [`is_autogated_node_token`]/
/// [`is_autogated_node_addr`] already fold for the unrelated autogate
/// question, just unfiltered by `autogate` and narrowed to ONE specific
/// node). Spawn accepts ONLY the token rung — a bare address match resolves
/// a node identity for attribution (Inject's `from` field, origin-stamping)
/// and for the ordinary autogate question, but never for spawning a process
/// attributed to that node; behind any NAT/reverse-proxy deployment an
/// address match is exactly the shared-source-IP situation that would
/// otherwise let one tenant spawn "as" another. The refusal is `-32006`,
/// naming both remaining prerequisites: the pairing ceremony (`pair`)
/// and a configured `token_file` (`node add --token-file`).
///
/// **Amendment (P-P4, `docs/architecture/PAIRING.md`'s "Wire authentication
/// (paired nodes)" section): the Spawn rung requirement moves a THIRD time
/// — from Token to Signature.** P-P3's Token rung above was an explicitly
/// interim shape: a `token_file`'s bearer is a shared secret, not a proof
/// of possession bound to any one request — spoofable by anyone who can
/// read that file or sniff the header, and identical across every request
/// the true node or an impersonator ever sends. P-P4 lands the per-request
/// UNFORGEABLE binding that shape always named as its own future lane: an
/// ed25519 signature over a canonical string binding method, path,
/// timestamp, nonce, and the body's `sha2` digest
/// (`aoide_storage::wire_auth::canonical_string`), resolved to the paired
/// node whose stored pubkey verifies it (`verify_signed_request`, this
/// file — #63 P-ID5: identity is the key, the `X-Aoide-Node` name is a
/// display label), a
/// ±120s replay window, and a bounded in-memory nonce cache — see that
/// function's own doc comment for the full verification flow. A request
/// that verifies resolves to [`aoide_storage::node_store::NodeRung::
/// Signature`], the new strongest rung; [`spawn_admitted`] now accepts
/// ONLY that rung — the Token rung, which P-P3 accepted, no longer reaches
/// [`do_spawn`] at all, even for a genuinely paired, `verified`,
/// `spawn`-allowed node. This is a DELIBERATE choice, not an oversight:
/// PAIRING.md's wire-auth section states the signature "replaces bearer
/// comparison for paired nodes" outright, and the whole point of landing
/// unforgeable per-request binding is that a paired node's spawn admission
/// no longer rests on a comparable, replayable secret at all. A caller that
/// resolves via Token (paired, but this particular request wasn't signed)
/// gets a taught error naming exactly that — "paired but not signed, your
/// aoide is too old or isn't signing" — never confused with "never paired,"
/// which still points at the pairing ceremony itself
/// ([`spawn_refusal`]'s own doc comment carries the full message-selection
/// table). Every OTHER arm this file gates (the read commands' `token_authorized`,
/// Inject's `effective_origin`/autogate coupling, the AgentCard GET) is
/// UNCHANGED by P-P4 — signature headers strengthen IDENTITY resolution
/// only, and only the Spawn arm's admission requirement moves; an unpaired
/// caller's read-arm access via the door-wide bearer is untouched, and so
/// is a PAIRED node's — pairing/signing narrows Spawn, it grants nothing
/// extra elsewhere in this phase.
///
/// **Amendment (2026-08-20, #50): a context-id send answers UNIFORMLY, not
/// with a hard gate, once a token is configured and the caller holds
/// neither a valid one nor an autogate match.** `message/send`'s Inject arm
/// used to run [`session_ref_lookup`] regardless of auth — an
/// unauthenticated caller could tell a real `contextId` from a bogus one by
/// the response shape (`-32001` vs an injected/queued Task), and a REAL id
/// got queued into `pending.json` with no credential at all. A hard `-32005`
/// here (mirroring Spawn) would be wrong instead: enrolled nodes authenticate
/// via their OWN per-node token
/// ([`aoide_storage::node_store::is_autogated_node_token`]), never the
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
    spawn_cwd: &str,
    origin: ConnOrigin,
    expected_token: &str,
    presented_token: Option<&str>,
    signed_node_name: Option<&str>,
) -> Result<Value, (i64, String)> {
    let (prompt, context_id, spawn_asked) = parse_message_send_params(params);
    let token_configured = !expected_token.is_empty();
    let token_state = classify_token(expected_token, presented_token);

    // Node resolution hoisted ABOVE the send-action decision: the uniform-
    // response guard below needs the autogate signals BEFORE
    // `decide_send_action` even runs, and the Inject arm further down still
    // needs both the autogate signals AND `resolved_node` AFTER — one
    // `load_nodes()` per `message_send` call, not two. Values and their
    // meaning are unchanged from before this amendment; only WHEN they're
    // computed moved.
    let nodes = aoide_storage::node_store::load_nodes();

    // The caller's resolved node IDENTITY, PLUS which rung resolved it
    // (P-P3, PAIRING.md decision 6/7) — deliberately a SEPARATE question
    // from `ip_autogate`/`token_autogate`/`sig_autogate` below (which fold
    // ONLY over `autogate`-marked nodes, for the unrelated "skip the
    // pending queue" question): `resolve_node` looks at EVERY registered
    // node, autogate or not. Used two ways below, DELIBERATELY UNEQUALLY:
    // the Inject arm, when it queues, stamps EITHER rung onto
    // `pending.json`'s `from` field for attribution only (never a gate —
    // see `do_inject`'s own doc comment); the Spawn arm's `spawn_admitted`
    // below requires specifically the SIGNATURE rung — neither a bare
    // address nor a bare token match must ever itself authorize launching a
    // process attributed to the matched node (2026-08-25 narrowing, see
    // `spawn_admitted`'s own doc comment).
    let addr = match origin {
        ConnOrigin::Remote(ip) => Some(ip),
        ConnOrigin::Loopback | ConnOrigin::Unknown => None,
    };
    // P-P4 (`docs/architecture/PAIRING.md` "Wire authentication"):
    // `signed_node_name` arrives ALREADY VERIFIED — the caller
    // (`handle_connection`, via `verify_signed_request`) checked the
    // ed25519 signature, the replay window, and the nonce cache BEFORE this
    // function ever ran, and only threads a name through on success. The
    // name it threads is the RESOLVED one (#63 P-ID5): the node record
    // whose stored pubkey verified the signature, never the wire-claimed
    // `X-Aoide-Node` label — so the find-by-name below is a lookup of an
    // already-key-authenticated record, not a trust decision. When
    // present, it is the SOLE resolution: no fallthrough to the
    // addr/token ladder for a request that presented signature headers
    // (fail-closed discipline, #84's own "sentinel on resolve failure, no
    // fallthrough to a weaker rung" precedent). `None` (no signature
    // headers on this request at all) is the untouched, existing path.
    let resolved_node = match signed_node_name {
        Some(name) => nodes
            .iter()
            .find(|p| p.name == name)
            .map(|p| (p, aoide_storage::node_store::NodeRung::Signature)),
        None => aoide_storage::node_store::resolve_node(&nodes, addr, presented_token),
    };

    // Autogate signals — computed AFTER `resolved_node` (P-S6) so the new
    // signature rung can join `ip_autogate`/`token_autogate` in the same
    // fold: `resolved_node` matched via `NodeRung::Signature` whose own
    // `autogate` flag is set is the like-for-like restoration for a node
    // the operator already marked auto-deliver, now that a verified
    // signature no longer rides `ConnOrigin::Loopback`'s free pass (see
    // `origin_for_inject`). `ip_autogate`/`token_autogate` are unchanged
    // from before this amendment.
    let ip_autogate = match origin {
        ConnOrigin::Remote(ip) => aoide_storage::node_store::is_autogated_node_addr(&nodes, ip),
        ConnOrigin::Loopback | ConnOrigin::Unknown => false,
    };
    let token_autogate = presented_token
        .map(|t| aoide_storage::node_store::is_autogated_node_token(&nodes, t))
        .unwrap_or(false);
    let sig_autogate =
        matches!(resolved_node, Some((node, aoide_storage::node_store::NodeRung::Signature)) if node.autogate);
    let autogate_match = ip_autogate || token_autogate || sig_autogate;

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
            // `should_deliver_now(ConnOrigin::Unknown, _)` is unconditionally
            // `false` — it ignores `autogate_match` entirely (the SAME
            // fail-safe arm `effective_origin`'s own token coercion already
            // rides: see `uniform_response_guard_never_fires_for_a_per_node_
            // autogated_token`'s doc comment for the pin). So the
            // `origin_for_inject` downgrade must NOT fire for a signed node
            // that is ITSELF signature-rung autogate-marked — that node
            // needs `should_deliver_now`'s ordinary Loopback/Remote arms
            // (which DO consult `autogate_match`) to keep delivering, the
            // like-for-like restoration `sig_autogate` exists for. A signed,
            // non-autogate node has no such exemption: it gets the downgrade
            // unconditionally, which is the narrowing itself.
            let eff_origin = origin_for_inject(
                effective_origin(origin, token_configured, token_state),
                signed_node_name.is_some() && !sig_autogate,
            );
            let deliver_now = should_deliver_now(eff_origin, autogate_match);
            // The `from` attribution rides ONLY the QUEUED path (P-P3
            // decision 7: "pending-queue entries a node's send creates").
            // `session_send`'s own `from` mechanism ALSO prefixes an
            // IMMEDIATELY-delivered payload's text ("from <sender>: ",
            // `provenance_prefix`) — scoping this to `!deliver_now` keeps
            // an already-autogated node's DELIVERED payload byte-identical
            // to before this phase (pinned by
            // `autogated_node_delivers_despite_being_non_loopback`), while
            // still attributing every entry that actually reaches
            // `pending.json`.
            let from = if deliver_now { None } else { resolved_node.map(|(p, _rung)| format!("node:{}", p.name)) };
            do_inject(&session_id, &prompt, audit_log, deliver_now, from.as_deref())
        }
        SendAction::Spawn { agent_cmd } => {
            if spawn_admitted(resolved_node) {
                let node = resolved_node.expect("spawn_admitted only returns true when resolved_node is Some").0;
                do_spawn(&agent_cmd, &prompt, audit_log, &node.name, spawn_cwd)
            } else {
                let (code, msg) = spawn_refusal(resolved_node);
                let _ = audit(
                    audit_log,
                    Door::A2a,
                    EventClass::Audit,
                    "a2a.message/send",
                    "unauthorized",
                    &msg,
                );
                Err((code, msg))
            }
        }
        SendAction::Error { code, msg } => Err((code, msg)),
    }
}

/// The node-side half of the Spawn admission check (P-P3, PAIRING.md
/// decision 6) — a paired node whose `allows` contains `"spawn"`. Pure,
/// split out of [`message_send`] so the gate table (paired+allowed /
/// paired+denied / unpaired) is directly unit-testable against plain
/// `Node` fixtures, without ever touching [`do_spawn`]'s real OS-level
/// process spawn. Deliberately says nothing about HOW the caller resolved
/// to this node — that question is [`spawn_admitted`]'s job, one layer up.
fn node_may_spawn(node: &aoide_storage::node_store::Node) -> bool {
    node.verified && node.allows.iter().any(|a| a == "spawn")
}

/// The Spawn arm's FULL admission check (P-P3 decision 6, narrowed
/// 2026-08-25 to the token rung; narrowed AGAIN 2026-08-25/P-P4 to the
/// SIGNATURE rung specifically — see [`spawn_refusal`]'s doc comment for the
/// full grounding). Neither the ADDR rung nor the (now superseded) TOKEN
/// rung reaches [`do_spawn`] any more: a bare source-address match carries
/// no possession proof at all, and a bare shared-secret token is not bound
/// to any one request — replayable, and identical across every request the
/// true node or an impersonator ever sends. Both rungs keep resolving a
/// node identity for every OTHER purpose (Inject's `from` attribution,
/// origin-stamping); this function is the ONE place the narrowing to
/// signature-only lives, rather than re-derived at each call site. Pure —
/// unit-testable directly against `(Node, NodeRung)` fixtures without
/// touching [`do_spawn`]'s real OS-level process spawn, the same
/// "predicate-level, not through `message_send`" precedent
/// [`node_may_spawn`]'s own doc comment already established.
fn spawn_admitted(resolved: Option<(&aoide_storage::node_store::Node, aoide_storage::node_store::NodeRung)>) -> bool {
    matches!(resolved, Some((node, aoide_storage::node_store::NodeRung::Signature)) if node_may_spawn(node))
}

/// The `-32006` refusal every Spawn attempt that fails [`spawn_admitted`]
/// returns (P-P3, message content narrowed P-P4) — a distinct code from
/// `unauthorized()`'s `-32005` (the door-wide bearer gate every OTHER arm
/// still uses), since this is a DIFFERENT question: not "do you hold a
/// valid door-wide token" but "do you resolve, via a verified per-request
/// SIGNATURE, to a specific node this operator has paired with and allowed
/// to spawn." The CODE stays `-32006` across every refusal shape (no new
/// code per shape — `message_send`'s callers already match on this one
/// value), but the MESSAGE is now shape-specific (P-P4 requirement: "a
/// taught error telling an unsigned paired caller that its aoide is too old
/// / must sign," distinguishable from "you were never paired at all"):
/// - **Resolved via the (now-superseded) Token rung, and genuinely
///   `verified`**: this caller IS a real, paired node — it just didn't sign
///   this request. Told to sign, not to re-pair; re-pairing would be
///   nonsensical noise for a caller whose only problem is an old client
///   that predates P-P4.
/// - **Resolved via Signature but `allows` lacks `spawn`**: pairing and
///   signing both succeeded — only the capability grant is missing. Told
///   the exact `node allow` fix, not to re-pair or re-sign.
/// - **Every other shape** (Addr rung, no resolution at all, an
///   unverified Token match): told to pair AND sign, the original P-P3
///   message's grounding, now naming the signature requirement too.
fn spawn_refusal(resolved: Option<(&aoide_storage::node_store::Node, aoide_storage::node_store::NodeRung)>) -> (i64, String) {
    use aoide_storage::node_store::NodeRung;
    match resolved {
        Some((node, NodeRung::Token)) if node.verified => (
            -32006,
            format!(
                "spawn refused: node `{}` is paired, but this request was not signed — spawn now \
                 requires a per-request ed25519 signature (docs/architecture/PAIRING.md's wire-auth \
                 section), and a bare token no longer admits it. The caller's aoide is too old to \
                 sign requests, or is failing to sign them — upgrade the caller",
                node.name
            ),
        ),
        Some((node, NodeRung::Signature)) => (
            -32006,
            format!(
                "spawn refused: node `{}` is paired and this request is validly signed, but `allows` \
                 does not include `spawn` — run `node allow {} spawn on`",
                node.name, node.name
            ),
        ),
        Some((_, NodeRung::Addr)) | Some((_, NodeRung::Token)) | None => (
            -32006,
            "spawn refused: spawn requires the caller be identified via a verified, per-request \
             SIGNED request from a paired node (an address match, or an unverified token match, \
             never admits spawn) — pair first via `aoide pair`, then `node allow <name> spawn on`"
                .to_string(),
        ),
    }
}

/// `aoide/graphSummary` (CONTRACTS.md §7): wrap the EXISTING resolved
/// `graph.json` v0 document ([`resolve_graph_document`], the exact same
/// function bare `graph` builds its document with) in the
/// federation envelope. No new graph vocabulary — `graph` below is that
/// document verbatim.
fn graph_summary(node_name: &str, self_url: &str) -> Result<Value, (i64, String)> {
    let graph = resolve_graph_document().map_err(|e| (-32603_i64, format!("internal error: {e}")))?;
    Ok(json!({
        "schemaVersion": "0",
        "instance": {
            "name": node_name,
            "url": self_url,
            "emittedAt": now_iso_utc(),
        },
        "graph": graph,
    }))
}

// ── `aoide/mailDeposit` (messaging plan P-M2, CONTRACTS.md §6) ─────────────
//
// The wire for directly-paired nodes: a caller identified via a verified
// PER-REQUEST SIGNATURE (never an address or bare-token match — the same
// signature-only narrowing `spawn_admitted` holds, applied to a new,
// independent capability) deposits one sealed [`aoide_storage::mail::
// Envelope`]. Admission answers ONE question — "is this signed caller a
// paired node holding `message`" — and is entirely separate from the
// envelope's OWN origin signature, which [`aoide_storage::mail::deposit`]
// verifies against `header.from.node`'s own key (spec item 3: the HOP that
// carried the request here and the ORIGIN that minted it are two
// independent lookups, coincident only because P-M2 has no relay yet).

/// The node-side half of the Message admission check — a paired node whose
/// `allows` contains `"message"`. Mirrors [`node_may_spawn`] exactly, one
/// capability over.
fn node_may_message(node: &aoide_storage::node_store::Node) -> bool {
    node.verified && node.allows.iter().any(|a| a == "message")
}

/// The Message arm's full admission check. Unlike [`spawn_admitted`], there
/// is no now-superseded Token-rung history to migrate off of — `message`
/// is introduced AFTER that narrowing already happened — so resolution
/// here is signature-only from the start, with no Addr/Token fallback rung
/// to even consider: `resolved` is `None` whenever the request carried no
/// verified signature, or the signature verified against a name that
/// (impossibly, absent a bug upstream) doesn't resolve to a registered
/// node.
fn deposit_admitted(resolved: Option<&aoide_storage::node_store::Node>) -> bool {
    matches!(resolved, Some(node) if node_may_message(node))
}

/// The refusal every deposit attempt that fails [`deposit_admitted`]
/// returns — a NEW, distinct code (never `-32006`, which stays `spawn`'s
/// own; never `-32007`, already taken by `verify_signed_request`'s
/// incomplete-headers/signature-mismatch refusals, CONTRACTS.md §6). Two
/// shapes only (simpler than [`spawn_refusal`]'s three: no historical
/// Token-rung caller to distinguish here) — paired-but-not-allowed, told
/// the exact `node allow` fix; everything else (unpaired, unsigned, no
/// resolution at all) told to pair and allow.
fn deposit_refusal(resolved: Option<&aoide_storage::node_store::Node>) -> (i64, String) {
    match resolved {
        Some(node) => (
            -32010,
            format!(
                "mail deposit refused: node `{}` is paired and this request is validly signed, but \
                 `allows` does not include `message` — run `node allow {} message on`",
                node.name, node.name
            ),
        ),
        None => (
            -32010,
            "mail deposit refused: this method requires the caller be identified via a verified, \
             per-request SIGNED request from a paired node — pair first via `aoide pair`, then \
             `node allow <name> message on`"
                .to_string(),
        ),
    }
}

/// `aoide/mailDeposit` (P-M2): `{envelope: <the sealed Envelope, exactly as
/// aoide_storage::mail::Envelope serializes>}`. Admission first
/// (signature-only, [`deposit_admitted`]), then the envelope's own content
/// is [`aoide_storage::mail::deposit`]'s job — recompute `msgid`, verify
/// the ORIGIN signature, dedup, file (spec item 4's short-circuiting
/// order; the zone check MAIL.md's step 3 describes is P-M4's, skipped
/// here, not stubbed).
///
/// **Self-audits under its own label, unconditionally** (spec item 11: a
/// deposit never passes `cli/src/dispatch.rs`'s own audit, so this is the
/// one place a flood becomes visible) — mirrors [`pair_request`]'s "audits
/// every call, not only a refusal" shape, once for the admission refusal
/// and once more after `deposit`'s own outcome, never
/// [`message_send`]'s narrower "only the notable branches" one: a flood's
/// signal is volume, and volume must show whether every one of those
/// deposits was accepted, refused, or malformed.
///
/// **Never called from inside `deposit`'s own lock.** `deposit` returns
/// before this function does anything else with the outcome — every
/// `outbox` call below runs AFTER that lock has already released, never
/// nested inside it: `outbox`'s own lock wraps the identical
/// `fs::try_stage_lock` `mail`'s does, and that lock is a plain blocking
/// `flock`, not re-entrant — nesting the two would deadlock a process
/// against its own held lock, not merely contend.
///
/// A filed **letter** mints and spools an ack addressed back to the
/// origin, then best-effort drains that node once, synchronously, reusing
/// the SAME [`aoide_conduct::mail_bridge::drain_node`] the daemon tick
/// calls — one drain implementation, no duplicate dial logic. A filed
/// **receipt** is the opposite leg: [`aoide_storage::outbox::retire_by_ack`]
/// retires the local outbox entry it confirms (spec item 7) — a pure
/// storage-crate lookup keyed on the receipt's own verified `from.node`
/// and `text` (the acked msgid), so a forged or stale ack simply finds no
/// matching entry and retires nothing (see that function's own doc for
/// why the lookup alone proves both of spec item 7's checks). A
/// **duplicate** whose original filing was a letter re-sends the ack
/// (spec item 5: the sender's earlier ack evidently never arrived);
/// every other duplicate is a silent no-op — acking an ack would ping-pong
/// forever, which the vocabulary (`letter`/`receipt` only) has no third
/// shape to end.
fn mail_deposit(params: &Value, ctx: &RequestCtx) -> Result<Value, (i64, String)> {
    let envelope: aoide_storage::mail::Envelope =
        match serde_json::from_value(params.get("envelope").cloned().unwrap_or(Value::Null)) {
            Ok(e) => e,
            Err(e) => return Err((-32602, format!("invalid params: envelope: {e}"))),
        };

    let nodes = aoide_storage::node_store::load_nodes();
    let resolved = ctx.signed_node_name.and_then(|name| nodes.iter().find(|p| p.name == name));
    if !deposit_admitted(resolved) {
        let (code, msg) = deposit_refusal(resolved);
        let _ = audit(ctx.audit_log, Door::A2a, EventClass::Audit, "a2a.aoide/mailDeposit", "unauthorized", &msg);
        return Err((code, msg));
    }
    let hop_name = ctx.signed_node_name.expect("deposit_admitted only returns true when signed_node_name is Some");

    let outcome = aoide_storage::mail::deposit(envelope.clone(), hop_name).map_err(|e| (-32603_i64, format!("internal error: {e}")))?;

    // Spec item 11: mail self-audits at the door (the one place a deposit
    // never passes `cli/src/dispatch.rs`'s own audit) — ONE line per call,
    // covering every outcome uniformly, mirroring `pair_request`'s own
    // "audits unconditionally, not just on refusal" shape (never
    // `message/send`'s narrower "only the notable branches" one): a flood
    // is a volume signal, and volume must be visible whether every one of
    // those deposits was accepted, refused, or malformed.
    let audit_detail = format!(
        "from {}/{} to {}/{} via {hop_name}: {outcome:?}",
        envelope.header.from.node, envelope.header.from.name, envelope.header.to.node, envelope.header.to.name
    );
    let audit_status = match &outcome {
        aoide_storage::mail::DepositOutcome::BadMsgid | aoide_storage::mail::DepositOutcome::UnverifiedOrigin => "invalid",
        _ => "ok",
    };
    let _ = audit(ctx.audit_log, Door::A2a, EventClass::Audit, "a2a.aoide/mailDeposit", audit_status, &audit_detail);

    match &outcome {
        aoide_storage::mail::DepositOutcome::Filed { msgid, kind } if kind == aoide_storage::mail::ENTRY_TYPE_LETTER => {
            spool_and_drain_ack(&envelope, msgid);
            Ok(json!({ "status": "accepted", "msgid": msgid }))
        }
        aoide_storage::mail::DepositOutcome::Filed { msgid, kind } if kind == aoide_storage::mail::ENTRY_TYPE_RECEIPT => {
            let _ = aoide_storage::outbox::retire_by_ack(&envelope);
            Ok(json!({ "status": "accepted", "msgid": msgid }))
        }
        aoide_storage::mail::DepositOutcome::Filed { msgid, .. } => {
            // No third `Header.kind` exists today — kept as a fallthrough
            // rather than an `unreachable!` so a future kind degrades to
            // "filed, no side effect" instead of a panic.
            Ok(json!({ "status": "accepted", "msgid": msgid }))
        }
        aoide_storage::mail::DepositOutcome::Duplicate { filed_letter: true } => {
            spool_and_drain_ack(&envelope, &envelope.msgid);
            Ok(json!({ "status": "duplicate" }))
        }
        aoide_storage::mail::DepositOutcome::Duplicate { filed_letter: false } => Ok(json!({ "status": "duplicate" })),
        aoide_storage::mail::DepositOutcome::BadMsgid => Ok(json!({
            "status": "refused",
            "reason": "bad-msgid",
            "detail": "envelope msgid does not match the recomputed value",
        })),
        aoide_storage::mail::DepositOutcome::UnverifiedOrigin => Ok(json!({
            "status": "refused",
            "reason": "unverified-origin",
            "detail": format!(
                "no key on record for `{}` verifies this envelope's origin signature",
                envelope.header.from.node
            ),
        })),
    }
}

/// Mint an ack for `acked_msgid` (destination is `envelope.header.to`,
/// the mailbox that just received it; origin is `envelope.header.from`,
/// who it goes back to), spool it into that origin's outbox, and
/// best-effort drain that node once. Shared by `mail_deposit`'s `Filed`
/// letter arm and its `Duplicate{filed_letter: true}` arm — the ack is
/// identical either way, just re-sent on the duplicate path.
///
/// Spooled via `aoide_storage::outbox::write_ack_if_absent`, never the bare
/// `write_entry`: a `Duplicate` redelivery of a letter whose ack is STILL
/// sitting undelivered in the outbox spools nothing new — without this
/// gate, a sender that keeps redelivering because its earlier ack never
/// arrived drove this function to mint a brand-new ack envelope, with a
/// brand-new msgid, on every single redelivery (the outbox investigation's
/// own root cause). Once that pending ack is actually delivered (removed by
/// `mail_wire::drain_node`'s `Delivered` arm), the next redelivery finds
/// nothing pending and respools — spec item 5's "a duplicate re-sends the
/// ack because the sender's earlier one evidently never arrived" still
/// holds for a genuine loss; see `write_ack_if_absent`'s own doc.
fn spool_and_drain_ack(envelope: &aoide_storage::mail::Envelope, acked_msgid: &str) {
    let Ok(ack) = aoide_storage::mail::mint_ack(&envelope.header.to.name, envelope.header.from.clone(), acked_msgid)
    else {
        return;
    };
    let origin_node = envelope.header.from.node.clone();
    let entry = aoide_storage::outbox::OutboxEntry::fresh(ack);
    if aoide_storage::outbox::write_ack_if_absent(&origin_node, acked_msgid, &entry) == Ok(true) {
        let _ = aoide_conduct::mail_bridge::drain_node(&origin_node);
    }
}

// ── The pairing ceremony wire (CONTRACTS.md §6, P-P2,
// ── `docs/architecture/PAIRING.md`) ─────────────────────────────────────────
//
// Four JSON-RPC methods, all deliberately UNAUTHENTICATED at the DOOR level
// (no token/origin gate) — this IS the bootstrap: there is no established
// pairing yet to gate `read_ok` against, and a parked/relayed request grants
// NOTHING by itself (PAIRING.md: "a parked request grants NOTHING until
// approved"). P-P4 (signed wire requests) is the later phase that adds real
// authentication to paired callers; unpaired bootstrap traffic like this
// stays exactly as open as `message/send`'s own unauthenticated read arms
// were before any token was ever configured. `aoide/pairPoll` (below) is
// "unauthenticated" in that same door-level sense only — it carries and
// verifies its OWN signature inline, unlike the other three.
//
// `aoide/pairRequest` is the REQUESTER -> APPROVER direction: box A asks box
// B to park a pairing request, carrying a COMMITMENT to A's own nonce, not
// the nonce itself (review-bounce Finding 1 — the original shape let an
// active on-path attacker choose four of the SAS transcript's six fields
// after observing the real ones; see `aoide_storage::pairing`'s module doc
// for the full commit-then-reveal reasoning, the Bluetooth SSP idiom this
// borrows). `aoide/pairReveal` is A's immediate follow-up (same `pair`
// invocation, two sequential POSTs) that hands over the nonce the
// commitment already fixed; B verifies it and only THEN has a SAS to show.
//
// `aoide/pairPoll` (Design A, task #119 — REPLACES the old `aoide/pairApprove`
// reverse callback) is A's own follow-up, POSTed to B's door over the SAME
// forward dial `aoide/pairRequest`/`aoide/pairReveal` already used — never a
// callback B initiates back to A. B's own operator approving
// (`pair <id>` on the inbound entry) is now PURELY LOCAL: it commits
// B's own node record for A and marks B's parked entry `approved`
// ([`aoide_storage::pairing::mark_inbound_approved`]) but dials nobody. A's
// `pair <id>` then POLLS this method until it sees `approved`,
// verifies the release is bound to the SAME transcript A already committed
// to, and only THEN runs its own confirm-then-commit. This is the whole
// point: a REQUESTER whose own A2A door is loopback-only ([[doors-loopback-only]])
// can now complete pairing, because nothing ever needs to dial IN to it —
// see [`pair_poll`]'s own doc for the auth mechanism and the existence-oracle
// discipline it holds.

/// [`ConnOrigin`] rendered for DISPLAY only — [`InboundPairingRequest`]'s
/// `originAddr` field (the bare `pair` pending listing's own column, PAIRING.md: "parks
/// pending (id, ... origin addr)"). Never a security decision in this
/// phase — there is no pairing yet to gate origin against.
fn origin_display(origin: ConnOrigin) -> String {
    match origin {
        ConnOrigin::Loopback => "loopback".to_string(),
        ConnOrigin::Remote(ip) => ip.to_string(),
        ConnOrigin::Unknown => "unknown".to_string(),
    }
}

/// A lowercase-hex string of exactly `len` characters. The one shape check
/// [`valid_pubkey_hex`]/[`valid_nonce_hex`]/[`valid_commit_hex`] each pin to
/// a different fixed length — pubkeys and commitments are both full
/// SHA-256/ed25519-key-shaped (64 hex chars), nonces are half that (32 hex
/// chars, 16 bytes) — factored once so the three validators can't drift out
/// of sync with each other's character-class check. Pure.
fn valid_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// A 64-lowercase-hex-char ed25519 public key, exactly as
/// [`aoide_storage::identity::IdentityInfo::pubkey_hex`] renders one. Pure.
fn valid_pubkey_hex(s: &str) -> bool {
    valid_hex(s, 64)
}

/// A 32-lowercase-hex-char (16-byte) nonce, exactly as
/// [`aoide_storage::pairing::random_hex(16)`] renders one — both this door
/// and the client crate mint nonces the same way, so this length is a fixed
/// contract, not a range. Pure.
fn valid_nonce_hex(s: &str) -> bool {
    valid_hex(s, 32)
}

/// A 64-lowercase-hex-char commitment, exactly as
/// [`aoide_storage::pairing::derive_commit`] renders one (a full SHA-256
/// digest, hex-encoded — the same length as a pubkey, a coincidence of both
/// being 32-byte digests, not a shared meaning). Pure.
fn valid_commit_hex(s: &str) -> bool {
    valid_hex(s, 64)
}

/// A URL sane enough to remember for the resulting node record's stored
/// address (FUTURE non-ceremony calls — `message/send`, `aoide/graphSummary`
/// pulls, spawn) — no scheme/host validation beyond "looks like a URL and
/// isn't absurdly long" (`post_json`/curl, `aoide-client`'s job, will fail
/// loudly on anything genuinely malformed when a real call is dialed).
/// Design A (task #119): the ceremony's OWN completion no longer dials this
/// URL at all (`aoide/pairPoll` reverses the direction — see the section doc
/// above), so this validation exists purely for the node record's own future
/// use, not for anything the ceremony itself does synchronously. Pure.
fn valid_node_url(s: &str) -> bool {
    !s.is_empty() && s.len() <= 2048 && s.contains("://")
}

/// The door URL THIS `a2a serve` process is actually answering on, derived
/// from `bind`/`port` — [`route`]'s own `aoide/graphSummary` handling
/// builds its `self_url` from this one formula. (The discovery
/// advertisement carries NO door URL at all — task #120's rendezvous-not-
/// authentication stance, `aoide_storage::advertise`'s module doc.)
fn self_url(bind: &str, port: u16) -> String {
    format!("http://{bind}:{port}/")
}

/// Best-effort emit onto aoided's own events feed for a pairing-ceremony
/// milestone (P-P5, CONTRACTS.md §6's "Pairing events feed" subsection):
/// `pair-parked` and `pair-revealed` are the two live kinds. The third,
/// `pair-awaiting-confirm`, is RETIRED with the callback that emitted it
/// (task #119 — approval is learned by the requester's own poll, which
/// runs client-side where this door-side feed writer never sees it);
/// `parse_pair_line` still reads it for old feed lines. Never `?`,
/// never panics — the posture
/// `aoide_secrets::broker::emit_notify` already holds, because a
/// notification write must never fail or block the ceremony itself
/// ([`FeedWriter::append`] is already best-effort internally; this
/// wrapper's own job is only to resolve the path and shape the record).
///
/// `a2a serve` is a SEPARATE process from `aoided` (module doc's DI-seam
/// note — this crate has no dependency on the resident daemon's runtime,
/// only its path/cap resolvers), so it opens its OWN [`FeedWriter`] onto
/// the SAME `$XDG_RUNTIME_DIR/aoide/events.jsonl` `aoided` already writes
/// through (`crate::daemon::events_path`) rather than routing through the
/// daemon process. Two independent writers sharing one capped,
/// truncate-in-place file means a cap-truncate race at the 1 MiB boundary
/// can lose a line — accepted, because the feed is ephemeral cues, not
/// the durable record (that stays the audit log, already written at every
/// one of these three call sites); the watcher's actual authority is
/// `aoide_storage::pairing::list_inbound`/`list_outbound`, and this feed
/// line is only ever a trigger to re-check them, never itself trusted
/// data.
///
/// `payload` carries fields BY NAME ONLY (`id`, `name`, `originAddr`,
/// `url`, `direction`) — never a SAS, pubkey, nonce, or commitment; the
/// watcher re-derives the SAS locally from its own identity plus
/// `list_inbound`/`list_outbound`, so nothing secret-shaped ever needs to
/// ride this line.
fn emit_pairing_event(kind: &str, payload: Value) {
    let events_path = crate::daemon::events_path(&crate::daemon::socket_path());
    let feed = aoide_protocol::feed::FeedWriter::new(events_path, crate::daemon::EVENTS_CAP_BYTES, 0o600);
    feed.append(&json!({
        "v": 0,
        "ts": aoide_protocol::audit::now_secs(),
        "class": serde_json::to_value(EventClass::Gate).unwrap_or_else(|_| json!("gate")),
        "kind": kind,
        "source": "a2a-door",
        "payload": payload,
    }));
}

/// `aoide/pairRequest` (CONTRACTS.md §6, P-P2): the pairing ceremony's
/// bootstrap request. Box A POSTs `{pubkeyHex, name, commitHex, url}` — its
/// own public key, its own SELF-CLAIMED instance name (A's
/// `local_host_name` chain — the name THIS instance will record A under), a
/// COMMITMENT to its own nonce (`aoide_storage::pairing::derive_commit`,
/// never the nonce itself — module doc on `aoide_storage::pairing`, the
/// commit-then-reveal fix), and its own advertised A2A door URL (recorded
/// for the resulting node record's own future non-ceremony calls — Design A,
/// task #119: the ceremony's own completion no longer dials this URL) —
/// PLUS an OPTIONAL `selfVia` (P-PV1, task #131): A's own self-asserted
/// `ssh://[user@]host` reach-back hop claim, carried alongside `url` for
/// exactly the case where A's door is loopback-only and reached through a
/// tunnel — B, dialed over that tunnel, can only ever OBSERVE the
/// connection arriving from loopback, so nothing about the connection
/// itself can answer "how do I dial A back"; `selfVia` is A's own claim of
/// that answer (same trust class as `url` — self-asserted data, a
/// transport marker only; trust stays in pubkeys + SAS). Absent on an old
/// requester, or when A has no such claim to make. THIS instance (box B)
/// parks it whole, `selfVia` included ([`aoide_storage::pairing::
/// park_inbound`], cap-checked — a full queue is `-32000`, review-bounce
/// Finding 3; a SAME-pubkey retry supersedes whatever this identity had
/// parked already, audited as a supersede but never named as one on the
/// wire — R3, `aoide_storage::pairing`'s own module doc), for its own
/// LATER `pair <id>` commit to read
/// (`aoide-client::commands::approve_inbound`'s own doc), and answers
/// SYNCHRONOUSLY with its OWN public key and a freshly-minted nonce —
/// public material, same "freely shown" stance `docs/architecture/
/// PAIRING.md`'s "Identity" section already states for `aoide identity`,
/// and safe to reveal immediately since B moves SECOND (nothing of B's is
/// fixed by a commitment A could exploit the way the reverse would be).
///
/// `name` is validated against [`aoide_storage::node_store::valid_node_name`]
/// HERE, at park time — not merely at `node add`'s door the way a
/// legacy-path name is — because `pair <id>` reuses this
/// self-claimed name VERBATIM as the approver's own local nickname (no
/// separate `--name` flag on `approve`), and that nickname later joins a
/// `state/node-cache/<name>.json` path; a traversal-shaped name must never
/// reach that far. A malformed request (bad pubkey/name/commit/url shape) is
/// refused with `-32602` before anything is parked.
fn pair_request(params: &Value, origin: ConnOrigin, audit_log: &Path) -> Result<Value, (i64, String)> {
    let pubkey_hex = params.get("pubkeyHex").and_then(Value::as_str).unwrap_or("");
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let commit_hex = params.get("commitHex").and_then(Value::as_str).unwrap_or("");
    let url = params.get("url").and_then(Value::as_str).unwrap_or("");
    // OPTIONAL (P-PV1, task #131) — an old requester's body carries no
    // `selfVia` key at all, and any shape that isn't a non-empty string
    // (absent, wrong type, empty) collapses to `None` the same way: this
    // field is never load-bearing enough to refuse a pairing request over,
    // only to enrich the approver's eventual commit when present.
    let self_via = params.get("selfVia").and_then(Value::as_str).filter(|s| !s.is_empty());

    if !valid_pubkey_hex(pubkey_hex) {
        return Err((-32602, "invalid params: pubkeyHex must be 64 hex characters".to_string()));
    }
    if !aoide_storage::node_store::valid_node_name(name) {
        return Err((
            -32602,
            "invalid params: name must match `^[a-z0-9][a-z0-9-]*$`".to_string(),
        ));
    }
    if !valid_commit_hex(commit_hex) {
        return Err((-32602, "invalid params: commitHex must be 64 hex characters".to_string()));
    }
    if !valid_node_url(url) {
        return Err((-32602, "invalid params: url must be a non-empty URL, at most 2048 characters".to_string()));
    }

    let (kp, _) =
        aoide_storage::identity::load_or_mint().map_err(|e| (-32603_i64, format!("loading this instance's identity: {e}")))?;
    let info = kp.info();

    let requested_at = now_iso_utc();
    let now_epoch = aoide_storage::time::parse_iso_utc(&requested_at).unwrap_or_else(|| unix_ts_now() as i64);
    let expires_at = aoide_storage::pairing::expires_at_from(now_epoch);

    let (entry, evicted_id) = aoide_storage::pairing::park_inbound(
        pubkey_hex,
        name,
        &origin_display(origin),
        url,
        commit_hex,
        &requested_at,
        &expires_at,
        self_via,
    )
    .map_err(|e| (-32000_i64, e))?;

    // R3 (one live parked request per requester identity,
    // `aoide_storage::pairing`'s own module doc): a same-pubkey retry
    // superseded whatever was parked before it. The audit STATUS names the
    // supersede and its evicted id; the WIRE response below never does —
    // an ordinary fresh-id response either way (CONTRACTS.md §6).
    let status = match &evicted_id {
        Some(old_id) => format!("parked (superseding {old_id})"),
        None => "parked".to_string(),
    };
    let _ = audit(
        audit_log,
        Door::A2a,
        EventClass::Audit,
        "a2a.pairRequest",
        &status,
        &format!(
            "pairing request `{}` parked (claimed name `{name}`, origin {})",
            entry.id,
            origin_display(origin)
        ),
    );

    emit_pairing_event(
        "pair-parked",
        json!({
            "id": entry.id,
            "name": entry.name,
            "originAddr": entry.origin_addr,
            "url": entry.url,
            "direction": "inbound",
        }),
    );

    Ok(json!({
        "id": entry.id,
        "pubkeyHex": info.pubkey_hex,
        "nonceHex": entry.approver_nonce_hex,
        "expiresAt": entry.expires_at,
    }))
}

/// `aoide/pairReveal` (CONTRACTS.md §6, P-P2, review-bounce Finding 1): box
/// A's immediate follow-up to `aoide/pairRequest` (same `pair`
/// invocation, two sequential POSTs), handing over the nonce its earlier
/// `commitHex` already fixed. `{id, nonceHex}` — `id` is the SAME id
/// [`pair_request`] handed back synchronously. THIS instance (box B) checks
/// `derive_commit(entry.pubkeyHex, nonceHex) == entry.commitHex`
/// ([`aoide_storage::pairing::reveal_inbound`]); a match stores the nonce
/// (so bare `pair`/`pair <id>` can finally derive a SAS for this
/// entry) and a MISMATCH drops the parked entry outright — there is nothing
/// left worth keeping once the commitment fails to check out (a genuine
/// tamper, or a bug; either way the honest path is to start over, not to
/// leave a broken entry sitting in the queue).
fn pair_reveal(params: &Value, audit_log: &Path) -> Result<Value, (i64, String)> {
    let id = params.get("id").and_then(Value::as_str).unwrap_or("");
    let nonce_hex = params.get("nonceHex").and_then(Value::as_str).unwrap_or("");
    if id.is_empty() {
        return Err((-32602, "invalid params: id is required".to_string()));
    }
    if !valid_nonce_hex(nonce_hex) {
        return Err((-32602, "invalid params: nonceHex must be 32 hex characters".to_string()));
    }

    let now_epoch = aoide_storage::time::parse_iso_utc(&now_iso_utc()).unwrap_or_else(|| unix_ts_now() as i64);
    match aoide_storage::pairing::reveal_inbound(id, nonce_hex, now_epoch) {
        Ok(entry) => {
            let _ = audit(
                audit_log,
                Door::A2a,
                EventClass::Audit,
                "a2a.pairReveal",
                "ok",
                &format!("pairing request `{id}` revealed — commitment verified (claimed name `{}`)", entry.name),
            );
            emit_pairing_event(
                "pair-revealed",
                json!({
                    "id": entry.id,
                    "name": entry.name,
                    "originAddr": entry.origin_addr,
                    "url": entry.url,
                    "direction": "inbound",
                }),
            );
            Ok(json!({ "ok": true }))
        }
        Err(aoide_storage::pairing::RevealError::Unknown) => Err((
            -32001,
            "no pending inbound pairing request with that id (unknown, already resolved, or expired)".to_string(),
        )),
        Err(aoide_storage::pairing::RevealError::Mismatch) => {
            let _ = audit(
                audit_log,
                Door::A2a,
                EventClass::Audit,
                "a2a.pairReveal",
                "mismatch",
                &format!("pairing request `{id}` dropped — the revealed nonce did not match its commitment"),
            );
            Err((
                -32002,
                "commitment mismatch: the revealed nonce does not match the pubkey's earlier commitment — the parked request has been dropped".to_string(),
            ))
        }
        Err(aoide_storage::pairing::RevealError::Io(e)) => Err((-32603, format!("resolving the inbound pairing request: {e}"))),
    }
}

/// `aoide/pairPoll` (Design A, task #119, CONTRACTS.md §6 — REPLACES the old
/// `aoide/pairApprove` reverse callback): the REQUESTER's `pair
/// <id>` POSTs this to the APPROVER's door, over the SAME forward dial
/// `aoide/pairRequest`/`aoide/pairReveal` already used, asking "has the
/// entry I parked with you been approved yet?" `{id, timestampIso, nonceHex,
/// signatureHex}` — `id` is the SAME id [`pair_request`] handed back
/// synchronously; the other three are a self-contained signature (never
/// P-P4's header-based scheme, which needs a VERIFIED node record to check
/// against — one doesn't exist on the approver's side until the id this
/// poll is asking about is ITSELF approved, a bootstrapping problem P-P4
/// can't solve here) proving the poller holds the private key matching
/// [`InboundPairingRequest::pubkey_hex`] — the REQUESTER's own pubkey,
/// captured at `aoide/pairRequest` time, long before any node record
/// exists. The signed message is
/// `aoide_storage::wire_auth::canonical_string("PAIRPOLL", id, timestampIso,
/// nonceHex, &[])` (the SAME canonical-string primitive P-P4 signs, reused
/// rather than reinvented, with an empty body — a poll carries no body of
/// its own to bind).
///
/// The nonce is signed but NOT replay-checked (no `nonce_is_replay` here,
/// unlike P-P4's request path): a captured poll replays cleanly inside the
/// skew window, and that is accepted deliberately — the response is
/// idempotent and releases only B's own pubkey, which `aoide/pairRequest`
/// already hands to any caller; there is nothing a replay gains. Timing is
/// likewise not uniform across the pending cases (an unknown id refuses
/// before the signature verify, a known one pays it) — the oracle
/// discipline below is byte-level, not timing-level, stated so nobody
/// reads a stronger claim into it.
///
/// **Existence-oracle discipline (mirrors the door's own Phase G/2026-08-20
/// amendment for `message/send`'s `contextId` lookup, CONTRACTS.md §6): an
/// unauthenticated or wrongly-signed poller must never learn anything an
/// authenticated one couldn't.** Three cases — the id doesn't exist (never
/// parked, already expired), the signature doesn't verify against the
/// entry's own stored `pubkey_hex`, or the entry exists and verifies but
/// isn't approved YET — all answer with the IDENTICAL `{"status":"pending"}`,
/// never a distinct error code that would let a caller tell "wrong id" apart
/// from "right id, wrong key" apart from "right id and key, just not
/// approved yet." Only a poll that BOTH verifies AND finds
/// [`InboundPairingRequest::approved`] `true` gets the release:
/// `{"status":"approved", "pubkeyHex": "<B's own pubkey>"}` — B's own
/// identity, re-loaded fresh (never stored on the parked entry; it's B's
/// OWN persistent key, always re-derivable) so the requester can bind this
/// release to the SAME transcript it already holds
/// (`aoide_storage::pairing::mark_outbound_awaiting_confirm`'s own pubkey
/// check on the requester's side is what actually enforces this — a
/// mismatch there rejects a substituted reveal without ever committing).
/// Malformed params (missing id, non-hex nonce/signature) refuse `-32602`
/// BEFORE any lookup — a shape error reveals nothing about any id's
/// existence, so it stays distinct from the uniform "pending" response.
fn pair_poll(params: &Value, audit_log: &Path) -> Result<Value, (i64, String)> {
    let id = params.get("id").and_then(Value::as_str).unwrap_or("");
    let timestamp = params.get("timestampIso").and_then(Value::as_str).unwrap_or("");
    let nonce_hex = params.get("nonceHex").and_then(Value::as_str).unwrap_or("");
    let signature_hex = params.get("signatureHex").and_then(Value::as_str).unwrap_or("");
    if id.is_empty() {
        return Err((-32602, "invalid params: id is required".to_string()));
    }
    if timestamp.is_empty() {
        return Err((-32602, "invalid params: timestampIso is required".to_string()));
    }
    if !valid_nonce_hex(nonce_hex) {
        return Err((-32602, "invalid params: nonceHex must be 32 hex characters".to_string()));
    }
    if signature_hex.is_empty() {
        return Err((-32602, "invalid params: signatureHex is required".to_string()));
    }

    let now_epoch = aoide_storage::time::parse_iso_utc(&now_iso_utc()).unwrap_or_else(|| unix_ts_now() as i64);
    let pending = json!({ "status": "pending" });

    let Some(entry) = aoide_storage::pairing::list_inbound(now_epoch).into_iter().find(|e| e.id == id) else {
        // Unknown or expired — the SAME response an authenticated-but-not-
        // yet-approved poll gets (module doc: existence-oracle discipline).
        return Ok(pending);
    };

    let ts_epoch = match aoide_storage::time::parse_iso_utc(timestamp) {
        Some(t) => t,
        None => return Ok(pending),
    };
    if !aoide_storage::wire_auth::within_skew(now_epoch, ts_epoch, aoide_storage::wire_auth::signature_skew_secs()) {
        return Ok(pending);
    }

    let canonical = aoide_storage::wire_auth::canonical_string("PAIRPOLL", id, timestamp, nonce_hex, &[]);
    if !aoide_storage::wire_auth::verify_signature_hex(&entry.pubkey_hex, canonical.as_bytes(), signature_hex) {
        // A bad signature against a REAL entry answers exactly like an
        // unknown one — no distinct code, nothing for an outsider to learn.
        return Ok(pending);
    }

    if !entry.approved {
        return Ok(pending);
    }

    let (kp, _) = aoide_storage::identity::load_or_mint().map_err(|e| (-32603_i64, format!("loading this instance's identity: {e}")))?;
    let info = kp.info();

    let _ = audit(
        audit_log,
        Door::A2a,
        EventClass::Audit,
        "a2a.pairPoll",
        "released",
        &format!("pairing request `{id}` released to `{}`'s own verified poll", entry.name),
    );

    Ok(json!({ "status": "approved", "pubkeyHex": info.pubkey_hex }))
}

/// Per-request context [`handle_jsonrpc`]/[`handle_jsonrpc_bytes`] thread
/// through to whichever method needs it: `message/send` needs
/// `audit_log`/`spawn_agent`/`origin`; `aoide/graphSummary` (CONTRACTS.md §7)
/// needs `node_name`/`self_url`. Bundled into one struct once a second method
/// needed request-scoped dependencies, rather than growing `handle_jsonrpc`'s
/// positional-arg list again.
struct RequestCtx<'a> {
    audit_log: &'a Path,
    spawn_agent: &'a str,
    spawn_cwd: &'a str,
    origin: ConnOrigin,
    node_name: &'a str,
    self_url: &'a str,
    /// The server's own expected A2A token (CONTRACTS.md §6 amendment,
    /// 2026-08-18) — empty means none configured (feature off). Resolved
    /// once at `a2a serve` launch, same as `spawn_agent`.
    expected_token: &'a str,
    /// This request's `Authorization: Bearer <token>`, if any.
    presented_token: Option<&'a str>,
    /// P-P4: `Some(name)` when [`verify_signed_request`] already verified
    /// this request's signature headers against a paired node — computed
    /// exactly once, in `handle_connection`, before either dispatch path,
    /// never re-verified here. `None` covers both "no signature headers at
    /// all" and "this ctx predates P-P4 in a test fixture."
    signed_node_name: Option<&'a str>,
}

/// Handle one parsed JSON-RPC 2.0 request `Value`, returning the response
/// `Value` (always — unlike `mcp.rs`'s stdio notifications, an HTTP POST
/// always gets a reply body).
fn handle_jsonrpc(req: &Value, ctx: &RequestCtx) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or(Value::Null);

    // Phase G (CONTRACTS.md §6 amendment, 2026-08-20): the read commands are
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
            ctx.spawn_cwd,
            ctx.origin,
            ctx.expected_token,
            ctx.presented_token,
            ctx.signed_node_name,
        ),
        "aoide/graphSummary" if !read_ok => Err(unauthorized()),
        "aoide/graphSummary" => graph_summary(ctx.node_name, ctx.self_url),
        // Deliberately UNGATED by `read_ok` — the pairing bootstrap has no
        // established credential to check yet (see the section doc above
        // `pair_request`).
        "aoide/pairRequest" => pair_request(&params, ctx.origin, ctx.audit_log),
        "aoide/pairReveal" => pair_reveal(&params, ctx.audit_log),
        "aoide/pairPoll" => pair_poll(&params, ctx.audit_log),
        "aoide/mailDeposit" => mail_deposit(&params, ctx),
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
    spawn_cwd: &str,
    origin: ConnOrigin,
    expected_token: &str,
    presented_token: Option<&str>,
    signed_node_name: Option<&str>,
) -> std::io::Result<()> {
    let rpc: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
    let rpc_id = rpc.get("id").cloned().unwrap_or(Value::Null);
    let params = rpc.get("params").cloned().unwrap_or(Value::Null);

    // Resolve the target task + its initial state. `message/stream` runs the
    // send FIRST (inject/spawn) and streams the task it produced;
    // `tasks/resubscribe` streams an existing task by id.
    //
    // Phase G (CONTRACTS.md §6 amendment, 2026-08-20): gate BOTH streaming
    // reads by the same token rule as the one-shot commands. When a token is
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
                message_send(&params, audit_log, spawn_agent, spawn_cwd, origin, expected_token, presented_token, signed_node_name)
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
    /// The four P-P4 signed-request headers (`aoide_storage::wire_auth`'s
    /// `HEADER_*` constants), raw header VALUES, unvalidated — captured
    /// together so `verify_signed_request` can tell "no signature headers
    /// at all" (every field `None`, the untouched path) from "a malformed
    /// signed request" (some but not all four present, refused outright)
    /// without re-parsing headers a second time. Each is `Some` the instant
    /// its own header line is seen, however many times — a request that
    /// repeats one of these headers keeps only the LAST value, same
    /// last-wins behavior `content_length`/`bearer` already had before this
    /// field existed.
    signed_node: Option<String>,
    signed_timestamp: Option<String>,
    signed_nonce: Option<String>,
    signed_signature: Option<String>,
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
    let mut signed_node: Option<String> = None;
    let mut signed_timestamp: Option<String> = None;
    let mut signed_nonce: Option<String> = None;
    let mut signed_signature: Option<String> = None;
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
            let value = value.trim();
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse().unwrap_or(0);
            } else if name.eq_ignore_ascii_case("authorization") {
                bearer = extract_bearer(value);
            } else if name.eq_ignore_ascii_case(aoide_storage::wire_auth::HEADER_NODE) {
                signed_node = (!value.is_empty()).then(|| value.to_string());
            } else if name.eq_ignore_ascii_case(aoide_storage::wire_auth::HEADER_TIMESTAMP) {
                signed_timestamp = (!value.is_empty()).then(|| value.to_string());
            } else if name.eq_ignore_ascii_case(aoide_storage::wire_auth::HEADER_NONCE) {
                signed_nonce = (!value.is_empty()).then(|| value.to_string());
            } else if name.eq_ignore_ascii_case(aoide_storage::wire_auth::HEADER_SIGNATURE) {
                signed_signature = (!value.is_empty()).then(|| value.to_string());
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

    Ok(HttpRequest {
        method,
        path,
        body,
        bearer,
        signed_node,
        signed_timestamp,
        signed_nonce,
        signed_signature,
    })
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

// ── P-P4: per-request signature verification for paired nodes ───────────────
//
// `docs/architecture/PAIRING.md`'s "Wire authentication (paired nodes)"
// section: a request carrying all four `aoide_storage::wire_auth::HEADER_*`
// headers claims to come from a specific, already-PAIRED node, proven by an
// ed25519 signature over that ONE request's own method/path/timestamp/
// nonce/body-digest. Verification runs ONCE, in [`handle_connection`],
// BEFORE either dispatch path (the one-shot `route`/`handle_jsonrpc_bytes`
// path AND the SSE `stream_task` path) — a request that claims a paired
// node and FAILS verification in any way is refused OUTRIGHT, fail-closed,
// with no fallthrough to the weaker addr/token ladder `resolve_node`
// already offers (the #84 "sentinel on resolve failure" discipline,
// applied here as an outright request refusal rather than an unmatchable
// token). A request carrying NONE of the four headers is untouched by any
// of this — [`SignedRequestOutcome::Unsigned`] — and flows through exactly
// as it did before this phase.

/// Bound on the in-memory replay-nonce cache — PROCESS-LOCAL, in-memory,
/// never disk-persisted (unlike everything else this door's underlying
/// crate stores — `aoide-storage`'s `wire_auth` module doc states this
/// placement's own reasoning). An `a2a serve` restart clears it outright: a
/// KNOWN, ACCEPTED limitation, the same "process-local guard, not durable
/// state" shape `aoide_storage::pairing`'s own `PARK_LOCK` doc already
/// accepts for a different concern. Within one process's lifetime this
/// correctly refuses a replay inside the skew window; a replay that arrives
/// after a restart (whose cache never survived it) is NOT caught by this
/// cache alone — the timestamp window ([`aoide_storage::wire_auth::
/// signature_skew_secs`]) is the OTHER, independent defense that narrow gap
/// leans on, which is why both checks run rather than either alone. Sized
/// generously relative to plausible signed-request rates within one skew
/// window (default ±120s) — bounds worst-case memory against a hostile or
/// malfunctioning node hammering the door; never expected to be reached in
/// normal operation.
const NONCE_CACHE_CAP: usize = 4096;

/// `(verifying pubkey hex, nonce)` pairs seen within roughly the current
/// replay window, oldest-first — see [`NONCE_CACHE_CAP`]'s doc for the
/// process-locality and sizing reasoning. Keyed on the PUBKEY that verified
/// the request, not any node name (#63 P-ID5: identity IS the key): the
/// `X-Aoide-Node` header is not part of the canonical string, so a captured
/// request replayed under a different claimed name still lands on the same
/// cache key — two verified records sharing one pubkey share one replay
/// namespace, exactly because they are one signer.
static NONCE_CACHE: Mutex<VecDeque<(String, String)>> = Mutex::new(VecDeque::new());

/// Check-and-record: `true` (nothing recorded) when `(key, nonce)` was
/// ALREADY seen — a replay the caller must refuse. `false` (now recorded)
/// the first time. Evicts the OLDEST entry once at [`NONCE_CACHE_CAP`],
/// never growing past it. Poison-recovering like every other process-local
/// lock in this workspace (`pairing.rs`'s `PARK_LOCK` precedent): a panic
/// inside one caller must never wedge every OTHER signed request behind a
/// poisoned lock forever.
fn nonce_is_replay(key: &str, nonce: &str) -> bool {
    let mut cache = NONCE_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if cache.iter().any(|(p, n)| p == key && n == nonce) {
        return true;
    }
    if cache.len() >= NONCE_CACHE_CAP {
        cache.pop_front();
    }
    cache.push_back((key.to_string(), nonce.to_string()));
    false
}

/// [`verify_signed_request`]'s result — three shapes, not a `Result`,
/// because "no signature headers at all" is a THIRD outcome distinct from
/// both success and refusal (the untouched, pre-P-P4 path), and collapsing
/// it into `Ok(None)`/`Err(())` would blur that distinction at every call
/// site.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SignedRequestOutcome {
    /// None of the four `HEADER_*` values were present — the existing
    /// addr/token resolution ladder applies exactly as before this phase.
    Unsigned,
    /// All four headers were present and verification succeeded. `resolved`
    /// is the name of the node RECORD whose stored pubkey verified the
    /// signature (#63 P-ID5: identity is the key) — the name every
    /// downstream consumer (allows lookup, `node:<name>` origin stamp,
    /// autogate) uses. `claimed` is what the `X-Aoide-Node` header said —
    /// display/attribution only, carried so the caller can audit a
    /// claimed-vs-resolved mismatch as attribution drift; it is never
    /// trusted and never wins over `resolved` anywhere.
    Verified { resolved: String, claimed: String },
    /// Signature headers were present but verification failed somewhere —
    /// the JSON-RPC `(code, message)` the WHOLE request refuses with, no
    /// matter which method it named.
    Refused(i64, String),
}

/// Verify a request's P-P4 signature headers, if it carries any (module doc
/// above). Pure aside from two reads: the node registry
/// (`aoide_storage::node_store::load_nodes`) and the process-local
/// [`NONCE_CACHE`] — `now_epoch` is the caller's own "now" so this stays
/// unit-testable against a fixed clock, the same shape
/// `aoide_storage::pairing::park_inbound`'s own `now_epoch` parameter
/// holds.
///
/// **Resolution is BY KEY, not by name (#63 P-ID5).** The signature proves
/// possession of a private key; the caller's identity is the node record
/// whose stored `pubkey` verifies that signature — found by trying the
/// signature against every VERIFIED node's stored pubkey (operator-curated
/// small N; one ed25519 verify is microseconds, and the skew check below
/// runs first so a stale request never costs any). The `X-Aoide-Node`
/// header does no identity work: it is display/attribution, checked only
/// for wire-format validity, and consulted for exactly one thing — the
/// exact-name tiebreak when MULTIPLE verified records share the verifying
/// pubkey (the same remote instance paired under two names; both records
/// hold the same proven key, so the tiebreak picks among equal-security
/// records, it never elevates a name to identity). Shared-key records with
/// no exact-name match refuse as ambiguous rather than picking one — their
/// `allows`/`autogate` may differ, and guessing would grant one record's
/// grants on the other's behalf.
///
/// A signature no verified node's key verifies refuses with the SAME code
/// and message as a bad signature — they are literally the same code path,
/// so the refusal is never an existence oracle over the registry (unknown
/// key, unverified node, keyless record, and tampered request are
/// indistinguishable from outside).
///
/// Checks run in an order that never spends work verifying a signature for
/// a request that's already disqualified for a cheaper reason (malformed
/// headers, unparsable timestamp, clock skew), and records the nonce ONLY
/// after a genuine signature match — a forged or garbage nonce never
/// consumes a cache slot.
fn verify_signed_request(req: &HttpRequest, now_epoch: i64) -> SignedRequestOutcome {
    use aoide_storage::wire_auth::{HEADER_NONCE, HEADER_NODE, HEADER_SIGNATURE, HEADER_TIMESTAMP, SIGNATURE_SKEW_ENV};

    let claims_signed =
        req.signed_node.is_some() || req.signed_timestamp.is_some() || req.signed_nonce.is_some() || req.signed_signature.is_some();
    if !claims_signed {
        return SignedRequestOutcome::Unsigned;
    }
    let (Some(node_name), Some(timestamp), Some(nonce), Some(signature)) = (
        req.signed_node.as_deref(),
        req.signed_timestamp.as_deref(),
        req.signed_nonce.as_deref(),
        req.signed_signature.as_deref(),
    ) else {
        return SignedRequestOutcome::Refused(
            -32007,
            format!(
                "incomplete signed-request headers: `{HEADER_NODE}`/`{HEADER_TIMESTAMP}`/\
                 `{HEADER_NONCE}`/`{HEADER_SIGNATURE}` must all be present together, or not at all"
            ),
        );
    };

    // Wire-format validity only — the VALUE never selects a record below.
    if !aoide_storage::node_store::valid_node_name(node_name) {
        return SignedRequestOutcome::Refused(-32007, format!("`{HEADER_NODE}` is not a well-formed node name: `{node_name}`"));
    }

    let Some(ts_epoch) = aoide_storage::time::parse_iso_utc(timestamp) else {
        return SignedRequestOutcome::Refused(-32007, format!("`{HEADER_TIMESTAMP}` is not a valid ISO-8601 timestamp: `{timestamp}`"));
    };
    let window = aoide_storage::wire_auth::signature_skew_secs();
    if !aoide_storage::wire_auth::within_skew(now_epoch, ts_epoch, window) {
        let skew = now_epoch - ts_epoch;
        return SignedRequestOutcome::Refused(
            -32008,
            format!(
                "clock skew too large: this request's `{HEADER_TIMESTAMP}` (`{timestamp}`) is {skew}s \
                 away from this instance's own now (`{}`) — the allowed window is ±{window}s \
                 (`{SIGNATURE_SKEW_ENV}` raises it)",
                aoide_storage::time::iso_utc_from_epoch(now_epoch),
            ),
        );
    }

    // `&req.method` (P-P4 review finding 2), not a hardcoded `"POST"`
    // literal: the OBSERVED method of THIS request, so the canonical
    // string is genuinely bound to what arrived, not a re-typed assumption
    // that happens to agree with it. Every real signed request today IS a
    // POST (the client's own `HTTP_METHOD` constant — `aoide-client::
    // commands` — never builds anything else), so this changes no byte of
    // any existing signature's canonical string or the pinned vectors
    // (CONTRACTS.md §6) — it only makes the module doc's "binds method"
    // claim structurally true instead of coincidentally true.
    let canonical = aoide_storage::wire_auth::canonical_string(&req.method, &req.path, timestamp, nonce, &req.body);
    let nodes = aoide_storage::node_store::load_nodes();
    // By-key resolution (fn doc): every verified record whose stored pubkey
    // verifies this signature. An unverified or keyless record never enters
    // the trial set — an unverified node's key can never resolve.
    let candidates: Vec<&aoide_storage::node_store::Node> = nodes
        .iter()
        .filter(|p| p.verified)
        .filter(|p| {
            p.pubkey
                .as_deref()
                .filter(|k| !k.is_empty())
                .is_some_and(|k| aoide_storage::wire_auth::verify_signature_hex(k, canonical.as_bytes(), signature))
        })
        .collect();
    // ONE refusal for unknown key / unverified node / keyless record / bad
    // signature alike — never an existence oracle over the registry.
    let resolved = match candidates.as_slice() {
        [] => return SignedRequestOutcome::Refused(-32007, "signature verification failed".to_string()),
        [one] => *one,
        several => {
            let Some(exact) = several.iter().find(|p| p.name == node_name) else {
                return SignedRequestOutcome::Refused(
                    -32007,
                    format!(
                        "ambiguous signer: {} verified node records share the public key that verifies this \
                         signature and none is named `{node_name}` — send `{HEADER_NODE}` naming one of them, \
                         or remove the duplicate record (`node remove`)",
                        several.len()
                    ),
                );
            };
            *exact
        }
    };
    // Case-normalized: hex_decode verifies case-insensitively, so twin
    // records whose stored pubkeys differ only in hex case (hand-edited
    // registry only — hex_encode always emits lowercase) must still share
    // one replay-cache key.
    let pubkey_hex = resolved.pubkey.as_deref().unwrap_or_default().to_ascii_lowercase();

    if nonce_is_replay(&pubkey_hex, nonce) {
        return SignedRequestOutcome::Refused(
            -32009,
            format!(
                "nonce replay: node `{}` reused a `{HEADER_NONCE}` value already seen within the current replay window",
                resolved.name
            ),
        );
    }

    SignedRequestOutcome::Verified {
        resolved: resolved.name.clone(),
        claimed: node_name.to_string(),
    }
}

/// The audit detail `handle_connection` logs when a verified request's
/// claimed `X-Aoide-Node` name and its key-resolved record disagree
/// (#63 P-ID5) — `None` when they agree (the overwhelmingly common case,
/// nothing logged). Drift is ATTRIBUTION news, never a gate: the request
/// already proved possession of the resolved record's key, so it proceeds
/// as the resolved node everywhere; this line only keeps the operator's
/// audit trail honest about what the wire claimed. Pure, extracted from
/// `handle_connection` the same way [`spawn_admitted`] is — testable
/// without a socket.
fn attribution_drift_detail(claimed: &str, resolved: &str) -> Option<String> {
    (claimed != resolved).then(|| {
        format!(
            "attribution drift: `{}` claimed `{claimed}` but the signature verifies against the stored \
             public key of node `{resolved}` — proceeding as `{resolved}`; the claimed name is a label, \
             never an identity",
            aoide_storage::wire_auth::HEADER_NODE
        )
    })
}

/// Route one parsed request to (HTTP status, response body, audit-log
/// command label). `audit_log`/`spawn_agent`/`origin` are only consulted by a
/// POST `/` whose body parses as `message/send`; `node_name` (plus the
/// `self_url` this function derives from `bind`/`port`, the same way
/// [`agent_card`]'s own `url` field does) is only consulted by
/// `aoide/graphSummary`; `registry` and `expected_token` (compared against
/// `req.bearer`, CONTRACTS.md §6 2026-08-20 amendment) are only consulted by
/// the AgentCard GET, which strips the card down to `name`/`protocolVersion`/
/// `url` when a token is configured and the bearer doesn't classify `Valid` —
/// every other route is pure I/O-free routing over what's already in `req`,
/// so it still unit-tests without a real socket, spawn, or audit-log write.
/// `signed_node_name` is P-P4's own addition: `Some(name)` when
/// [`verify_signed_request`] already verified this request's signature
/// headers against a paired node — the KEY-resolved record's name
/// (#63 P-ID5), never the wire-claimed label (never re-verified here — `handle_connection`
/// runs that check exactly once, before EITHER dispatch path), threaded
/// straight into [`RequestCtx`] for `message/send` to consume.
fn route(
    req: &HttpRequest,
    bind: &str,
    port: u16,
    audit_log: &Path,
    spawn_agent: &str,
    spawn_cwd: &str,
    node_name: &str,
    origin: ConnOrigin,
    expected_token: &str,
    registry: &Registry,
    signed_node_name: Option<&str>,
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
                    Some("aoide/pairRequest") => "aoide/pairRequest",
                    Some("aoide/pairReveal") => "aoide/pairReveal",
                    Some("aoide/pairPoll") => "aoide/pairPoll",
                    Some("aoide/mailDeposit") => "aoide/mailDeposit",
                    _ => "rpc",
                };
                let self_url = self_url(bind, port);
                let ctx = RequestCtx {
                    audit_log,
                    spawn_agent,
                    spawn_cwd,
                    origin,
                    node_name,
                    self_url: &self_url,
                    expected_token,
                    presented_token: req.bearer.as_deref(),
                    signed_node_name,
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

// ── Inbound bearer resolved via the secrets broker (task #84) ───────────────
//
// The token-FILE mechanism above (`resolve_token_file`/`read_expected_token`)
// reads its value ONCE, at `a2a serve` launch, and holds it in memory for the
// server's whole lifetime — fine for a file, since revoking it means editing
// the file and restarting the daemon anyway. A secrets-broker-resolved
// bearer must NOT work that way: the whole point of routing it through the
// broker is that `secrets rm`/a policy edit takes effect immediately, with
// no daemon restart — so this door must resolve it FRESH, every connection,
// never once and cached. That is the one deliberate architectural
// difference from the file mechanism below, and it is why
// [`InboundBearerConfig`] carries the INPUTS to a resolve (a secret name, a
// socket path) rather than a resolved value.

/// The self-asserted consumer name this door presents to the secrets broker
/// when resolving its own inbound bearer — see `crates/secrets/AGENTS.md`'s
/// honesty note (consumer identity is self-asserted; #63's seal
/// authenticates the session and its origin class, never this string):
/// nothing on the wire authenticates this string, it is simply the name an operator's
/// `policy.json` `consumers[]`/`automation.consumers` lists to grant
/// `a2a serve` access to the named secret.
const BEARER_CONSUMER_DOOR: &str = "a2a-door";

/// Bound on the inbound bearer resolve's socket READ (the PARKING HAZARD,
/// task #84): a misconfigured `requireTotp`-gated bearer secret with no
/// `automation`-open exemption for [`BEARER_CONSUMER_DOOR`] would otherwise
/// let the broker hold this call's read open for up to
/// `AOIDE_SECRETS_PARK_TIMEOUT` (default 300s) — an HTTP door has no human
/// to type a code into. `aoide_secrets::client::resolve_bounded`'s own
/// `wait:false` on the wire means the deployed, automation-open happy path
/// never even reaches this timeout; it exists purely as the second,
/// independent bound for a misconfigured deployment (that function's own
/// doc comment).
const BEARER_RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);

/// The inbound-bearer MECHANISM `a2a serve` resolves once at launch (task
/// #84) — everything [`resolve_inbound_bearer`] needs to compute one
/// request's expected token fresh, never the value itself. `Clone` so
/// [`serve`]'s accept loop can hand each spawned connection-handler thread
/// its own copy, the same shape every other per-connection input below
/// already takes.
#[derive(Clone)]
struct InboundBearerConfig {
    /// [`resolve_bearer_secret`]'s result — a secrets-broker secret NAME,
    /// resolved fresh on every connection when non-empty. Takes precedence
    /// over `file_token` below.
    bearer_secret: String,
    /// The secrets broker's socket path (`aoide_secrets::socket::
    /// socket_path`), resolved once at launch — reused for every
    /// connection's resolve, never re-derived per request.
    secrets_socket: std::path::PathBuf,
    /// [`read_expected_token`]'s result — the pre-existing token-FILE
    /// mechanism's value, read once at launch. Consulted only when
    /// `bearer_secret` is empty; unchanged from before this task.
    file_token: String,
}

/// Resolve THIS connection's effective expected inbound bearer token (task
/// #84). `cfg.bearer_secret`, when set, takes precedence over
/// `cfg.file_token` and is resolved FRESH from the secrets broker via
/// [`aoide_secrets::client::resolve_bounded`] — nothing this function
/// returns is ever cached: `handle_connection` calls it once per accepted
/// connection and drops it once that connection's response has been
/// written, the "value lives only in the request path" discipline task
/// #84's brief calls for (`crates/secrets/AGENTS.md`'s "NO CACHE, EVER"
/// invariant, extended here to this door's consumption of the broker).
///
/// **Fails CLOSED without a second `token_configured` boolean rippling
/// through every downstream function (and its tests) in this file.** A
/// broker resolve failure (unreachable, denied, or
/// [`BEARER_RESOLVE_TIMEOUT`] elapsing) returns [`resolve_failure_sentinel`]
/// instead of an empty string. Unlike the true "no bearer mechanism
/// configured at all" case (empty string), this is a FRESH,
/// practically-unguessable-per-call value — so every downstream call site's
/// existing `!expected_token.is_empty()` "is a token configured" check
/// still reads `true` (every bearer check this request denies), while no
/// presented `Authorization: Bearer <token>` can ever happen to equal it
/// ([`resolve_failure_sentinel`]'s own doc). This reuses the EXACT
/// [`token_authorized`]/[`classify_token`] machinery every other bearer
/// check in this file already runs — `route`/`message_send`/`handle_jsonrpc`/
/// `stream_task` are UNCHANGED by this task, only `handle_connection`/
/// [`serve`] resolve the value differently now.
fn resolve_inbound_bearer(cfg: &InboundBearerConfig) -> String {
    if cfg.bearer_secret.is_empty() {
        return cfg.file_token.clone();
    }
    match aoide_secrets::client::resolve_bounded(
        &cfg.secrets_socket,
        &cfg.bearer_secret,
        BEARER_CONSUMER_DOOR,
        BEARER_RESOLVE_TIMEOUT,
    ) {
        Ok(value) => value,
        Err(e) => {
            // `e` is one of the resolve wire's own error strings
            // (CONTRACTS.md's "Secrets wire" catalog) — never the secret's
            // VALUE (this crate's own invariant, restated in
            // `resolve_bounded`'s doc); safe to log the secret's NAME and
            // this reason for an operator debugging a misconfiguration.
            eprintln!(
                "aoide a2a: inbound bearer resolve failed for secret `{}` via {}: {e} — \
                 refusing every bearer check on this connection (fail closed)",
                cfg.bearer_secret,
                cfg.secrets_socket.display(),
            );
            resolve_failure_sentinel()
        }
    }
}

/// A fresh, non-empty value no remote caller could predict or observe —
/// [`resolve_inbound_bearer`]'s fail-closed return on a broker resolve
/// failure. Built ONLY from this process's own pid, the current instant to
/// nanosecond precision, and a per-process atomic counter — never printed,
/// logged, or compared against anything but a presented bearer (and even
/// then, only ever on the LOSING side of that comparison: this value exists
/// solely to keep `!expected_token.is_empty()` true so every check fails
/// closed, not to BE a real credential).
fn resolve_failure_sentinel() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("unresolvable-a2a-bearer-secret::{}::{nanos}::{n}", std::process::id())
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
///
/// The advertise thread (`discovery::spawn_advertiser`) is the ONE thing
/// this function starts besides the accept loop itself — always spawned,
/// so the runtime switch (`aoide node advertise on|off`, read fresh every
/// tick) can take effect without a restart. `discovery_advertise` (P-P6,
/// [`resolve_discovery_advertise`]) is the launch-time FORCE-ON half,
/// OR'd with that switch per tick; with both off (the default) the thread
/// ticks silently and sends nothing. No identity file is touched either
/// way — the advertisement carries name + ssh hop info only, never a
/// fingerprint (rendezvous, not authentication; `aoide_storage::
/// advertise`'s module doc). A refused thread spawn is logged and costs
/// discovery only, never the door itself.
//
// TODO(a2a-hardening): chunked Transfer-Encoding and extra systemd
// sandboxing (aoide-a2a.service) are deliberately out of scope for this
// pass — see the security-review notes that produced this hardening.
pub fn serve(
    bind: &str,
    port: u16,
    audit_log: &Path,
    spawn_agent: &str,
    spawn_cwd: &str,
    node_name: &str,
    expected_token: &str,
    bearer_secret: &str,
    secrets_socket: &Path,
    discovery_advertise: bool,
    registry: &'static Registry,
) -> std::io::Result<()> {
    let listener = TcpListener::bind((bind, port))?;
    eprintln!("aoide a2a: listening on http://{bind}:{port}/");
    let bearer_cfg = InboundBearerConfig {
        bearer_secret: bearer_secret.to_string(),
        secrets_socket: secrets_socket.to_path_buf(),
        file_token: expected_token.to_string(),
    };

    // Discovery advertising (P-P6 + task #120) — the thread always spawns
    // so the runtime switch (`aoide node advertise on|off`) works without
    // a restart; whether a tick SENDS is `discovery_advertise ||
    // aoide_storage::advertise::enabled()`, checked inside the thread.
    // `user` is this process's own login ($USER → $LOGNAME, the same chain
    // `aoide-client::tunnel::resolve_login` walks) — with neither set
    // there is no ssh hop to advertise, so advertising is skipped with a
    // taught line rather than emitting a line every listener would drop as
    // invalid. The join handle is deliberately dropped: dropping a
    // `JoinHandle` detaches nothing extra (the thread already runs
    // independent of it), and this function itself never returns until the
    // process exits, so there is no later point to join it against anyway
    // (module doc's "clean shutdown needs no signal" note).
    {
        let host = aoide_storage::display::local_host_name();
        let user = std::env::var("USER")
            .ok()
            .filter(|u| !u.trim().is_empty())
            .or_else(|| std::env::var("LOGNAME").ok().filter(|u| !u.trim().is_empty()))
            .unwrap_or_default();
        if !aoide_storage::advertise::valid_user(&user) {
            eprintln!(
                "aoide a2a discovery: no usable ssh login for an advertisement (neither $USER \
                 nor $LOGNAME holds one) — continuing without discovery advertising"
            );
        } else if crate::discovery::spawn_advertiser(node_name, &host, &user, discovery_advertise)
            .is_some()
            && discovery_advertise
        {
            // The "advertising" claim is only printed when this process is
            // FORCED on — the runtime switch's state can change under a
            // long-lived process, so its ticks speak for themselves.
            eprintln!(
                "aoide a2a discovery: advertising {node_name} ({user}@{host}) by broadcast \
                 {}:{}",
                aoide_storage::advertise::BROADCAST_ADDR,
                aoide_storage::advertise::PORT
            );
        }
    }

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
        let spawn_cwd = spawn_cwd.to_string();
        let node_name = node_name.to_string();
        let bearer_cfg = bearer_cfg.clone();
        std::thread::spawn(move || {
            let _guard = ConnGuard; // released on every exit path, incl. panic
            if let Err(e) = handle_connection(
                stream,
                &bind,
                port,
                &audit_log,
                &spawn_agent,
                &spawn_cwd,
                &node_name,
                &bearer_cfg,
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
    spawn_cwd: &str,
    node_name: &str,
    bearer_cfg: &InboundBearerConfig,
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

    // task #84: resolve THIS connection's effective expected bearer fresh —
    // AFTER a successful parse (a malformed request never touches the
    // broker at all), never once at `a2a serve` launch when a broker secret
    // is configured — see `resolve_inbound_bearer`'s own doc for the
    // fail-closed/no-cache reasoning. `expected_token` is a local `String`
    // that lives only for the rest of this one connection's handling.
    let expected_token = resolve_inbound_bearer(bearer_cfg);

    // P-P4 (`docs/architecture/PAIRING.md`'s "Wire authentication" section):
    // verify this request's signature headers, if any, EXACTLY ONCE here —
    // before EITHER dispatch path below — so a request that claims a paired
    // node and fails verification is refused fail-closed regardless of
    // which JSON-RPC method it named, never reaching `stream_task` OR
    // `route`/`handle_jsonrpc_bytes`. A request carrying no signature
    // headers at all (`SignedRequestOutcome::Unsigned`) is completely
    // untouched by this — `signed_node_name` stays `None`, and everything
    // below behaves exactly as it did before this phase.
    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let signed_node_name = match verify_signed_request(&req, now_epoch) {
        SignedRequestOutcome::Unsigned => None,
        // The RESOLVED name (the record whose key verified — #63 P-ID5) is
        // what flows downstream: allows lookup, `node:<name>` origin stamp,
        // autogate. The claimed header name is attribution only; when it
        // disagrees, the drift is audited and the resolved name still wins.
        SignedRequestOutcome::Verified { resolved, claimed } => {
            if let Some(detail) = attribution_drift_detail(&claimed, &resolved) {
                let _ = audit(audit_log, Door::A2a, EventClass::Audit, "a2a.signed-request", "attribution-drift", &detail);
            }
            Some(resolved)
        }
        SignedRequestOutcome::Refused(code, message) => {
            let body_val = jsonrpc_error_value(code, message.clone());
            let body = serde_json::to_vec(&body_val).unwrap_or_default();
            let _ = audit(
                audit_log,
                Door::A2a,
                EventClass::Audit,
                "a2a.signed-request",
                "unauthorized",
                &message,
            );
            return write_http_response(&mut writer, 200, &body);
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
            spawn_cwd,
            origin,
            &expected_token,
            req.bearer.as_deref(),
            signed_node_name.as_deref(),
        );
    }

    let (status, body, audit_cmd) = route(
        &req,
        bind,
        port,
        audit_log,
        spawn_agent,
        spawn_cwd,
        node_name,
        origin,
        &expected_token,
        registry,
        signed_node_name.as_deref(),
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
            spawn_cwd: "",
            origin: ConnOrigin::Loopback,
            node_name: "aoide",
            self_url: "http://127.0.0.1:8710/",
            expected_token: "",
            presented_token: None,
            signed_node_name: None,
        }
    }

    /// A minimal `Node` fixture (P-P3) — unpaired/unautogated/no-token by
    /// default, the same "mostly default, caller sets what it needs" shape
    /// `aoide_storage::node_store::tests::fixture_node` uses in its own
    /// crate; kept as a separate small copy here (this crate's tests build
    /// several ad hoc `Node { .. }` literals of their own already, and this
    /// one intentionally matches that local style rather than reaching for
    /// a cross-crate test helper that doesn't exist).
    fn fixture_node(name: &str, url: &str, autogate: bool) -> aoide_storage::node_store::Node {
        aoide_storage::node_store::Node {
            name: name.to_string(),
            url: url.to_string(),
            autogate,
            token_file: None,
            bearer_secret: None,
            hub: false,
            pubkey: None,
            verified: false,
            allows: Vec::new(),
            via: None,
            added_at: "2026-08-25T00:00:00Z".to_string(),
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
            internal: false,
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
            internal: false,
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

    // (b2) task #33 — the dead-session override, pure: dead=true -> `failed`
    // for every canonical state; dead=false is byte-identical to the plain
    // fold `task_state_mapping_matches_contracts_section_6` already pins.
    #[test]
    fn task_state_checked_dead_overrides_every_canonical_state_to_failed() {
        for (canonical, needs_sudo) in [
            ("working", false),
            ("stopped", false),
            ("awaiting", false),
            ("awaiting", true),
            ("idle", false),
            ("done", false),
        ] {
            assert_eq!(a2a_task_state_checked(true, canonical, needs_sudo), "failed");
        }
    }

    #[test]
    fn task_state_checked_alive_matches_the_plain_fold_exactly() {
        for (canonical, needs_sudo) in [
            ("working", false),
            ("stopped", false),
            ("awaiting", false),
            ("awaiting", true),
            ("idle", false),
            ("done", false),
        ] {
            assert_eq!(
                a2a_task_state_checked(false, canonical, needs_sudo),
                a2a_task_state(canonical, needs_sudo),
            );
        }
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
        // `send`'s own `not-conductable` rejection.
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

    // ── `session_ref_lookup` — `has_socket` is disk-derived (the identical
    // bug shape `e2758f7` fixed on the `graph` door,
    // `conduct::graph::doc::is_conductable_now`) ─────────────────────────────

    #[test]
    fn session_ref_lookup_has_socket_tracks_the_file_on_disk_without_touching_the_stored_record() {
        // `shellbridge.service` owns `$XDG_RUNTIME_DIR/aoide` with
        // `RuntimeDirectoryPreserve=no`, so a rebuild deletes a live
        // session's socket file without ever touching `sessions.json` — a
        // stored socket STRING can long outlive the file it names.
        // `has_socket` must track the file, not just non-emptiness.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = std::env::temp_dir().join(format!(
            "aoide-server-a2a-sessionref-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let socket = stage.join("session-a.sock");
        std::fs::write(&socket, b"").unwrap();

        let sf = SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![conductable_session("a", &socket)],
        };
        write_stage(&sessions_path(), &sf).unwrap();

        let sref = session_ref_lookup("a").unwrap();
        assert!(sref.conductable);
        assert!(sref.has_socket, "an existing socket file reports has_socket");

        // The socket vanishes (a rebuild tearing down the runtime dir) — the
        // ORIGINAL record is never touched; only the REPORTED value changes.
        std::fs::remove_file(&socket).unwrap();
        let sref2 = session_ref_lookup("a").unwrap();
        assert!(sref2.conductable, "conductable is untouched by the missing socket");
        assert!(!sref2.has_socket, "a removed socket file reports NOT has_socket");

        let after: SessionsFile = load_stage(&sessions_path()).unwrap();
        let rec = after.sessions.iter().find(|s| s.session_id == "a").unwrap();
        assert_eq!(rec.conductable, Some(true), "the stored flag is never modified by a read");
        assert_eq!(
            rec.socket,
            Some(socket.to_string_lossy().into_owned()),
            "the stored socket path is never cleared or migrated by a read"
        );

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
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

    /// P-P5b (`node spawn`): the exact body `handle_node_spawn`
    /// (`aoide-client::commands`) posts is
    /// `aoide_client::wire::build_message_send_body(text, id, None)` — this
    /// proves that shape routes all the way to `SendAction::Spawn`, carrying
    /// the client's prompt text verbatim as the argument `do_spawn` would
    /// type as the newly spawned session's first turn, against the SERVER's
    /// own `parse_message_send_params`/`decide_send_action`, not a guessed
    /// shape.
    #[test]
    fn build_message_send_body_routes_to_the_spawn_arm_exactly_as_do_spawn_expects() {
        let body = aoide_client::wire::build_message_send_body("status check please", "mid-456", None);
        let (prompt, ctx, spawn_asked) = parse_message_send_params(&body["params"]);
        assert_eq!(prompt, "status check please");
        assert_eq!(ctx, None, "no contextId — the Spawn signal `decide_send_action` reads");
        assert!(!spawn_asked, "spawn is signaled by the ABSENT contextId, not the metadata flag — `node spawn` never sets it");

        let action = decide_send_action(ctx.as_deref(), spawn_asked, "claude", session_ref_lookup);
        assert_eq!(
            action,
            SendAction::Spawn { agent_cmd: "claude".to_string() },
            "routes to Spawn with `do_spawn`'s prompt arg equal to `prompt` above (\"status check please\")"
        );
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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

    /// LANE IDENTITY P-ID0 (G16/G5): `stamp_spawn_origin` is the record-layer
    /// authority `do_spawn` now calls directly, rather than threading a
    /// `node:*` value through the child's own env — proven up to, but never
    /// through, `do_spawn`'s real process spawn, same documented boundary
    /// `node_spawn_signed_and_allowed_is_admitted_up_to_the_do_spawn_
    /// boundary` draws above: the record here is written directly (as
    /// `session_conduct`'s own registration would, once the child comes up),
    /// so the retry loop finds it on its very first poll.
    #[test]
    fn stamp_spawn_origin_lands_a_node_origin_on_an_already_registered_record() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = std::env::temp_dir().join(format!(
            "aoide-server-a2a-stamp-origin-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let sf = SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![fixture_session("a2a-spawned-1", "working", None)],
        };
        write_stage(&sessions_path(), &sf).unwrap();

        stamp_spawn_origin("a2a-spawned-1", "node:yomi-strix");

        let after: SessionsFile = load_stage(&sessions_path()).unwrap();
        let rec = after.sessions.iter().find(|s| s.session_id == "a2a-spawned-1").unwrap();
        assert_eq!(rec.origin.as_deref(), Some("node:yomi-strix"));

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn unknown_method_is_minus_32601() {
        let req = json!({ "jsonrpc": "2.0", "id": 2, "method": "bogus/method", "params": {} });
        let resp = handle_jsonrpc(&req, &test_ctx(Path::new("/dev/null"), ""));
        assert_eq!(resp["error"]["code"], -32601);
    }

    #[test]
    fn tasks_get_end_to_end_reads_the_stage_sessions_file() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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

    /// Task #33, end to end: a session whose recorded `pid` is
    /// guaranteed-absent — `999_999_999`, the same "no real process anywhere
    /// near this pid" fixture value `graph_residency_p_d6.rs`'s reap-over-
    /// the-socket test uses, since `/proc/999999999` does not exist on any
    /// Linux box — reads `failed` over `tasks/get`, not stale `submitted`/
    /// `working`. `state: "working"` (mid-turn) on purpose: `is_session_dead`'s
    /// `pid_signal` fires unconditionally off the real `/proc` probe,
    /// independent of state/staleness timers, so this is deterministic
    /// without a wall-clock wait or a live compositor.
    ///
    /// The inverse guard sits in the SAME test, against the SAME stage: a
    /// pid-less, windowless "hook-only" record (`fixture_session`'s default
    /// shape) must NOT read dead. `is_session_dead`'s other arms that could
    /// otherwise catch it — window-gone (no `windowAddress` to be gone),
    /// pre-boot-ghost and orphaned-subagent (both sweep-level checks outside
    /// `is_session_dead` itself, never consulted here) — are structurally
    /// out of reach; the one arm that IS in reach, `stale_abandoned`, cannot
    /// fire either, because `task_from_sessions` feeds `is_session_dead` a
    /// `last_seen` that always answers `None` on this read path (no hyprctl
    /// round trip, no reap-style evidence gathering) — and absence of
    /// evidence is never evidence of staleness (`is_session_dead`'s own
    /// "never-false-reap" guard).
    #[test]
    fn tasks_get_end_to_end_a_dead_pid_reads_failed_and_a_hook_only_record_does_not() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = std::env::temp_dir().join(format!(
            "aoide-server-a2a-dead-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let dead_pid_session = SessionRecord {
            session_id: "s-dead".to_string(),
            state: "working".to_string(),
            // No real process anywhere near this pid — see the doc comment.
            pid: Some(999_999_999),
            ..Default::default()
        };
        let sf = SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![
                dead_pid_session,
                fixture_session("s-hook-only", "idle", None),
            ],
        };
        write_stage(&sessions_path(), &sf).unwrap();

        let req = json!({ "jsonrpc": "2.0", "id": 9, "method": "tasks/get", "params": { "id": "s-dead" } });
        let resp = handle_jsonrpc(&req, &test_ctx(Path::new("/dev/null"), ""));
        assert_eq!(resp["result"]["status"]["state"], "failed");

        let req = json!({ "jsonrpc": "2.0", "id": 10, "method": "tasks/get", "params": { "id": "s-hook-only" } });
        let resp = handle_jsonrpc(&req, &test_ctx(Path::new("/dev/null"), ""));
        assert_eq!(
            resp["result"]["status"]["state"], "submitted",
            "a pid-less hook-only record must read its plain idle->submitted mapping, never failed"
        );

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    /// Phase G: the read commands (`tasks/get`, `aoide/graphSummary`) are
    /// token-gated by the same rule as spawn. When a token IS configured, an
    /// absent or wrong bearer is a clean `-32005` BEFORE the read runs; a
    /// valid bearer passes through to the normal handler.
    #[test]
    fn read_commands_are_token_gated_when_a_token_is_configured() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
            spawn_cwd: "",
            origin: ConnOrigin::Loopback,
            node_name: "aoide",
            self_url: "http://127.0.0.1:8710/",
            expected_token: "s3cr3t",
            presented_token: presented,
            signed_node_name: None,
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
    /// commands stay open exactly as before — the gate only bites when armed.
    #[test]
    fn read_commands_stay_open_when_no_token_is_configured() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let req = HttpRequest {
            method: "POST".to_string(),
            path: "/".to_string(),
            body,
            bearer: None,
            signed_node: None,
            signed_timestamp: None,
            signed_nonce: None,
            signed_signature: None,
        };

        let mut out: Vec<u8> = Vec::new();
        let result = stream_task(
            &mut out,
            &req,
            "tasks/resubscribe",
            Path::new("/dev/null"),
            "",
            "",
            ConnOrigin::Loopback,
            "s3cr3t",
            None,
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let req = HttpRequest {
            method: "POST".to_string(),
            path: "/".to_string(),
            body,
            bearer: None,
            signed_node: None,
            signed_timestamp: None,
            signed_nonce: None,
            signed_signature: None,
        };

        let audit_log = root.join("log");
        let mut out: Vec<u8> = Vec::new();
        let result = stream_task(
            &mut out,
            &req,
            "message/stream",
            &audit_log,
            "",
            "",
            ConnOrigin::Loopback,
            "s3cr3t",
            None,
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let req = HttpRequest {
            method: "POST".to_string(),
            path: "/".to_string(),
            body,
            bearer: None,
            signed_node: None,
            signed_timestamp: None,
            signed_nonce: None,
            signed_signature: None,
        };

        let mut out: Vec<u8> = Vec::new();
        let result = stream_task(
            &mut out,
            &req,
            "tasks/resubscribe",
            Path::new("/dev/null"),
            "",
            "",
            ConnOrigin::Loopback,
            "",
            None,
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
    // UNCONDITIONALLY, so any reachable node could inject text into any
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
        assert_eq!(classify_origin(Some("127.0.0.1".parse().unwrap())), ConnOrigin::Loopback);
        assert_eq!(classify_origin(Some("::1".parse().unwrap())), ConnOrigin::Loopback);
        assert_eq!(
            classify_origin(Some("10.0.0.5".parse().unwrap())),
            ConnOrigin::Remote("10.0.0.5".parse().unwrap())
        );
        assert_eq!(classify_origin(None), ConnOrigin::Unknown);
    }

    #[test]
    fn classify_origin_maps_cgnat_tailnet_and_lan_addresses_to_remote() {
        // Table test (M3, task #16): a Melete-triggered job dials in from a
        // real box's LAN or tailnet address, never loopback — this is the
        // shape `classify_origin` must fold to `Remote` so `should_deliver_now`
        // gates it, not the shape that (incorrectly) free-passes it. No
        // CIDR/tailnet special-casing exists or is added here: every one of
        // these is just "some non-loopback `Some(ip)`", the same arm
        // `10.0.0.5` already exercises above — this table only widens the
        // address SHAPES covered (CGNAT/tailnet 100.64.0.0/10, ordinary LAN),
        // it does not add a new code path.
        let cases: &[(&str, ConnOrigin)] = &[
            // sakaki's tailscale0 (100.82.117.51, brief's verified recon) —
            // CGNAT-range tailnet address.
            ("100.82.117.51", ConnOrigin::Remote("100.82.117.51".parse().unwrap())),
            // sakaki's LAN address (192.168.1.202, brief's verified recon).
            ("192.168.1.202", ConnOrigin::Remote("192.168.1.202".parse().unwrap())),
            // Loopback stays loopback regardless of address family —
            // unchanged by this table, restated here so the two families
            // sit side by side in one place.
            ("127.0.0.1", ConnOrigin::Loopback),
            ("::1", ConnOrigin::Loopback),
        ];
        for (addr, expected) in cases {
            let ip: IpAddr = addr.parse().unwrap();
            assert_eq!(classify_origin(Some(ip)), *expected, "address {addr}");
        }
    }

    #[test]
    fn should_deliver_now_covers_every_origin_autogate_combination() {
        // Loopback is unconditionally trusted — unchanged from before this
        // amendment, regardless of any autogate match.
        assert!(should_deliver_now(ConnOrigin::Loopback, false));
        assert!(should_deliver_now(ConnOrigin::Loopback, true));
        // A remote origin only delivers when it matched an autogate node.
        let remote = ConnOrigin::Remote("10.0.0.5".parse().unwrap());
        assert!(!should_deliver_now(remote, false));
        assert!(should_deliver_now(remote, true));
        // An unresolvable origin never delivers, even if (hypothetically) an
        // autogate match were somehow claimed for it — fail-safe.
        assert!(!should_deliver_now(ConnOrigin::Unknown, false));
        assert!(!should_deliver_now(ConnOrigin::Unknown, true));
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
            ConnOrigin::Loopback,
            ConnOrigin::Remote("10.0.0.5".parse().unwrap()),
            ConnOrigin::Unknown,
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
            effective_origin(ConnOrigin::Loopback, true, TokenState::Absent),
            ConnOrigin::Unknown
        );
        assert_eq!(
            effective_origin(ConnOrigin::Loopback, true, TokenState::Invalid),
            ConnOrigin::Unknown
        );
        // A VALID token restores loopback's original standing exactly.
        assert_eq!(
            effective_origin(ConnOrigin::Loopback, true, TokenState::Valid),
            ConnOrigin::Loopback
        );
        // A remote origin without a valid token is ALSO coerced — it was
        // already untrusted by default, but this proves the coercion isn't
        // loopback-specific plumbing that happens to skip Remote.
        assert_eq!(
            effective_origin(ConnOrigin::Remote("10.0.0.5".parse().unwrap()), true, TokenState::Absent),
            ConnOrigin::Unknown
        );
    }

    #[test]
    fn origin_for_inject_is_the_identity_function_when_unsigned() {
        // The untouched, pre-P-S6 path: no signature headers on the request
        // at all, so `origin` passes through byte-identical — the hard
        // "loopback is unchanged for local callers" regression pin holds by
        // construction here, same as `effective_origin`'s own off-path.
        for origin in [ConnOrigin::Loopback, ConnOrigin::Remote("10.0.0.5".parse().unwrap()), ConnOrigin::Unknown] {
            assert_eq!(origin_for_inject(origin, false), origin);
        }
    }

    #[test]
    fn origin_for_inject_downgrades_loopback_once_the_request_is_signed() {
        // The P-S6 narrowing itself: a verified per-request signature is by
        // construction a REMOTE node (an ssh tunnel makes it LOOK loopback
        // to `peer_addr()`), so it loses Loopback's free pass — coerced to
        // `Unknown`, `should_deliver_now`'s existing fail-safe arm, not a
        // fourth `ConnOrigin` kind.
        assert_eq!(origin_for_inject(ConnOrigin::Loopback, true), ConnOrigin::Unknown);
        // A signed request was never trusted by origin anyway for these two
        // — proving the downgrade is total, not loopback-specific plumbing
        // that happens to skip the others.
        assert_eq!(
            origin_for_inject(ConnOrigin::Remote("10.0.0.5".parse().unwrap()), true),
            ConnOrigin::Unknown
        );
        assert_eq!(origin_for_inject(ConnOrigin::Unknown, true), ConnOrigin::Unknown);
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
        // still fully gates spawn, and the read commands stay open, when no
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
    fn message_send_spawn_rejects_an_unpaired_caller_with_the_p_p3_taught_error() {
        // No contextId → the Spawn arm — spawn_agent is non-empty so
        // `decide_send_action` resolves to Spawn, and the P-P3 gate must
        // reject it BEFORE `do_spawn` ever runs (so this never actually
        // spawns a process — the house rule every other error-branch test in
        // this suite already follows). No node is registered at all, so
        // NEITHER the old door-wide-token gate NOR the new pairing gate can
        // possibly pass — -32006, not the old -32005.
        let params = json!({
            "message": { "parts": [{ "kind": "text", "text": "hi" }] }
        });
        let err = message_send(
            &params,
            Path::new("/dev/null"),
            "claude",
            "",
            ConnOrigin::Loopback,
            "expected-secret",
            None, None
        )
        .unwrap_err();
        assert_eq!(err.0, -32006);

        let err2 = message_send(
            &params,
            Path::new("/dev/null"),
            "claude",
            "",
            ConnOrigin::Loopback,
            "expected-secret",
            Some("wrong-secret"), None
        )
        .unwrap_err();
        assert_eq!(err2.0, -32006);
    }

    // ── Spawn liveness check (task #103) ──────────────────────────────────
    //
    // `poll_bounded_exit` and `spawn_died_immediately_message` are the pure
    // halves of `do_spawn`'s bounded liveness check, factored out exactly so
    // they're testable without a real spawn — same "never through `do_spawn`
    // itself" precedent the table below states for the gate predicates.

    #[test]
    fn poll_bounded_exit_returns_the_status_the_moment_try_wait_reports_one() {
        use std::os::unix::process::ExitStatusExt;
        let mut calls = 0u32;
        let status = poll_bounded_exit(
            || {
                calls += 1;
                if calls == 3 {
                    Ok(Some(std::process::ExitStatus::from_raw(1 << 8))) // exit code 1
                } else {
                    Ok(None)
                }
            },
            10,
            Duration::ZERO,
        );
        assert_eq!(status.and_then(|s| s.code()), Some(1));
        assert_eq!(calls, 3, "must stop polling the instant an exit is reported");
    }

    #[test]
    fn poll_bounded_exit_gives_up_after_the_full_budget_with_the_child_still_alive() {
        let mut calls = 0u32;
        let status = poll_bounded_exit(
            || {
                calls += 1;
                Ok(None)
            },
            5,
            Duration::ZERO,
        );
        assert_eq!(status, None, "still alive past the budget — never a false failure");
        assert_eq!(calls, 5, "the full attempt budget must be spent, no early giving-up");
    }

    #[test]
    fn spawn_died_immediately_message_names_the_program_never_the_full_command_line() {
        use std::os::unix::process::ExitStatusExt;
        let status = std::process::ExitStatus::from_raw(1 << 8); // exit code 1
        let msg = spawn_died_immediately_message("claude --dangerously-skip-permissions", status);
        assert!(msg.contains("`claude`"), "names the configured binary: {msg}");
        assert!(
            !msg.contains("--dangerously-skip-permissions"),
            "never echoes flag values back — taught, not a raw command dump: {msg}"
        );
        assert!(!msg.contains("PATH="), "no env leakage");
    }

    // ── S-B: spawn env sanitize + bounded spawn cwd ──────────────────────────
    //
    // `spawn_child_command` and `resolve_bounded_spawn_cwd` are `do_spawn`'s
    // own pure-ish halves, factored out exactly so they're testable without a
    // real OS-level spawn — same "never through `do_spawn` itself" precedent
    // `spawn_inject_prompts_success_branch_files_the_opening_turn_into_the_
    // mailbase`'s doc comment states for `current_exe()` resolving to the
    // TEST binary under `cargo test`.

    #[test]
    fn a2a_spawn_clears_the_daemons_own_session_id_from_the_child() {
        // The Osaka wrong-ancestry bug: the `aoide-a2a` unit's own
        // environment can carry the operator's live `AOIDE_SESSION_ID`
        // (inherited from whatever terminal the unit itself descends from),
        // and a spawned child must never see it. First proven via
        // `Command::get_envs()` (stable since Rust 1.57): it enumerates only
        // the EXPLICIT `.env()`/`.env_remove()` calls a `Command` carries — a
        // removed var reports `Some(None)`, and a var the `Command` never
        // mentions is simply ABSENT from the map, meaning ordinary fork/exec
        // inheritance still applies to it. Then proven for real: with a
        // sibling var and a synthetic session id actually set in THIS
        // process's own environment, the child is actually spawned (stdio
        // re-piped over `spawn_child_command`'s null default — `Command`'s
        // builder setters are last-call-wins, so re-configuring after the
        // fact is safe) and its own stdout is read back, showing the sibling
        // var passed through by ordinary inheritance while
        // `AOIDE_SESSION_ID` did not — the removal targets
        // `AOIDE_SESSION_ORIGIN`/`AOIDE_SESSION_ID` by name, nothing else.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_sibling = std::env::var("AOIDE_A2A_SIBLING_TEST_VAR").ok();
        let saved_session_id = std::env::var("AOIDE_SESSION_ID").ok();
        std::env::set_var("AOIDE_A2A_SIBLING_TEST_VAR", "sibling-ok");
        std::env::set_var("AOIDE_SESSION_ID", "a2a-test-synthetic-session-id");

        let mut cmd = spawn_child_command(
            Path::new("/bin/sh"),
            &[
                "-c".to_string(),
                "printf '%s|%s' \"$AOIDE_A2A_SIBLING_TEST_VAR\" \"${AOIDE_SESSION_ID:-unset}\""
                    .to_string(),
            ],
            Path::new("/tmp/aoide-a2a-test-audit-does-not-need-to-exist.log"),
            None,
        );
        let envs: std::collections::HashMap<&std::ffi::OsStr, Option<&std::ffi::OsStr>> =
            cmd.get_envs().collect();
        assert_eq!(
            envs.get(std::ffi::OsStr::new("AOIDE_SESSION_ID")),
            Some(&None),
            "AOIDE_SESSION_ID must be explicitly removed from the child, not merely absent: {envs:?}"
        );
        assert_eq!(
            envs.get(std::ffi::OsStr::new("AOIDE_SESSION_ORIGIN")),
            Some(&None),
            "the pre-existing AOIDE_SESSION_ORIGIN removal must still be present, unreplaced: {envs:?}"
        );

        let output = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("spawning /bin/sh must succeed in the test sandbox");
        assert!(
            output.status.success(),
            "the child must exit cleanly: {output:?}"
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "sibling-ok|unset",
            "the sibling var passes through untouched and AOIDE_SESSION_ID is gone, proven by \
             an actually spawned child reading its own environment back — not just the \
             Command's builder state"
        );

        match saved_sibling {
            Some(v) => std::env::set_var("AOIDE_A2A_SIBLING_TEST_VAR", v),
            None => std::env::remove_var("AOIDE_A2A_SIBLING_TEST_VAR"),
        }
        match saved_session_id {
            Some(v) => std::env::set_var("AOIDE_SESSION_ID", v),
            None => std::env::remove_var("AOIDE_SESSION_ID"),
        }
    }

    #[test]
    fn a2a_spawn_uses_a_registered_project_root_as_the_child_cwd() {
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-spawncwd-ok-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let root_str = root.to_string_lossy().into_owned();
        let projects = vec![Project {
            name: "aoide".into(),
            path: root_str.clone(),
            ..Default::default()
        }];
        let audit_log = root.join("audit.log");

        let resolved = resolve_bounded_spawn_cwd(&root_str, &projects, &audit_log);
        assert_eq!(
            resolved,
            Some(root_str),
            "a byte-identical registered, existing root is accepted"
        );
        assert!(
            std::fs::read_to_string(&audit_log)
                .unwrap_or_default()
                .is_empty(),
            "the accept path never audits — only the reject path does"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a2a_spawn_ignores_an_unregistered_spawn_cwd_and_audits_it() {
        let registered_root = std::env::temp_dir().join(format!(
            "aoide-a2a-spawncwd-registered-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let unregistered_dir = std::env::temp_dir().join(format!(
            "aoide-a2a-spawncwd-unregistered-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&registered_root).unwrap();
        std::fs::create_dir_all(&unregistered_dir).unwrap();
        let projects = vec![Project {
            name: "aoide".into(),
            path: registered_root.to_string_lossy().into_owned(),
            ..Default::default()
        }];
        let audit_log = registered_root.join("audit.log");

        let unregistered_str = unregistered_dir.to_string_lossy().into_owned();
        let resolved = resolve_bounded_spawn_cwd(&unregistered_str, &projects, &audit_log);
        assert_eq!(
            resolved, None,
            "a real, existing directory that is simply not a registered root is still refused"
        );

        let log = std::fs::read_to_string(&audit_log).unwrap_or_default();
        assert!(
            log.contains("\"door\":\"a2a\""),
            "audited through Door::A2a: {log}"
        );
        assert!(
            log.contains("\"status\":\"skipped\""),
            "the reject path audits exactly once, as \"skipped\": {log}"
        );
        assert!(
            log.contains(&unregistered_str),
            "names the rejected path, never silently: {log}"
        );

        let _ = std::fs::remove_dir_all(&registered_root);
        let _ = std::fs::remove_dir_all(&unregistered_dir);
    }

    // ── Spawn gate table (P-P3, PAIRING.md decision 6) ───────────────────────
    //
    // `node_may_spawn` (the pure predicate) covers paired+allowed / paired+
    // denied / unpaired, and `spawn_admitted` (the full check, folding in
    // WHICH rung resolved the caller) covers token-rung-admitted /
    // addr-rung-refused, both directly against fixtures — never through
    // `message_send`/`do_spawn`, which would actually launch a process (see
    // `spawn_inject_prompts_success_branch_files_the_opening_turn_into_the_mailbase`'s
    // own doc comment on why no test in this file drives `do_spawn`'s real
    // OS-level spawn). The integration tests below drive `message_send`
    // itself for the REFUSAL branches, which never reach `do_spawn` at all.

    #[test]
    fn node_may_spawn_covers_paired_allowed_paired_denied_and_unpaired() {
        let mut paired_allowed = fixture_node("box-b", "http://10.0.0.5:8710/", false);
        paired_allowed.verified = true;
        paired_allowed.allows = vec!["read".to_string(), "spawn".to_string()];
        assert!(node_may_spawn(&paired_allowed), "paired + spawn in allows");

        let mut paired_denied = paired_allowed.clone();
        paired_denied.allows = vec!["read".to_string()]; // spawn revoked.
        assert!(!node_may_spawn(&paired_denied), "paired but spawn NOT in allows");

        let mut unpaired = paired_allowed.clone();
        unpaired.verified = false; // never completed the ceremony.
        assert!(!node_may_spawn(&unpaired), "allows populated but never verified — still refused");
    }

    #[test]
    fn spawn_admitted_requires_the_signature_rung_specifically() {
        // P-P4's narrowing (superseding the 2026-08-25/P-P3 narrowing this
        // test used to pin): `node_may_spawn` alone says nothing about HOW
        // the caller resolved to this node — `spawn_admitted` is the full
        // check, and it must refuse the SAME paired+allowed node whenever
        // anything less than a verified per-request SIGNATURE resolved it,
        // including the Token rung that P-P3 itself admitted. Proven at the
        // predicate/wiring level directly against `(Node, NodeRung)`
        // fixtures, the same "never through `message_send`/`do_spawn`"
        // precedent this suite already holds for the positive case.
        let mut paired_allowed = fixture_node("box-b", "http://10.0.0.5:8710/", false);
        paired_allowed.verified = true;
        paired_allowed.allows = vec!["read".to_string(), "spawn".to_string()];

        assert!(
            spawn_admitted(Some((&paired_allowed, aoide_storage::node_store::NodeRung::Signature))),
            "paired + spawn in allows + resolved via a VERIFIED SIGNATURE — admitted"
        );
        assert!(
            !spawn_admitted(Some((&paired_allowed, aoide_storage::node_store::NodeRung::Token))),
            "the SAME paired+allowed node, resolved only via its bare token — refused as of P-P4: \
             a shared secret is no longer sufficient, only a per-request signature is"
        );
        assert!(
            !spawn_admitted(Some((&paired_allowed, aoide_storage::node_store::NodeRung::Addr))),
            "the SAME paired+allowed node, resolved only by address — refused: address alone never admits spawn"
        );
        assert!(!spawn_admitted(None), "no resolution at all — refused");
    }

    #[test]
    fn spawn_refusal_names_the_right_reason_for_each_shape() {
        // P-P4: the taught error MESSAGE (not just the code, still `-32006`
        // uniformly) now distinguishes "paired but unsigned" from "never
        // paired" from "signed but not allowed" — the brief's own
        // requirement ("a taught error telling an unsigned paired caller
        // that its aoide is too old / must sign").
        use aoide_storage::node_store::NodeRung;
        let mut paired_allowed = fixture_node("box-b", "http://10.0.0.5:8710/", false);
        paired_allowed.verified = true;
        paired_allowed.allows = vec!["spawn".to_string()];

        let (code, msg) = spawn_refusal(Some((&paired_allowed, NodeRung::Token)));
        assert_eq!(code, -32006);
        assert!(msg.contains("was not signed"), "Token-rung-but-verified must name signing specifically: {msg:?}");

        let mut paired_denied = paired_allowed.clone();
        paired_denied.allows = vec!["read".to_string()];
        let (code, msg) = spawn_refusal(Some((&paired_denied, NodeRung::Signature)));
        assert_eq!(code, -32006);
        assert!(msg.contains("node allow"), "Signature-rung-but-not-allowed must name the `node allow` fix: {msg:?}");

        let (code, msg) = spawn_refusal(None);
        assert_eq!(code, -32006);
        assert!(msg.contains("aoide pair"), "no resolution at all must point at the pairing ceremony: {msg:?}");

        let mut unverified = fixture_node("box-c", "http://10.0.0.6:8710/", false);
        unverified.allows = vec!["spawn".to_string()]; // allows populated but never actually paired.
        let (code, msg) = spawn_refusal(Some((&unverified, NodeRung::Token)));
        assert_eq!(code, -32006);
        assert!(
            msg.contains("aoide pair"),
            "Token rung but NOT verified is the generic 'never paired' message, not the 'must sign' one: {msg:?}"
        );
    }

    // ── P-P4: `verify_signed_request` (docs/architecture/PAIRING.md's
    // "Wire authentication (paired nodes)" section) ─────────────────────────

    /// Register `node_name` as a VERIFIED node holding THIS test process's
    /// own P-P1 identity's pubkey, and return that keypair to sign with.
    /// A test-only shortcut: in production a node's stored pubkey is always
    /// the OTHER instance's, never this process's own, but a single-process
    /// test has no second identity to mint — signing "as itself" and
    /// registering itself as its own trusted node exercises the
    /// canonical-string/verify plumbing in isolation with no second process
    /// involved, exactly the same "one process plays both roles" shortcut
    /// `identity.rs`'s own sign/verify round-trip test already takes.
    fn setup_signed_node(node_name: &str) -> aoide_storage::identity::Keypair {
        let (kp, _) = aoide_storage::identity::load_or_mint().unwrap();
        let mut node = fixture_node(node_name, "http://node/", false);
        node.verified = true;
        node.pubkey = Some(kp.info().pubkey_hex);
        aoide_storage::node_store::save_nodes(&[node]).unwrap();
        kp
    }

    /// [`setup_signed_node`]'s sibling with a controllable `allows` set —
    /// P-P5b's own admission/revocation round-trip tests need a genuinely
    /// paired+verified node whose `allows` they choose, not the empty
    /// default `setup_signed_node` stamps.
    fn setup_signed_node_with_allows(node_name: &str, allows: &[&str]) -> aoide_storage::identity::Keypair {
        let (kp, _) = aoide_storage::identity::load_or_mint().unwrap();
        let mut node = fixture_node(node_name, "http://node/", false);
        node.verified = true;
        node.pubkey = Some(kp.info().pubkey_hex);
        node.allows = allows.iter().map(|s| s.to_string()).collect();
        aoide_storage::node_store::save_nodes(&[node]).unwrap();
        kp
    }

    /// Build a signed [`HttpRequest`] for `path`/`body`, timestamped
    /// `ts_epoch` seconds since epoch, nonce `nonce` — the test-side mirror
    /// of `aoide-client`'s real wire builder, built directly against
    /// `aoide_storage::wire_auth` rather than through a real curl call.
    fn signed_request(kp: &aoide_storage::identity::Keypair, node_name: &str, path: &str, body: &[u8], ts_epoch: i64, nonce: &str) -> HttpRequest {
        let timestamp = aoide_storage::time::iso_utc_from_epoch(ts_epoch);
        let canonical = aoide_storage::wire_auth::canonical_string("POST", path, &timestamp, nonce, body);
        let signature = aoide_storage::wire_auth::sign_hex(kp, canonical.as_bytes());
        HttpRequest {
            method: "POST".to_string(),
            path: path.to_string(),
            body: body.to_vec(),
            bearer: None,
            signed_node: Some(node_name.to_string()),
            signed_timestamp: Some(timestamp),
            signed_nonce: Some(nonce.to_string()),
            signed_signature: Some(signature),
        }
    }

    /// A unique nonce per test call — `NONCE_CACHE` is a single process-wide
    /// static shared across every test in this binary (module doc), so two
    /// tests reusing the same literal nonce string could spuriously see
    /// each other's entries; a wall-clock-derived suffix keeps every test's
    /// nonces disjoint, the same "derive a unique string from pid+nanos"
    /// idiom this file's temp-dir helpers already use.
    fn unique_nonce(tag: &str) -> String {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        format!("{tag}-{}-{nanos}", std::process::id())
    }

    #[test]
    fn verify_signed_request_with_no_headers_at_all_is_unsigned() {
        let req = HttpRequest {
            method: "POST".into(),
            path: "/".into(),
            body: b"{}".to_vec(),
            bearer: None,
            signed_node: None,
            signed_timestamp: None,
            signed_nonce: None,
            signed_signature: None,
        };
        assert_eq!(
            verify_signed_request(&req, 0),
            SignedRequestOutcome::Unsigned,
            "no signature headers at all — the untouched, pre-P-P4 path"
        );
    }

    #[test]
    fn verify_signed_request_refuses_incomplete_headers_without_touching_the_node_registry() {
        // Claims a node (the `X-Aoide-Node` header present) but is missing
        // the other three — refused OUTRIGHT, never treated as "unsigned"
        // (the brief's "unsigned-but-claiming-paired refusal" case).
        let req = HttpRequest {
            method: "POST".into(),
            path: "/".into(),
            body: b"{}".to_vec(),
            bearer: None,
            signed_node: Some("box-b".to_string()),
            signed_timestamp: None,
            signed_nonce: None,
            signed_signature: None,
        };
        match verify_signed_request(&req, 0) {
            SignedRequestOutcome::Refused(code, msg) => {
                assert_eq!(code, -32007);
                assert!(msg.contains("must all be present together"));
            }
            other => panic!("expected Refused, got {other:?}"),
        }
    }

    #[test]
    fn verify_signed_request_round_trips_a_genuine_signature() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-verify-sig-ok-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::env::set_var("AOIDE_STATE_DIR", &root);

        let kp = setup_signed_node("box-b");
        let now = 1_800_000_000_i64;
        let req = signed_request(&kp, "box-b", "/", b"{\"a\":1}", now, &unique_nonce("ok"));
        assert_eq!(
            verify_signed_request(&req, now),
            SignedRequestOutcome::Verified {
                resolved: "box-b".to_string(),
                claimed: "box-b".to_string()
            }
        );

        let _ = std::fs::remove_dir_all(&root);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    #[test]
    fn an_unknown_or_unverified_signer_is_refused_identically_to_a_bad_signature() {
        // #63 P-ID5's no-existence-oracle pin: a signature matching NO
        // verified node's stored key (empty registry, or a node registered
        // but never verified) refuses with the EXACT code+message a merely
        // tampered/bad signature earns — an outsider can never distinguish
        // "your key isn't registered here" from "your signature is wrong".
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-verify-sig-unknown-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::env::set_var("AOIDE_STATE_DIR", &root);

        let (kp, _) = aoide_storage::identity::load_or_mint().unwrap();
        let now = 1_800_000_000_i64;

        // Unknown key: nothing registered at all — the claimed name resolves
        // nothing because names resolve nothing; no stored key verifies.
        let req = signed_request(&kp, "nobody", "/", b"{}", now, &unique_nonce("unknown"));
        let unknown_key_refusal = match verify_signed_request(&req, now) {
            SignedRequestOutcome::Refused(code, msg) => {
                assert_eq!(code, -32007);
                (code, msg)
            }
            other => panic!("expected Refused, got {other:?}"),
        };

        // Registered, correct pubkey, but never actually paired
        // (`verified: false`) — its key never enters the trial set.
        let mut unverified_node = fixture_node("box-c", "http://node/", false);
        unverified_node.pubkey = Some(kp.info().pubkey_hex);
        aoide_storage::node_store::save_nodes(&[unverified_node]).unwrap();
        let req2 = signed_request(&kp, "box-c", "/", b"{}", now, &unique_nonce("unverified"));
        let unverified_refusal = match verify_signed_request(&req2, now) {
            SignedRequestOutcome::Refused(code, msg) => (code, msg),
            other => panic!("expected Refused, got {other:?}"),
        };

        // A genuinely VERIFIED node, but a tampered body — the plain
        // bad-signature refusal every case above must be indistinguishable
        // from.
        let mut verified_node = fixture_node("box-c", "http://node/", false);
        verified_node.verified = true;
        verified_node.pubkey = Some(kp.info().pubkey_hex);
        aoide_storage::node_store::save_nodes(&[verified_node]).unwrap();
        let mut req3 = signed_request(&kp, "box-c", "/", b"{\"real\":true}", now, &unique_nonce("bad-sig"));
        req3.body = b"{\"real\":false}".to_vec();
        let bad_sig_refusal = match verify_signed_request(&req3, now) {
            SignedRequestOutcome::Refused(code, msg) => (code, msg),
            other => panic!("expected Refused, got {other:?}"),
        };

        assert_eq!(unknown_key_refusal, bad_sig_refusal, "unknown key vs bad signature must be indistinguishable");
        assert_eq!(unverified_refusal, bad_sig_refusal, "unverified node's key vs bad signature must be indistinguishable");

        let _ = std::fs::remove_dir_all(&root);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    #[test]
    fn verify_signed_request_refuses_a_tampered_body_or_path() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-verify-sig-tamper-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::env::set_var("AOIDE_STATE_DIR", &root);

        let kp = setup_signed_node("box-b");
        let now = 1_800_000_000_i64;

        // Signed over one body; the ARRIVING body is different — the digest
        // (and so the canonical string, and so the signature) no longer
        // matches.
        let mut req = signed_request(&kp, "box-b", "/", b"{\"real\":true}", now, &unique_nonce("tamper-body"));
        req.body = b"{\"real\":false}".to_vec();
        match verify_signed_request(&req, now) {
            SignedRequestOutcome::Refused(code, msg) => {
                assert_eq!(code, -32007);
                assert!(msg.contains("signature verification failed"));
            }
            other => panic!("a tampered body must refuse, got {other:?}"),
        }

        // Signed for path "/"; the ARRIVING request line names a different
        // path — same signature, different canonical string.
        let mut req2 = signed_request(&kp, "box-b", "/", b"{}", now, &unique_nonce("tamper-path"));
        req2.path = "/other".to_string();
        match verify_signed_request(&req2, now) {
            SignedRequestOutcome::Refused(code, _) => assert_eq!(code, -32007),
            other => panic!("a tampered path must refuse, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&root);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    #[test]
    fn verify_signed_request_refuses_clock_skew_beyond_the_window_naming_both_timestamps() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-verify-sig-skew-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::env::set_var("AOIDE_STATE_DIR", &root);

        let kp = setup_signed_node("box-b");
        let signed_at = 1_800_000_000_i64;
        // The verifier's own "now" is 10 minutes later — well past the
        // ±120s default window.
        let verifier_now = signed_at + 600;
        let req = signed_request(&kp, "box-b", "/", b"{}", signed_at, &unique_nonce("skew"));
        match verify_signed_request(&req, verifier_now) {
            SignedRequestOutcome::Refused(code, msg) => {
                assert_eq!(code, -32008);
                assert!(msg.contains(&aoide_storage::time::iso_utc_from_epoch(signed_at)), "must name the request's OWN timestamp: {msg:?}");
                assert!(
                    msg.contains(&aoide_storage::time::iso_utc_from_epoch(verifier_now)),
                    "must name the verifier's OWN now too (both timestamps): {msg:?}"
                );
            }
            other => panic!("expected Refused, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&root);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    #[test]
    fn verify_signed_request_refuses_a_replayed_nonce_inside_the_window() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-verify-sig-replay-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::env::set_var("AOIDE_STATE_DIR", &root);

        let kp = setup_signed_node("box-b");
        let now = 1_800_000_000_i64;
        let nonce = unique_nonce("replay");
        let req = signed_request(&kp, "box-b", "/", b"{}", now, &nonce);

        assert_eq!(
            verify_signed_request(&req, now),
            SignedRequestOutcome::Verified {
                resolved: "box-b".to_string(),
                claimed: "box-b".to_string()
            },
            "the FIRST use of this nonce must verify"
        );

        // The EXACT same request, replayed — same nonce, still inside the
        // window — must now refuse, even though the signature itself is
        // still perfectly valid.
        match verify_signed_request(&req, now) {
            SignedRequestOutcome::Refused(code, msg) => {
                assert_eq!(code, -32009);
                assert!(msg.contains("replay"));
            }
            other => panic!("a replayed nonce must refuse on its SECOND use, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&root);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    #[test]
    fn a_signature_resolves_the_node_whose_key_signed_even_when_the_name_header_claims_another() {
        // #63 P-ID5's core inversion: `box-a` holds the signing key, the
        // wire claims `box-b` (a different, genuinely registered node) —
        // resolution follows the KEY, the claimed name survives only as
        // attribution, and the mismatch produces a drift audit line.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-verify-by-key-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::env::set_var("AOIDE_STATE_DIR", &root);

        let (kp, _) = aoide_storage::identity::load_or_mint().unwrap();
        let mut box_a = fixture_node("box-a", "http://node-a/", false);
        box_a.verified = true;
        box_a.pubkey = Some(kp.info().pubkey_hex);
        let mut box_b = fixture_node("box-b", "http://node-b/", false);
        box_b.verified = true;
        // Well-formed but unrelated key material — never verifies anything.
        box_b.pubkey = Some("aa".repeat(32));
        aoide_storage::node_store::save_nodes(&[box_a, box_b]).unwrap();

        let now = 1_800_000_000_i64;
        let req = signed_request(&kp, "box-b", "/", b"{}", now, &unique_nonce("by-key"));
        match verify_signed_request(&req, now) {
            SignedRequestOutcome::Verified { resolved, claimed } => {
                assert_eq!(resolved, "box-a", "the record whose stored key verifies IS the caller");
                assert_eq!(claimed, "box-b", "the wire's claim rides along for attribution");
                let detail = attribution_drift_detail(&claimed, &resolved).expect("a claimed-vs-resolved mismatch must produce a drift audit line");
                assert!(detail.contains("box-a") && detail.contains("box-b"), "the drift line names both: {detail:?}");
            }
            other => panic!("expected Verified resolving box-a, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&root);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    #[test]
    fn a_locally_renamed_node_still_authenticates_by_its_key() {
        // The defect that motivated this phase (PAIRING.md's former
        // known-limitation note): the operator renamed the record, the far
        // end still claims its old self name — the key hasn't changed, so
        // authentication must not break.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-verify-renamed-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::env::set_var("AOIDE_STATE_DIR", &root);

        let kp = setup_signed_node("renamed-node");
        let now = 1_800_000_000_i64;
        // The wire still claims the name from before the local rename —
        // registered nowhere.
        let req = signed_request(&kp, "old-name", "/", b"{}", now, &unique_nonce("renamed"));
        match verify_signed_request(&req, now) {
            SignedRequestOutcome::Verified { resolved, claimed } => {
                assert_eq!(resolved, "renamed-node");
                assert_eq!(claimed, "old-name");
            }
            other => panic!("a renamed node's signature must still resolve it, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&root);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    #[test]
    fn shared_key_records_take_the_exact_name_tiebreak_or_refuse_ambiguous() {
        // Collision semantics (#63 P-ID5, pinned in CONTRACTS §6): two
        // verified records CAN share a pubkey (`upsert_paired_node` matches
        // by name only — the same remote instance paired under two names).
        // Both hold the same PROVEN key, so the claimed name may pick among
        // them (equal security, possibly different allows/autogate); with no
        // exact-name match, refusing beats guessing which grants apply.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-verify-shared-key-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::env::set_var("AOIDE_STATE_DIR", &root);

        let (kp, _) = aoide_storage::identity::load_or_mint().unwrap();
        let pubkey = kp.info().pubkey_hex;
        let mut twin_a = fixture_node("twin-a", "http://node-a/", false);
        twin_a.verified = true;
        twin_a.pubkey = Some(pubkey.clone());
        let mut twin_b = fixture_node("twin-b", "http://node-b/", false);
        twin_b.verified = true;
        twin_b.pubkey = Some(pubkey);
        aoide_storage::node_store::save_nodes(&[twin_a, twin_b]).unwrap();

        let now = 1_800_000_000_i64;
        // Claimed name matches one twin exactly — that one wins.
        let req = signed_request(&kp, "twin-b", "/", b"{}", now, &unique_nonce("twin-exact"));
        match verify_signed_request(&req, now) {
            SignedRequestOutcome::Verified { resolved, claimed } => {
                assert_eq!(resolved, "twin-b");
                assert_eq!(claimed, "twin-b");
            }
            other => panic!("an exact-name match among shared-key records must resolve it, got {other:?}"),
        }

        // Claimed name matches neither — refused as ambiguous, taught.
        let req2 = signed_request(&kp, "twin-c", "/", b"{}", now, &unique_nonce("twin-none"));
        match verify_signed_request(&req2, now) {
            SignedRequestOutcome::Refused(code, msg) => {
                assert_eq!(code, -32007);
                assert!(msg.contains("ambiguous"), "must refuse as ambiguous, never pick a record arbitrarily: {msg:?}");
            }
            other => panic!("shared-key records with no exact-name match must refuse, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&root);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    #[test]
    fn a_nonce_replay_is_caught_across_shared_key_records() {
        // The nonce cache keys on the verifying PUBKEY, not any name
        // (`NONCE_CACHE`'s doc): `X-Aoide-Node` is outside the canonical
        // string, so a captured request replayed under a shared-key twin's
        // name still lands on the same cache key and refuses.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-verify-twin-replay-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::env::set_var("AOIDE_STATE_DIR", &root);

        let (kp, _) = aoide_storage::identity::load_or_mint().unwrap();
        let pubkey = kp.info().pubkey_hex;
        let mut twin_a = fixture_node("twin-a", "http://node-a/", false);
        twin_a.verified = true;
        twin_a.pubkey = Some(pubkey.clone());
        let mut twin_b = fixture_node("twin-b", "http://node-b/", false);
        twin_b.verified = true;
        twin_b.pubkey = Some(pubkey);
        aoide_storage::node_store::save_nodes(&[twin_a, twin_b]).unwrap();

        let now = 1_800_000_000_i64;
        let nonce = unique_nonce("twin-replay");
        let req = signed_request(&kp, "twin-a", "/", b"{}", now, &nonce);
        assert!(
            matches!(verify_signed_request(&req, now), SignedRequestOutcome::Verified { .. }),
            "first use must verify"
        );

        // The same request re-sent claiming the twin: the name header is
        // OUTSIDE the canonical string, so the identical method/path/
        // timestamp/nonce/body yields the byte-identical (deterministic
        // ed25519) signature — exactly what a captured-and-relabeled replay
        // carries. Same key, same nonce: still a replay.
        let replayed = signed_request(&kp, "twin-b", "/", b"{}", now, &nonce);
        match verify_signed_request(&replayed, now) {
            SignedRequestOutcome::Refused(code, _) => assert_eq!(code, -32009),
            other => panic!("a replay under the twin's name must still be caught, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&root);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    #[test]
    fn attribution_drift_detail_fires_only_on_a_mismatch_and_names_both() {
        assert_eq!(attribution_drift_detail("box-a", "box-a"), None, "agreement logs nothing");
        let detail = attribution_drift_detail("claimed-name", "resolved-name").expect("a mismatch must produce the audit detail");
        assert!(detail.contains("claimed-name") && detail.contains("resolved-name"), "both names in the line: {detail:?}");
        assert!(detail.contains("X-Aoide-Node"), "names the header the claim rode in on: {detail:?}");
    }

    #[test]
    fn nonce_is_replay_is_capped_and_evicts_the_oldest_entry_fifo() {
        // A tiny, direct pin on the cache primitive itself (module doc,
        // `NONCE_CACHE_CAP`) — proves the FIFO eviction shape without
        // driving `NONCE_CACHE_CAP` (4096) real entries through the full
        // `verify_signed_request` flow. Uses its own uniquely-tagged node
        // namespace so it can never collide with any OTHER test's entries
        // in the same process-wide static cache.
        let tag = unique_nonce("cap-probe-node");
        assert!(!nonce_is_replay(&tag, "n1"), "first use of a fresh (node, nonce) pair is never a replay");
        assert!(nonce_is_replay(&tag, "n1"), "the SAME pair, reused, is a replay");
        assert!(!nonce_is_replay(&tag, "n2"), "a DIFFERENT nonce for the SAME node tag is not a replay");
    }

    // ── P-P5b (`node spawn`) — the real signed wire round trip ──────────────
    //
    // Both tests below build the SPAWN-SHAPED body via `aoide_client::wire::
    // build_message_send_body(text, id, None)` — the exact function
    // `aoide-client::commands::handle_node_spawn` calls — and a REAL ed25519
    // signature over it (`signed_request`, the same helper the P-P4 tests
    // above use), so this is a genuine client-body + real-crypto round trip,
    // not a hand-typed guess at either shape.

    /// "A signed node spawn is ADMITTED" (PAIRING.md's own live-gate
    /// wording) — proven up to, but never through, `do_spawn`'s real
    /// OS-level process spawn: `verify_signed_request` really verifies the
    /// signature, and `spawn_admitted` — fed the EXACT resolution
    /// `message_send` itself performs when `signed_node_name` is `Some`
    /// (the two-line `nodes.iter().find(name).map(|p| (p,
    /// NodeRung::Signature))`) — really admits it. This file's own
    /// established discipline (see the doc comment atop the "Spawn gate
    /// table" section above, and `spawn_inject_prompts_success_branch_
    /// files_the_opening_turn_into_the_mailbase`'s) is that NO test here drives
    /// `do_spawn`'s real process spawn, because `std::env::current_exe()`
    /// inside a `cargo test` binary is the TEST binary, not a real `aoide`
    /// — calling `message_send`'s Spawn arm all the way through on the
    /// ADMITTED path would do exactly that. `spawn_admitted` returning
    /// `true` from a REAL verified signature is precisely the boundary
    /// `do_spawn` would be invoked from (`message_send`'s own `if
    /// spawn_admitted(resolved_node) { do_spawn(...) }`); proving up to
    /// it is this suite's documented choice, not a gap.
    #[test]
    fn node_spawn_signed_and_allowed_is_admitted_up_to_the_do_spawn_boundary() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-node-spawn-admitted-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::env::set_var("AOIDE_STATE_DIR", &root);

        let kp = setup_signed_node_with_allows("yomi-strix", &["read", "spawn"]);
        let body = aoide_client::wire::build_message_send_body("status check please", "mid-spawn-1", None);
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let now = 1_800_000_000_i64;
        let req = signed_request(&kp, "yomi-strix", "/", &body_bytes, now, &unique_nonce("admit"));

        let signed_node_name = match verify_signed_request(&req, now) {
            SignedRequestOutcome::Verified { resolved, .. } => resolved,
            other => panic!("expected a REAL genuine signature to verify, got {other:?}"),
        };
        assert_eq!(signed_node_name, "yomi-strix");

        // The exact resolution `message_send` performs when `signed_node_name`
        // is `Some` — the SOLE resolution, no fallthrough to addr/token (P-P4).
        let nodes = aoide_storage::node_store::load_nodes();
        let resolved = nodes
            .iter()
            .find(|p| p.name == signed_node_name)
            .map(|p| (p, aoide_storage::node_store::NodeRung::Signature));
        assert!(spawn_admitted(resolved), "a genuinely signed, paired, spawn-allowed node must be ADMITTED");
        // The exact name that would flow into `do_spawn`'s `node_name` arg,
        // and hence into `origin: format!("node:{name}")` — the wire-verified
        // name, not a guess.
        assert_eq!(resolved.unwrap().0.name, "yomi-strix");

        let _ = std::fs::remove_dir_all(&root);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    /// The live-gate's other half (PAIRING.md: "a spawn refused for a node
    /// with spawn revoked") — same real signature round trip as above, but
    /// SAFE to drive all the way through the REAL `message_send` (not just
    /// `spawn_admitted`): a refusal never reaches `do_spawn`, matching this
    /// file's "REFUSAL branches only" precedent for calling `message_send`
    /// directly.
    #[test]
    fn node_spawn_revoked_is_refused_through_the_real_message_send_wire_path() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-node-spawn-revoked-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::env::set_var("AOIDE_STATE_DIR", root.join("state"));
        std::env::set_var("AOIDE_STAGE_DIR", root.join("stage"));

        // Paired, verified, spawn REVOKED — `allows` carries only "read".
        let kp = setup_signed_node_with_allows("yomi-strix", &["read"]);
        let body = aoide_client::wire::build_message_send_body("status check please", "mid-spawn-2", None);
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let now = 1_800_000_000_i64;
        let req = signed_request(&kp, "yomi-strix", "/", &body_bytes, now, &unique_nonce("revoked"));
        let signed_node_name = match verify_signed_request(&req, now) {
            SignedRequestOutcome::Verified { resolved, .. } => resolved,
            other => panic!("expected a REAL genuine signature to verify, got {other:?}"),
        };

        let err = message_send(
            &body["params"],
            &root.join("log"),
            "claude",
            "",
            ConnOrigin::Loopback,
            "",
            None,
            Some(signed_node_name.as_str()),
        )
        .unwrap_err();
        assert_eq!(err.0, -32006, "genuinely signed and paired, but `spawn` was revoked from allows");
        assert!(err.1.contains("node allow"), "taught error must name the exact fix: {}", err.1);

        let _ = std::fs::remove_dir_all(&root);
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    #[test]
    fn message_send_spawn_refuses_a_paired_node_whose_allows_lacks_spawn() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-spawn-denied-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", root.join("stage"));
        std::env::set_var("AOIDE_STATE_DIR", root.join("state"));

        let mut node = fixture_node("denied-node", "http://10.0.0.5:8710/", false);
        node.verified = true;
        node.allows = vec!["read".to_string()]; // spawn explicitly absent (revoked or never granted).
        aoide_storage::node_store::save_nodes(&[node]).unwrap();

        let params = json!({ "message": { "parts": [{ "kind": "text", "text": "hi" }] } });
        let remote_origin = ConnOrigin::Remote("10.0.0.5".parse().unwrap());
        let err = message_send(
            &params,
            &root.join("log"),
            "claude",
            "",
            remote_origin,
            "",
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(err.0, -32006, "resolved to a REAL node, but `spawn` is not in its allows");

        let _ = std::fs::remove_dir_all(&root);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    #[test]
    fn message_send_spawn_refuses_an_addr_resolved_paired_and_allowed_node_with_no_token_file_configured() {
        // The gap the 2026-08-25 review finding closed: a node that IS
        // paired AND has `spawn` in `allows` — everything decision 6
        // originally asked for — but has no `token_file` set, so it can
        // ONLY resolve via the address rung. Before the narrowing this
        // would have reached `do_spawn`; behind any NAT/reverse-proxy
        // deployment a shared source address is exactly the unsigned
        // signal that must never itself authorize launching a process
        // attributed to this node.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-spawn-addr-only-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", root.join("stage"));
        std::env::set_var("AOIDE_STATE_DIR", root.join("state"));

        let mut node = fixture_node("addr-only-node", "http://10.0.0.5:8710/", false);
        node.verified = true;
        node.allows = vec!["read".to_string(), "spawn".to_string()];
        // `token_file` deliberately left `None` — this node can only ever
        // resolve via the address rung.
        aoide_storage::node_store::save_nodes(&[node]).unwrap();

        let params = json!({ "message": { "parts": [{ "kind": "text", "text": "hi" }] } });
        let remote_origin = ConnOrigin::Remote("10.0.0.5".parse().unwrap());
        let err = message_send(
            &params,
            &root.join("log"),
            "claude",
            "",
            remote_origin,
            "",
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(
            err.0, -32006,
            "paired AND `spawn` in allows, but resolved ONLY via address — still refused"
        );

        let _ = std::fs::remove_dir_all(&root);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    #[test]
    fn message_send_spawn_refuses_the_door_wide_bearer_alone_with_no_node_identity() {
        // The exact scenario decision 6 names explicitly: a caller presenting
        // a VALID door-wide bearer (the OLD gate this amendment replaces)
        // but resolving to no specific registered node at all — no node's
        // own `token_file` matches this token, and the registry is empty so
        // no address can match either. Under the pre-P-P3 gate this would
        // have passed (`token_authorized` was the whole gate); now it must
        // still refuse.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-spawn-doorwide-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", root.join("stage"));
        std::env::set_var("AOIDE_STATE_DIR", root.join("state"));

        let params = json!({ "message": { "parts": [{ "kind": "text", "text": "hi" }] } });
        let err = message_send(
            &params,
            &root.join("log"),
            "claude",
            "",
            ConnOrigin::Loopback,
            "the-door-wide-secret",
            Some("the-door-wide-secret"), // matches expected_token exactly.
            None,
        )
        .unwrap_err();
        assert_eq!(err.0, -32006, "a valid DOOR-WIDE bearer alone no longer reaches the spawn arm");

        let _ = std::fs::remove_dir_all(&root);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    #[test]
    fn non_loopback_message_send_is_held_pending_not_delivered() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let remote_origin = ConnOrigin::Remote("10.0.0.9".parse().unwrap());
        let result = message_send(&params, &audit_log, "", "", remote_origin, "", None, None);
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
        // audit path `send` already uses (`conduct::graph::send::
        // audit_send`), never a second logging path.
        let log = std::fs::read_to_string(&audit_log).unwrap_or_default();
        assert!(log.contains("\"door\":\"a2a\""), "audited through Door::A2a: {log}");
        assert!(log.contains("\"status\":\"pending\""), "audited as pending: {log}");
        assert!(log.contains("send"), "reuses send's own audit command label: {log}");

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
    fn a_held_pending_send_from_a_resolved_but_non_autogated_node_carries_its_origin() {
        // P-P3 decision 7: a pending-queue entry a NODE's send creates
        // carries that resolved node's identity — even an UNPAIRED,
        // non-autogated one (attribution, not a gate — same "ATTRIBUTION,
        // NOT SECURITY" posture `resolve_sender`/`--from` already document).
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-pending-origin-{}-{}",
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

        // Registered, resolvable by address, but NOT autogate-marked — the
        // send still queues (unaffected), but now RESOLVES to a name.
        aoide_storage::node_store::save_nodes(&[fixture_node("watching-node", "http://10.0.0.9:8710/", false)]).unwrap();

        let id = "attributed-target";
        let socket = aoide_conduct::graph::conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();

        let sf = SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![conductable_session(id, &socket)],
        };
        write_stage(&sessions_path(), &sf).unwrap();

        let audit_log = root.join("log");
        let params = serde_json::json!({
            "message": { "parts": [{ "kind": "text", "text": "who sent this" }], "contextId": id }
        });
        let remote_origin = ConnOrigin::Remote("10.0.0.9".parse().unwrap());
        let result = message_send(&params, &audit_log, "", "", remote_origin, "", None, None);
        assert!(result.is_ok(), "still a submitted Task, never a JSON-RPC error");

        let pending: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(stage.join("pending.json")).unwrap()).unwrap();
        let entries = pending["pending"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["from"], "node:watching-node", "the resolved node's identity stamps the pending entry");

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
    fn message_send_resolves_via_signed_node_name_producing_signature_rung_attribution() {
        // P-P4: `message_send`'s `signed_node_name` param (already verified
        // by `verify_signed_request`, one layer up) is the SOLE resolution
        // when present — this test drives that resolution directly (the
        // signature verification itself is `verify_signed_request`'s own
        // test suite above), proving the resulting `NodeRung::Signature`
        // attribution reaches `pending.json` the same way Token/Addr
        // already did before this phase.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-sig-attr-{}-{}",
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

        let mut signed_node = fixture_node("signed-node", "http://10.0.0.9:8710/", false);
        signed_node.verified = true;
        aoide_storage::node_store::save_nodes(&[signed_node]).unwrap();

        let id = "sig-attr-tgt";
        let socket = aoide_conduct::graph::conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();

        let sf = SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![conductable_session(id, &socket)],
        };
        write_stage(&sessions_path(), &sf).unwrap();

        let audit_log = root.join("log");
        let params = serde_json::json!({
            "message": { "parts": [{ "kind": "text", "text": "signed hello" }], "contextId": id }
        });
        // A REMOTE, non-autogated origin with NO token presented at all —
        // under the pre-P-P4 ladder this would resolve to nothing
        // (`resolve_node` needs a token or a matching address); it resolves
        // here purely because `signed_node_name` is `Some`.
        let remote_origin = ConnOrigin::Remote("203.0.113.1".parse().unwrap());
        let result = message_send(
            &params,
            &audit_log,
            "",
            "",
            remote_origin,
            "",
            None,
            Some("signed-node"),
        );
        assert!(result.is_ok());

        let pending: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(stage.join("pending.json")).unwrap()).unwrap();
        let entries = pending["pending"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["from"], "node:signed-node", "resolution via signed_node_name attributes correctly");

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
    fn message_send_signed_node_name_never_falls_through_to_the_addr_token_ladder() {
        // Fail-closed discipline (#84 precedent, brief point 2): a
        // `signed_node_name` that names a node NOT actually present in the
        // (freshly reloaded) registry — an edge case `verify_signed_request`
        // itself already prevents in practice, since it only ever hands
        // back a name it just confirmed is registered+verified — must
        // resolve to NOTHING, never silently fall back to whatever the
        // presented token/address WOULD otherwise have resolved to.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-sig-nofall-{}-{}",
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

        // A REAL registered node that WOULD resolve via its own token, if
        // the addr/token ladder ever ran.
        let token_file = root.join("real-node.token");
        std::fs::write(&token_file, "real-secret").unwrap();
        let mut real_node = fixture_node("real-node", "http://10.0.0.9:8710/", false);
        real_node.token_file = Some(token_file.to_string_lossy().into_owned());
        aoide_storage::node_store::save_nodes(&[real_node]).unwrap();

        let id = "nofall-tgt";
        let socket = aoide_conduct::graph::conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();

        let sf = SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![conductable_session(id, &socket)],
        };
        write_stage(&sessions_path(), &sf).unwrap();

        let audit_log = root.join("log");
        let params = serde_json::json!({
            "message": { "parts": [{ "kind": "text", "text": "hi" }], "contextId": id }
        });
        let remote_origin = ConnOrigin::Remote("10.0.0.9".parse().unwrap());
        // Presents the REAL node's own valid token AND claims a signed node
        // name ("ghost") that doesn't exist in the registry at all.
        let result = message_send(
            &params,
            &audit_log,
            "",
            "",
            remote_origin,
            "",
            Some("real-secret"),
            Some("ghost"),
        );
        assert!(result.is_ok());

        let pending: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(stage.join("pending.json")).unwrap()).unwrap();
        let entries = pending["pending"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(
            entries[0].get("from").is_none() || entries[0]["from"].is_null(),
            "a signed_node_name resolving to nothing must NOT fall back to the token-resolved `real-node` — got {:?}",
            entries[0].get("from")
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

    /// LANE IDENTITY P-ID3 (G9): the exact `from: None` shape the test above
    /// already produces (an unresolvable `signed_node_name`), but with
    /// `AOIDE_SESSION_ID` set in THIS PROCESS's own env first — standing in
    /// for whatever `aoide a2a serve` might have inherited at launch. Before
    /// the fix, `do_inject`'s bare `if let Some(f) = from` left `--from`
    /// entirely absent on an unattributed inject, so `session_send`'s
    /// `resolve_sender` fell back to reading THIS env var and misattributed
    /// the pending entry to it. The fix stamps `--from ""` explicitly
    /// whenever `from` is `None`, which `resolve_sender` documents as
    /// skipping the env fallback outright — so the pending entry's `from`
    /// must stay unattributed no matter what `AOIDE_SESSION_ID` says.
    #[test]
    fn an_unattributed_inject_never_falls_back_to_this_processs_own_ambient_session_id() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_session_id = std::env::var("AOIDE_SESSION_ID").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-g9-no-env-leak-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_STATE_DIR", root.join("state"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        // The one line that matters: this stands in for a stray
        // `AOIDE_SESSION_ID` in `aoide a2a serve`'s OWN launch environment —
        // never the remote caller's, which has no channel to set it at all.
        std::env::set_var("AOIDE_SESSION_ID", "daemons-own-stray-session");

        let token_file = root.join("real-node.token");
        std::fs::write(&token_file, "real-secret").unwrap();
        let mut real_node = fixture_node("real-node", "http://10.0.0.9:8710/", false);
        real_node.token_file = Some(token_file.to_string_lossy().into_owned());
        aoide_storage::node_store::save_nodes(&[real_node]).unwrap();

        let id = "g9-no-env-leak-tgt";
        let socket = aoide_conduct::graph::conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();

        let sf = SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![conductable_session(id, &socket)],
        };
        write_stage(&sessions_path(), &sf).unwrap();

        let audit_log = root.join("log");
        let params = serde_json::json!({
            "message": { "parts": [{ "kind": "text", "text": "hi" }], "contextId": id }
        });
        let remote_origin = ConnOrigin::Remote("10.0.0.9".parse().unwrap());
        // An unresolvable `signed_node_name` ("ghost") — `do_inject` sees
        // `from: None`, exactly the shape that used to fall through to the
        // env.
        let result = message_send(
            &params,
            &audit_log,
            "",
            "",
            remote_origin,
            "",
            Some("real-secret"),
            Some("ghost"),
        );
        assert!(result.is_ok(), "{:?}", result.err());
        assert!(listener.accept().is_err(), "unattributed + non-autogate must never touch the socket");

        let pending: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(stage.join("pending.json")).unwrap()).unwrap();
        let entries = pending["pending"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(
            entries[0].get("from").is_none() || entries[0]["from"].is_null(),
            "an unattributed inject must NEVER pick up this process's own ambient AOIDE_SESSION_ID — got {:?}",
            entries[0].get("from")
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
        match saved_session_id {
            Some(v) => std::env::set_var("AOIDE_SESSION_ID", v),
            None => std::env::remove_var("AOIDE_SESSION_ID"),
        }
    }

    #[test]
    fn loopback_message_send_still_auto_delivers_exactly_as_before() {
        // Regression test (hard requirement): this amendment must NOT change
        // loopback semantics at all — a loopback origin still auto-delivers,
        // byte-for-byte the same as `do_inject`'s pre-amendment unconditional
        // `--yes` behavior.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let result = message_send(
            &params,
            &audit_log,
            "",
            "",
            ConnOrigin::Loopback,
            "",
            None,
            None,
        );
        let got = acc.join().unwrap();
        assert_eq!(String::from_utf8(got).unwrap(), "hello loopback\r");

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
    fn message_send_injects_with_an_existing_socket_and_refuses_once_it_is_removed() {
        // The A2A-door half of the identical bug `e2758f7` fixed on `graph`:
        // a stored `conductable` session whose control socket has since been
        // deleted (`shellbridge.service` owns `$XDG_RUNTIME_DIR/aoide` with
        // `RuntimeDirectoryPreserve=no`, so a rebuild deletes it out from
        // under every live session) must take the EXISTING -32004 "session
        // not conductable" arm — never `SendAction::Inject` reaching an
        // address nothing can reach. Matters more here than on `graph`: this
        // is the cross-node path, so a remote node would be told delivery is
        // happening when it cannot be.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-socket-gone-{}-{}",
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

        let id = "socket-gone-target";
        let socket = aoide_conduct::graph::conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();

        let sf = SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![conductable_session(id, &socket)],
        };
        write_stage(&sessions_path(), &sf).unwrap();

        let audit_log = root.join("log");

        // While the socket still exists, delivery is unaffected — byte-for-
        // byte the same as `loopback_message_send_still_auto_delivers_
        // exactly_as_before` above.
        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });
        let params = serde_json::json!({
            "message": { "parts": [{ "kind": "text", "text": "still here" }], "contextId": id }
        });
        let result = message_send(
            &params,
            &audit_log,
            "",
            "",
            ConnOrigin::Loopback,
            "",
            None,
            None,
        );
        let got = acc.join().unwrap();
        assert_eq!(String::from_utf8(got).unwrap(), "still here\r");
        assert_eq!(result.unwrap()["id"], id);

        // The socket file is deleted (a rebuild tearing down the runtime
        // dir) — the STORED record is untouched, but the SAME contextId
        // must now refuse rather than inject into a dead address.
        std::fs::remove_file(&socket).unwrap();
        let params2 = serde_json::json!({
            "message": { "parts": [{ "kind": "text", "text": "too late" }], "contextId": id }
        });
        let err = message_send(
            &params2,
            &audit_log,
            "",
            "",
            ConnOrigin::Loopback,
            "",
            None,
            None,
        )
        .expect_err("a missing socket must be a structured error, not a failed connect");
        assert_eq!(err.0, -32004);
        assert_eq!(err.1, "session not conductable");

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
    fn a_successfully_delivered_message_send_files_into_the_mailbase() {
        // Messaging plan P-M1: `do_inject` files no entry of its own (see its
        // doc comment) — this proves the SHARED seam actually fires for an
        // A2A-delivered message, end to end through `message_send`.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-mail-{}-{}",
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

        let id = "mail-a2a-target";
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
            "message": { "parts": [{ "kind": "text", "text": "hello from a node" }], "contextId": id }
        });
        let result = message_send(
            &params,
            &audit_log,
            "",
            "",
            ConnOrigin::Loopback,
            "",
            None,
            None,
        );
        let _ = acc.join().unwrap();
        assert!(result.is_ok(), "{:?}", result.err());

        let entries = aoide_storage::mail::read_base().unwrap();
        assert_eq!(entries.len(), 1, "one delivered A2A message, one mailbase entry — not two");
        assert_eq!(entries[0].envelope.header.to.name, id);
        assert_eq!(entries[0].envelope.text, "hello from a node");
        // The a2a door has no caller identity to offer today (#51's scope) —
        // `do_inject`'s Invocation never sets `--from`, and this test process
        // has no AOIDE_SESSION_ID either, so the honest attribution is empty.
        assert_eq!(entries[0].envelope.header.from.name, "");

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
    fn spawn_inject_prompts_success_branch_files_the_opening_turn_into_the_mailbase() {
        // Messaging plan P-M1, the bounce-fix hole: `message/send` with NO
        // contextId (or `spawn_asked`) resolves to `SendAction::Spawn` and
        // `do_spawn` — a brand-new session's FIRST turn is typed by
        // `spawn_inject_prompt`, the SECOND (and last) mailbase-filing site
        // alongside `deliver_local`'s (see its own doc comment for why it
        // can't reach `deliver_local`).
        //
        // This drives `spawn_inject_prompt` directly rather than through
        // `message_send`/`do_spawn`: `do_spawn` launches the configured
        // agent via `std::env::current_exe()`, which inside `cargo test` IS
        // THE TEST BINARY ITSELF — invoking it with `conduct --agent a2a
        // --id … -- …` would hand those words to the test harness as
        // positional filter args and actually re-run (a subset of) this
        // suite as a detached child process, never bind the real socket,
        // and time out this test's 3s retry budget for nothing. No test in
        // this file exercises `do_spawn`'s OS-level spawn for that reason
        // (there is no `AOIDE_A2A_BIN`-style override seam for it) —
        // `spawn_inject_prompt` is the exact function the mailbase-filing
        // code lives in, and driving it directly against a stand-in
        // listener is the same boundary `aoide_conduct::graph::conduct`'s
        // own PTY-injection test already uses for the underlying
        // socket-write mechanism (see `spawn_inject_prompt`'s doc comment).
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_runtime = std::env::var("XDG_RUNTIME_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-spawninject-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_STATE_DIR", root.join("state"));

        let id = "spawn-inject-target";
        let socket = aoide_conduct::graph::conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();

        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });

        spawn_inject_prompt(id, "hello new session");
        let got = acc.join().unwrap();
        assert_eq!(String::from_utf8(got).unwrap(), "hello new session\n", "--submit's newline, same as do_spawn's payload");

        let entries = aoide_storage::mail::read_base().unwrap();
        assert_eq!(entries.len(), 1, "the spawned session's opening turn is filed exactly once");
        assert_eq!(entries[0].envelope.header.to.name, id);
        assert_eq!(entries[0].envelope.text, "hello new session");
        assert_eq!(entries[0].envelope.header.from.name, "", "no caller identity to offer — #51's scope");

        let _ = std::fs::remove_dir_all(&root);
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        match saved_runtime {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
    }

    #[test]
    fn spawn_inject_prompt_on_an_empty_prompt_files_nothing() {
        // The existing early return (`if prompt.is_empty() { return; }`) —
        // an empty prompt never connects at all, so it must not file a
        // mailbase entry either.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-spawninject-empty-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::env::set_var("AOIDE_STATE_DIR", root.join("state"));

        spawn_inject_prompt("whatever-id", "");
        assert!(aoide_storage::mail::read_base().unwrap().is_empty());

        let _ = std::fs::remove_dir_all(&root);
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let result = message_send(
            &params,
            &audit_log,
            "",
            "",
            ConnOrigin::Loopback,
            "the-real-token",
            None,
            None,
        );
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
            "",
            ConnOrigin::Loopback,
            "the-real-token",
            Some("the-real-token"), None
        );
        let got = acc.join().unwrap();
        assert_eq!(String::from_utf8(got).unwrap(), "authenticated loopback\r");
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
    fn autogated_node_delivers_despite_being_non_loopback() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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

        // A node explicitly marked `autogate: true`, whose url resolves (as
        // an IP literal — no real DNS) to the connecting address.
        aoide_storage::node_store::save_nodes(&[aoide_storage::node_store::Node {
            name: "trusted-node".into(),
            url: "http://10.0.0.9:8710/".into(),
            autogate: true,
            token_file: None,
            bearer_secret: None,
            hub: false,
            pubkey: None,
            verified: false,
            allows: Vec::new(),
            via: None,
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
        let remote_origin = ConnOrigin::Remote("10.0.0.9".parse().unwrap());
        let result = message_send(&params, &audit_log, "", "", remote_origin, "", None, None);
        let got = acc.join().unwrap();
        assert_eq!(
            String::from_utf8(got).unwrap(),
            "trusted send\r",
            "an autogate-marked node's non-loopback send still auto-delivers"
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
    fn autogated_node_delivers_via_a_matching_token_even_when_ip_does_not_match() {
        // The actual replacement for the dead IP match: behind a proxy the
        // caller's real address is unknowable, but a per-node TOKEN survives
        // the hop. No global A2A token is configured here at all — this is
        // entirely the node_store-level identification, independent of the
        // `message_send` expected_token/presented_token plumbing.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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

        let token_path = root.join("node.token");
        std::fs::write(&token_path, "node-secret\n").unwrap();
        aoide_storage::node_store::save_nodes(&[aoide_storage::node_store::Node {
            name: "proxied-node".into(),
            // A URL that resolves to an address the caller is NOT actually
            // connecting from — proving delivery here comes from the TOKEN
            // match, not a coincidental IP match.
            url: "http://192.0.2.99:8710/".into(),
            autogate: true,
            token_file: Some(token_path.to_string_lossy().into_owned()),
            bearer_secret: None,
            hub: false,
            pubkey: None,
            verified: false,
            allows: Vec::new(),
            via: None,
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
        let remote_origin = ConnOrigin::Remote("10.0.0.9".parse().unwrap());
        let result = message_send(
            &params,
            &audit_log,
            "",
            "",
            remote_origin,
            "",
            Some("node-secret"),
            None,
        );
        let got = acc.join().unwrap();
        assert_eq!(String::from_utf8(got).unwrap(), "token-identified send\r");
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

    // ── Signed requests outrank loopback for Inject (P-S6, CONTRACTS.md §6 ──
    // ── amendment 2026-08-26) ─────────────────────────────────────────────
    //
    // An ssh `-L` tunnel makes a remote node's request arrive at
    // `peer_addr()` looking exactly like a genuinely local caller — the top
    // risk the ssh-transport lane's plan names explicitly. These two tests
    // are the pin: a signed, non-autogate node over a LOOPBACK connection
    // must NOT get the free pass a real local caller gets (this is the
    // regression a tunnel would otherwise introduce), while a signed,
    // autogate-marked node over the same loopback connection keeps
    // delivering (the like-for-like restoration — narrowing must not cost
    // an already-trusted node its existing behavior).

    #[test]
    fn signed_inject_from_a_non_autogate_node_on_a_loopback_connection_is_held_pending() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-sig-loop-pending-{}-{}",
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

        // Paired, verified, NOT autogate-marked — a signed send from this
        // node must queue, never auto-deliver, whatever the connection's
        // own origin looks like.
        let mut signed_node = fixture_node("tunneled-node", "http://10.0.0.9:8710/", false);
        signed_node.verified = true;
        aoide_storage::node_store::save_nodes(&[signed_node]).unwrap();

        let id = "sig-loop-pending-tgt";
        let socket = aoide_conduct::graph::conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        // Nothing must ever connect here — a wrongly-delivered send would.
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();

        let sf = SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![conductable_session(id, &socket)],
        };
        write_stage(&sessions_path(), &sf).unwrap();

        let audit_log = root.join("log");
        let params = serde_json::json!({
            "message": { "parts": [{ "kind": "text", "text": "tunneled send" }], "contextId": id }
        });
        // The defect this pin closes: an ssh `-L` forward makes a tunneled
        // node's connection classify as `ConnOrigin::Loopback`
        // (`classify_origin`, `peer_addr()`) exactly like this. Before the
        // P-S6 narrowing, `should_deliver_now(Loopback, _)` was
        // unconditionally `true`, so this would have auto-delivered.
        let result = message_send(
            &params,
            &audit_log,
            "",
            "",
            ConnOrigin::Loopback,
            "",
            None,
            Some("tunneled-node"),
        );
        assert!(result.is_ok(), "{:?}", result.err());
        assert!(listener.accept().is_err(), "a signed, non-autogate node's send must never touch the socket, loopback or not");

        let pending: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(stage.join("pending.json")).unwrap()).unwrap();
        let entries = pending["pending"].as_array().unwrap();
        assert_eq!(entries.len(), 1, "the send is held pending, not dropped");
        assert_eq!(entries[0]["from"], "node:tunneled-node");

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
    fn signed_inject_from_an_autogate_node_on_a_loopback_connection_still_auto_delivers() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-sig-loop-autogate-{}-{}",
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

        // Paired, verified, AND autogate-marked — the operator already
        // trusted this node to skip the pending queue; the P-S6 narrowing
        // must not cost it that.
        let mut signed_node = fixture_node("trusted-tunneled-node", "http://10.0.0.9:8710/", true);
        signed_node.verified = true;
        aoide_storage::node_store::save_nodes(&[signed_node]).unwrap();

        let id = "sig-loop-autogate-tgt";
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
            "message": { "parts": [{ "kind": "text", "text": "trusted tunneled send" }], "contextId": id }
        });
        let result = message_send(
            &params,
            &audit_log,
            "",
            "",
            ConnOrigin::Loopback,
            "",
            None,
            Some("trusted-tunneled-node"),
        );
        let got = acc.join().unwrap();
        assert_eq!(
            String::from_utf8(got).unwrap(),
            "trusted tunneled send\r",
            "an autogate-marked node's signed send still auto-delivers through a loopback-classified connection"
        );
        assert!(result.is_ok(), "{:?}", result.err());

        let pending_path = stage.join("pending.json");
        if pending_path.exists() {
            let pending: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&pending_path).unwrap()).unwrap();
            assert!(pending["pending"].as_array().map(Vec::is_empty).unwrap_or(true), "a delivered send never queues");
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
                let result = message_send(
                    &params,
                    &audit_log,
                    "",
                    "",
                    ConnOrigin::Loopback,
                    "s3cr3t",
                    presented,
                    None,
                );
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        // Remote + no registered autogate node, so a real send is held
        // pending rather than delivered — same as the pre-#50 Inject arm,
        // and it proves `do_inject` (not the uniform guard) ran: only that
        // path writes `pending.json`.
        let remote_origin = ConnOrigin::Remote("10.0.0.9".parse().unwrap());

        let params = serde_json::json!({
            "message": { "parts": [{ "kind": "text", "text": "authed send" }], "contextId": real_id }
        });
        let result = message_send(
            &params,
            &audit_log,
            "",
            "",
            remote_origin,
            "s3cr3t",
            Some("s3cr3t"),
            None,
        );
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
        let bogus_err = message_send(
            &bogus_params,
            &audit_log,
            "",
            "",
            remote_origin,
            "s3cr3t",
            Some("s3cr3t"),
            None,
        )
        .unwrap_err();
        assert_eq!(bogus_err.0, -32001);

        let noncond_params = serde_json::json!({
            "message": { "parts": [{ "kind": "text", "text": "x" }], "contextId": noncond_id }
        });
        let noncond_err = message_send(
            &noncond_params,
            &audit_log,
            "",
            "",
            remote_origin,
            "s3cr3t",
            Some("s3cr3t"),
            None,
        )
        .unwrap_err();
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let result = message_send(
            &params,
            &audit_log,
            "",
            "",
            ConnOrigin::Loopback,
            "",
            None,
            None,
        );
        let got = acc.join().unwrap();
        assert_eq!(String::from_utf8(got).unwrap(), "off-path send\r", "no token configured: loopback still auto-delivers");
        assert!(result.is_ok());

        let bogus_params = serde_json::json!({
            "message": { "parts": [{ "kind": "text", "text": "x" }], "contextId": bogus_id }
        });
        let bogus_err = message_send(
            &bogus_params,
            &audit_log,
            "",
            "",
            ConnOrigin::Loopback,
            "",
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(bogus_err.0, -32001);

        let noncond_params = serde_json::json!({
            "message": { "parts": [{ "kind": "text", "text": "x" }], "contextId": noncond_id }
        });
        let noncond_err = message_send(
            &noncond_params,
            &audit_log,
            "",
            "",
            ConnOrigin::Loopback,
            "",
            None,
            None,
        )
        .unwrap_err();
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
    fn uniform_response_guard_never_fires_for_a_per_node_autogated_token() {
        // A server-wide token IS configured (and the presented bearer does
        // NOT match it), but the presented token DOES match an enrolled
        // node's own `token_file` — the exact scenario the amendment's
        // grounding names: enrolled nodes authenticate per-node, never
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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

        let token_path = root.join("node.token");
        std::fs::write(&token_path, "node-secret\n").unwrap();
        aoide_storage::node_store::save_nodes(&[aoide_storage::node_store::Node {
            name: "enrolled-node".into(),
            url: "http://192.0.2.99:8710/".into(),
            autogate: true,
            token_file: Some(token_path.to_string_lossy().into_owned()),
            bearer_secret: None,
            hub: false,
            pubkey: None,
            verified: false,
            allows: Vec::new(),
            via: None,
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
            "message": { "parts": [{ "kind": "text", "text": "per-node authed" }], "contextId": id }
        });
        let remote_origin = ConnOrigin::Remote("10.0.0.9".parse().unwrap());
        // "server-secret" is configured server-wide; "node-secret" (what's
        // presented) does NOT match it — only the per-node autogate match
        // saves this from the #50 uniform guard.
        let result = message_send(
            &params,
            &audit_log,
            "",
            "",
            remote_origin,
            "server-secret",
            Some("node-secret"),
            None,
        );
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

    // ── `resolve_node_name` precedence (flag → env → hostname → default) ────

    #[test]
    fn resolve_node_name_prefers_flag_then_env_then_falls_back() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_A2A_NODE_NAME").ok();

        let mut flags = std::collections::BTreeMap::new();
        flags.insert("node-name".to_string(), "flag-name".to_string());
        let inv = Invocation { path: vec![], args: vec![], flags, door: Door::Cli };
        std::env::set_var("AOIDE_A2A_NODE_NAME", "env-name");
        assert_eq!(resolve_node_name(&inv), "flag-name", "an explicit flag wins outright");

        let inv_no_flag = Invocation {
            path: vec![],
            args: vec![],
            flags: std::collections::BTreeMap::new(),
            door: Door::Cli,
        };
        assert_eq!(resolve_node_name(&inv_no_flag), "env-name", "falls back to the env var");

        std::env::remove_var("AOIDE_A2A_NODE_NAME");
        // Falls back to the OS hostname (or, failing that, "aoide") — either
        // way, never empty.
        assert!(!resolve_node_name(&inv_no_flag).is_empty());

        match saved {
            Some(v) => std::env::set_var("AOIDE_A2A_NODE_NAME", v),
            None => std::env::remove_var("AOIDE_A2A_NODE_NAME"),
        }
    }

    // ── `resolve_discovery_advertise` (P-P6) — off unless a flag or a
    // ── truthy env explicitly opts in. This is the launch-time FORCE-ON
    // ── half `serve` hands `discovery::spawn_advertiser`; the runtime
    // ── half is `aoide_storage::advertise::enabled()` (its own crate's
    // ── tests), OR'd in per tick. `false` here + switch off (the
    // ── default) = a tick that sends nothing — proven with no real
    // ── thread, socket, or sleep involved. ──────────────────────────────

    #[test]
    fn resolve_discovery_advertise_is_off_by_default() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_DISCOVERY_ADVERTISE").ok();
        std::env::remove_var("AOIDE_DISCOVERY_ADVERTISE");

        let inv = Invocation { path: vec![], args: vec![], flags: std::collections::BTreeMap::new(), door: Door::Cli };
        assert!(!resolve_discovery_advertise(&inv), "no flag, no env — discovery stays off");

        match saved {
            Some(v) => std::env::set_var("AOIDE_DISCOVERY_ADVERTISE", v),
            None => std::env::remove_var("AOIDE_DISCOVERY_ADVERTISE"),
        }
    }

    #[test]
    fn resolve_discovery_advertise_honors_the_flag_and_the_truthy_env_vocabulary() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_DISCOVERY_ADVERTISE").ok();

        let mut flags = std::collections::BTreeMap::new();
        flags.insert("discovery-advertise".to_string(), String::new());
        let flag_inv = Invocation { path: vec![], args: vec![], flags, door: Door::Cli };
        std::env::remove_var("AOIDE_DISCOVERY_ADVERTISE");
        assert!(resolve_discovery_advertise(&flag_inv), "bare flag presence turns it on");

        let no_flag_inv = Invocation { path: vec![], args: vec![], flags: std::collections::BTreeMap::new(), door: Door::Cli };
        for truthy in ["1", "true", "yes", "all"] {
            std::env::set_var("AOIDE_DISCOVERY_ADVERTISE", truthy);
            assert!(resolve_discovery_advertise(&no_flag_inv), "`{truthy}` must be truthy");
        }
        for not_truthy in ["0", "false", "no", "", "TRUE", "garbage"] {
            std::env::set_var("AOIDE_DISCOVERY_ADVERTISE", not_truthy);
            assert!(!resolve_discovery_advertise(&no_flag_inv), "`{not_truthy}` must NOT be truthy");
        }

        match saved {
            Some(v) => std::env::set_var("AOIDE_DISCOVERY_ADVERTISE", v),
            None => std::env::remove_var("AOIDE_DISCOVERY_ADVERTISE"),
        }
    }

    // ── `aoide/graphSummary` (CONTRACTS.md §7) ───────────────────────────────

    #[test]
    fn graph_summary_wraps_the_resolved_graph_document_verbatim() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        // bare `graph` uses) produces — no second vocabulary.
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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

    // ── The pairing ceremony wire (CONTRACTS.md §6, P-P2) ────────────────────

    /// Set `AOIDE_STATE_DIR`/`AOIDE_STAGE_DIR` to a fresh tempdir under
    /// `root` — used to stand in for "acting as one box" in the sequential
    /// ceremony test below, which plays BOTH box A and box B in the same
    /// process by swapping this env between steps (never concurrently —
    /// `aoide-storage`'s state resolution is process-global, so two REAL
    /// concurrent identities cannot coexist in one test binary; the
    /// REAL two-instance HTTP proof for the pre-existing `node
    /// add`/`pull` surface, `cli/tests/node_connectivity.rs`, is the
    /// pattern this test cannot fully match for THIS feature — the ceremony
    /// writes DISTINCT per-side state (each box's own `nodes.json`/
    /// identity), unlike a read-only `graphSummary` pull, which that
    /// existing test's two threads can share one state dir for).
    fn act_as(root: &std::path::Path, who: &str) {
        let dir = root.join(who);
        std::fs::create_dir_all(dir.join("stage")).unwrap();
        std::env::set_var("AOIDE_STATE_DIR", dir.join("state"));
        std::env::set_var("AOIDE_STAGE_DIR", dir.join("stage"));
    }

    #[test]
    fn pair_request_parks_and_returns_the_approvers_public_identity_and_nonce() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-pairrequest-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        act_as(&root, "b");

        let audit_log = root.join("log");
        let commit = aoide_storage::pairing::derive_commit(&"a".repeat(64), &"c".repeat(16));
        let params = json!({
            "pubkeyHex": "a".repeat(64),
            "name": "box-a",
            "commitHex": commit,
            "url": "http://box-a:8710/",
        });
        let resp = pair_request(&params, ConnOrigin::Remote("10.0.0.5".parse().unwrap()), &audit_log).unwrap();
        assert!(resp["id"].as_str().unwrap().len() == 8);
        assert!(valid_pubkey_hex(resp["pubkeyHex"].as_str().unwrap()), "B's own real pubkey, not A's");
        assert_ne!(resp["pubkeyHex"], "a".repeat(64), "B answers with its OWN key, not an echo of A's");
        assert!(valid_nonce_hex(resp["nonceHex"].as_str().unwrap()));
        assert!(resp["expiresAt"].as_str().unwrap().ends_with('Z'));

        // Parked on disk, origin recorded for display, NOT YET revealed —
        // no nonce, so no SAS to show, until `aoide/pairReveal` runs.
        let now_epoch = aoide_storage::time::parse_iso_utc(&now_iso_utc()).unwrap();
        let pending = aoide_storage::pairing::list_inbound(now_epoch);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].name, "box-a");
        assert_eq!(pending[0].origin_addr, "10.0.0.5");
        assert_eq!(pending[0].url, "http://box-a:8710/");
        assert_eq!(pending[0].commit_hex, commit);
        assert!(pending[0].requester_nonce_hex.is_none(), "unrevealed at request time");

        // Audited.
        let log = std::fs::read_to_string(&audit_log).unwrap_or_default();
        assert!(log.contains("a2a.pairRequest"), "{log}");

        let _ = std::fs::remove_dir_all(&root);
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    #[test]
    fn pair_request_rejects_malformed_pubkey_name_commit_or_url_before_parking_anything() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-pairrequest-invalid-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        act_as(&root, "b");
        let audit_log = root.join("log");

        let commit = aoide_storage::pairing::derive_commit(&"a".repeat(64), &"c".repeat(16));
        let good = json!({ "pubkeyHex": "a".repeat(64), "name": "box-a", "commitHex": commit, "url": "http://a/" });

        let bad_pubkey = { let mut p = good.clone(); p["pubkeyHex"] = json!("too-short"); p };
        assert_eq!(pair_request(&bad_pubkey, ConnOrigin::Loopback, &audit_log).unwrap_err().0, -32602);

        let bad_name = { let mut p = good.clone(); p["name"] = json!("../../evil"); p };
        assert_eq!(pair_request(&bad_name, ConnOrigin::Loopback, &audit_log).unwrap_err().0, -32602);

        let bad_commit = { let mut p = good.clone(); p["commitHex"] = json!("zz"); p };
        assert_eq!(pair_request(&bad_commit, ConnOrigin::Loopback, &audit_log).unwrap_err().0, -32602);

        let bad_url = { let mut p = good.clone(); p["url"] = json!(""); p };
        assert_eq!(pair_request(&bad_url, ConnOrigin::Loopback, &audit_log).unwrap_err().0, -32602);

        let now_epoch = aoide_storage::time::parse_iso_utc(&now_iso_utc()).unwrap();
        assert!(
            aoide_storage::pairing::list_inbound(now_epoch).is_empty(),
            "nothing was parked — every malformed request was refused first"
        );

        let _ = std::fs::remove_dir_all(&root);
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    #[test]
    fn pair_request_refuses_beyond_the_park_cap() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_cap = std::env::var(aoide_storage::pairing::PAIRING_PARK_CAP_ENV).ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-pairrequest-cap-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        act_as(&root, "b");
        std::env::set_var(aoide_storage::pairing::PAIRING_PARK_CAP_ENV, "1");
        let audit_log = root.join("log");

        // DISTINCT pubkeys (R3, `aoide_storage::pairing`'s own module doc) —
        // a SAME-pubkey retry now supersedes rather than refusing, so this
        // cap-refusal test needs two genuinely different identities to
        // still exercise the cap itself.
        let request = |pubkey_byte: char, name: &str| {
            let pubkey = pubkey_byte.to_string().repeat(64);
            let commit = aoide_storage::pairing::derive_commit(&pubkey, &"c".repeat(16));
            json!({ "pubkeyHex": pubkey, "name": name, "commitHex": commit, "url": "http://a/" })
        };
        pair_request(&request('a', "box-a"), ConnOrigin::Loopback, &audit_log).expect("first request is under the cap");
        let err = pair_request(&request('b', "box-c"), ConnOrigin::Loopback, &audit_log).unwrap_err();
        assert_eq!(err.0, -32000, "a distinct code from ordinary invalid-params -32602");

        let now_epoch = aoide_storage::time::parse_iso_utc(&now_iso_utc()).unwrap();
        assert_eq!(aoide_storage::pairing::list_inbound(now_epoch).len(), 1, "the refused request wrote nothing");

        let _ = std::fs::remove_dir_all(&root);
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        match saved_cap {
            Some(v) => std::env::set_var(aoide_storage::pairing::PAIRING_PARK_CAP_ENV, v),
            None => std::env::remove_var(aoide_storage::pairing::PAIRING_PARK_CAP_ENV),
        }
    }

    /// R3, door level: a second `aoide/pairRequest` from the SAME pubkey
    /// evicts the first parked entry rather than coexisting with it — the
    /// audit line names the evicted id, but the WIRE response stays the
    /// ordinary fresh-id shape (CONTRACTS.md §6 — the evicted id never
    /// rides the wire).
    #[test]
    fn pair_request_from_the_same_pubkey_supersedes_the_prior_parked_request_and_audits_it() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-pairrequest-supersede-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        act_as(&root, "b");
        let audit_log = root.join("log");

        let pubkey = "a".repeat(64);
        let request = |name: &str, nonce_byte: char| {
            let commit = aoide_storage::pairing::derive_commit(&pubkey, &nonce_byte.to_string().repeat(16));
            json!({ "pubkeyHex": pubkey, "name": name, "commitHex": commit, "url": "http://a/" })
        };

        let resp1 = pair_request(&request("box-a", 'c'), ConnOrigin::Loopback, &audit_log).unwrap();
        let id1 = resp1["id"].as_str().unwrap().to_string();

        let resp2 = pair_request(&request("box-a-retry", 'd'), ConnOrigin::Loopback, &audit_log).unwrap();
        let id2 = resp2["id"].as_str().unwrap().to_string();
        assert_ne!(id1, id2, "the superseding request gets its own fresh id");

        // Exactly one parked entry survives — the newer one.
        let now_epoch = aoide_storage::time::parse_iso_utc(&now_iso_utc()).unwrap();
        let pending = aoide_storage::pairing::list_inbound(now_epoch);
        assert_eq!(pending.len(), 1, "the first entry is superseded, not left coexisting");
        assert_eq!(pending[0].id, id2);
        assert_eq!(pending[0].name, "box-a-retry");

        // The wire response stays exactly the ordinary four keys.
        let keys: std::collections::BTreeSet<String> = resp2.as_object().unwrap().keys().cloned().collect();
        assert_eq!(
            keys,
            ["expiresAt", "id", "nonceHex", "pubkeyHex"].iter().map(|s| s.to_string()).collect::<std::collections::BTreeSet<_>>(),
            "the wire response never grows an evicted-id field"
        );

        // The audit log names the supersede and the evicted id.
        let log = std::fs::read_to_string(&audit_log).unwrap_or_default();
        assert!(log.contains(&format!("superseding {id1}")), "{log}");

        let _ = std::fs::remove_dir_all(&root);
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    #[test]
    fn pair_request_from_a_case_varied_pubkey_still_supersedes_the_prior_parked_request() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-pairrequest-supersede-case-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        act_as(&root, "b");
        let audit_log = root.join("log");

        let pubkey_lower = "a".repeat(64);
        let pubkey_case_varied = format!("{}A", "a".repeat(63));
        let request = |pubkey: &str, name: &str, nonce_byte: char| {
            let commit = aoide_storage::pairing::derive_commit(pubkey, &nonce_byte.to_string().repeat(16));
            json!({ "pubkeyHex": pubkey, "name": name, "commitHex": commit, "url": "http://a/" })
        };

        let resp1 = pair_request(&request(&pubkey_lower, "box-a", 'c'), ConnOrigin::Loopback, &audit_log).unwrap();
        let id1 = resp1["id"].as_str().unwrap().to_string();

        // Same key, one hex character uppercased on the retry — the wire's
        // own `valid_pubkey_hex` already accepts either case.
        let resp2 = pair_request(&request(&pubkey_case_varied, "box-a-retry", 'd'), ConnOrigin::Loopback, &audit_log).unwrap();
        let id2 = resp2["id"].as_str().unwrap().to_string();
        assert_ne!(id1, id2, "the superseding request gets its own fresh id");

        let now_epoch = aoide_storage::time::parse_iso_utc(&now_iso_utc()).unwrap();
        let pending = aoide_storage::pairing::list_inbound(now_epoch);
        assert_eq!(pending.len(), 1, "a hex-case-varied pubkey is still the same requester — one survivor, not two");
        assert_eq!(pending[0].id, id2);

        let log = std::fs::read_to_string(&audit_log).unwrap_or_default();
        assert!(log.contains(&format!("superseding {id1}")), "{log}");

        let _ = std::fs::remove_dir_all(&root);
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    #[test]
    fn pair_reveal_completes_the_commitment_and_the_entry_gains_a_sas() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-pairreveal-ok-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        act_as(&root, "b");
        let audit_log = root.join("log");

        let nonce_a = "c".repeat(32);
        let commit = aoide_storage::pairing::derive_commit(&"a".repeat(64), &nonce_a);
        let request_params = json!({ "pubkeyHex": "a".repeat(64), "name": "box-a", "commitHex": commit, "url": "http://a/" });
        let resp = pair_request(&request_params, ConnOrigin::Loopback, &audit_log).unwrap();
        let id = resp["id"].as_str().unwrap().to_string();

        let reveal_resp = pair_reveal(&json!({ "id": id, "nonceHex": nonce_a }), &audit_log).unwrap();
        assert_eq!(reveal_resp["ok"], true);

        let now_epoch = aoide_storage::time::parse_iso_utc(&now_iso_utc()).unwrap();
        let pending = aoide_storage::pairing::list_inbound(now_epoch);
        assert_eq!(pending.len(), 1, "revealing never removes the entry");
        assert_eq!(pending[0].requester_nonce_hex.as_deref(), Some(nonce_a.as_str()));

        let log = std::fs::read_to_string(&audit_log).unwrap_or_default();
        assert!(log.contains("a2a.pairReveal"), "{log}");

        let _ = std::fs::remove_dir_all(&root);
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    #[test]
    fn pair_reveal_rejects_a_wrong_nonce_and_drops_the_parked_entry() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-pairreveal-mismatch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        act_as(&root, "b");
        let audit_log = root.join("log");

        let commit = aoide_storage::pairing::derive_commit(&"a".repeat(64), &"c".repeat(32));
        let request_params = json!({ "pubkeyHex": "a".repeat(64), "name": "box-a", "commitHex": commit, "url": "http://a/" });
        let resp = pair_request(&request_params, ConnOrigin::Loopback, &audit_log).unwrap();
        let id = resp["id"].as_str().unwrap().to_string();

        let err = pair_reveal(&json!({ "id": id, "nonceHex": "d".repeat(32) }), &audit_log).unwrap_err();
        assert_eq!(err.0, -32002, "a distinct code from an unknown id or ordinary invalid params");

        let now_epoch = aoide_storage::time::parse_iso_utc(&now_iso_utc()).unwrap();
        assert!(aoide_storage::pairing::list_inbound(now_epoch).is_empty(), "the mismatched reveal dropped the parked entry outright");

        let _ = std::fs::remove_dir_all(&root);
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    #[test]
    fn pair_reveal_rejects_an_unknown_id() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-pairreveal-unknown-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        act_as(&root, "b");
        let audit_log = root.join("log");

        let err = pair_reveal(&json!({ "id": "nosuchid", "nonceHex": "c".repeat(32) }), &audit_log).unwrap_err();
        assert_eq!(err.0, -32001);

        let _ = std::fs::remove_dir_all(&root);
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    /// Sign a `PAIRPOLL` poll of `id` with `kp` — the exact canonical string
    /// [`pair_poll`] itself verifies against, built once here so every
    /// `pair_poll_*` test below signs identically to how a real requester
    /// would (`aoide-client`'s own poll body-builder, unit-tested separately
    /// against this same shape).
    fn sign_poll(kp: &aoide_storage::identity::Keypair, id: &str, timestamp: &str, nonce: &str) -> String {
        let canonical = aoide_storage::wire_auth::canonical_string("PAIRPOLL", id, timestamp, nonce, &[]);
        aoide_storage::wire_auth::sign_hex(kp, canonical.as_bytes())
    }

    /// Existence-oracle discipline (module doc on [`pair_poll`]): an unknown
    /// id, a known id polled with a signature from the WRONG key (a
    /// non-original-requester — exactly the "arbitrary poller cannot
    /// harvest/complete someone else's pairing" security invariant), and a
    /// known id polled correctly but not yet approved all answer with the
    /// IDENTICAL `{"status":"pending"}` — nothing distinguishes them to an
    /// unauthenticated or wrongly-authenticated caller.
    #[test]
    fn pair_poll_returns_pending_uniformly_for_unknown_id_wrong_signer_and_not_yet_approved() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-pairpoll-uniform-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        act_as(&root, "b");
        let (kp_requester, _) = aoide_storage::identity::load_or_mint().unwrap();
        let requester_pubkey = kp_requester.info().pubkey_hex;
        let (kp_impostor, _) = {
            // A second, DIFFERENT identity under its own state dir, minted
            // then torn straight back down to "b"'s — this test only needs
            // its keypair, never its files.
            act_as(&root, "impostor");
            let kp = aoide_storage::identity::load_or_mint().unwrap();
            act_as(&root, "b");
            kp
        };

        let now = now_iso_utc();
        let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();
        let commit = aoide_storage::pairing::derive_commit(&requester_pubkey, &"c".repeat(32));
        let (entry, _evicted) = aoide_storage::pairing::park_inbound(
            &requester_pubkey, "box-a", "10.0.0.5", "http://box-a:8710/", &commit, &now,
            &aoide_storage::pairing::expires_at_from(now_epoch),
            None,
        )
        .unwrap();
        aoide_storage::pairing::reveal_inbound(&entry.id, &"c".repeat(32), now_epoch).unwrap();

        let audit_log = root.join("log");
        let nonce = "9".repeat(32);

        // Unknown id entirely.
        let sig_unknown = sign_poll(&kp_requester, "nosuchid", &now, &nonce);
        let resp = pair_poll(&json!({ "id": "nosuchid", "timestampIso": now, "nonceHex": nonce, "signatureHex": sig_unknown }), &audit_log).unwrap();
        assert_eq!(resp["status"], "pending");

        // Real id, but signed by a DIFFERENT key than the original requester's.
        let sig_impostor = sign_poll(&kp_impostor, &entry.id, &now, &nonce);
        let resp = pair_poll(&json!({ "id": entry.id, "timestampIso": now, "nonceHex": nonce, "signatureHex": sig_impostor }), &audit_log).unwrap();
        assert_eq!(resp["status"], "pending", "a non-original-requester's signature must never release anything");

        // Real id, correctly signed by the ORIGINAL requester — still
        // pending, because nobody has approved it yet.
        let sig_real = sign_poll(&kp_requester, &entry.id, &now, &nonce);
        let resp = pair_poll(&json!({ "id": entry.id, "timestampIso": now, "nonceHex": nonce, "signatureHex": sig_real }), &audit_log).unwrap();
        assert_eq!(resp["status"], "pending", "not yet approved");

        // All three responses are byte-identical shapes — an outsider
        // learns nothing about which case they hit.
        assert_eq!(resp.to_string(), json!({ "status": "pending" }).to_string());

        let _ = std::fs::remove_dir_all(&root);
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    /// Once the approver's own operator has locally approved (module doc on
    /// [`pair_poll`]: no network callback — `mark_inbound_approved` is the
    /// ONLY thing that flips this), a poll correctly signed by the ORIGINAL
    /// requester gets the release: `{"status":"approved","pubkeyHex":<B's
    /// own pubkey>}` — B's identity re-derived fresh, never stored on the
    /// parked entry. One audit line records the release.
    #[test]
    fn pair_poll_releases_the_approvers_pubkey_only_once_approved_and_correctly_signed() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-pairpoll-released-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        act_as(&root, "b");
        let (kp_b, _) = aoide_storage::identity::load_or_mint().unwrap();
        let (kp_requester, _) = {
            act_as(&root, "a");
            let kp = aoide_storage::identity::load_or_mint().unwrap();
            act_as(&root, "b");
            kp
        };
        let requester_pubkey = kp_requester.info().pubkey_hex;

        let now = now_iso_utc();
        let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();
        let commit = aoide_storage::pairing::derive_commit(&requester_pubkey, &"c".repeat(32));
        let (entry, _evicted) = aoide_storage::pairing::park_inbound(
            &requester_pubkey, "box-a", "10.0.0.5", "http://box-a:8710/", &commit, &now,
            &aoide_storage::pairing::expires_at_from(now_epoch),
            None,
        )
        .unwrap();
        aoide_storage::pairing::reveal_inbound(&entry.id, &"c".repeat(32), now_epoch).unwrap();

        let audit_log = root.join("log");
        let nonce = "9".repeat(32);
        let sig = sign_poll(&kp_requester, &entry.id, &now, &nonce);
        let params = json!({ "id": entry.id, "timestampIso": now, "nonceHex": nonce, "signatureHex": sig });

        // Not yet approved — pending.
        assert_eq!(pair_poll(&params, &audit_log).unwrap()["status"], "pending");

        // The approver's own operator approves — PURELY LOCAL, no network
        // call anywhere in this line (module doc: this is the whole point).
        aoide_storage::pairing::mark_inbound_approved(&entry.id, now_epoch).unwrap();

        let resp = pair_poll(&params, &audit_log).unwrap();
        assert_eq!(resp["status"], "approved");
        assert_eq!(resp["pubkeyHex"], kp_b.info().pubkey_hex, "the release carries B's OWN identity, re-derived fresh");

        let log = std::fs::read_to_string(&audit_log).unwrap();
        assert!(log.contains("a2a.pairPoll"), "{log}");

        // Approving never removed the parked entry — a repeated poll (e.g.
        // the requester's connection dropped after the first release) still
        // finds it.
        assert_eq!(aoide_storage::pairing::list_inbound(now_epoch).len(), 1);

        let _ = std::fs::remove_dir_all(&root);
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    #[test]
    fn pair_poll_rejects_malformed_params_before_any_lookup() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-pairpoll-malformed-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        act_as(&root, "b");
        let audit_log = root.join("log");

        assert_eq!(pair_poll(&json!({}), &audit_log).unwrap_err().0, -32602, "missing id");
        assert_eq!(
            pair_poll(&json!({ "id": "x", "timestampIso": "2026-08-28T00:00:00Z", "nonceHex": "short", "signatureHex": "s" }), &audit_log)
                .unwrap_err()
                .0,
            -32602,
            "malformed nonceHex"
        );

        let _ = std::fs::remove_dir_all(&root);
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    // ── P-P5: the pairing events feed (`emit_pairing_event`) ────────────

    /// Save/restore `AOIDE_DAEMON_EVENTS` alongside the existing
    /// `AOIDE_STATE_DIR`/`AOIDE_STAGE_DIR` pair, mirroring `act_as`'s own
    /// save/restore shape one level up — this env var is what redirects
    /// [`emit_pairing_event`]'s `crate::daemon::events_path` resolution
    /// onto a tempfile instead of the real runtime dir, under the same
    /// `env_lock` every test in this module already holds.
    fn set_events_path(p: &std::path::Path) -> Option<String> {
        let saved = std::env::var("AOIDE_DAEMON_EVENTS").ok();
        std::env::set_var("AOIDE_DAEMON_EVENTS", p);
        saved
    }
    fn restore_events_path(saved: Option<String>) {
        match saved {
            Some(v) => std::env::set_var("AOIDE_DAEMON_EVENTS", v),
            None => std::env::remove_var("AOIDE_DAEMON_EVENTS"),
        }
    }

    #[test]
    fn pair_request_emits_one_gate_classed_parked_line() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-pairevent-parked-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        act_as(&root, "b");
        let events_path = root.join("events.jsonl");
        let saved_events = set_events_path(&events_path);
        let audit_log = root.join("log");

        let commit = aoide_storage::pairing::derive_commit(&"a".repeat(64), &"c".repeat(32));
        let params = json!({ "pubkeyHex": "a".repeat(64), "name": "box-a", "commitHex": commit, "url": "http://box-a:8710/" });
        pair_request(&params, ConnOrigin::Remote("10.0.0.5".parse().unwrap()), &audit_log).unwrap();

        let feed = std::fs::read_to_string(&events_path).unwrap();
        let lines: Vec<&str> = feed.lines().collect();
        assert_eq!(lines.len(), 1, "exactly one line: {feed}");
        let rec: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(rec["class"], "gate");
        assert_eq!(rec["kind"], "pair-parked");
        assert_eq!(rec["source"], "a2a-door");
        assert_eq!(rec["payload"]["name"], "box-a");
        assert_eq!(rec["payload"]["originAddr"], "10.0.0.5");
        assert_eq!(rec["payload"]["url"], "http://box-a:8710/");
        assert_eq!(rec["payload"]["direction"], "inbound");

        restore_events_path(saved_events);
        let _ = std::fs::remove_dir_all(&root);
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    #[test]
    fn pairing_feed_lines_never_carry_a_sas_pubkey_nonce_or_commitment() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-pairevent-nosecrets-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        act_as(&root, "b");
        let events_path = root.join("events.jsonl");
        let saved_events = set_events_path(&events_path);
        let audit_log = root.join("log");

        let requester_pubkey = "a".repeat(64);
        let requester_nonce = "c".repeat(32);
        let commit = aoide_storage::pairing::derive_commit(&requester_pubkey, &requester_nonce);
        let params = json!({ "pubkeyHex": requester_pubkey, "name": "box-a", "commitHex": commit, "url": "http://box-a:8710/" });
        let resp = pair_request(&params, ConnOrigin::Loopback, &audit_log).unwrap();
        let id = resp["id"].as_str().unwrap().to_string();
        let approver_nonce = resp["nonceHex"].as_str().unwrap().to_string();
        pair_reveal(&json!({ "id": id, "nonceHex": requester_nonce }), &audit_log).unwrap();

        let feed = std::fs::read_to_string(&events_path).unwrap();
        assert!(!feed.is_empty());
        // No field named sas/pubkey/pubkeyHex/nonce/nonceHex/commit/commitHex
        // anywhere on the feed, AND the actual hex values never ride it —
        // both checks, per the plan (a field-name check alone would miss a
        // renamed-but-still-secret field slipping through).
        for banned_field in ["sas", "pubkey", "pubkeyHex", "nonce", "nonceHex", "commit", "commitHex"] {
            assert!(!feed.contains(banned_field), "feed line named a forbidden field `{banned_field}`: {feed}");
        }
        for secret_value in [&requester_pubkey, &requester_nonce, &approver_nonce, &commit] {
            assert!(!feed.contains(secret_value.as_str()), "feed line carried a secret hex value: {feed}");
        }

        restore_events_path(saved_events);
        let _ = std::fs::remove_dir_all(&root);
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    #[test]
    fn pair_reveal_emits_revealed_on_ok_and_nothing_on_a_mismatch() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-pairevent-reveal-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        act_as(&root, "b");
        let events_path = root.join("events.jsonl");
        let saved_events = set_events_path(&events_path);
        let audit_log = root.join("log");

        // `pair_request` itself already emits `pair-parked`, so "nothing on
        // a mismatch" is checked as "no NEW line", not "the feed stays
        // empty" — the feed already carries that one line by this point.
        let commit = aoide_storage::pairing::derive_commit(&"a".repeat(64), &"c".repeat(32));
        let params = json!({ "pubkeyHex": "a".repeat(64), "name": "box-a", "commitHex": commit, "url": "http://a/" });
        let id = pair_request(&params, ConnOrigin::Loopback, &audit_log).unwrap()["id"].as_str().unwrap().to_string();
        let lines_before_mismatch = std::fs::read_to_string(&events_path).unwrap().lines().count();
        assert_eq!(lines_before_mismatch, 1, "pair_request's own pair-parked line");
        let _ = pair_reveal(&json!({ "id": id, "nonceHex": "d".repeat(32) }), &audit_log).unwrap_err();
        let lines_after_mismatch = std::fs::read_to_string(&events_path).unwrap().lines().count();
        assert_eq!(lines_after_mismatch, lines_before_mismatch, "a reveal mismatch must emit nothing");

        // Now a genuine ok reveal: exactly one `pair-revealed` line.
        let commit2 = aoide_storage::pairing::derive_commit(&"b".repeat(64), &"e".repeat(32));
        let params2 = json!({ "pubkeyHex": "b".repeat(64), "name": "box-c", "commitHex": commit2, "url": "http://c/" });
        let id2 = pair_request(&params2, ConnOrigin::Loopback, &audit_log).unwrap()["id"].as_str().unwrap().to_string();
        pair_reveal(&json!({ "id": id2, "nonceHex": "e".repeat(32) }), &audit_log).unwrap();

        let feed = std::fs::read_to_string(&events_path).unwrap();
        let kinds: Vec<String> = feed.lines().map(|l| serde_json::from_str::<Value>(l).unwrap()["kind"].as_str().unwrap().to_string()).collect();
        assert_eq!(
            kinds,
            vec!["pair-parked".to_string(), "pair-parked".to_string(), "pair-revealed".to_string()],
            "the second `pair_request` parks its own line before its `pair_reveal` adds the third"
        );

        restore_events_path(saved_events);
        let _ = std::fs::remove_dir_all(&root);
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    /// P-P5: an unwritable events path must never fail the ceremony itself
    /// — same precedent as `aoide_secrets::broker`'s
    /// `resolve_still_succeeds_when_the_events_feed_path_is_unwritable`.
    /// Root ignores directory permissions too, so this skips under a root
    /// test runner, same precedent.
    #[test]
    fn pair_request_still_succeeds_when_the_events_path_is_unwritable() {
        if aoide_secrets::home::effective_uid() == 0 {
            return;
        }
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-pairevent-unwritable-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        act_as(&root, "b");

        let ro_dir = root.join("events-ro-dir");
        std::fs::create_dir_all(&ro_dir).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let events_path = ro_dir.join("events.jsonl");
        let saved_events = set_events_path(&events_path);
        let audit_log = root.join("log");

        let commit = aoide_storage::pairing::derive_commit(&"a".repeat(64), &"c".repeat(32));
        let params = json!({ "pubkeyHex": "a".repeat(64), "name": "box-a", "commitHex": commit, "url": "http://a/" });
        let resp = pair_request(&params, ConnOrigin::Loopback, &audit_log);

        std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(resp.is_ok(), "the ceremony must succeed even when the events feed is unwritable: {resp:?}");
        assert!(!events_path.exists(), "the feed file must never have been created under a read-only parent");

        restore_events_path(saved_events);
        let _ = std::fs::remove_dir_all(&root);
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    /// The full ceremony, end to end, over BOTH its typed codes (the
    /// mutual-code redesign, R1): request -> reveal -> pending -> B's own
    /// gate code shown (both sides derive the SAME `derive_sas` value
    /// independently) -> B approves PURELY LOCALLY (commits B's own
    /// record, marks its parked entry approved — NO network call to A —
    /// and derives its OWN reply code, `derive_reply_sas`, the code A's
    /// operator will need) -> A polls B (`aoide/pairPoll`, signed with A's
    /// OWN identity, over the SAME forward dial the request/reveal already
    /// used) -> A's own operator confirms against B's reply code (commits
    /// A's own record only once its own independently-derived
    /// `derive_reply_sas` matches B's) — PAIRING.md's own "The ceremony"
    /// diagram under Design A (task #119) and decision 4's mutual
    /// confirmation, review-bounce Findings 1 and 2 both still exercised
    /// end to end, driven through the real handler functions
    /// (`pair_request`/`pair_reveal`/`pair_poll`) and the real
    /// `aoide_storage::node_store`/`pairing` state, with
    /// `AOIDE_STATE_DIR`/`AOIDE_STAGE_DIR` swapped between steps to play box
    /// A then box B then box A again (see [`act_as`]'s own doc for why this
    /// test cannot be a genuine two-thread two-identity proof the way
    /// `cli/tests/node_connectivity.rs` is for the read-only `graphSummary`
    /// pull). B's own approve gate (`aoide-client::commands::
    /// approve_inbound`) and A's OWN final confirm-then-commit step
    /// (`pair <id>` on a polled-approved outbound entry,
    /// `aoide-client::commands::commit_outbound`) both live in
    /// `aoide-client` — simulated here by calling the same library
    /// functions those handlers call
    /// (`mark_outbound_awaiting_confirm`/`upsert_paired_node`/
    /// `take_outbound`) plus the SAME two derivations they gate on
    /// (`derive_sas`/`derive_reply_sas`), since this crate cannot depend on
    /// `aoide-client` (wrong DAG direction) — asserting both sides
    /// independently reach the IDENTICAL value for each of the two codes
    /// is what proves this end-to-end, not merely that a function of that
    /// name was called. A's own advertised `url` is deliberately a bogus,
    /// undialable address (`http://box-a-is-loopback-only.invalid/`) —
    /// under the OLD callback design B would have had to dial it to
    /// deliver the approval and the ceremony could never have completed;
    /// under Design A nothing ever dials it, so the ceremony completing
    /// anyway is itself the proof that no approver->requester network
    /// callback exists.
    #[test]
    fn full_pairing_ceremony_request_reveal_pending_approve_poll_confirm_writes_records_on_both_ends() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let root = std::env::temp_dir().join(format!(
            "aoide-a2a-ceremony-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let audit_log = root.join("log");

        // ── Step 1: box A mints its identity, picks a nonce, and commits to
        // it (`aoide-client`'s own body-builder is unit-tested separately
        // against this exact shape; here we construct the wire params
        // directly, the same way `pair_request`/`pair_reveal` will receive
        // them). A's `url` is undialable ON PURPOSE — module doc above.
        act_as(&root, "a");
        let (kp_a, _) = aoide_storage::identity::load_or_mint().unwrap();
        let pubkey_a = kp_a.info().pubkey_hex;
        let nonce_a = aoide_storage::pairing::random_hex(16);
        let commit_a = aoide_storage::pairing::derive_commit(&pubkey_a, &nonce_a);
        let request_params = json!({
            "pubkeyHex": pubkey_a, "name": "box-a", "commitHex": commit_a, "url": "http://box-a-is-loopback-only.invalid/",
        });

        // ── Step 2: box B receives it — parks pending (no SAS yet, unrevealed),
        // answers with its own pubkey + nonce.
        act_as(&root, "b");
        let resp = pair_request(&request_params, ConnOrigin::Remote("10.0.0.9".parse().unwrap()), &audit_log).unwrap();
        let id = resp["id"].as_str().unwrap().to_string();
        let pubkey_b = resp["pubkeyHex"].as_str().unwrap().to_string();
        let nonce_b = resp["nonceHex"].as_str().unwrap().to_string();

        // ── Step 3: back on box A — reveal the nonce the commitment already
        // fixed (review-bounce Finding 1's own second POST), then derive its
        // OWN SAS (now that it has both nonces) and remember the outbound
        // request in `awaiting-approval`.
        let reveal_params = json!({ "id": id, "nonceHex": nonce_a });
        act_as(&root, "b");
        let reveal_resp = pair_reveal(&reveal_params, &audit_log).unwrap();
        assert_eq!(reveal_resp["ok"], true);
        act_as(&root, "a");
        let sas_a = aoide_storage::pairing::derive_sas(&pubkey_a, &pubkey_b, &nonce_a, &nonce_b);
        let now_epoch = aoide_storage::time::parse_iso_utc(&now_iso_utc()).unwrap();
        aoide_storage::pairing::park_outbound(aoide_storage::pairing::OutboundPairingRequest {
            id: id.clone(),
            url: "http://box-b:9-a2a/".to_string(),
            name: "box-b".to_string(),
            pubkey_hex: pubkey_b.clone(),
            requester_nonce_hex: nonce_a.clone(),
            approver_nonce_hex: nonce_b.clone(),
            requested_at: now_iso_utc(),
            expires_at: aoide_storage::pairing::expires_at_from(now_epoch),
            state: aoide_storage::pairing::OutboundState::AwaitingApproval,
            via: None,
            tries: 0,
        })
        .unwrap();

        // ── Step 4: box B's operator lists pending, derives the SAME gate
        // code independently from its own stored (now-revealed) copy of
        // the transcript, and approves — committing B's OWN node record
        // for A. B also derives its OWN reply code here (`derive_reply_sas`
        // — the mutual-code redesign, R1): the SAME transcript plus a
        // leading domain tag, never the code just used above, since B's
        // own approve is what `commands::approve_inbound` computes and
        // relays to A's operator the moment it commits.
        act_as(&root, "b");
        let pending = aoide_storage::pairing::list_inbound(now_epoch);
        assert_eq!(pending.len(), 1);
        let entry = pending.into_iter().find(|e| e.id == id).unwrap();
        let requester_nonce = entry.requester_nonce_hex.clone().expect("revealed by step 3");
        let (kp_b, _) = aoide_storage::identity::load_or_mint().unwrap();
        let sas_b = aoide_storage::pairing::derive_sas(
            &entry.pubkey_hex,
            &kp_b.info().pubkey_hex,
            &requester_nonce,
            &entry.approver_nonce_hex,
        );
        assert_eq!(sas_a, sas_b, "both sides must derive the IDENTICAL gate code from the same transcript");
        let reply_sas_b = aoide_storage::pairing::derive_reply_sas(
            &entry.pubkey_hex,
            &kp_b.info().pubkey_hex,
            &requester_nonce,
            &entry.approver_nonce_hex,
        );
        assert_ne!(sas_b, reply_sas_b, "the gate code and the reply code must never coincide");

        // A poll BEFORE approval must answer `pending` — never leak that the
        // id exists as anything more (module doc on `pair_poll`).
        let poll_nonce = "9".repeat(32);
        let poll_ts = now_iso_utc();
        let poll_sig_pre = sign_poll(&kp_a, &id, &poll_ts, &poll_nonce);
        let poll_params = json!({ "id": id, "timestampIso": poll_ts, "nonceHex": poll_nonce, "signatureHex": poll_sig_pre });
        let poll_before = pair_poll(&poll_params, &audit_log).unwrap();
        assert_eq!(poll_before["status"], "pending", "not approved yet");

        // Design A (task #119): B's own node record commits, exactly as
        // before — but approving is now PURELY LOCAL. `mark_inbound_approved`
        // (not `take_inbound`) leaves the entry PARKED so A's later poll can
        // still find it; nothing here dials A's `url` at all.
        aoide_storage::pairing::mark_inbound_approved(&id, now_epoch).unwrap();
        let mut nodes_b = aoide_storage::node_store::load_nodes();
        aoide_storage::node_store::upsert_paired_node(&mut nodes_b, &entry.name, &entry.url, &entry.pubkey_hex, &now_iso_utc(), &["read".to_string()]);
        aoide_storage::node_store::save_nodes(&nodes_b).unwrap();

        // B's own record for A: pubkey = A's real key, verified, name =
        // A's claimed name, url = what A self-reported (the UNDIALABLE
        // address — B's own commit above never touched it as a network
        // target, only as a stored string).
        let nodes_b_final = aoide_storage::node_store::load_nodes();
        assert_eq!(nodes_b_final.len(), 1);
        assert_eq!(nodes_b_final[0].name, "box-a");
        assert_eq!(nodes_b_final[0].pubkey.as_deref(), Some(pubkey_a.as_str()));
        assert!(nodes_b_final[0].verified);
        assert_eq!(nodes_b_final[0].url, "http://box-a-is-loopback-only.invalid/");
        // P-P3's lane, untouched this phase.
        assert!(!nodes_b_final[0].autogate);
        assert!(!nodes_b_final[0].hub);

        // ── Step 5: A polls B's door — `aoide/pairPoll`, signed with A's OWN
        // identity, over the SAME forward dial the request/reveal already
        // used. This REPLACES the old reverse callback outright: nothing
        // dials A's (undialable) `url` anywhere in this test, and the
        // ceremony completes anyway — that IS the "no callback" proof.
        let poll_sig = sign_poll(&kp_a, &id, &poll_ts, &poll_nonce);
        let poll_params_post_approve = json!({ "id": id, "timestampIso": poll_ts, "nonceHex": poll_nonce, "signatureHex": poll_sig });
        let poll_resp = pair_poll(&poll_params_post_approve, &audit_log).unwrap();
        assert_eq!(poll_resp["status"], "approved");
        assert_eq!(poll_resp["pubkeyHex"], kp_b.info().pubkey_hex);
        assert!(aoide_storage::node_store::load_nodes().len() == 1, "still only B's own record — the poll commits nothing on B's side");

        // ── Step 6: back on A — the poll response transitions A's outbound
        // entry (`mark_outbound_awaiting_confirm`, the SAME function the old
        // callback handler used to call — only the TRIGGER moved), rejecting
        // a mismatched pubkey the same way a substituted reveal would be
        // rejected (review-bounce Finding 2, preserved). A's OWN operator
        // then confirms — gating on B's REPLY code, never the gate code A's
        // own screen already showed (`pair <id>` a second time,
        // requester-side — `aoide-client::commands::commit_outbound`'s own
        // confirm branch; simulated here via the same library calls that
        // handler makes, since this crate cannot depend on `aoide-client`).
        act_as(&root, "a");
        let polled_pubkey = poll_resp["pubkeyHex"].as_str().unwrap();
        let marked = aoide_storage::pairing::mark_outbound_awaiting_confirm(&id, polled_pubkey, now_epoch).unwrap();
        assert_eq!(marked.state, aoide_storage::pairing::OutboundState::AwaitingConfirm);
        let reply_sas_a = aoide_storage::pairing::derive_reply_sas(&pubkey_a, &marked.pubkey_hex, &marked.requester_nonce_hex, &marked.approver_nonce_hex);
        assert_eq!(reply_sas_a, reply_sas_b, "A independently re-derives the IDENTICAL reply code B already computed at approve time");
        assert_ne!(reply_sas_a, sas_a, "A's own confirm gates on the reply code, never the gate code its own screen already showed");
        let mut nodes_a = aoide_storage::node_store::load_nodes();
        aoide_storage::node_store::upsert_paired_node(&mut nodes_a, &marked.name, &marked.url, &marked.pubkey_hex, &now_iso_utc(), &["read".to_string()]);
        aoide_storage::node_store::save_nodes(&nodes_a).unwrap();
        aoide_storage::pairing::take_outbound(&id, now_epoch).unwrap();

        // A's own record for B: pubkey = B's real key, verified, name = the
        // nickname A itself chose at request time, url = what A dialed.
        let nodes_a_final = aoide_storage::node_store::load_nodes();
        assert_eq!(nodes_a_final.len(), 1);
        assert_eq!(nodes_a_final[0].name, "box-b");
        assert_eq!(nodes_a_final[0].pubkey.as_deref(), Some(pubkey_b.as_str()));
        assert!(nodes_a_final[0].verified);
        assert_eq!(nodes_a_final[0].url, "http://box-b:9-a2a/");

        // The outbound entry is consumed — a second confirm with the same
        // id now finds nothing.
        assert!(aoide_storage::pairing::list_outbound(now_epoch).is_empty());

        // B's own inbound entry, meanwhile, stays parked (approved, never
        // taken) until it expires — the poll never removes it either, so a
        // repeated/duplicate poll from A would still find the SAME release.
        act_as(&root, "b");
        assert_eq!(aoide_storage::pairing::list_inbound(now_epoch).len(), 1);

        // The private key never rode any wire body this test constructed —
        // grep every JSON value exchanged for anything key-shaped beyond the
        // public hex fields already asserted above.
        for v in [&request_params, &resp, &reveal_params, &reveal_resp, &poll_params, &poll_before, &poll_params_post_approve, &poll_resp] {
            let dumped = v.to_string().to_lowercase();
            assert!(!dumped.contains("signing"), "no private material anywhere on the wire: {dumped}");
        }

        let _ = std::fs::remove_dir_all(&root);
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
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
            signed_node: None,
            signed_timestamp: None,
            signed_nonce: None,
            signed_signature: None,
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
        // Wrong method / path / unparseable body → not a stream.
        assert_eq!(streaming_method(&mk("GET", "/", r#"{"method":"message/stream"}"#)), None);
        assert_eq!(streaming_method(&mk("POST", "/other", r#"{"method":"message/stream"}"#)), None);
        assert_eq!(streaming_method(&mk("POST", "/", "not json")), None);
    }

    // Routing: non-matching path/method -> 404/405 with a JSON-RPC-style body.
    #[test]
    fn unknown_path_is_404_and_wrong_method_on_a_known_path_is_405() {
        let registry = Registry::new();
        let (status, body, _) = route(
            &HttpRequest {
                method: "GET".into(),
                path: "/nope".into(),
                body: vec![],
                bearer: None,
                signed_node: None,
                signed_timestamp: None,
                signed_nonce: None,
                signed_signature: None,
            },
            "127.0.0.1",
            8710,
            Path::new("/dev/null"),
            "",
            "",
            "aoide",
            ConnOrigin::Loopback,
            "",
            &registry,
            None,
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
                signed_node: None,
                signed_timestamp: None,
                signed_nonce: None,
                signed_signature: None,
            },
            "127.0.0.1",
            8710,
            Path::new("/dev/null"),
            "",
            "",
            "aoide",
            ConnOrigin::Loopback,
            "",
            &registry,
            None,
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
                signed_node: None,
                signed_timestamp: None,
                signed_nonce: None,
                signed_signature: None,
            };
            let (status, body, label) = route(
                &req,
                "127.0.0.1",
                8710,
                Path::new("/dev/null"),
                "",
                "",
                "aoide",
                ConnOrigin::Loopback,
                "",
                &registry,
                None,
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
            signed_node: None,
            signed_timestamp: None,
            signed_nonce: None,
            signed_signature: None,
        };
        let (status, body, label) = route(
            &req,
            "127.0.0.1",
            8710,
            Path::new("/dev/null"),
            "",
            "",
            "aoide",
            ConnOrigin::Loopback,
            "s3cr3t",
            &registry,
            None,
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
            signed_node: None,
            signed_timestamp: None,
            signed_nonce: None,
            signed_signature: None,
        };
        let (status, body, _) = route(
            &req,
            "127.0.0.1",
            8710,
            Path::new("/dev/null"),
            "",
            "",
            "aoide",
            ConnOrigin::Loopback,
            "s3cr3t",
            &registry,
            None,
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
            signed_node: None,
            signed_timestamp: None,
            signed_nonce: None,
            signed_signature: None,
        };
        let (status, body, _) = route(
            &req,
            "127.0.0.1",
            8710,
            Path::new("/dev/null"),
            "",
            "",
            "aoide",
            ConnOrigin::Loopback,
            "s3cr3t",
            &registry,
            None,
        );
        assert_eq!(status, 200);
        let served: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(served, expected);
    }

    // ── task #84: inbound bearer resolved via the secrets broker ────────────

    fn bearer_cfg(bearer_secret: &str, secrets_socket: &Path, file_token: &str) -> InboundBearerConfig {
        InboundBearerConfig {
            bearer_secret: bearer_secret.to_string(),
            secrets_socket: secrets_socket.to_path_buf(),
            file_token: file_token.to_string(),
        }
    }

    #[test]
    fn resolve_inbound_bearer_falls_through_to_the_file_token_when_bearer_secret_is_unset() {
        let cfg = bearer_cfg("", Path::new("/tmp/aoide-a2a-unused.sock"), "file-token-value");
        assert_eq!(resolve_inbound_bearer(&cfg), "file-token-value");
    }

    #[test]
    fn resolve_inbound_bearer_with_neither_configured_is_the_empty_off_path() {
        let cfg = bearer_cfg("", Path::new("/tmp/aoide-a2a-unused.sock"), "");
        assert_eq!(resolve_inbound_bearer(&cfg), "");
        // Off-path is byte-identical to before this task: `token_authorized`
        // never gates anything when `expected_token` is empty.
        assert!(token_authorized(false, classify_token("", None)));
    }

    /// A dead broker socket (unreachable — the same shape as a stopped
    /// broker) FAILS CLOSED: [`resolve_inbound_bearer`] returns a non-empty
    /// sentinel, never the file token (a resolve failure must not silently
    /// fall back to the weaker mechanism) and never empty (which would read
    /// as "not configured" and open the door wide).
    #[test]
    fn resolve_inbound_bearer_fails_closed_on_an_unreachable_broker() {
        let dead = Path::new("/tmp/aoide-a2a-bearer-nonexistent-test.sock");
        let cfg = bearer_cfg("some-secret", dead, "file-token-should-be-ignored");
        let sentinel = resolve_inbound_bearer(&cfg);
        assert!(!sentinel.is_empty(), "a resolve failure must never read as 'not configured'");
        assert_ne!(sentinel, "file-token-should-be-ignored", "must not silently fall back to the file token");

        // Feed it through the EXACT machinery every other bearer check in
        // this file runs: nothing a caller could plausibly present matches,
        // and even the sentinel value ITSELF is never handed to a caller —
        // it only ever exists on this side of the comparison.
        assert!(!token_authorized(true, classify_token(&sentinel, Some("wrong"))));
        assert!(!token_authorized(true, classify_token(&sentinel, None)));
    }

    /// Two consecutive resolve failures never produce the same sentinel —
    /// pinning that it is fresh per call, not a fixed placeholder string an
    /// attacker could learn once and replay.
    #[test]
    fn resolve_inbound_bearer_sentinel_is_fresh_every_call() {
        let dead = Path::new("/tmp/aoide-a2a-bearer-nonexistent-test-2.sock");
        let cfg = bearer_cfg("some-secret", dead, "");
        let a = resolve_inbound_bearer(&cfg);
        let b = resolve_inbound_bearer(&cfg);
        assert_ne!(a, b);
    }

    /// A real broker + socket round trip: `bearer_secret` set AND a
    /// (deliberately wrong) `file_token` also set — the broker-resolved
    /// value wins outright, proving the precedence [`resolve_inbound_bearer`]'s
    /// own doc states.
    #[test]
    fn resolve_inbound_bearer_prefers_a_resolved_broker_secret_over_the_file_token() {
        let home = std::env::temp_dir().join(format!(
            "aoide-a2a-bearer-precedence-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        aoide_secrets::store::save_policies(
            &home,
            &[aoide_secrets::policy::Policy::new("melete-door-token", "file", "k")],
        )
        .unwrap();

        let socket_path = std::path::PathBuf::from(format!(
            "/tmp/aoide-a2a-bearer-precedence-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let home_for_thread = home.clone();
        let sock_for_thread = socket_path.clone();
        let broker_thread = std::thread::spawn(move || {
            let _ = aoide_secrets::broker::serve(&home_for_thread, &sock_for_thread);
        });
        let mut connected = false;
        for _ in 0..50 {
            if UnixStream::connect(&socket_path).is_ok() {
                connected = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(connected, "broker did not bind {} in time", socket_path.display());

        assert_eq!(
            aoide_secrets::client::put(&socket_path, "melete-door-token", "the-broker-value", false),
            Ok(false)
        );

        let cfg = bearer_cfg("melete-door-token", &socket_path, "the-file-value-must-lose");
        assert_eq!(resolve_inbound_bearer(&cfg), "the-broker-value");

        drop(broker_thread);
        std::fs::remove_file(&socket_path).ok();
        std::fs::remove_dir_all(&home).ok();
    }

    // ── NO-CACHE / no-log grep gate (task #84 PINNED CONSTRAINT) ────────────

    /// A resolved/expected bearer value must NEVER reach an `audit(...)`
    /// call — grep this crate's own source for every `audit(` call site and
    /// forbid the identifiers that hold token bytes (`expected_token`,
    /// `presented_token`) from appearing inside its argument list. A future
    /// edit that accidentally threads either one into an audit line fails
    /// this test loudly instead of silently leaking a bearer into
    /// `~/Aoide/log`.
    /// Only the PRODUCTION half of this file (everything before `mod
    /// tests {`) — scanning the test module itself would trip over this
    /// very grep gate's own source text (its doc comments and string
    /// literals mention "audit(`"/`expected_token` by name to describe
    /// what it checks), which is noise, not a real call site.
    fn production_source() -> &'static str {
        let src = include_str!("a2a.rs");
        let test_mod_start = src.find("#[cfg(test)]\nmod tests {").expect("this file has a `mod tests` block");
        &src[..test_mod_start]
    }

    /// Every balanced-paren call site in `production_source()` whose callee
    /// name is `name` (e.g. `"audit"`, `"eprintln!"` including its `!`) —
    /// paren-depth tracked so a call whose OWN arguments contain a nested
    /// `(...)` (a `format!(...)` argument, a `Door::A2a` path — none
    /// actually parenthesized, but future-proofed anyway) is captured
    /// whole, not truncated at the first inner `)`.
    fn call_sites<'a>(src: &'a str, name: &str) -> Vec<&'a str> {
        let needle = format!("{name}(");
        let mut sites = Vec::new();
        let mut idx = 0;
        while let Some(rel) = src[idx..].find(&needle) {
            let start = idx + rel;
            let mut depth = 0i32;
            let mut end = None;
            for (offset, ch) in src[start..].char_indices() {
                match ch {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(start + offset + 1);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let Some(end) = end else { break };
            sites.push(&src[start..end]);
            idx = end;
        }
        sites
    }

    /// A resolved/expected bearer value must NEVER reach an `audit(...)`
    /// call — grep this crate's own PRODUCTION source (never the test
    /// module — see `production_source`'s doc) for every `audit(` call
    /// site and forbid the identifiers that hold token bytes
    /// (`expected_token`, `presented_token`) from appearing inside its
    /// argument list. A future edit that accidentally threads either one
    /// into an audit line fails this test loudly instead of silently
    /// leaking a bearer into `~/Aoide/log`.
    #[test]
    fn bearer_identifiers_never_reach_an_audit_call_grep_gate() {
        let src = production_source();
        let forbidden = ["expected_token", "presented_token"];
        let sites = call_sites(src, "audit");
        for call in &sites {
            for name in forbidden {
                assert!(
                    !call.contains(name),
                    "an audit(...) call mentions `{name}` — a resolved/expected bearer value must \
                     never reach the audit log:\n{call}"
                );
            }
        }
        assert!(sites.len() > 5, "sanity: this file should have several audit( call sites to check");
    }

    /// Same discipline, `eprintln!` (`resolve_inbound_bearer`'s own
    /// diagnostic on a resolve failure logs the SECRET'S NAME and the
    /// broker's error reason — never a resolved value).
    #[test]
    fn bearer_identifiers_never_reach_an_eprintln_call_grep_gate() {
        let src = production_source();
        let forbidden = ["expected_token", "presented_token"];
        for call in call_sites(src, "eprintln!") {
            for name in forbidden {
                assert!(
                    !call.contains(name),
                    "an eprintln!(...) call mentions `{name}` — a resolved/expected bearer value must \
                     never reach a log line:\n{call}"
                );
            }
        }
    }

    // ── `aoide/mailDeposit` (messaging plan P-M2, CONTRACTS.md §6) ──────────

    fn mail_deposit_root(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "aoide-a2a-maildeposit-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ))
    }

    /// Restores `AOIDE_STATE_DIR`/`AOIDE_STAGE_DIR` and removes `root` — the
    /// closing half of every test below, matching `a_successfully_
    /// delivered_message_send_files_into_the_mailbase`'s own inline shape
    /// rather than introducing a new fixture struct for eight call sites.
    fn mail_deposit_cleanup(root: &std::path::Path, saved_state: Option<String>, saved_stage: Option<String>) {
        let _ = std::fs::remove_dir_all(root);
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    fn mail_deposit_ctx<'a>(audit_log: &'a std::path::Path, signed_node_name: Option<&'a str>) -> RequestCtx<'a> {
        RequestCtx {
            audit_log,
            spawn_agent: "",
            spawn_cwd: "",
            origin: ConnOrigin::Loopback,
            node_name: "",
            self_url: "",
            expected_token: "",
            presented_token: None,
            signed_node_name,
        }
    }

    #[test]
    fn node_may_message_covers_paired_allowed_paired_denied_and_unpaired() {
        let mut paired_allowed = fixture_node("box-b", "http://10.0.0.5:8710/", false);
        paired_allowed.verified = true;
        paired_allowed.allows = vec!["read".to_string(), "message".to_string()];
        assert!(node_may_message(&paired_allowed), "paired + message in allows");

        let mut paired_denied = paired_allowed.clone();
        paired_denied.allows = vec!["read".to_string()]; // message revoked.
        assert!(!node_may_message(&paired_denied), "paired but message NOT in allows");

        let mut unpaired = paired_allowed.clone();
        unpaired.verified = false; // never completed the ceremony.
        assert!(!node_may_message(&unpaired), "allows populated but never verified — still refused");
    }

    #[test]
    fn deposit_admitted_requires_the_signature_rung_specifically() {
        // Unlike `spawn_admitted`, `deposit_admitted` takes a plain
        // `Option<&Node>`, never `Option<(&Node, NodeRung)>` — `message` has
        // no now-superseded Token-rung history to migrate off of
        // (`node_may_message`'s own doc: "signature-only from the start"),
        // so there is no THIRD rung to construct a case from. `resolved` is
        // populated ONLY by `mail_deposit`'s own `ctx.signed_node_name.
        // and_then(...)` line, so `Some` here already MEANS "resolved via a
        // verified per-request signature" — this test pins that a
        // paired+allowed node still refuses the instant resolution drops to
        // `None`, the shape an unsigned, addr-only, or bare-token caller
        // collapses to (proven at the integration level by
        // `an_unsigned_caller_is_refused_by_mail_deposit`, below).
        let mut paired_allowed = fixture_node("box-b", "http://10.0.0.5:8710/", false);
        paired_allowed.verified = true;
        paired_allowed.allows = vec!["message".to_string()];

        assert!(deposit_admitted(Some(&paired_allowed)), "paired + message in allows + signature-resolved — admitted");
        assert!(!deposit_admitted(None), "no signature resolution at all — refused, with no fallback rung to try instead");
    }

    #[test]
    fn an_unsigned_caller_is_refused_by_mail_deposit() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let root = mail_deposit_root("unsigned");
        act_as(&root, "here");

        let audit_log = root.join("log");
        let envelope = aoide_storage::mail::mint_outbound_letter("alice", "there", "bob", "hi").unwrap();
        let ctx = mail_deposit_ctx(&audit_log, None);
        let params = json!({ "envelope": envelope });
        let err = mail_deposit(&params, &ctx).expect_err("no signature headers — must refuse, never file");
        assert_eq!(err.0, -32010);

        assert!(aoide_storage::mail::read_base().unwrap().is_empty(), "an unsigned caller's envelope is never filed");

        mail_deposit_cleanup(&root, saved_state, saved_stage);
    }

    #[test]
    fn a_paired_node_without_message_is_refused_with_a_taught_error() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let root = mail_deposit_root("noallow");
        act_as(&root, "here");

        setup_signed_node_with_allows("box-b", &["read"]); // verified, paired, but no "message"

        let audit_log = root.join("log");
        let envelope = aoide_storage::mail::mint_outbound_letter("alice", "there", "bob", "hi").unwrap();
        let ctx = mail_deposit_ctx(&audit_log, Some("box-b"));
        let params = json!({ "envelope": envelope });
        let (code, msg) = mail_deposit(&params, &ctx).expect_err("paired but message not in allows — must refuse");
        assert_eq!(code, -32010);
        assert!(msg.contains("node allow box-b message on"), "names the exact fix: {msg}");

        mail_deposit_cleanup(&root, saved_state, saved_stage);
    }

    /// Registers a node under `display::local_host_name()` — the only name
    /// [`aoide_storage::mail::mint_outbound_letter`] will ever stamp as
    /// `header.from.node` (P-M1 ruling: self never crosses the wire) — so an
    /// envelope this test mints has a genuinely verifiable origin, using
    /// this test process's own identity as BOTH the origin's and the hop's
    /// key (the same "one process plays both roles" shortcut
    /// [`setup_signed_node`] already documents). Origin and hop coincide in
    /// P-M2, so this ALSO doubles as the connection's signed hop.
    fn setup_verifiable_origin(allows: &[&str]) -> String {
        let origin_name = aoide_storage::display::local_host_name();
        setup_signed_node_with_allows(&origin_name, allows);
        origin_name
    }

    #[test]
    fn a_deposit_from_a_verified_message_holding_node_files_a_letter() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let root = mail_deposit_root("files");
        act_as(&root, "here");

        let origin_name = setup_verifiable_origin(&["message"]);
        let envelope = aoide_storage::mail::mint_outbound_letter("alice", "here", "conductor", "hello from the wire").unwrap();
        assert_eq!(envelope.header.from.node, origin_name);

        let audit_log = root.join("log");
        let ctx = mail_deposit_ctx(&audit_log, Some(&origin_name));
        let req = json!({ "jsonrpc": "2.0", "id": 1, "method": "aoide/mailDeposit", "params": { "envelope": envelope } });
        let resp = handle_jsonrpc(&req, &ctx);
        assert_eq!(resp["result"]["status"], "accepted", "{resp}");

        let entries = aoide_storage::mail::read_base().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].envelope.header.to.name, "conductor");
        assert_eq!(entries[0].via, origin_name, "via is the HOP's resolved name");

        mail_deposit_cleanup(&root, saved_state, saved_stage);
    }

    #[test]
    fn a_filed_remote_letter_does_not_ring_in_the_door_process() {
        // P-M5a-2c: the architecture owner's ruling on b8af466 withdrew
        // `mail_deposit`'s in-process `aoide_conduct::graph::ring` call — a
        // ring now executes only inside the resident daemon. The fixture is
        // unchanged from the slice this corrects (a REAL headless wrap +
        // hook-fed child pair, armed for `conductor`, built the identical
        // way `aoide-conduct`'s own `graph::doorbell` tests build it) so the
        // ONLY thing that changed is the assertion: the deposit still files
        // and acks, but the armed reader's socket must never see a
        // connection, and the letter's own latch must stay armed for the
        // next daemon-side trigger (P-M5b-2 gives this door a forward path
        // of its own).
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_runtime = std::env::var("XDG_RUNTIME_DIR").ok();
        let root = mail_deposit_root("no-ring");
        act_as(&root, "here");
        std::fs::create_dir_all(root.join("runtime")).unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", root.join("runtime"));

        let origin_name = setup_verifiable_origin(&["message"]);

        let wrap_id = "wrap-1";
        let child_id = "wrap-1-child";
        let socket = root.join("wrap-1.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let wrap = SessionRecord {
            session_id: wrap_id.to_string(),
            state: "idle".to_string(),
            agent: "claude".to_string(),
            conductable: Some(true),
            socket: Some(socket.to_string_lossy().into_owned()),
            headless: true,
            ..Default::default()
        };
        let child = SessionRecord {
            session_id: child_id.to_string(),
            state: "stopped".to_string(),
            agent: "claude".to_string(),
            parent_session_id: Some(wrap_id.to_string()),
            ..Default::default()
        };
        write_stage(&sessions_path(), &SessionsFile { schema_version: String::new(), sessions: vec![wrap, child] }).unwrap();
        aoide_storage::mail::enrol_reader("conductor", wrap_id).unwrap();

        let envelope = aoide_storage::mail::mint_outbound_letter("alice", "here", "conductor", "hello from the wire").unwrap();
        let audit_log = root.join("log");
        let ctx = mail_deposit_ctx(&audit_log, Some(&origin_name));
        let req = json!({ "jsonrpc": "2.0", "id": 1, "method": "aoide/mailDeposit", "params": { "envelope": envelope } });

        let resp = handle_jsonrpc(&req, &ctx);
        assert_eq!(resp["result"]["status"], "accepted", "{resp}");

        // No bytes ever arrive — a short bounded poll, not a blocking
        // `accept`: there is no ring left in this process to connect, so
        // nothing here is ever supposed to become readable.
        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(200);
        loop {
            match listener.accept() {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                other => panic!("the door process must never ring the target itself: {other:?}"),
            }
            if std::time::Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let targets = aoide_storage::mail::ring_targets("conductor").unwrap();
        assert_eq!(targets.armed.len(), 1, "still armed for the next daemon-side trigger — a deposit files and acks, it does not ring");

        // Structural, same discipline the slice this corrects held: no arm
        // of `mail_deposit` may call `graph::ring(` anymore (flipped from
        // that slice's own "the letter arm must call it" assertion).
        let src = production_source();
        assert!(call_sites(src, "graph::ring").is_empty(), "aoide-server must never call graph::ring( directly anymore");

        mail_deposit_cleanup(&root, saved_state, saved_stage);
        match saved_runtime {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
    }

    #[test]
    fn a_duplicate_deposit_returns_duplicate_and_files_nothing_twice() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let root = mail_deposit_root("dup");
        act_as(&root, "here");

        // `spool_and_drain_ack`'s best-effort drain must never hang or
        // block this test — a dead loopback port refuses instantly, unlike
        // the file's own `"http://node/"` placeholder (unresolvable
        // hostname, fine for the pure-predicate tests above that never
        // actually dial it, wrong for one that does).
        let origin_name = setup_verifiable_origin(&["message"]);
        let mut nodes = aoide_storage::node_store::load_nodes();
        nodes[0].url = "http://127.0.0.1:1/".to_string();
        aoide_storage::node_store::save_nodes(&nodes).unwrap();

        let envelope = aoide_storage::mail::mint_outbound_letter("alice", "here", "conductor", "hello twice").unwrap();
        let audit_log = root.join("log");
        let ctx = mail_deposit_ctx(&audit_log, Some(&origin_name));
        let params = json!({ "envelope": envelope });

        let first = mail_deposit(&params, &ctx).unwrap();
        assert_eq!(first["status"], "accepted");

        let second = mail_deposit(&params, &ctx).unwrap();
        assert_eq!(second["status"], "duplicate");

        let entries = aoide_storage::mail::read_base().unwrap();
        assert_eq!(entries.len(), 1, "the duplicate deposit files nothing a second time");

        mail_deposit_cleanup(&root, saved_state, saved_stage);
    }

    #[test]
    fn a_duplicate_of_a_filed_letter_respools_its_ack() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let root = mail_deposit_root("dup-respool");
        act_as(&root, "here");

        let origin_name = setup_verifiable_origin(&["message"]);
        let mut nodes = aoide_storage::node_store::load_nodes();
        nodes[0].url = "http://127.0.0.1:1/".to_string();
        aoide_storage::node_store::save_nodes(&nodes).unwrap();

        let envelope = aoide_storage::mail::mint_outbound_letter("alice", "here", "conductor", "hi").unwrap();
        let audit_log = root.join("log");
        let ctx = mail_deposit_ctx(&audit_log, Some(&origin_name));
        let params = json!({ "envelope": envelope });

        mail_deposit(&params, &ctx).unwrap();
        let before = aoide_storage::outbox::list_entries(&origin_name).unwrap();
        assert_eq!(before.len(), 1, "filing a letter spools an ack toward the origin");
        aoide_storage::outbox::remove_entry(&origin_name, &before[0].envelope.msgid).unwrap();
        assert!(aoide_storage::outbox::list_entries(&origin_name).unwrap().is_empty(), "ack removed, simulating an earlier successful drain");

        mail_deposit(&params, &ctx).unwrap(); // the SAME envelope again — a duplicate.
        let after = aoide_storage::outbox::list_entries(&origin_name).unwrap();
        assert_eq!(after.len(), 1, "a duplicate of a filed LETTER respools its ack");
        assert_eq!(after[0].envelope.header.kind, aoide_storage::mail::ENTRY_TYPE_RECEIPT);

        mail_deposit_cleanup(&root, saved_state, saved_stage);
    }

    #[test]
    fn repeated_duplicate_redeliveries_spool_exactly_one_ack() {
        // The outbox investigation's own root cause: a sender that never
        // sees its ack redelivers the SAME letter, `mail::deposit`
        // correctly classifies each redelivery as `Duplicate{filed_letter:
        // true}`, and `spool_and_drain_ack` used to mint a BRAND-NEW ack
        // envelope — new msgid, new file — on every single one, with the
        // ack still sitting undelivered in the spool the whole time (never
        // removed, so this never depends on `mail_deposit`'s own
        // best-effort drain succeeding or failing). This pins the ledger
        // fix: N redeliveries of the same letter must leave exactly ONE
        // spooled ack for that (reader, msgid), not N.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let root = mail_deposit_root("dup-flood-one-ack");
        act_as(&root, "here");

        let origin_name = setup_verifiable_origin(&["message"]);
        let mut nodes = aoide_storage::node_store::load_nodes();
        nodes[0].url = "http://127.0.0.1:1/".to_string();
        aoide_storage::node_store::save_nodes(&nodes).unwrap();

        let envelope = aoide_storage::mail::mint_outbound_letter("alice", "here", "conductor", "hi").unwrap();
        let audit_log = root.join("log");
        let ctx = mail_deposit_ctx(&audit_log, Some(&origin_name));
        let params = json!({ "envelope": envelope });

        let first = mail_deposit(&params, &ctx).unwrap();
        assert_eq!(first["status"], "accepted");
        let first_spool = aoide_storage::outbox::list_entries(&origin_name).unwrap();
        assert_eq!(first_spool.len(), 1, "the first filing spools exactly one ack");
        let ack_msgid = first_spool[0].envelope.msgid.clone();

        // The ack is deliberately left in the spool (undelivered) across
        // every redelivery below — exactly the "dead link" condition that
        // produced 16.5k duplicates.
        for _ in 0..10 {
            let redelivered = mail_deposit(&params, &ctx).unwrap();
            assert_eq!(redelivered["status"], "duplicate");
        }

        let spool = aoide_storage::outbox::list_entries(&origin_name).unwrap();
        assert_eq!(spool.len(), 1, "ten redeliveries must still leave exactly one spooled ack");
        assert_eq!(spool[0].envelope.msgid, ack_msgid, "the surviving ack is the ORIGINAL one, never re-minted");

        mail_deposit_cleanup(&root, saved_state, saved_stage);
    }

    #[test]
    fn filing_a_letter_spools_an_ack_signed_by_this_box() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let root = mail_deposit_root("ack-shape");
        act_as(&root, "here");

        let origin_name = setup_verifiable_origin(&["message"]);
        let mut nodes = aoide_storage::node_store::load_nodes();
        nodes[0].url = "http://127.0.0.1:1/".to_string();
        aoide_storage::node_store::save_nodes(&nodes).unwrap();

        let envelope = aoide_storage::mail::mint_outbound_letter("alice", "here", "conductor", "hi").unwrap();
        let audit_log = root.join("log");
        let ctx = mail_deposit_ctx(&audit_log, Some(&origin_name));
        let params = json!({ "envelope": envelope });
        let result = mail_deposit(&params, &ctx).unwrap();
        let msgid = result["msgid"].as_str().unwrap().to_string();

        let spooled = aoide_storage::outbox::list_entries(&origin_name).unwrap();
        assert_eq!(spooled.len(), 1);
        let ack = &spooled[0].envelope;
        assert_eq!(ack.header.kind, aoide_storage::mail::ENTRY_TYPE_RECEIPT);
        assert_eq!(ack.header.to.node, origin_name, "the ack's `to` is the origin");
        assert_eq!(ack.text, msgid, "the ack's text is the acked msgid");
        assert_eq!(ack.header.from.node, aoide_storage::display::local_host_name(), "signed by this box");

        mail_deposit_cleanup(&root, saved_state, saved_stage);
    }

    #[test]
    fn a_deposit_audits_under_its_own_method_label() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let root = mail_deposit_root("audit-label");
        act_as(&root, "here");

        let origin_name = setup_verifiable_origin(&["message"]);
        let mut nodes = aoide_storage::node_store::load_nodes();
        nodes[0].url = "http://127.0.0.1:1/".to_string();
        aoide_storage::node_store::save_nodes(&nodes).unwrap();

        let envelope = aoide_storage::mail::mint_outbound_letter("alice", "here", "conductor", "hi").unwrap();
        let audit_log = root.join("log");
        let ctx = mail_deposit_ctx(&audit_log, Some(&origin_name));
        let params = json!({ "envelope": envelope });
        mail_deposit(&params, &ctx).unwrap();

        let log = std::fs::read_to_string(&audit_log).unwrap();
        assert!(log.contains("a2a.aoide/mailDeposit"), "{log}");
        assert!(!log.contains("a2a.rpc"), "never falls back to the generic label: {log}");

        mail_deposit_cleanup(&root, saved_state, saved_stage);
    }

    #[test]
    fn an_envelope_whose_origin_key_is_unknown_is_unverified_origin() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let root = mail_deposit_root("unverified-origin");
        act_as(&root, "here");

        // The HOP is a genuinely admitted, message-holding node — but
        // registered under a DIFFERENT name than the envelope's own origin
        // (`display::local_host_name()`, which `mint_outbound_letter`
        // always stamps and which this test never registers), so admission
        // succeeds while the origin lookup still has no key to try. This is
        // the two-lookup split itself (spec item 3): the hop and the origin
        // are read from two different places, and P-M2 having them usually
        // coincide is not the same as them being the same read.
        setup_signed_node_with_allows("box-hop", &["message"]);

        let envelope = aoide_storage::mail::mint_outbound_letter("alice", "here", "conductor", "hi").unwrap();
        let origin_name = envelope.header.from.node.clone();
        assert!(
            aoide_storage::node_store::load_nodes().iter().all(|n| n.name != origin_name),
            "sanity: nothing is registered under the envelope's own origin name"
        );

        let audit_log = root.join("log");
        let ctx = mail_deposit_ctx(&audit_log, Some("box-hop"));
        let params = json!({ "envelope": envelope });
        // MAIL.md §Wire: admission (step 1) is a JSON-RPC error; what
        // becomes of a well-formed envelope (steps 2 onward, this one) is a
        // RESULT — a refused outcome is not the same answer as "you may
        // not speak to this method at all."
        let result = mail_deposit(&params, &ctx).expect("no key on record for the origin is an OUTCOME, not a protocol error");
        assert_eq!(result["status"], "refused");
        assert_eq!(result["reason"], "unverified-origin");
        assert!(result["detail"].as_str().unwrap().contains(&origin_name), "{result}");

        let log = std::fs::read_to_string(&audit_log).unwrap();
        assert!(log.contains("\"status\":\"invalid\""), "a refused RESULT still audits as invalid, unconditionally: {log}");

        assert!(aoide_storage::mail::read_base().unwrap().is_empty(), "an unverified origin is never filed");

        mail_deposit_cleanup(&root, saved_state, saved_stage);
    }

    #[test]
    fn a_deposit_with_a_mismatched_msgid_is_a_refused_result_not_a_protocol_error() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let root = mail_deposit_root("bad-msgid");
        act_as(&root, "here");

        // A genuinely verifiable origin (unlike the sibling test above) —
        // this proves the msgid check is what refuses, not a side effect of
        // an origin this test never bothered to register.
        let origin_name = setup_verifiable_origin(&["message"]);
        let mut envelope = aoide_storage::mail::mint_outbound_letter("alice", "here", "conductor", "hi").unwrap();
        envelope.msgid = "0".repeat(64); // well-formed hex, does not recompute

        let audit_log = root.join("log");
        let ctx = mail_deposit_ctx(&audit_log, Some(&origin_name));
        let params = json!({ "envelope": envelope });
        let result = mail_deposit(&params, &ctx).expect("a tampered msgid is an OUTCOME, not a protocol error");
        assert_eq!(result["status"], "refused");
        assert_eq!(result["reason"], "bad-msgid");
        assert!(result["detail"].as_str().unwrap().contains("recomputed"), "{result}");

        let log = std::fs::read_to_string(&audit_log).unwrap();
        assert!(log.contains("\"status\":\"invalid\""), "a refused RESULT still audits as invalid, unconditionally: {log}");

        assert!(aoide_storage::mail::read_base().unwrap().is_empty(), "a bad msgid is never filed");

        mail_deposit_cleanup(&root, saved_state, saved_stage);
    }
}
