//! The A2A (Agent2Agent) door — a hand-rolled, dependency-free JSON-RPC 2.0
//! over HTTP/1.1 server (CONTRACTS.md §6, Phase B: server MVP, read-only
//! half).
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
//!   - `POST /` — JSON-RPC 2.0: `tasks/get` (real), `message/send` (a
//!     well-formed "not yet" error — execution semantics land in a later
//!     phase), anything else → `-32601 method not found`.
//!
//! A forwarded A2A message is untrusted DATA, never executed — this door
//! only reads `sessions.json` and reports state; it runs nothing.

use crate::daemon::{self, Door};
use crate::dispatch::Invocation;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
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
        "capabilities": { "streaming": false },
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": skills,
    })
}

/// The real AgentCard, derived from the process-wide command registry.
fn agent_card(bind: &str, port: u16) -> Value {
    agent_card_from_commands(crate::dispatch::registry().commands(), bind, port)
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
/// session tracking yet). TODO(a2a-b2): once `message/send` lands and a
/// session can carry more than one in-flight turn, split Task id from
/// contextId for real.
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
        // TODO(a2a-b2): task id == sessionId, contextId == sessionId — see
        // the doc comment above.
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

/// Handle one parsed JSON-RPC 2.0 request `Value`, returning the response
/// `Value` (always — unlike `mcp.rs`'s stdio notifications, an HTTP POST
/// always gets a reply body).
fn handle_jsonrpc(req: &Value) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or(Value::Null);

    let result: Result<Value, (i64, String)> = match method {
        "tasks/get" => {
            let task_id = params.get("id").and_then(Value::as_str).unwrap_or("");
            task_get(task_id)
        }
        "message/send" => Err((
            -32004,
            "message/send lands in a later A2A phase (execution semantics pending)".to_string(),
        )),
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

fn handle_jsonrpc_bytes(body: &[u8]) -> Value {
    match serde_json::from_slice::<Value>(body) {
        Ok(req) => handle_jsonrpc(&req),
        Err(e) => jsonrpc_error_value(-32700, format!("parse error: {e}")),
    }
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
/// command label). Kept pure — no I/O beyond what's already in `req` — so it
/// unit-tests without a real socket.
fn route(req: &HttpRequest, bind: &str, port: u16) -> (u16, Vec<u8>, String) {
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
                let resp = handle_jsonrpc_bytes(&req.body);
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
pub fn serve(bind: &str, port: u16, audit_log: &Path) -> std::io::Result<()> {
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
        std::thread::spawn(move || {
            let _guard = ConnGuard; // released on every exit path, incl. panic
            if let Err(e) = handle_connection(stream, &bind, port, &audit_log) {
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
) -> std::io::Result<()> {
    // Never let one slow/hostile client wedge a server thread forever: the
    // per-read timeout catches a fully-idle client, and the absolute
    // `MAX_REQUEST` deadline (checked inside `parse_http_request`) catches
    // one that dribbles a byte at a time just inside that timeout.
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;

    let start = Instant::now();
    let (status, body, audit_cmd) = match parse_http_request(&mut reader, start) {
        Ok(req) => route(&req, bind, port),
        Err(e) => {
            let b = jsonrpc_error_value(-32700, format!("bad request: {}", e.message));
            (
                e.status,
                serde_json::to_vec(&b).unwrap_or_default(),
                "a2a.bad-request".to_string(),
            )
        }
    };

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
        assert_eq!(card["capabilities"]["streaming"], false);

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

    #[test]
    fn message_send_is_a_well_formed_not_yet_error() {
        let req = json!({ "jsonrpc": "2.0", "id": 1, "method": "message/send", "params": {} });
        let resp = handle_jsonrpc(&req);
        assert_eq!(resp["error"]["code"], -32004);
        assert!(resp["error"]["message"]
            .as_str()
            .unwrap()
            .contains("later A2A phase"));
        assert_eq!(resp["id"], 1);
    }

    #[test]
    fn unknown_method_is_minus_32601() {
        let req = json!({ "jsonrpc": "2.0", "id": 2, "method": "bogus/verb", "params": {} });
        let resp = handle_jsonrpc(&req);
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
        let resp = handle_jsonrpc(&req);
        assert_eq!(resp["result"]["status"]["state"], "completed");

        let req = json!({ "jsonrpc": "2.0", "id": 8, "method": "tasks/get", "params": { "id": "ghost" } });
        let resp = handle_jsonrpc(&req);
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

    // Routing: non-matching path/method -> 404/405 with a JSON-RPC-style body.
    #[test]
    fn unknown_path_is_404_and_wrong_method_on_a_known_path_is_405() {
        let (status, body, _) = route(
            &HttpRequest { method: "GET".into(), path: "/nope".into(), body: vec![] },
            "127.0.0.1",
            8710,
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
        );
        assert_eq!(status, 405);
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert!(v["error"]["code"].is_i64());
    }
}
