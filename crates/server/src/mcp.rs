//! Minimal MCP stdio server (concepts/Agent-Interface, Tier 2).
//!
//! The tool list is GENERATED from the command registry — each command
//! becomes one tool — and `tools/call` dispatches back into the same command
//! handlers the CLI uses. One implementation, three doors, no drift (the
//! third, A2A — `a2a.rs`, CONTRACTS.md §6 — rides the same schema).
//!
//! This is a minimal, dependency-free JSON-RPC 2.0 over newline-delimited
//! stdin/stdout: enough for a per-session agent to enumerate and call tools.
//!
//! Extracted from root `src/mcp.rs` (Phase 4c restructure,
//! docs/architecture/PACKAGE-LAYOUT.md). The old `dispatch::registry()` /
//! `dispatch::dispatch()` calls this module made are impossible here — the
//! fully-assembled command registry doesn't move to any crate until Phase 6
//! (`cli`), and `aoide-server` must sit BELOW the trunk, never depend on it.
//! [`serve_stdio`] (and everything it calls) takes the registry and a
//! dispatch fn pointer as parameters instead; root `lib.rs`'s
//! `mcp serve --stdio` launch site passes `dispatch::registry()` and
//! `dispatch::dispatch` in.

use crate::daemon::{read_capped_line, LineReadError, MAX_REQUEST_LINE_BYTES};
use aoide_conduct::graph::channel_socket_path;
use aoide_protocol::output::{Outcome, Status};
use aoide_protocol::registry::Registry;
use aoide_protocol::wire::{
    ExperimentalCapabilities, InitializeCapabilities, InitializeResult, JsonRpcResponse,
    ServerInfo, Tool, ToolAnnotations, ToolCallContent, ToolCallResult, ToolInputSchema, ToolList,
    ToolProperty, ToolsCapability,
};
use aoide_protocol::{Door, Invocation};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};

const PROTOCOL_VERSION: &str = "2024-11-05";

/// `initialize`'s `instructions` (P-M5c-2, `docs/architecture/
/// CLAUDE-CHANNEL-PROOF.md`): tells the model that a channel event is
/// pushed, not typed — one-way, nothing to reply into.
const CHANNEL_INSTRUCTIONS: &str = "Events pushed over the aoide channel arrive as \
    <channel source=\"aoide\">...</channel> notifications. They are one-way: read and act on \
    them — there is no reply path back through the notification itself.";

/// A dispatch fn pointer: matches `aoide::dispatch::dispatch`'s exact
/// signature (a plain `fn`, not a closure — the process-wide dispatcher
/// captures nothing), so root can hand it in directly at the launch site.
pub type DispatchFn = fn(&Invocation) -> Outcome;

/// Generate the MCP `tools` array from the command schema. Each command →
/// one tool named by its dotted path; its args/flags become the inputSchema.
pub fn tool_list(registry: &Registry) -> Value {
    let tools: Vec<Tool> = registry
        .commands()
        .map(|c| {
            let mut properties: BTreeMap<String, ToolProperty> = BTreeMap::new();
            let mut required: Vec<String> = Vec::new();

            for a in c.args {
                properties.insert(
                    a.name.to_string(),
                    ToolProperty { kind: json_type(a.ty).to_string(), description: a.description.to_string() },
                );
                if a.required {
                    required.push(a.name.to_string());
                }
            }
            for f in c.flags {
                properties.insert(
                    f.name.to_string(),
                    ToolProperty { kind: json_type(f.ty).to_string(), description: f.description.to_string() },
                );
            }

            Tool {
                name: c.dotted(),
                description: c.summary.to_string(),
                input_schema: ToolInputSchema { kind: "object".to_string(), properties, required },
                // Surface the gate so an MCP client can warn before calling.
                annotations: ToolAnnotations { gated: c.gated },
            }
        })
        .collect();

    serde_json::to_value(ToolList { tools }).expect("ToolList always serializes")
}

fn json_type(ty: &str) -> &'static str {
    match ty {
        "int" | "integer" => "integer",
        "bool" | "boolean" => "boolean",
        _ => "string",
    }
}

/// Build an [`Invocation`] from an MCP `tools/call` (tool name + arguments).
fn invocation_from_call(name: &str, arguments: &Value, registry: &Registry) -> Option<Invocation> {
    let cmd = registry.commands().find(|c| c.dotted() == name)?;
    let path: Vec<String> = cmd.path.iter().map(|s| s.to_string()).collect();

    let mut args: Vec<String> = Vec::new();
    let mut flags: BTreeMap<String, String> = BTreeMap::new();

    if let Some(obj) = arguments.as_object() {
        // Positional args, in schema order.
        for a in cmd.args {
            if let Some(v) = obj.get(a.name) {
                args.push(value_to_string(v));
            }
        }
        // Flags by name.
        for f in cmd.flags {
            if let Some(v) = obj.get(f.name) {
                flags.insert(f.name.to_string(), value_to_string(v));
            }
        }
    }

    Some(Invocation {
        path,
        args,
        flags,
        door: Door::Mcp,
    })
}

/// `pub(crate)` (not `pub`) so [`crate::daemon`]'s own `dispatch` op
/// (P-D4, `docs/architecture/AOIDED.md`'s "L2" section) can reuse the exact
/// same JSON-value-to-wire-string conversion its `flags`/`args` parsing
/// needs — the "no cross-crate copying" convention
/// (`pkgs/aoide/crates/AGENTS.md`) applied within one crate too: widen a
/// `pub(crate)` scope rather than fork the four-line match a second time.
pub(crate) fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Handle one JSON-RPC request, returning the response Value (or None for
/// notifications that take no reply).
fn handle(req: &Value, registry: &Registry, dispatch: DispatchFn) -> Option<Value> {
    let id = req.get("id").cloned();
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");

    let result: Result<Value, (i64, String)> = match method {
        "initialize" => {
            let init = InitializeResult {
                protocol_version: PROTOCOL_VERSION.to_string(),
                capabilities: InitializeCapabilities {
                    tools: ToolsCapability {},
                    experimental: ExperimentalCapabilities::default(),
                },
                server_info: ServerInfo {
                    name: "aoide".to_string(),
                    version: aoide_protocol::registry::AOIDE_VERSION.to_string(),
                },
                instructions: CHANNEL_INSTRUCTIONS.to_string(),
            };
            Ok(serde_json::to_value(init).expect("InitializeResult always serializes"))
        }
        "tools/list" => Ok(tool_list(registry)),
        "tools/call" => {
            let params = req.get("params").cloned().unwrap_or(Value::Null);
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
            match invocation_from_call(name, &arguments, registry) {
                Some(inv) => {
                    let outcome = dispatch(&inv);
                    let text = serde_json::to_string_pretty(&outcome).unwrap_or_default();
                    let result = ToolCallResult {
                        content: vec![ToolCallContent { kind: "text".to_string(), text }],
                        is_error: outcome.status != Status::Ok,
                    };
                    Ok(serde_json::to_value(result).expect("ToolCallResult always serializes"))
                }
                None => Err((-32602, format!("unknown tool: {name}"))),
            }
        }
        // Notifications (no id) — acknowledge silently.
        m if m.starts_with("notifications/") => return None,
        other => Err((-32601, format!("method not found: {other}"))),
    };

    // Notifications without an id get no response.
    id.as_ref()?;
    let id = id.expect("id present (checked above)");

    let resp = match result {
        Ok(value) => JsonRpcResponse::ok(id, value),
        Err((code, message)) => JsonRpcResponse::err(id, code, message),
    };
    Some(serde_json::to_value(&resp).expect("JsonRpcResponse always serializes"))
}

/// Write one line to the shared writer, then flush — the whole thing under
/// `out`'s lock, so a reply and a channel notification (below) never
/// interleave on the underlying stream (P-M5c-2): a torn JSON-RPC line is a
/// dead channel.
fn write_line<W: Write>(out: &Mutex<W>, line: &str) -> std::io::Result<()> {
    let mut w = out
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    writeln!(w, "{line}")?;
    w.flush()
}

/// The mailbox name a channel-socket line names, if any — the mail
/// doorbell's own `nudge_line` shape (`conduct/src/graph/doorbell.rs`,
/// P-M5c-3: `... --for <name>`, the mailbox's own `mail read --for <name>`
/// fix spelled out verbatim). A bare suffix parse, not a dependency on
/// `doorbell.rs` — that module is private to `aoide-conduct` and this crate
/// has no business knowing its internals, only the line SHAPE it writes to
/// the socket. No recognizable `--for <name>` suffix means no mailbox to
/// name.
fn channel_line_mailbox(line: &str) -> Option<String> {
    let (_, name) = line.rsplit_once("--for ")?;
    let name = name.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Build the one `notifications/claude/channel` line for a line received on
/// the channel socket (P-M5c-2): `content` is the line verbatim, `meta`
/// names the mailbox it names (`{"mailbox": <name>}`) or stays empty when it
/// names none. Meta keys are bare identifiers throughout — a hyphenated key
/// is silently dropped by the harness.
fn channel_notification(content: &str) -> Value {
    let meta = match channel_line_mailbox(content) {
        Some(name) => json!({ "mailbox": name }),
        None => json!({}),
    };
    json!({
        "jsonrpc": "2.0",
        "method": "notifications/claude/channel",
        "params": { "content": content, "meta": meta },
    })
}

/// The channel's one listener thread (P-M5c-2): serially accepts
/// connections and, for each, relays every newline-delimited line it reads
/// as one `notifications/claude/channel` line on `out` — one connection is
/// read start-to-finish (to EOF or a dropped line) before the next is even
/// accepted, so no second thread ever touches the socket. A caller is
/// expected to connect, write one line, and close (the doorbell's own
/// `nudge_line` write does exactly that); a connection held open past its
/// one line stalls every later caller until it closes.
///
/// Lines are read via [`read_capped_line`] under the SAME
/// [`MAX_REQUEST_LINE_BYTES`] cap the daemon socket already enforces
/// (P-M5c-2 review) rather than the unbounded `BufRead::lines()` this
/// started with: a client that never sends `\n` grew this thread's buffer
/// without bound. A line over the cap, or one that isn't valid UTF-8, drops
/// just that connection — no reply (this socket is one-way), no panic —
/// and the listener moves on to the next `accept`.
fn run_channel_listener<W: Write + Send + 'static>(listener: UnixListener, out: Arc<Mutex<W>>) {
    for conn in listener.incoming().flatten() {
        let mut reader = std::io::BufReader::new(conn);
        loop {
            let line_bytes = match read_capped_line(&mut reader, MAX_REQUEST_LINE_BYTES) {
                Ok(None) => break, // EOF: caller closed.
                Ok(Some(bytes)) => bytes,
                Err(LineReadError::TooLarge) => break, // over the cap: drop this connection.
                Err(LineReadError::Io) => break,       // read error: drop this connection.
            };
            let Ok(line) = String::from_utf8(line_bytes) else {
                break; // invalid UTF-8: drop this connection.
            };
            if line.is_empty() {
                continue;
            }
            let note = channel_notification(&line);
            let _ = write_line(&out, &note.to_string());
        }
    }
}

/// Bind `id`'s channel socket and spawn the one listener thread above
/// (P-M5c-2). Unlink-then-bind, the same convention
/// `aoide_conduct::graph::conduct`'s own per-session socket already follows
/// — clears a stale socket left by a prior crash — then chmod `0600`
/// (P-M5c-2 review: structural, not umask luck, matching `daemon::
/// bind_socket`'s own posture — this socket carries no envelope, so
/// same-uid-only is the entire access control it has). The socket IS the
/// registration (house rule 7): no record, no command, no flag; its
/// lifetime is this MCP subprocess's own, never `aoided`'s. `None` on a
/// bind or chmod failure (best-effort, matching that same per-session
/// socket's own posture): a session that can't secure the channel socket
/// stays reachable over stdio, just not over the channel.
fn spawn_channel_socket<W: Write + Send + 'static>(
    id: &str,
    out: Arc<Mutex<W>>,
) -> Option<std::path::PathBuf> {
    let path = channel_socket_path(id);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(&path); // clear a stale socket from a prior crash.
    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("aoide mcp serve: channel socket bind failed: {e}");
            return None;
        }
    };
    // 0600, structural, not umask luck — the same posture
    // `daemon::bind_socket` already holds for its own control socket.
    if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
        eprintln!("aoide mcp serve: channel socket chmod failed: {e}");
        return None;
    }
    std::thread::spawn(move || run_channel_listener(listener, out));
    Some(path)
}

/// The one gate `serve_stdio` binds the channel on: `$AOIDE_SESSION_ID` set
/// and non-empty. Factored out so a test can drive the exact same gate
/// without blocking on real stdin.
fn maybe_spawn_channel_socket<W: Write + Send + 'static>(
    out: Arc<Mutex<W>>,
) -> Option<std::path::PathBuf> {
    let id = std::env::var("AOIDE_SESSION_ID")
        .ok()
        .filter(|s| !s.is_empty())?;
    spawn_channel_socket(&id, out)
}

/// Unlinks the channel socket when serving ends, on ANY return path
/// (P-M5c-2) — the socket's lifetime is exactly `serve_stdio`'s own.
struct ChannelSocketGuard(std::path::PathBuf);

impl Drop for ChannelSocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Serve the MCP protocol over stdio (newline-delimited JSON-RPC).
///
/// `registry`/`dispatch` are injected (see the module doc comment) — root
/// `lib.rs` passes `dispatch::registry()` and `dispatch::dispatch`.
///
/// When `$AOIDE_SESSION_ID` is set and non-empty (P-M5c-2), also binds this
/// session's channel socket and spawns the listener that turns each line
/// written to it into one `notifications/claude/channel` line — `out` moves
/// behind an `Arc<Mutex<_>>` so the request loop below and that listener
/// thread never write an interleaved line to stdout.
pub fn serve_stdio(registry: &Registry, dispatch: DispatchFn) -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let out: Arc<Mutex<std::io::Stdout>> = Arc::new(Mutex::new(std::io::stdout()));

    let channel_path = maybe_spawn_channel_socket(Arc::clone(&out));
    let _channel_guard = channel_path.map(ChannelSocketGuard);

    for line in stdin.lock().lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                let err = serde_json::to_value(JsonRpcResponse::err(
                    Value::Null,
                    -32700,
                    format!("parse error: {e}"),
                ))
                .expect("JsonRpcResponse always serializes");
                write_line(&out, &err.to_string())?;
                continue;
            }
        };
        if let Some(resp) = handle(&req, registry, dispatch) {
            write_line(&out, &resp.to_string())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aoide_protocol::registry::Command;

    fn fake_handler(_inv: &Invocation) -> Outcome {
        Outcome::ok("fake", "fake")
    }

    /// A small fixture registry standing in for the real, fully-assembled one
    /// (`dispatch::registry()`, root-only — see the module doc comment): two
    /// commands, one gated, exercising the same shape `tool_list`/`handle`
    /// need without pulling in every command family.
    fn fixture_registry() -> Registry {
        let mut r = Registry::new();
        r.insert(Command {
            path: &["foo", "bar"],
            summary: "does a thing",
            args: &[],
            flags: &[],
            gated: true,
            implemented: true,
            internal: false,
            exit_codes: (),
            examples: &[],
            handler: fake_handler,
            available: || true,
        });
        r.insert(Command {
            path: &["guide"],
            summary: "onboarding text",
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
        r
    }

    #[test]
    fn tool_list_is_derived_one_to_one_from_the_registry() {
        let registry = fixture_registry();
        let tools = tool_list(&registry);
        let arr = tools["tools"].as_array().unwrap();
        assert_eq!(arr.len(), registry.commands().count());
        // Every command name appears as a tool name, and the gate surfaces.
        let names: std::collections::HashSet<String> = arr
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect();
        for c in registry.commands() {
            assert!(names.contains(&c.dotted()), "tool missing for {}", c.dotted());
        }
        let bar = arr.iter().find(|t| t["name"] == "foo.bar").unwrap();
        assert_eq!(bar["annotations"]["gated"], true);
    }

    #[test]
    fn tools_call_dispatches_into_the_injected_handler() {
        let registry = fixture_registry();
        let req = json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "guide", "arguments": {} }
        });
        let resp = handle(&req, &registry, fake_handler).unwrap();
        assert!(resp["result"]["content"][0]["text"].is_string());
        assert_eq!(resp["result"]["isError"], false);
    }

    #[test]
    fn tools_call_on_an_unknown_tool_is_minus_32602() {
        let registry = fixture_registry();
        let req = json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": { "name": "nope", "arguments": {} }
        });
        let resp = handle(&req, &registry, fake_handler).unwrap();
        assert_eq!(resp["error"]["code"], -32602);
    }

    // ── P-M5c-2: the Claude channel bridge ──────────────────────────────

    /// A short, private `$XDG_RUNTIME_DIR` under `/tmp` — a full channel
    /// socket path (`<dir>/aoide/channel-<id>.sock`) must stay under the
    /// 108-byte `AF_UNIX` path cap, and this must never collide with, or
    /// touch, the live `$XDG_RUNTIME_DIR/aoide/`.
    fn short_runtime_dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let dir =
            std::path::PathBuf::from(format!("/tmp/av-mcp-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_line_on_the_channel_socket_becomes_one_channel_notification() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("XDG_RUNTIME_DIR").ok();
        let root = short_runtime_dir("line");
        std::env::set_var("XDG_RUNTIME_DIR", &root);

        let out: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let path = spawn_channel_socket("chan-1", Arc::clone(&out))
            .expect("bind must succeed under a fresh tempdir");

        {
            let mut conn = std::os::unix::net::UnixStream::connect(&path).unwrap();
            writeln!(
                conn,
                "[aoide mail] new mail for alice — aoide mail read --for alice"
            )
            .unwrap();
        }

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let line = loop {
            {
                let buf = out.lock().unwrap();
                if let Ok(s) = std::str::from_utf8(&buf) {
                    if let Some(l) = s.lines().next() {
                        if !l.is_empty() {
                            break l.to_string();
                        }
                    }
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the channel listener never emitted a notification"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        };

        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["method"], "notifications/claude/channel");
        assert_eq!(
            v["params"]["content"],
            "[aoide mail] new mail for alice — aoide mail read --for alice"
        );
        assert_eq!(v["params"]["meta"]["mailbox"], "alice");

        std::fs::remove_file(&path).ok();
        match saved {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
    }

    #[test]
    fn the_channel_socket_is_unbound_when_no_session_id_is_set() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_id = std::env::var("AOIDE_SESSION_ID").ok();
        let saved_runtime = std::env::var("XDG_RUNTIME_DIR").ok();
        std::env::remove_var("AOIDE_SESSION_ID");
        let root = short_runtime_dir("noid");
        std::env::set_var("XDG_RUNTIME_DIR", &root);

        let out: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let bound = maybe_spawn_channel_socket(out);
        assert!(bound.is_none(), "no session id must mean no channel socket");
        assert!(
            !root.join("aoide").exists(),
            "no session id must mean the aoide runtime dir is never even created"
        );

        match saved_id {
            Some(v) => std::env::set_var("AOIDE_SESSION_ID", v),
            None => std::env::remove_var("AOIDE_SESSION_ID"),
        }
        match saved_runtime {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
    }

    #[test]
    fn a_notification_and_a_tool_reply_never_interleave_on_stdout() {
        let out: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let reply = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"x\":\"REPLY-PAYLOAD-PADDING-0000000000000000\"}}";
        let notice = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/claude/channel\",\"params\":{\"content\":\"NOTICE-PAYLOAD-PADDING-0000000000000000\",\"meta\":{}}}";

        let mut handles = Vec::new();
        for _ in 0..50 {
            let out_a = Arc::clone(&out);
            handles.push(std::thread::spawn(move || {
                write_line(&out_a, reply).unwrap();
            }));
            let out_b = Arc::clone(&out);
            handles.push(std::thread::spawn(move || {
                write_line(&out_b, notice).unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let buf = out.lock().unwrap();
        let text = std::str::from_utf8(&buf).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines.len(),
            100,
            "every write must land as exactly one whole line"
        );
        for line in lines {
            assert!(
                line == reply || line == notice,
                "a torn/interleaved line: {line}"
            );
        }
    }

    #[test]
    fn a_channel_line_over_the_cap_is_dropped_and_the_listener_survives() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("XDG_RUNTIME_DIR").ok();
        let root = short_runtime_dir("cap");
        std::env::set_var("XDG_RUNTIME_DIR", &root);

        let out: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let path = spawn_channel_socket("chan-cap", Arc::clone(&out))
            .expect("bind must succeed under a fresh tempdir");

        // First connection: stream past the cap with no trailing newline,
        // then close — the listener must drop it silently, never emitting
        // a notification for it.
        {
            let mut conn = std::os::unix::net::UnixStream::connect(&path).unwrap();
            let chunk = vec![b'x'; 64 * 1024];
            let mut sent: usize = 0;
            while sent <= MAX_REQUEST_LINE_BYTES {
                match conn.write(&chunk) {
                    Ok(0) => break,
                    Ok(n) => sent += n,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::BrokenPipe
                            || e.kind() == std::io::ErrorKind::ConnectionReset =>
                    {
                        break
                    }
                    Err(e) => panic!("unexpected write error: {e}"),
                }
            }
        }

        // Second connection: one well-formed line — the listener must still
        // be alive to accept it and emit exactly one notification for it.
        {
            let mut conn = std::os::unix::net::UnixStream::connect(&path).unwrap();
            writeln!(
                conn,
                "[aoide mail] new mail for bob — aoide mail read --for bob"
            )
            .unwrap();
        }

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let line = loop {
            {
                let buf = out.lock().unwrap();
                if let Ok(s) = std::str::from_utf8(&buf) {
                    if let Some(l) = s.lines().next() {
                        if !l.is_empty() {
                            break l.to_string();
                        }
                    }
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the listener never recovered to notify the second connection's line"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        };

        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["method"], "notifications/claude/channel");
        assert_eq!(
            v["params"]["content"],
            "[aoide mail] new mail for bob — aoide mail read --for bob"
        );
        assert_eq!(v["params"]["meta"]["mailbox"], "bob");

        // The oversized connection produced no notification of its own —
        // exactly one line total, from the second connection alone.
        {
            let buf = out.lock().unwrap();
            let text = std::str::from_utf8(&buf).unwrap();
            assert_eq!(
                text.lines().count(),
                1,
                "the oversized connection must never have produced a notification"
            );
        }

        std::fs::remove_file(&path).ok();
        match saved {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
    }

    #[test]
    fn the_channel_socket_is_owner_only() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("XDG_RUNTIME_DIR").ok();
        let root = short_runtime_dir("mode");
        std::env::set_var("XDG_RUNTIME_DIR", &root);

        let out: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let path = spawn_channel_socket("chan-mode", Arc::clone(&out))
            .expect("bind must succeed under a fresh tempdir");

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "expected the channel socket to be user-private, got {mode:o}"
        );

        std::fs::remove_file(&path).ok();
        match saved {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
    }
}
