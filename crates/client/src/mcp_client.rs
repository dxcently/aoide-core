//! The Melete MCP client (M2, task #14): `melete status|graph|call`.
//!
//! Melete's own operator manual is explicit that its "only machine surface
//! is its MCP connector" — so reaching it is a CLIENT concern, the same
//! shape every `peer` command already holds for a remote aoide door, not a
//! new inbound "door" of our own. This module speaks MCP (JSON-RPC 2.0 over
//! HTTP POST — `initialize`/`tools/list`/`tools/call`) over
//! [`crate::commands::post_json`], the SAME curl transport `peer`'s own
//! calls use — no new Cargo dependency, TLS comes free with curl. Three
//! verbs, one POST each:
//!
//! - `melete status` — an `initialize` handshake; reports reachability plus
//!   the server's own `serverInfo`/`protocolVersion`.
//! - `melete graph` — a `tools/call` of Melete's `graph_view` tool; writes
//!   the result to `state/melete-graph.json` under the runtime root
//!   (`aoide_storage::fs::state_dir()`, `$AOIDE_ROOT/state` — NEVER a
//!   hardcoded path, same getter `usage`'s own `state/usage.json` write
//!   uses).
//! - `melete call <tool> [--args <json>]` — a generic gated `tools/call`
//!   passthrough covering `job_status`/`run_code_task`/`schedule_*`/
//!   `stop_run`/`steer_run` and anything else Melete exposes. Deliberately
//!   NO per-tool verbs: a change to Melete's own tool list never needs a
//!   matching aoide release.
//!
//! **Configuration (`AOIDE_MELETE_URL`/`AOIDE_MELETE_TOKEN`, env-only,
//! interim).** Investigated two existing precedents before choosing this:
//! `aoide_storage::peer_store::Peer` (url + `bearer_secret`, resolved
//! through the secrets broker) models AOIDE-TO-AOIDE federation —
//! AgentCard-verified, signed, per-peer `allows` — over aoide's OWN wire
//! protocol; Melete is a third-party claude.ai service speaking plain MCP,
//! never an aoide peer, so that shape doesn't fit. `aoide_storage::commands`'s
//! `usage` verb (its `live` block) is the closer precedent — a single,
//! external, bearer-authenticated endpoint — but its token rides a LOCAL
//! FILE Claude Code itself already maintains (`~/.claude/.credentials.json`);
//! aoide has no equivalent on-disk source for a Melete connector url/token,
//! and inventing one is explicitly out of scope for this pass (the live
//! wiring — most likely a secrets-broker-resolved secret, mirroring
//! `peer add --bearer-secret` — comes later). So both ride a plain env var,
//! read fresh on every call: absent (either var, or both) is a structured,
//! taught [`Outcome::error`] naming the two var names, never a silent
//! degrade and never an invented credential.
//!
//! **Door gate.** All three verbs are CLI-only, matching `aoide-secrets`'s
//! blanket stance for its own command family (`crate::secrets::commands
//! ::require_cli`, gating the WHOLE `secrets` group, not just its admin
//! quartet): every Melete verb here sends a live bearer token to an
//! external service and `call` can trigger real, potentially
//! cost-incurring action (job triggers, schedule mutations, run control —
//! Melete's own docs single these out as the one class of call it holds
//! for operator approval elsewhere). A compromised inbound MCP/A2A request
//! must never be able to walk this token out through `aoide` itself, so
//! the whole family — not just `call` — is refused over any door but
//! `Cli`, the same reasoning `secrets`' blanket gate already established
//! for its own externally-consequential surface.
//!
//! **Assumed wire shape (documented here since this is a first integration,
//! not yet proven against a live Melete instance).** Each verb is ONE POST
//! — no `initialize`→session-id handshake is threaded into `graph`/`call`;
//! Melete's connector is treated as a stateless-per-request bearer-token
//! API, the minimal shape the three verbs need. A response is parsed as
//! plain JSON first; failing that, defensively as an SSE-framed body
//! (`data: ` lines, per streamable-HTTP MCP) — [`parse_response_body`].
//! Neither the request nor the response is forced through
//! `aoide_protocol::wire::mcp`'s `InitializeResult`/`ToolCallResult`
//! structs (those describe aoide's OWN outbound guarantees as an MCP
//! *server*, e.g. "always exactly one text content block" — a promise
//! Melete never made us); every field is read defensively off a raw
//! [`Value`] instead, the same inbound-tolerance stance
//! `aoide_protocol::wire::jsonrpc`'s own module doc states for a
//! structurally odd reply.

use aoide_protocol::output::Outcome;
use aoide_protocol::registry::{arg, cmd, flag, Registry};
use aoide_protocol::wire::JsonRpcRequest;
use aoide_protocol::{Door, Invocation};
use serde_json::{json, Value};

/// The MCP protocol version this client claims in `initialize` — mirrors
/// `aoide-server::mcp::PROTOCOL_VERSION` (aoide's own MCP *server* constant)
/// byte-for-byte, redefined here rather than imported: this crate sits
/// BELOW `aoide-server` in the workspace DAG (`peer`/AGENTS.md's `daemon::
/// socket_path` note holds the identical reasoning for re-deriving instead
/// of importing).
const PROTOCOL_VERSION: &str = "2024-11-05";

/// Env var naming Melete's MCP connector HTTP endpoint (the JSON-RPC POST
/// URL). See this module's doc for why this rides a plain env var rather
/// than `peer_store` or a local credentials file.
const MELETE_URL_VAR: &str = "AOIDE_MELETE_URL";
/// Env var naming the bearer token presented to the connector. Read fresh
/// on every call and held only in this process's own memory for the span
/// of one curl invocation — never written to disk, never logged, never
/// argv (see [`crate::commands::post_json`]'s own doc for the `-H @-`
/// stdin trick this reuses).
const MELETE_TOKEN_VAR: &str = "AOIDE_MELETE_TOKEN";

/// Resolved connector config for one call. `Debug` is test-only
/// (`unwrap_err`'s own bound) — deliberately not derived for production
/// code, so nothing outside a test's own panic message can ever `{:?}`-print
/// a live token by accident.
#[cfg_attr(test, derive(Debug))]
struct MeleteConfig {
    url: String,
    token: String,
}

/// Resolve [`MELETE_URL_VAR`]/[`MELETE_TOKEN_VAR`], or a structured, taught
/// error naming both — never a silent degrade (unlike `usage`'s `live`
/// block, there is no "local" half here to fall back to: every one of
/// these three verbs has nothing to do without reaching Melete).
fn resolve_config(cmd: &str) -> Result<MeleteConfig, Outcome> {
    let url = std::env::var(MELETE_URL_VAR).ok().filter(|s| !s.trim().is_empty());
    let token = std::env::var(MELETE_TOKEN_VAR).ok().filter(|s| !s.trim().is_empty());
    match (url, token) {
        (Some(url), Some(token)) => Ok(MeleteConfig { url, token }),
        _ => Err(Outcome::error(
            cmd,
            format!(
                "melete is not configured on this host: set {MELETE_URL_VAR} (the connector's \
                 MCP HTTP endpoint) and {MELETE_TOKEN_VAR} (its bearer token) — melete has no \
                 local credentials to invent, so both must be set explicitly"
            ),
        )
        .with_data(json!({
            "reason": "unconfigured",
            "urlVar": MELETE_URL_VAR,
            "tokenVar": MELETE_TOKEN_VAR,
        }))),
    }
}

/// Shared door gate for the whole `melete` family — see this module's doc
/// for why the READ-only verbs (`status`/`graph`) are gated identically to
/// `call`, not just the consequential one.
fn require_cli(inv: &Invocation, cmd: &str) -> Option<Outcome> {
    match inv.door {
        Door::Cli => None,
        _ => Some(Outcome::usage(
            cmd,
            "melete commands send a live bearer token to an external service and can trigger \
             real action; CLI-only — run this from a terminal (not over this door)",
        )),
    }
}

/// Parse a curl response body into a [`Value`]: plain JSON first, else
/// defensively as an SSE-framed (`text/event-stream`) body — a streamable-
/// HTTP MCP server may reply with `data: <json>` lines instead of a bare
/// JSON object. Per the SSE spec, multiple consecutive `data:` lines inside
/// one event are joined with `\n` to form a single message; this collects
/// each event's `data:` lines (blank line = event boundary) and keeps the
/// LAST event that parses as JSON — a streamable response's final event
/// carries the JSON-RPC reply. `Err` when neither reading succeeds.
fn parse_response_body(body: &str) -> Result<Value, String> {
    let trimmed = body.trim();
    if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
        return Ok(v);
    }
    let mut current: Vec<&str> = Vec::new();
    let mut last: Option<Value> = None;
    let flush = |lines: &mut Vec<&str>, last: &mut Option<Value>| {
        if lines.is_empty() {
            return;
        }
        if let Ok(v) = serde_json::from_str::<Value>(&lines.join("\n")) {
            *last = Some(v);
        }
        lines.clear();
    };
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("data:") {
            current.push(rest.strip_prefix(' ').unwrap_or(rest));
        } else if line.trim().is_empty() {
            flush(&mut current, &mut last);
        }
    }
    flush(&mut current, &mut last);
    last.ok_or_else(|| "response is not JSON and carries no recognizable SSE `data:` frame".to_string())
}

/// Pull `result`/`error` off a parsed JSON-RPC response, read defensively
/// (no forced struct shape — see this module's doc). A present `error`
/// always wins (even alongside a `result`, which the spec forbids but a
/// hostile/buggy server could still send); an absent `result` with no
/// `error` either is a malformed reply.
fn extract_result(cmd: &str, v: &Value) -> Result<Value, Outcome> {
    if let Some(err) = v.get("error") {
        let msg = err.get("message").and_then(Value::as_str).unwrap_or("unknown error");
        return Err(Outcome::error(
            cmd,
            match err.get("code").and_then(Value::as_i64) {
                Some(code) => format!("melete rejected the call: {msg} (code {code})"),
                None => format!("melete rejected the call: {msg}"),
            },
        ));
    }
    match v.get("result") {
        Some(r) => Ok(r.clone()),
        None => Err(Outcome::error(
            cmd,
            "melete's response carried neither `result` nor `error` — malformed JSON-RPC reply",
        )),
    }
}

/// One JSON-RPC POST to the configured connector: build the request via
/// [`JsonRpcRequest`] (the SAME builder `wire::build_message_send_body`
/// already uses for outbound A2A), send it through
/// [`crate::commands::post_json`] with the bearer riding its stdin-hidden
/// `-H @-` path (never argv, never disk), and parse the reply
/// ([`parse_response_body`] + [`extract_result`]). `Accept: application/
/// json, text/event-stream` is sent on every call — the pair streamable-
/// HTTP MCP expects a client to advertise, since either response shape is
/// valid.
fn call(cmd: &str, cfg: &MeleteConfig, method: &str, params: Value) -> Result<Value, Outcome> {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: json!(1),
        method: method.to_string(),
        params,
    };
    let body = serde_json::to_value(&req).expect("JsonRpcRequest always serializes").to_string();
    let headers = [("Accept".to_string(), "application/json, text/event-stream".to_string())];
    match crate::commands::post_json(&cfg.url, &body, Some(&cfg.token), &headers, 20) {
        Ok((200, raw)) => {
            let v = parse_response_body(&raw)
                .map_err(|e| Outcome::error(cmd, format!("melete returned an unparseable response: {e}")))?;
            extract_result(cmd, &v)
        }
        Ok((401, _)) | Ok((403, _)) => Err(Outcome::error(
            cmd,
            format!("melete rejected the bearer token (http 401/403) — check {MELETE_TOKEN_VAR}"),
        )),
        Ok((code, _)) => Err(Outcome::error(cmd, format!("melete responded http {code}"))),
        Err(reason) => Err(Outcome::error(cmd, format!("reaching melete: {reason}"))),
    }
}

fn handle_melete_status(inv: &Invocation) -> Outcome {
    let cmd = "melete.status";
    if let Some(hint) = require_cli(inv, cmd) {
        return hint;
    }
    let cfg = match resolve_config(cmd) {
        Ok(c) => c,
        Err(out) => return out,
    };
    let params = json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": { "name": "aoide", "version": aoide_protocol::registry::AOIDE_VERSION },
    });
    let result = match call(cmd, &cfg, "initialize", params) {
        Ok(r) => r,
        Err(out) => return out,
    };
    let protocol_version = result.get("protocolVersion").and_then(Value::as_str).unwrap_or("unknown");
    let name = result
        .get("serverInfo")
        .and_then(|s| s.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let version = result
        .get("serverInfo")
        .and_then(|s| s.get("version"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    Outcome::ok(cmd, format!("melete reachable — {name} {version} (MCP {protocol_version})"))
        .with_data(json!({ "reachable": true, "result": result }))
}

fn handle_melete_graph(inv: &Invocation) -> Outcome {
    let cmd = "melete.graph";
    if let Some(hint) = require_cli(inv, cmd) {
        return hint;
    }
    let cfg = match resolve_config(cmd) {
        Ok(c) => c,
        Err(out) => return out,
    };
    let params = json!({ "name": "graph_view", "arguments": {} });
    let result = match call(cmd, &cfg, "tools/call", params) {
        Ok(r) => r,
        Err(out) => return out,
    };
    let body = json!({
        "schemaVersion": "0",
        "fetchedAt": aoide_storage::time::now_iso_utc(),
        "result": result,
    });
    let text = serde_json::to_string_pretty(&body).unwrap_or_default() + "\n";
    let target = aoide_storage::fs::state_dir().join("melete-graph.json");
    if let Err(e) = aoide_storage::fs::atomic_write(&target, &text) {
        return Outcome::error(cmd, format!("failed to write {}: {e}", target.display())).with_data(json!({
            "reason": "state-write-failed",
            "target": target.to_string_lossy(),
        }));
    }
    Outcome::ok(cmd, format!("melete graph snapshot written to {}", target.display()))
        .changed(vec![target.to_string_lossy().into_owned()])
        .with_data(body)
}

fn handle_melete_call(inv: &Invocation) -> Outcome {
    let cmd = "melete.call";
    if let Some(hint) = require_cli(inv, cmd) {
        return hint;
    }
    const USAGE: &str = "usage: aoide melete call <tool> [--args <json>]";
    let tool = match inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(t) => t.to_string(),
        None => return Outcome::usage(cmd, USAGE),
    };
    let args_raw = inv.flags.get("args").map(String::as_str).unwrap_or("{}");
    let arguments: Value = match serde_json::from_str(args_raw) {
        Ok(v) => v,
        Err(e) => return Outcome::usage(cmd, format!("--args is not valid JSON: {e}")),
    };
    let cfg = match resolve_config(cmd) {
        Ok(c) => c,
        Err(out) => return out,
    };
    let params = json!({ "name": tool, "arguments": arguments });
    match call(cmd, &cfg, "tools/call", params) {
        Ok(result) => Outcome::ok(cmd, format!("melete call `{tool}` complete")).with_data(json!({
            "tool": tool,
            "result": result,
        })),
        Err(out) => out,
    }
}

/// `melete status|graph|call`, appended newest (Registry discipline,
/// `pkgs/aoide/crates/AGENTS.md`) into `cli`'s `commands::all()`.
pub fn register_melete(r: &mut Registry) {
    r.insert(cmd!(
        path: ["melete", "status"],
        summary: "Check the Melete MCP connector's reachability and report its server info (an `initialize` handshake, nothing more).",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_melete_status,
        examples: ["melete status"],
    ));
    r.insert(cmd!(
        path: ["melete", "graph"],
        summary: "Call Melete's graph_view tool and write the snapshot to state/melete-graph.json.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_melete_graph,
        examples: ["melete graph"],
    ));
    r.insert(cmd!(
        path: ["melete", "call"],
        summary: "Generic gated passthrough to any Melete MCP tool (job_status/run_code_task/schedule_*/stop_run/steer_run/…) — deliberately no per-tool verbs, so a change to Melete's own tool list never needs a matching aoide release.",
        args: [arg!("tool", "string", true, "The Melete MCP tool name to call verbatim, e.g. job_status.")],
        flags: [flag!("args", "string", "The tool's arguments as a JSON object, e.g. '{\"run_id\":\"...\"}'. Defaults to {} when omitted.")],
        gated: false,
        implemented: true,
        handler: handle_melete_call,
        examples: ["melete call job_status --args '{\"run_id\":\"r-123\"}'"],
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        crate::env_lock().lock().unwrap_or_else(|e| e.into_inner())
    }

    fn clear_melete_env() {
        std::env::remove_var(MELETE_URL_VAR);
        std::env::remove_var(MELETE_TOKEN_VAR);
    }

    fn cli_inv(path: &[&str], args: &[&str], flags: &[(&str, &str)]) -> Invocation {
        Invocation {
            path: path.iter().map(|s| s.to_string()).collect(),
            args: args.iter().map(|s| s.to_string()).collect(),
            flags: flags.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            door: Door::Cli,
        }
    }

    // ── parse_response_body (pure, no network) ──────────────────────────────

    #[test]
    fn parse_response_body_reads_plain_json_directly() {
        let v = parse_response_body(r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#).unwrap();
        assert_eq!(v["result"]["ok"], true);
    }

    #[test]
    fn parse_response_body_reads_a_single_sse_data_frame() {
        let body = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n";
        let v = parse_response_body(body).unwrap();
        assert_eq!(v["result"]["ok"], true);
    }

    #[test]
    fn parse_response_body_joins_multiple_data_lines_in_one_event() {
        // SSE joins consecutive `data:` lines with `\n` to form one message.
        let body = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\n\
                     data: \"result\":{\"ok\":true}}\n\n";
        let v = parse_response_body(body).unwrap();
        assert_eq!(v["result"]["ok"], true);
    }

    #[test]
    fn parse_response_body_keeps_the_last_event_when_several_are_framed() {
        let body = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"first\":true}}\n\n\
                     data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"second\":true}}\n\n";
        let v = parse_response_body(body).unwrap();
        assert_eq!(v["result"]["second"], true);
    }

    #[test]
    fn parse_response_body_rejects_garbage() {
        assert!(parse_response_body("not json, not sse").is_err());
    }

    // ── extract_result (pure) ────────────────────────────────────────────────

    #[test]
    fn extract_result_returns_the_result_value() {
        let v = json!({"jsonrpc":"2.0","id":1,"result":{"a":1}});
        let r = extract_result("melete.status", &v).unwrap();
        assert_eq!(r["a"], 1);
    }

    #[test]
    fn extract_result_maps_a_jsonrpc_error_to_a_named_outcome() {
        let v = json!({"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}});
        let out = extract_result("melete.call", &v).unwrap_err();
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert!(out.message.contains("method not found"), "{}", out.message);
        assert!(out.message.contains("-32601"), "{}", out.message);
    }

    #[test]
    fn extract_result_refuses_a_reply_with_neither_result_nor_error() {
        let v = json!({"jsonrpc":"2.0","id":1});
        assert!(extract_result("melete.status", &v).is_err());
    }

    // ── resolve_config ────────────────────────────────────────────────────────

    #[test]
    fn resolve_config_reports_a_structured_taught_error_when_unconfigured() {
        let _g = env_guard();
        clear_melete_env();
        let out = resolve_config("melete.status").unwrap_err();
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert_eq!(out.data.as_ref().unwrap()["reason"], "unconfigured");
        assert!(out.message.contains(MELETE_URL_VAR), "{}", out.message);
        assert!(out.message.contains(MELETE_TOKEN_VAR), "{}", out.message);
        clear_melete_env();
    }

    #[test]
    fn resolve_config_refuses_a_url_with_no_token_and_vice_versa() {
        let _g = env_guard();
        clear_melete_env();
        std::env::set_var(MELETE_URL_VAR, "http://melete.example/mcp");
        assert!(resolve_config("melete.status").is_err());
        clear_melete_env();
        std::env::set_var(MELETE_TOKEN_VAR, "tok");
        assert!(resolve_config("melete.status").is_err());
        clear_melete_env();
    }

    #[test]
    fn resolve_config_reads_both_vars_when_present() {
        let _g = env_guard();
        clear_melete_env();
        std::env::set_var(MELETE_URL_VAR, "http://melete.example/mcp");
        std::env::set_var(MELETE_TOKEN_VAR, "tok-123");
        let cfg = resolve_config("melete.status").unwrap();
        assert_eq!(cfg.url, "http://melete.example/mcp");
        assert_eq!(cfg.token, "tok-123");
        clear_melete_env();
    }

    // ── door gate — every verb, not just `call` ──────────────────────────────

    #[test]
    fn every_melete_verb_refuses_a_non_cli_door_without_touching_config() {
        let _g = env_guard();
        clear_melete_env(); // proves the gate runs BEFORE resolve_config too
        for door in [Door::Mcp, Door::A2a, Door::Daemon] {
            let status_inv = Invocation { door, ..cli_inv(&["melete", "status"], &[], &[]) };
            let out = handle_melete_status(&status_inv);
            assert_eq!(out.status, aoide_protocol::output::Status::Usage, "status over {door:?}");

            let graph_inv = Invocation { door, ..cli_inv(&["melete", "graph"], &[], &[]) };
            let out = handle_melete_graph(&graph_inv);
            assert_eq!(out.status, aoide_protocol::output::Status::Usage, "graph over {door:?}");

            let call_inv = Invocation { door, ..cli_inv(&["melete", "call"], &["job_status"], &[]) };
            let out = handle_melete_call(&call_inv);
            assert_eq!(out.status, aoide_protocol::output::Status::Usage, "call over {door:?}");
        }
    }

    // ── handle_melete_call's own arg/flag parsing (no network needed) ───────

    #[test]
    fn handle_melete_call_reports_usage_on_a_missing_tool_argument() {
        let inv = cli_inv(&["melete", "call"], &[], &[]);
        let out = handle_melete_call(&inv);
        assert_eq!(out.status, aoide_protocol::output::Status::Usage);
    }

    #[test]
    fn handle_melete_call_reports_usage_on_malformed_args_json_before_touching_config() {
        let _g = env_guard();
        clear_melete_env(); // an unconfigured host still gets the USAGE error, not "unconfigured"
        let inv = cli_inv(&["melete", "call"], &["job_status"], &[("args", "{not json")]);
        let out = handle_melete_call(&inv);
        assert_eq!(out.status, aoide_protocol::output::Status::Usage);
        assert!(out.message.contains("--args"), "{}", out.message);
    }

    // ── PATH-shim end-to-end (pair_watch/secrets precedent — #!/bin/sh,
    // ── never #!/usr/bin/env; no real network, no real curl process) ────────

    /// Writes a fake `curl` onto a fresh `PATH` prefix that echoes a fixed
    /// response body + a trailing status line — the exact shape
    /// `run_curl_with_timeout`'s `-w '\n%{http_code}'` produces — and, when
    /// `capture_body_into` is set, first copies the `--data-binary @<path>`
    /// scratch file (the outbound JSON-RPC request body — `post_json`'s
    /// bearer branch never puts it on stdin) to that marker path, so a test
    /// can assert on exactly what this module put on the wire.
    fn write_curl_shim(tag: &str, response_body: &str, status: u16, capture_body_into: Option<&std::path::Path>) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aoide-client-mcp-client-curlshim-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let shim = dir.join("curl");
        let mut script = String::from("#!/bin/sh\n");
        if let Some(marker) = capture_body_into {
            script.push_str(&format!(
                "prev=\"\"\nfor a in \"$@\"; do\n  if [ \"$prev\" = \"--data-binary\" ]; then\n    f=$(echo \"$a\" | sed 's/^@//')\n    cp \"$f\" '{}'\n  fi\n  prev=\"$a\"\ndone\n",
                marker.display()
            ));
        }
        script.push_str(&format!("printf '%s' '{response_body}'\nprintf '\\n{status}'\n"));
        std::fs::write(&shim, script).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        dir
    }

    fn with_curl_shim<T>(dir: &std::path::Path, f: impl FnOnce() -> T) -> T {
        let saved = std::env::var("PATH").ok();
        std::env::set_var("PATH", format!("{}:{}", dir.display(), saved.clone().unwrap_or_default()));
        let out = f();
        match saved {
            Some(p) => std::env::set_var("PATH", p),
            None => std::env::remove_var("PATH"),
        }
        out
    }

    #[test]
    fn handle_melete_status_reports_reachable_on_a_clean_initialize_reply() {
        let _g = env_guard();
        clear_melete_env();
        std::env::set_var(MELETE_URL_VAR, "http://melete.invalid/mcp");
        std::env::set_var(MELETE_TOKEN_VAR, "tok-abc");

        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"melete","version":"9.9.9"}}}"#;
        let dir = write_curl_shim("status-ok", body, 200, None);
        let out = with_curl_shim(&dir, || handle_melete_status(&cli_inv(&["melete", "status"], &[], &[])));
        std::fs::remove_dir_all(&dir).ok();
        clear_melete_env();

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");
        assert!(out.message.contains("melete"), "{}", out.message);
        assert!(out.message.contains("9.9.9"), "{}", out.message);
    }

    #[test]
    fn handle_melete_status_surfaces_a_401_as_a_bearer_error_naming_the_token_var() {
        let _g = env_guard();
        clear_melete_env();
        std::env::set_var(MELETE_URL_VAR, "http://melete.invalid/mcp");
        std::env::set_var(MELETE_TOKEN_VAR, "bad-tok");

        let dir = write_curl_shim("status-401", "unauthorized", 401, None);
        let out = with_curl_shim(&dir, || handle_melete_status(&cli_inv(&["melete", "status"], &[], &[])));
        std::fs::remove_dir_all(&dir).ok();
        clear_melete_env();

        assert_eq!(out.status, aoide_protocol::output::Status::Error, "{out:?}");
        assert!(out.message.contains(MELETE_TOKEN_VAR), "{}", out.message);
    }

    #[test]
    fn handle_melete_status_never_invokes_curl_when_unconfigured() {
        let _g = env_guard();
        clear_melete_env();
        let dir_marker = std::env::temp_dir().join(format!(
            "aoide-client-mcp-client-noconfig-marker-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let curl_ran_marker = dir_marker.join("curl-was-invoked");
        std::fs::create_dir_all(&dir_marker).unwrap();
        let shim = dir_marker.join("curl");
        std::fs::write(&shim, format!("#!/bin/sh\ntouch {}\nexit 1\n", curl_ran_marker.display())).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let out = with_curl_shim(&dir_marker, || handle_melete_status(&cli_inv(&["melete", "status"], &[], &[])));
        let curl_ran = curl_ran_marker.exists();
        std::fs::remove_dir_all(&dir_marker).ok();

        assert_eq!(out.status, aoide_protocol::output::Status::Error, "{out:?}");
        assert!(!curl_ran, "unconfigured melete must never invoke curl");
    }

    #[test]
    fn handle_melete_graph_writes_the_snapshot_under_the_env_overridden_state_dir() {
        // `AOIDE_STATE_DIR` (absolute-path-wins) is `state_dir()`'s own test
        // seam — the SAME override `commands.rs`'s `with_peer_state` already
        // uses, cheaper than pointing `AOIDE_ROOT` at a scratch tree since it
        // names the state dir directly.
        let _g = env_guard();
        clear_melete_env();
        std::env::set_var(MELETE_URL_VAR, "http://melete.invalid/mcp");
        std::env::set_var(MELETE_TOKEN_VAR, "tok-abc");

        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let scratch = std::env::temp_dir().join(format!(
            "aoide-client-mcp-client-graph-state-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&scratch).unwrap();
        std::env::set_var("AOIDE_STATE_DIR", &scratch);

        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"nodes\":[]}"}],"isError":false}}"#;
        let dir = write_curl_shim("graph-ok", body, 200, None);
        let out = with_curl_shim(&dir, || handle_melete_graph(&cli_inv(&["melete", "graph"], &[], &[])));
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");
        let target = scratch.join("melete-graph.json");
        assert!(target.exists(), "expected {} to exist", target.display());
        let written = std::fs::read_to_string(&target).unwrap();
        assert!(written.contains("\"schemaVersion\""), "{written}");
        assert!(written.contains("nodes"), "{written}");

        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        std::fs::remove_dir_all(&scratch).ok();
        clear_melete_env();
    }

    #[test]
    fn handle_melete_call_sends_the_named_tool_and_parsed_args_verbatim() {
        let _g = env_guard();
        clear_melete_env();
        std::env::set_var(MELETE_URL_VAR, "http://melete.invalid/mcp");
        std::env::set_var(MELETE_TOKEN_VAR, "tok-abc");

        let capture_dir = std::env::temp_dir().join(format!(
            "aoide-client-mcp-client-call-capture-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&capture_dir).unwrap();
        let marker = capture_dir.join("captured-body.json");

        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}],"isError":false}}"#;
        let dir = write_curl_shim("call-ok", body, 200, Some(&marker));
        let inv = cli_inv(&["melete", "call"], &["job_status"], &[("args", r#"{"run_id":"r-1"}"#)]);
        let out = with_curl_shim(&dir, || handle_melete_call(&inv));
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");
        let captured = std::fs::read_to_string(&marker).expect("curl shim should have captured the request body");
        let captured: Value = serde_json::from_str(&captured).unwrap();
        assert_eq!(captured["method"], "tools/call");
        assert_eq!(captured["params"]["name"], "job_status");
        assert_eq!(captured["params"]["arguments"]["run_id"], "r-1");

        std::fs::remove_dir_all(&capture_dir).ok();
        clear_melete_env();
    }
}
