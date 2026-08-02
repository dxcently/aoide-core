//! `a2a serve` / `a2a agent add|list|remove|send` — the A2A (Agent2Agent) door
//! group (CONTRACTS.md §6). Phase B flipped `a2a serve` real (a JSON-RPC/HTTP
//! server, `src/a2a.rs`: AgentCard + `tasks/get`); Phase B2 landed
//! `message/send` execution (inject into a known conductable session, or
//! spawn a freshly conducted one running the operator-configured
//! `aoide.a2a.spawnAgent`). `a2a serve` itself is a long-running blocking
//! server, so `lib.rs::run_cli` special-cases its launch exactly like
//! `mcp serve --stdio`/`conductor`; the `serve` handler below only covers the
//! non-Cli-door / metadata path (mirrors `commands/infra.rs::handle_conductor`).
//!
//! Phase D (CLIENT side) makes the `agent` verbs real: aoide registers an
//! EXTERNAL A2A agent by its AgentCard URL (`agent add`), lists/removes them
//! (`agent list`/`remove`), and DRIVES one (`agent send`) — the outbound half
//! of the bidirectional link. The registry lives in `state/a2a-agents.json`
//! (`src/a2a.rs`: [`crate::a2a::load_agents`] et al) and folds into the session
//! DAG as `kind:"a2a"` nodes (`graph/doc.rs::build_graph`). These endpoints are
//! external and carry NO local credential, so — unlike `commands/usage.rs`'s
//! token fetch — a plain curl (url/body in argv or stdin) is fine; we reuse its
//! `(code, body)` parsing discipline. SSRF isn't guarded: the url is the user's
//! own CLI argument, a user-initiated fetch.

use crate::daemon::Door;
use crate::dispatch::Invocation;
use crate::output::Outcome;
use crate::registry::{arg, cmd, flag, Registry};
use serde_json::{json, Value};
use std::io::Write;
use std::process::Stdio;

/// `a2a serve`'s handler. On the Cli door this is only ever reached via
/// `run_cli`'s special-case (dispatch first, to record the launch, THEN
/// block in the accept loop — see `lib.rs`); on any other door (e.g. an MCP
/// `tools/call` for `a2a.serve`) it never blocks that door, it just reports
/// how to actually raise the server.
fn handle_a2a_serve(inv: &Invocation) -> Outcome {
    let (bind, port) = crate::a2a::resolve_bind_port(inv);
    match inv.door {
        Door::Cli => Outcome::ok(
            "a2a.serve",
            format!("raising the A2A server on http://{bind}:{port}/"),
        )
        .with_data(json!({ "interactive": true, "bind": bind, "port": port })),
        _ => Outcome::ok(
            "a2a.serve",
            "a2a serve is a long-running server; run `aoide a2a serve` from a terminal \
             or the aoide-a2a systemd unit (not over this door)",
        )
        .with_data(json!({ "interactive": true, "door": "non-cli" })),
    }
}

// ── curl transport ((code, body) discipline from commands/usage.rs) ─────────

/// Run `curl -sS --max-time 15 -w '\n%{http_code}' <extra…>`, optionally piping
/// `stdin_body` (for a POST via `--data-binary @-`), and return
/// `(http_code, body)`. The `-w` trailing line is the status; the rest is the
/// body. A spawn/pipe failure, empty/garbled output, or a `000` (connection
/// failure/timeout) all map to `Err`. `stderr` is nulled so nothing curl prints
/// surfaces. No secret is involved (external endpoint, no local credential), so
/// the url/body may ride in argv freely — this reuses usage.rs's parsing, not
/// its token-hiding.
fn run_curl(extra: &[&str], stdin_body: Option<&str>) -> Result<(u16, String), String> {
    let mut cmd = std::process::Command::new("curl");
    cmd.args(["-sS", "--max-time", "15", "-w", "\n%{http_code}"]);
    cmd.args(extra);
    cmd.stdout(Stdio::piped()).stderr(Stdio::null());
    cmd.stdin(if stdin_body.is_some() { Stdio::piped() } else { Stdio::null() });
    let mut child = cmd
        .spawn()
        .map_err(|_| "curl failed (is curl installed?)".to_string())?;
    if let Some(body) = stdin_body {
        let mut si = child.stdin.take().ok_or_else(|| "curl failed".to_string())?;
        si.write_all(body.as_bytes())
            .map_err(|_| "curl failed".to_string())?;
    }
    let out = child
        .wait_with_output()
        .map_err(|_| "curl failed".to_string())?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let (body, code_str) = match stdout.rsplit_once('\n') {
        Some((b, c)) => (b, c.trim()),
        None => ("", stdout.trim()),
    };
    let code: u16 = code_str
        .parse()
        .map_err(|_| "curl failed (no HTTP status)".to_string())?;
    if code == 0 {
        return Err("could not reach the agent (connection failed or timed out)".to_string());
    }
    Ok((code, body.to_string()))
}

/// A unique `messageId` for one outbound `message/send` (pid + wall-clock
/// nanos — never reused within a process).
fn gen_message_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("aoide-{}-{}", std::process::id(), nanos)
}

/// A short human summary of a `message/send` reply (a Task or a Message).
fn describe_result(resp: &Value) -> String {
    let Some(result) = resp.get("result") else {
        return "reply received".to_string();
    };
    if let Some(state) = result
        .get("status")
        .and_then(|s| s.get("state"))
        .and_then(Value::as_str)
    {
        let id = result.get("id").and_then(Value::as_str).unwrap_or("");
        return format!("task {id} [{state}]");
    }
    match result.get("kind").and_then(Value::as_str) {
        Some(kind) => format!("{kind} reply"),
        None => "reply received".to_string(),
    }
}

// ── The four `agent` verbs (client side, CONTRACTS.md §6) ────────────────────

/// `a2a agent add <url>` — fetch the AgentCard, parse it, register the agent.
fn handle_agent_add(inv: &Invocation) -> Outcome {
    let cmd = "a2a.agent.add";
    let url = match inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(u) => u.to_string(),
        None => return Outcome::usage(cmd, "usage: aoide a2a agent add <url> [--json]"),
    };
    let card_url = crate::a2a::resolve_card_url(&url);
    let (code, body) = match run_curl(&["--", &card_url], None) {
        Ok(v) => v,
        Err(e) => {
            return Outcome::error(cmd, format!("fetching AgentCard {card_url}: {e}"))
                .with_data(json!({ "reason": "fetch-failed", "url": card_url }))
        }
    };
    if code != 200 {
        return Outcome::error(cmd, format!("fetching AgentCard {card_url}: HTTP {code}"))
            .with_data(json!({ "reason": "fetch-http-error", "url": card_url, "httpCode": code }));
    }
    let card: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            return Outcome::error(cmd, format!("parsing AgentCard {card_url}: {e}"))
                .with_data(json!({ "reason": "card-unparseable", "url": card_url }))
        }
    };
    let now = aoide_storage::time::now_iso_utc();
    let agent = match crate::a2a::parse_agent_card(&card, &card_url, &now) {
        Ok(a) => a,
        Err(e) => {
            return Outcome::error(cmd, format!("invalid AgentCard {card_url}: {e}"))
                .with_data(json!({ "reason": "card-invalid", "url": card_url }))
        }
    };
    let mut agents = crate::a2a::load_agents();
    let replaced = agents.iter().any(|a| a.name == agent.name);
    crate::a2a::upsert_agent(&mut agents, agent.clone());
    if let Err(e) = crate::a2a::save_agents(&agents) {
        return Outcome::error(cmd, format!("writing the agent registry: {e}"))
            .with_data(json!({ "reason": "registry-write-failed" }));
    }
    let verb = if replaced { "updated" } else { "registered" };
    Outcome::ok(
        cmd,
        format!(
            "{verb} A2A agent `{}` → {} ({} total)",
            agent.name,
            agent.url,
            agents.len()
        ),
    )
    .changed(vec![crate::a2a::agents_path().to_string_lossy().into_owned()])
    .with_data(json!({ "agent": agent, "count": agents.len(), "replaced": replaced }))
}

/// `a2a agent list` — the registered agents (name · url · description).
fn handle_agent_list(_inv: &Invocation) -> Outcome {
    let cmd = "a2a.agent.list";
    let agents = crate::a2a::load_agents();
    let msg = if agents.is_empty() {
        "no external A2A agents registered".to_string()
    } else {
        let lines: Vec<String> = agents
            .iter()
            .map(|a| {
                if a.description.is_empty() {
                    format!("{} · {}", a.name, a.url)
                } else {
                    format!("{} · {} · {}", a.name, a.url, a.description)
                }
            })
            .collect();
        format!(
            "{} registered A2A agent(s):\n{}",
            agents.len(),
            lines.join("\n")
        )
    };
    Outcome::ok(cmd, msg).with_data(json!({ "agents": agents, "count": agents.len() }))
}

/// `a2a agent remove <name>` — drop the named agent (idempotent).
fn handle_agent_remove(inv: &Invocation) -> Outcome {
    let cmd = "a2a.agent.remove";
    let name = match inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(n) => n.to_string(),
        None => return Outcome::usage(cmd, "usage: aoide a2a agent remove <name> [--json]"),
    };
    let mut agents = crate::a2a::load_agents();
    if !crate::a2a::remove_agent(&mut agents, &name) {
        return Outcome::ok(cmd, format!("no A2A agent named `{name}` (nothing to remove)"))
            .with_data(json!({ "removed": false, "name": name, "count": agents.len() }));
    }
    if let Err(e) = crate::a2a::save_agents(&agents) {
        return Outcome::error(cmd, format!("writing the agent registry: {e}"))
            .with_data(json!({ "reason": "registry-write-failed" }));
    }
    Outcome::ok(
        cmd,
        format!("removed A2A agent `{name}` ({} remaining)", agents.len()),
    )
    .changed(vec![crate::a2a::agents_path().to_string_lossy().into_owned()])
    .with_data(json!({ "removed": true, "name": name, "count": agents.len() }))
}

/// `a2a agent send <name> <message>` — DRIVE a registered external agent: POST
/// a JSON-RPC `message/send` to its endpoint and report the returned
/// Task/Message. The outbound half of the bidirectional A2A link.
fn handle_agent_send(inv: &Invocation) -> Outcome {
    let cmd = "a2a.agent.send";
    let name = match inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(n) => n.to_string(),
        None => return Outcome::usage(cmd, "usage: aoide a2a agent send <name> <message> [--json]"),
    };
    let message = match inv.args.get(1).filter(|s| !s.is_empty()) {
        Some(m) => m.to_string(),
        None => return Outcome::usage(cmd, "usage: aoide a2a agent send <name> <message> [--json]"),
    };
    let agents = crate::a2a::load_agents();
    let agent = match agents.iter().find(|a| a.name == name) {
        Some(a) => a.clone(),
        None => {
            return Outcome::error(
                cmd,
                format!("no A2A agent named `{name}` — register it first with `aoide a2a agent add <url>`"),
            )
            .with_data(json!({ "reason": "unknown-agent", "name": name }))
        }
    };
    let message_id = gen_message_id();
    let body = crate::a2a::build_message_send_body(&message, &message_id);
    let body_str = serde_json::to_string(&body).unwrap_or_default();
    let (code, resp) = match run_curl(
        &[
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "--data-binary",
            "@-",
            "--",
            &agent.url,
        ],
        Some(&body_str),
    ) {
        Ok(v) => v,
        Err(e) => {
            return Outcome::error(cmd, format!("driving `{name}` at {}: {e}", agent.url))
                .with_data(json!({ "reason": "send-failed", "name": name, "url": agent.url }))
        }
    };
    if code != 200 {
        return Outcome::error(cmd, format!("driving `{name}` at {}: HTTP {code}", agent.url))
            .with_data(json!({
                "reason": "send-http-error", "name": name, "url": agent.url,
                "httpCode": code, "body": resp,
            }));
    }
    let parsed: Value = serde_json::from_str(&resp).unwrap_or(Value::Null);
    // A JSON-RPC error still returns HTTP 200 — surface it as an error Outcome.
    if let Some(err) = parsed.get("error") {
        let detail = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("(no message)");
        return Outcome::error(cmd, format!("agent `{name}` returned an error: {detail}"))
            .with_data(json!({ "reason": "agent-error", "name": name, "response": parsed }));
    }
    Outcome::ok(
        cmd,
        format!("sent to `{name}` at {} — {}", agent.url, describe_result(&parsed)),
    )
    .with_data(json!({
        "name": name, "url": agent.url, "messageId": message_id, "response": parsed,
    }))
}

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["a2a", "serve"],
        summary: "Run the A2A (Agent2Agent) server: expose aoide-orchestrated sessions as a discoverable A2A agent (AgentCard + message/send + tasks/get). Localhost, user-only, off by default.",
        args: [],
        flags: [
            flag!("port", "int", "Override the A2A HTTP port (default aoide.a2a.port)."),
            flag!("bind", "string", "Override the A2A HTTP bind address (default aoide.a2a.bindAddress)."),
            flag!("spawn-agent", "string", "Override the command message/send's spawn path conducts (default aoide.a2a.spawnAgent; empty = spawning disabled)."),
        ],
        gated: false,
        implemented: true,
        handler: handle_a2a_serve,
    ));
    r.insert(cmd!(
        path: ["a2a", "agent", "add"],
        summary: "Register an external A2A agent (by AgentCard URL) as a node in the session DAG.",
        args: [arg!("url", "string", true, "The external agent's AgentCard URL (or origin — the well-known path is appended).")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_agent_add,
    ));
    r.insert(cmd!(
        path: ["a2a", "agent", "list"],
        summary: "List registered external A2A agents.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_agent_list,
    ));
    r.insert(cmd!(
        path: ["a2a", "agent", "remove"],
        summary: "Unregister an external A2A agent.",
        args: [arg!("name", "string", true, "The registered agent's name.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_agent_remove,
    ));
    r.insert(cmd!(
        path: ["a2a", "agent", "send"],
        summary: "Drive a registered external A2A agent: POST a JSON-RPC message/send and report the returned Task/Message.",
        args: [
            arg!("name", "string", true, "The registered agent's name."),
            arg!("message", "string", true, "The message text to send."),
        ],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_agent_send,
    ));
}
