//! `a2a serve` / `a2a agent add|list|remove` — the A2A (Agent2Agent) door
//! group (CONTRACTS.md §6). Phase B flipped `a2a serve` real (a JSON-RPC/HTTP
//! server, `src/a2a.rs`: AgentCard + `tasks/get`); Phase B2 landed
//! `message/send` execution (inject into a known conductable session, or
//! spawn a freshly conducted one running the operator-configured
//! `aoide.a2a.spawnAgent`). `a2a serve` itself is a long-running blocking
//! server, so `lib.rs::run_cli` special-cases its launch exactly like
//! `mcp serve --stdio`/`conductor`; the handler below only covers the
//! non-Cli-door / metadata path (mirrors `commands/infra.rs::handle_conductor`).
//! `a2a agent add|list|remove` stay `implemented: false` stubs — the
//! client-side registry is a later phase.

use crate::daemon::Door;
use crate::dispatch::Invocation;
use crate::output::Outcome;
use crate::registry::{arg, cmd, flag, Registry};
use serde_json::json;

/// Never invoked — `dispatch()` returns the not-implemented envelope itself
/// for any command with `implemented: false`, without calling `handler`
/// (same convention as `commands/stubs.rs::unimplemented`).
fn unimplemented(_inv: &Invocation) -> Outcome {
    unreachable!("dispatch() never calls the handler of a not-implemented command")
}

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
        args: [arg!("url", "string", true, "The external agent's AgentCard URL.")],
        flags: [],
        gated: false,
        implemented: false,
        handler: unimplemented,
    ));
    r.insert(cmd!(
        path: ["a2a", "agent", "list"],
        summary: "List registered external A2A agents.",
        args: [],
        flags: [],
        gated: false,
        implemented: false,
        handler: unimplemented,
    ));
    r.insert(cmd!(
        path: ["a2a", "agent", "remove"],
        summary: "Unregister an external A2A agent.",
        args: [arg!("name", "string", true, "The registered agent's name.")],
        flags: [],
        gated: false,
        implemented: false,
        handler: unimplemented,
    ));
}
