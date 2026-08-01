//! `a2a serve` / `a2a agent add|list|remove` — the A2A (Agent2Agent) door
//! group (CONTRACTS.md §6, v0). Walking-skeleton CONTRACT phase: metadata-only
//! registrations, every entry `implemented: false`. This module is the group
//! home a later phase flips to real handlers (server + client-side registry)
//! — `commands/mod.rs::all()` appends it last so the existing schema order is
//! unperturbed.

use crate::dispatch::Invocation;
use crate::output::Outcome;
use crate::registry::{arg, cmd, flag, Registry};

/// Never invoked — `dispatch()` returns the not-implemented envelope itself
/// for any command with `implemented: false`, without calling `handler`
/// (same convention as `commands/stubs.rs::unimplemented`).
fn unimplemented(_inv: &Invocation) -> Outcome {
    unreachable!("dispatch() never calls the handler of a not-implemented command")
}

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["a2a", "serve"],
        summary: "Run the A2A (Agent2Agent) server: expose aoide-orchestrated sessions as a discoverable A2A agent (AgentCard + message/send + tasks/get). Localhost, user-only, off by default.",
        args: [],
        flags: [
            flag!("port", "int", "Override the A2A HTTP port (default aoide.a2a.port)."),
            flag!("bind", "string", "Override the A2A HTTP bind address (default aoide.a2a.bindAddress)."),
        ],
        gated: false,
        implemented: false,
        handler: unimplemented,
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
