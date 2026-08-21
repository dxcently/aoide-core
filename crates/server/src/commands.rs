//! The server domain's CLI verbs: `a2a serve`'s door-hint handler and
//! `daemon` (the aoided skeleton).
//!
//! Moved from the root package's `src/commands/a2a.rs` + the server half of
//! `src/commands/infra.rs` (Phase 9 restructure,
//! docs/architecture/PACKAGE-LAYOUT.md): a domain's CLI verbs live with the
//! domain. The root package's `commands::all()` calls [`register_infra`]
//! directly after its own root-coupled `mcp serve` registration and
//! [`register_a2a_serve`] directly before
//! `aoide_client::commands::register_agents`, so `schema --json` order never
//! shifts.
//!
//! `shellbridge` moved out at P-A2 of the binary-split workstream
//! (docs/architecture/PACKAGE-LAYOUT.md): it belongs with the graphical
//! binary (`lyra`), not core, so its registration now lives in
//! `aoide_conduct::commands::shellbridge` — `commands::all()` calls it
//! directly after [`register_infra`] so the assembled order is unchanged.
//!
//! `a2a serve` itself is a long-running blocking server, so the root
//! package's `run_cli` special-cases its launch exactly like
//! `mcp serve --stdio`/`conductor`; the `serve` handler below only covers the
//! non-Cli-door / metadata path. (`mcp serve`'s handler stays in the ROOT
//! package — it reads the assembled registry's tool count, the one coupling
//! the DI seam cannot sever.)

use aoide_protocol::output::Outcome;
use aoide_protocol::registry::{cmd, flag, Registry};
use aoide_protocol::{Door, Invocation};
use serde_json::json;

/// `a2a serve`'s handler. On the Cli door this is only ever reached via
/// `run_cli`'s special-case (dispatch first, to record the launch, THEN
/// block in the accept loop); on any other door (e.g. an MCP `tools/call`
/// for `a2a.serve`) it never blocks that door, it just reports how to
/// actually raise the server.
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

fn handle_daemon(inv: &Invocation) -> Outcome {
    let log = aoide_protocol::audit_log_path(inv);
    let status = crate::daemon::run(log);
    Outcome::ok("daemon", "aoided skeleton self-check complete").with_data(status)
}

/// `daemon`, registered directly after the root package's own `mcp serve`
/// entry (the historical pre-`graph` order; `shellbridge` used to register
/// here too — see the module doc for where it moved).
pub fn register_infra(r: &mut Registry) {
    r.insert(cmd!(
        path: ["daemon"],
        summary: "Run the aoided daemon skeleton (policy, lint, gate, single audit log).",
        args: [],
        flags: [flag!("audit-log", "string", "Override the audit log path (default aoide.auditLog).")],
        gated: false,
        implemented: true,
        handler: handle_daemon,
    ));
}

/// `a2a serve`, registered directly before `aoide-client`'s four `agent`
/// verbs (the historical `a2a` group order).
pub fn register_a2a_serve(r: &mut Registry) {
    r.insert(cmd!(
        path: ["a2a", "serve"],
        summary: "Run the A2A (Agent2Agent) server: expose aoide-orchestrated sessions as a discoverable A2A agent (AgentCard + message/send + tasks/get). Localhost, user-only, off by default.",
        args: [],
        flags: [
            flag!("port", "int", "Override the A2A HTTP port (default aoide.a2a.port)."),
            flag!("bind", "string", "Override the A2A HTTP bind address (default aoide.a2a.bindAddress)."),
            flag!("spawn-agent", "string", "Override the command message/send's spawn path conducts (default aoide.a2a.spawnAgent; empty = spawning disabled)."),
            flag!("peer-name", "string", "Override this instance's aoide/graphSummary instance name (default: the OS hostname)."),
            flag!("token-file", "string", "Path to a file holding the shared secret an inbound message/send must present (Authorization: Bearer <token>) (default aoide.a2a.tokenFile; empty = no token required, loopback keeps today's automatic trust)."),
        ],
        gated: false,
        implemented: true,
        handler: handle_a2a_serve,
    ));
}
