//! `mcp serve` / `daemon` / `shellbridge` / `adapter melete` / `conductor` —
//! the infra-glue commands. `mcp serve --stdio` and `conductor` are
//! interactive; their real execution paths are special-cased in
//! `lib.rs::run_cli` (unchanged by this refactor). The handlers here
//! reproduce exactly what `dispatch()` used to do when reached through a
//! non-interactive door (or, for `conductor`, to record the Cli-door launch
//! before `run_cli` hands off to the terminal loop).

use crate::daemon::{self, Door};
use crate::dispatch::Invocation;
use crate::output::Outcome;
use crate::registry::{cmd, flag, Registry};
use serde_json::json;

/// Registrations positioned before the `graph` group in the historical order:
/// `mcp serve`, `daemon`, `shellbridge`.
pub fn register_pre_graph(r: &mut Registry) {
    r.insert(cmd!(
        path: ["mcp", "serve"],
        summary: "Run the stdio MCP server; its tool list is generated from this schema.",
        args: [],
        flags: [flag!("stdio", "bool", "Serve over stdio (the per-session agent form).")],
        gated: false,
        implemented: true,
        handler: handle_mcp_serve,
    ));
    r.insert(cmd!(
        path: ["daemon"],
        summary: "Run the aoided daemon skeleton (policy, lint, gate, single audit log).",
        args: [],
        flags: [flag!("audit-log", "string", "Override the audit log path (default aoide.auditLog).")],
        gated: false,
        implemented: true,
        handler: handle_daemon,
    ));
    r.insert(cmd!(
        path: ["shellbridge"],
        summary: "Run the shellbridge process: publish session/hook state to song/stage/ atomically.",
        args: [],
        flags: [flag!("run", "bool", "Run the long-lived shellbridge process.")],
        gated: false,
        implemented: true,
        handler: handle_shellbridge,
    ));
}

/// Registrations positioned after the `graph`/`conduct` group in the
/// historical order: `adapter melete`, `conductor`.
pub fn register_post_graph(r: &mut Registry) {
    r.insert(cmd!(
        path: ["adapter", "melete"],
        summary: "Run the melete-adapter: consume the neutral event stream (default-deny per class).",
        args: [],
        flags: [flag!("run", "bool", "Run the long-lived adapter process.")],
        gated: false,
        implemented: true,
        handler: handle_adapter_melete,
    ));
    r.insert(cmd!(
        path: ["conductor"],
        summary: "Raise the conductor: the interactive terminal UI to conduct the agent sessions — the session DAG, projects, audit log, and stage status (every action routes through the one dispatcher). Distinct from `aoide conduct`, which wraps a single process into the conductor channel.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_conductor,
    ));
}

fn handle_mcp_serve(_inv: &Invocation) -> Outcome {
    Outcome::ok(
        "mcp.serve",
        "MCP stdio server is spawned via the binary entrypoint; \
         its tool list is generated from `schema --json`",
    )
    .with_data(json!({
        "hint": "run `aoide mcp serve --stdio` to serve; tools derive from the schema",
        "toolCount": crate::dispatch::registry().commands().count(),
    }))
}

fn handle_daemon(inv: &Invocation) -> Outcome {
    let log = crate::dispatch::audit_log_path(inv);
    let status = daemon::run(log);
    Outcome::ok("daemon", "aoided skeleton self-check complete").with_data(status)
}

fn handle_shellbridge(_inv: &Invocation) -> Outcome {
    let status = crate::shellbridge::run();
    Outcome::ok("shellbridge", "shellbridge skeleton self-check complete").with_data(status)
}

fn handle_adapter_melete(_inv: &Invocation) -> Outcome {
    let status = crate::adapter::run_melete();
    Outcome::ok(
        "adapter.melete",
        "melete-adapter skeleton self-check complete",
    )
    .with_data(status)
}

// `conductor` is interactive: like `mcp serve --stdio`, the loop itself is
// resolved at the entry point (lib.rs) — everything below stays
// frontend-agnostic. This handler only RECORDS the launch (so the audit log
// carries the door-open the conductor then tails) and, for a non-interactive
// door (MCP/daemon), returns the "run it from a terminal" outcome. The CLI
// door short-circuits in run_cli AFTER dispatching here, so on the Cli path
// this is the audit record, not a stub.
fn handle_conductor(inv: &Invocation) -> Outcome {
    match inv.door {
        Door::Cli => Outcome::ok("conductor", "raising the conductor over the agent sessions")
            .with_data(json!({
                "interactive": true,
                "stageDir": crate::shellbridge::stage_dir().to_string_lossy(),
            })),
        _ => Outcome::ok(
            "conductor",
            "conductor is interactive; run `aoide conductor` from a terminal (not over this door)",
        )
        .with_data(json!({ "interactive": true, "door": "non-cli" })),
    }
}
