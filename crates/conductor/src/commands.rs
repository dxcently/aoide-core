//! The conductor domain's one CLI verb: `conductor` — raise the interactive
//! terminal UI.
//!
//! Moved from the root package's `src/commands/infra.rs` (Phase 9
//! restructure, docs/architecture/PACKAGE-LAYOUT.md): a domain's CLI verbs
//! live with the domain. The root package's `commands::all()` calls
//! [`register`] directly after `aoide_client::commands::register_post_graph`,
//! so `schema --json` order never shifts.

use aoide_protocol::output::Outcome;
use aoide_protocol::registry::{cmd, Registry};
use aoide_protocol::{Door, Invocation};
use serde_json::json;

// `conductor` is interactive: like `mcp serve --stdio`, the loop itself is
// resolved at the entry point (the root package's `run_cli`) — everything
// below stays frontend-agnostic. This handler only RECORDS the launch (so
// the audit log carries the door-open the conductor then tails) and, for a
// non-interactive door (MCP/daemon), returns the "run it from a terminal"
// outcome. The CLI door short-circuits in run_cli AFTER dispatching here,
// so on the Cli path this is the audit record, not a stub.
fn handle_conductor(inv: &Invocation) -> Outcome {
    match inv.door {
        Door::Cli => Outcome::ok("conductor", "raising the conductor over the agent sessions")
            .with_data(json!({
                "interactive": true,
                "stageDir": aoide_storage::fs::stage_dir().to_string_lossy(),
            })),
        _ => Outcome::ok(
            "conductor",
            "conductor is interactive; run `aoide conductor` from a terminal (not over this door)",
        )
        .with_data(json!({ "interactive": true, "door": "non-cli" })),
    }
}

pub fn register(r: &mut Registry) {
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
