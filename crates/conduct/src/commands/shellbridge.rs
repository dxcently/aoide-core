//! `shellbridge` — the stage bridge process's CLI command.
//!
//! Split out of `aoide-server`'s `commands::register_infra` (P-A2 of the
//! binary-split workstream, docs/architecture/PACKAGE-LAYOUT.md): `daemon`
//! stays a core command, but `shellbridge` belongs with the graphical binary
//! (`lyra`) alongside `rice`/`screen`/`herald`/`quickshell` — this module is
//! what P-A4 points `lyra` at. The socket-loop implementation
//! (`crate::shellbridge::run`) does NOT move; only this registration does.
//! The root package's `commands::all()` still calls this directly after
//! `aoide_server::commands::register_infra` so `schema --json` order never
//! shifts.

use aoide_protocol::output::Outcome;
use aoide_protocol::registry::{cmd, flag, Registry};
use aoide_protocol::Invocation;

fn handle_shellbridge(_inv: &Invocation) -> Outcome {
    let status = crate::shellbridge::run();
    Outcome::ok("shellbridge", "shellbridge skeleton self-check complete").with_data(status)
}

/// `shellbridge`, registered directly after `daemon`
/// (`aoide_server::commands::register_infra`) — the historical pre-`graph`
/// order.
pub fn register(r: &mut Registry) {
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
