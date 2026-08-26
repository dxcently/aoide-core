//! `mcp serve` — the ONE infra command that stays in the root package
//! (Phase 9 restructure, docs/architecture/PACKAGE-LAYOUT.md).
//!
//! Its handler reads the fully-assembled registry's tool count
//! (`crate::dispatch::registry()`) — the one coupling the `aoide-server` DI
//! seam cannot sever, since that registry only exists here. Everything else
//! that used to live in this file moved with its domain: `daemon` +
//! `shellbridge` + `a2a serve` → `aoide-server`, `adapter melete` +
//! the four `a2a agent` commands → `aoide-client`, `conductor` →
//! `aoide-conductor`. `mcp serve --stdio`'s real execution path stays
//! special-cased in `lib.rs::run_cli` (unchanged).

use crate::dispatch::Invocation;
use crate::output::Outcome;
use crate::registry::{cmd, flag, Registry};
use serde_json::json;

/// Registrations positioned before the `daemon`/`shellbridge` pair
/// (`aoide-server`) in the historical order: just `mcp serve` now.
pub fn register_mcp(r: &mut Registry) {
    r.insert(cmd!(
        path: ["mcp", "serve"],
        summary: "Run the stdio MCP server; its tool list is generated from this schema.",
        args: [],
        flags: [flag!("stdio", "bool", "Serve over stdio (the per-session agent form).")],
        gated: false,
        implemented: true,
        handler: handle_mcp_serve,
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
