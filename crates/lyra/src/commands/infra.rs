//! `mcp serve` — registered here (not left implicit) for the same reason
//! core keeps it root-coupled (`aoide-cli`'s own `commands/infra.rs`): its
//! handler reads the fully-assembled registry's tool count, and — the part
//! that actually matters for this crate — `lib.rs`'s `special` hook can only
//! ever fire for a path `aoide_protocol::door::parse` already recognizes.
//! `mcp serve --stdio`'s real execution stays special-cased in `lib.rs`
//! (unchanged pattern); this registration is what lets that invocation parse
//! at all. This is the one command lyra registers outside the plan's named
//! rice/draft/mode/cover/livery/shellbridge/quickshell/screen/herald/take
//! groups — see the crate's module doc for the count.

use crate::dispatch::Invocation;
use crate::output::Outcome;
use crate::registry::{cmd, flag, Registry};
use serde_json::json;

pub fn register_mcp(r: &mut Registry) {
    r.insert(cmd!(
        path: ["mcp", "serve"],
        summary: "Run lyra's stdio MCP server; its tool list is generated from this schema.",
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
         its tool list is generated from `lyra schema --json`",
    )
    .with_data(json!({
        "hint": "run `lyra mcp serve --stdio` to serve; tools derive from the schema",
        "toolCount": crate::dispatch::registry().commands().count(),
    }))
}
