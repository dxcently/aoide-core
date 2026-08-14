//! The self-registering command registry (CONTRACTS.md §3, v0).
//!
//! Every command in the tree is described here ONCE, alongside the handler
//! that runs it. The CLI dispatcher (`dispatch.rs`), the `schema --json`
//! emitter, the MCP tool list, and the A2A AgentCard (`a2a.rs`) all derive
//! from this single [`Registry`] — the "three doors, one schema" contract
//! (concepts/Agent-Interface). Nothing else in the crate enumerates commands.
//!
//! Each command group lives in its own `commands/<group>.rs` module and
//! contributes its entries via a `register(&mut Registry)` function; see
//! `commands/mod.rs::all()` for the assembly order (which reproduces the
//! historical `schema.rs` table order byte-for-byte — `schema --json` and the
//! MCP tool list must never reorder).
//!
//! The types (`Arg`, `Flag`, `Command`, `Schema`, `Registry`, `JSON_FLAG`,
//! the version consts) moved to `aoide-protocol` (Phase 2 restructure,
//! docs/architecture/PACKAGE-LAYOUT.md) and are re-exported here so every
//! existing `crate::registry::*` caller is untouched. The `cmd!`/`arg!`/`flag!`
//! macros moved there too (Phase 9 restructure) so every domain crate's
//! `commands::register()` can describe its own verbs — they expand to
//! `$crate::registry::Command { .. }` literals resolved inside the protocol
//! crate, and are re-exported here under the same names.

pub use aoide_protocol::registry::*;

#[cfg(test)]
mod tests {
    #[test]
    fn every_command_carries_the_json_flag_and_exit_codes() {
        let r = crate::commands::all();
        for c in r.commands() {
            assert!(
                c.flags.iter().any(|f| f.name == "json"),
                "{} missing --json",
                c.dotted()
            );
            let v = serde_json::to_value(c).unwrap();
            assert_eq!(v["exitCodes"]["0"], "ok");
            assert_eq!(v["exitCodes"]["64"], "not-implemented");
        }
    }

    #[test]
    fn command_paths_are_unique() {
        let r = crate::commands::all();
        let mut seen = std::collections::HashSet::new();
        for c in r.commands() {
            assert!(seen.insert(c.dotted()), "duplicate command {}", c.dotted());
        }
    }

    /// Golden snapshot: the sorted list of every command path. Adding,
    /// removing, or renaming a command is a reviewable diff here — this
    /// replaces the old magic `len() >= 33` assertion.
    #[test]
    fn command_paths_match_the_golden_snapshot() {
        let r = crate::commands::all();
        let mut got: Vec<String> = r.commands().map(|c| c.dotted()).collect();
        got.sort();

        let mut expected: Vec<&str> = vec![
            "a2a.agent.add",
            "a2a.agent.list",
            "a2a.agent.remove",
            "a2a.agent.send",
            "a2a.serve",
            "adapter.melete",
            "conduct",
            "conductor",
            "content.approve",
            "content.ingest",
            "content.propose",
            "content.query",
            "content.register",
            "cover.set",
            "daemon",
            "graph.emit",
            "graph.focus",
            "graph.link",
            "graph.project.add",
            "graph.project.list",
            "graph.project.remove",
            "graph.prune",
            "graph.reap",
            "graph.send",
            "graph.session.end",
            "graph.session.hook",
            "graph.session.phase",
            "graph.session.start",
            "graph.view",
            "graph.wrap",
            "guide",
            "hooks.install",
            "livery.emit",
            "livery.lint",
            "livery.resolve",
            "make",
            "mcp.serve",
            "onboard",
            "rice.adopt",
            "rice.design.enter",
            "rice.design.exit",
            "rice.design.status",
            "rice.gen",
            "rice.lint",
            "rice.compose",
            "rice.mode.declarative",
            "rice.mode.stage",
            "rice.mode.status",
            "rice.stage",
            "rice.transpose",
            "schema",
            "shellbridge",
            "update",
            "usage",
        ];
        expected.sort();

        assert_eq!(got, expected, "command path set drifted from the golden snapshot");
    }
}
