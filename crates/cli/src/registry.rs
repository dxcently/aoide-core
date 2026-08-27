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
//! `commands::register()` can describe its own commands — they expand to
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

    /// `examples` is additive (CONTRACTS.md §3): a command WITHOUT examples
    /// serializes byte-identical to before the field existed — no `examples`
    /// key at all — while one WITH examples carries it.
    #[test]
    fn examples_key_is_absent_unless_populated() {
        let r = crate::commands::all();
        let with = r
            .commands()
            .find(|c| c.dotted() == "project.add")
            .expect("project add carries examples");
        let v = serde_json::to_value(with).unwrap();
        assert_eq!(v["examples"][0], "project add aoide ~/Aoide");

        let without = r
            .commands()
            .find(|c| c.dotted() == "session.prune")
            .expect("session prune carries none");
        let v = serde_json::to_value(without).unwrap();
        assert!(
            v.get("examples").is_none(),
            "no examples → no key (byte-identical schema): {v}"
        );
    }

    /// `internal` is additive (CONTRACTS.md §3), same discipline `examples`
    /// carries above: a non-internal command's schema stays byte-identical
    /// to before the field existed (no `internal` key at all), while the
    /// hook-plumbing family (task #101 R1) carries `"internal":true`.
    #[test]
    fn internal_key_is_absent_unless_the_command_is_hook_plumbing() {
        let r = crate::commands::all();
        let hook_cmd = r
            .commands()
            .find(|c| c.dotted() == "session.start")
            .expect("session start is the hook-plumbing family");
        assert!(hook_cmd.internal, "session.start is marked internal");
        let v = serde_json::to_value(hook_cmd).unwrap();
        assert_eq!(v["internal"], true);

        let operator_cmd = r
            .commands()
            .find(|c| c.dotted() == "graph")
            .expect("bare graph is an ordinary operator command");
        assert!(!operator_cmd.internal);
        let v = serde_json::to_value(operator_cmd).unwrap();
        assert!(
            v.get("internal").is_none(),
            "non-internal command carries no `internal` key at all: {v}"
        );
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

        // The R1 graph-prefix cutover (task #101, Lane R) renamed 18 of the 19
        // former `graph.*` spellings in place — same 73-count, no aliases:
        // `graph.view` -> bare `graph` (the render; `graph.link` alone
        // survives the family), `graph.send`/`graph.spawn`/`graph.resurrect`
        // -> bare `send`/`spawn`/`resurrect`, `graph.session.*`/`graph.permit`/
        // `graph.pending.*`/`graph.reap`/`graph.prune` -> `session.*`,
        // `graph.project.*` -> `project.*`. See `conduct/src/commands/
        // graph.rs`'s module doc for the full table.
        let mut expected: Vec<&str> = vec![
            "a2a.serve",
            "adapter.melete",
            "conduct",
            "conductor",
            "content.approve",
            "content.ingest",
            "content.propose",
            "content.query",
            "content.register",
            "daemon",
            "events.tail",
            "graph",
            "graph.link",
            "guide",
            "hooks.install",
            "identity",
            "inbox.clear",
            "inbox.list",
            "inbox.read",
            "make",
            "mcp.serve",
            "onboard",
            "peer.add",
            "peer.allow",
            "peer.discover",
            "peer.hub",
            "peer.invite",
            "peer.pair.approve",
            "peer.pair.pending",
            "peer.pair.reject",
            "peer.pair.request",
            "peer.pull",
            "peer.remove",
            "peer.spawn",
            "peer.status",
            "project.add",
            "project.list",
            "project.remove",
            "resurrect",
            "schema",
            "secrets.add",
            "secrets.approve",
            "secrets.automate",
            "secrets.dismiss",
            "secrets.enroll",
            "secrets.exec",
            "secrets.expose",
            "secrets.grant",
            "secrets.migrate",
            "secrets.pending",
            "secrets.put",
            "secrets.revoke",
            "secrets.rm",
            "secrets.serve",
            "secrets.set-totp",
            "secrets.watch",
            "send",
            "session.end",
            "session.hook",
            "session.pending.approve",
            "session.pending.deny",
            "session.pending.list",
            "session.permit",
            "session.phase",
            "session.prune",
            "session.reap",
            "session.start",
            "session.undying",
            "soundcheck",
            "spawn",
            "update",
            "usage",
            "who",
        ];
        expected.sort();

        assert_eq!(got, expected, "command path set drifted from the golden snapshot");
    }
}
