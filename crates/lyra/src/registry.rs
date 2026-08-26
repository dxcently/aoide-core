//! The self-registering command registry — re-exported from `aoide-protocol`
//! (same seam `aoide-cli`'s own `registry.rs` uses) so every
//! `crate::registry::*` caller here reads exactly like the core crate's.
//!
//! Golden snapshot: the sorted list of every command path lyra registers.
//! Mirrors `aoide-cli`'s `registry.rs` test module — same invariant checks,
//! lyra's own 42-path bundle (P-A4; see `commands/mod.rs::all()` for the
//! assembly order and why it's 42, not the plan's estimated 41).

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
            .find(|c| c.dotted() == "rice.compose")
            .expect("rice compose carries examples");
        let v = serde_json::to_value(with).unwrap();
        assert_eq!(v["examples"][0], "rice compose moonlight --from sonata");

        let without = r
            .commands()
            .find(|c| c.dotted() == "rice.lint")
            .expect("rice lint carries none");
        let v = serde_json::to_value(without).unwrap();
        assert!(
            v.get("examples").is_none(),
            "no examples → no key (byte-identical schema): {v}"
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
    /// removing, or renaming a command is a reviewable diff here — this is
    /// lyra's own golden, independent of the core crate's.
    #[test]
    fn command_paths_match_the_golden_snapshot() {
        let r = crate::commands::all();
        let mut got: Vec<String> = r.commands().map(|c| c.dotted()).collect();
        got.sort();

        let mut expected: Vec<&str> = vec![
            "cover.set",
            "guide",
            "herald.push",
            "livery.emit",
            "livery.lint",
            "livery.resolve",
            "mcp.serve",
            "quickshell.reload",
            "rice.back",
            "rice.compose",
            "rice.declare",
            "rice.draft.drop",
            "rice.draft.list",
            "rice.draft.save",
            "rice.lint",
            "rice.mode.declarative",
            "rice.mode.draft",
            "rice.mode.stage",
            "rice.mode.status",
            "rice.stage",
            "rice.take",
            "rice.take.diff",
            "rice.take.list",
            "rice.take.mark",
            "rice.take.prune",
            "rice.transpose",
            "schema",
            "screen.diff",
            "screen.info",
            "screen.ocr",
            "screen.point.click",
            "screen.point.drag",
            "screen.point.hover",
            "screen.point.idle",
            "screen.point.move",
            "screen.point.restore",
            "screen.point.save",
            "screen.point.scroll",
            "screen.point.text",
            "screen.send",
            "screen.shot",
            "shellbridge",
        ];
        expected.sort();

        assert_eq!(got, expected, "command path set drifted from lyra's golden snapshot");
        assert_eq!(got.len(), 42, "lyra's golden path count");
    }
}
