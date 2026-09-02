//! The self-registering command registry — re-exported from `aoide-protocol`
//! (same seam `aoide-cli`'s own `registry.rs` uses) so every
//! `crate::registry::*` caller here reads exactly like the core crate's.
//!
//! Golden snapshot: the sorted list of every command path lyra registers —
//! the sole authority for lyra's command set, no count tracked elsewhere.
//! Mirrors `aoide-cli`'s `registry.rs` test module — same invariant checks.
//! P-A4 minted the base bundle; P-I3 added `onboard`; P3 added `secrets
//! ask`; L-E1 added `element seed`; P-PV3 added `pair ask`, then its own
//! revert added `pair confirm`; `quickshell healthcheck` — the
//! placeholder-screen watchdog — followed; R2 (the mutual-code redesign's
//! popup phase) repurposed `pair confirm` into `pair show`, the ceremony's
//! reply-code display dialog (net zero — one path dies, one lands). `lyra
//! reload` (design settled 2026-08-31) repurposed `quickshell.reload` into
//! `reload`, the one mode-aware iteration command — the SAME net-zero swap
//! shape. See `commands/mod.rs::all()` for the assembly order.

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

    /// `external` is additive too (task #138, CONTRACTS.md §3), mirroring
    /// `aoide-cli`'s own `registry.rs` twin: a host with zero `lyra-*`
    /// plugins on `PATH` gets a `schema --json` byte-identical to before the
    /// field existed — no `external` key at all — while dropping one on a
    /// scoped `PATH` surfaces it by name, resolved command spelling, and
    /// path.
    #[test]
    fn external_key_is_absent_unless_a_plugin_is_on_path() {
        let _guard = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var_os("PATH");
        let dir = std::env::temp_dir().join(format!("aoide_lyra_external_schema_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("PATH", &dir);

        let r = crate::commands::all();
        let v = serde_json::to_value(r.schema("lyra")).unwrap();
        assert!(v.get("external").is_none(), "no plugins on PATH -> no key at all: {v}");

        let plugin = dir.join("lyra-clipboard-copy");
        std::fs::write(&plugin, "#!/bin/sh\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&plugin).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&plugin, perms).unwrap();
        }

        let v = serde_json::to_value(r.schema("lyra")).unwrap();
        assert_eq!(v["external"][0]["name"], "clipboard-copy");
        assert_eq!(v["external"][0]["command"], "lyra-clipboard-copy");
        assert_eq!(v["external"][0]["path"], plugin.to_string_lossy().to_string());

        match saved {
            Some(val) => std::env::set_var("PATH", val),
            None => std::env::remove_var("PATH"),
        }
        let _ = std::fs::remove_dir_all(&dir);
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
            "element.seed",
            "guide",
            "herald.push",
            "livery.emit",
            "livery.lint",
            "livery.resolve",
            "mcp.serve",
            "onboard",
            "pair.ask",
            "pair.show",
            "quickshell.healthcheck",
            "reload",
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
            "secrets.ask",
            "shellbridge",
        ];
        expected.sort();

        assert_eq!(got, expected, "command path set drifted from lyra's golden snapshot");
    }
}
