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

    /// `external` is additive too (task #138, CONTRACTS.md §3), same
    /// discipline `examples`/`internal` carry above, but at the SCHEMA level
    /// rather than per-command: a host with zero `aoide-*` plugins on `PATH`
    /// gets a `schema --json` byte-identical to before the field existed —
    /// no `external` key at all — while dropping one on a scoped `PATH`
    /// surfaces it by name, resolved command spelling, and path.
    #[test]
    fn external_key_is_absent_unless_a_plugin_is_on_path() {
        let _guard = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var_os("PATH");
        let dir = std::env::temp_dir().join(format!("aoide_cli_external_schema_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("PATH", &dir);

        let r = crate::commands::all();
        let v = serde_json::to_value(r.schema("aoide")).unwrap();
        assert!(v.get("external").is_none(), "no plugins on PATH -> no key at all: {v}");

        let plugin = dir.join("aoide-deploy");
        std::fs::write(&plugin, "#!/bin/sh\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&plugin).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&plugin, perms).unwrap();
        }

        let v = serde_json::to_value(r.schema("aoide")).unwrap();
        assert_eq!(v["external"][0]["name"], "deploy");
        assert_eq!(v["external"][0]["command"], "aoide-deploy");
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
        // graph.rs`'s module doc for the full table. Bumped by 1 for bare
        // `session` — the undying picker (U3, command-defrag lane U) — a
        // parent command alongside `session.*` the same way bare `graph`
        // sits alongside `graph.link`: reached 74. Bumped by 1 more for
        // `node.pair.watch` (P-P5): reached 75. Bumped by 3 for `melete
        // status`/`melete graph`/`melete call` (M2, task #14) — the Melete
        // MCP client, `aoide_client::mcp_client` — reached 78. Bumped by 1
        // for `node.advertise` (task #120) — the discovery advertise
        // switch — reached 79. Bumped by 1 for `node.list` (task #120 P2)
        // — the one-glance mesh roster (this host + registered nodes +
        // advertising instances, sessions under each), registered from
        // `aoide-conduct` because it folds `who`'s probe core — reached 80.
        // Bumped by 1 for bare `pair` (task #120 P3) — the interactive
        // pairing picker, one sweep + a select menu driving the SAME
        // `run_pair_request` ceremony core `node invite` uses — reached 81.
        // Bumped by 1 for `secrets allow-remote-origin` (LANE IDENTITY
        // P-ID4) — the per-secret remote-origin admission bit the broker's
        // origin gate enforces (deny by default; the first real consumer
        // of the sealed session credential) — reached 82.
        //
        // Session-surface redesign (command-defrag lane X, 2026-08-28) —
        // three movements in the SAME commit, net 82 -> 81:
        //   - `session.undying` RETIRED (-1, 82 -> 81): absorbed into
        //     `session.grant`'s positional `<kind>` grammar below — the
        //     standalone scripted spelling is now unknown, same as a typo.
        //   - `session.grant` ADDED (+1, 81 -> 82): the grant family — one
        //     kind today, `undying` (bare = interactive picker, relocated
        //     verbatim from the old bare `session`; `on|off` = the scripted
        //     mark `session.undying` used to be).
        //   - `who` RETIRED (-1, 82 -> 81): folded entirely into bare
        //     `session` — `session --hosts` now renders exactly what `who`
        //     used to (byte-identical), and plain bare `session` groups by
        //     PROJECT instead of by host. `session` itself keeps its
        //     existing path (no count change from it — only its meaning
        //     changed, from the U3 undying picker to the roster).
        // Net: 82 - 1 + 1 - 1 = 81.
        //
        // P-PV2 (the User's locked spec, three grill rounds) collapses the
        // pairing command surface, net 81 -> 80: `node.invite` (-1) and
        // `node.pair.request` (-1) DIE outright, hard cutover, no aliases —
        // folded into ONE `node.pair` (+1, positional `<target>`, SMART
        // TARGET dispatch: a URL dials directly, anything else resolves by
        // discovery sweep — reuses the same `run_pair_request` core both
        // dead commands called). `node.pair.pending` RENAMES to
        // `node.pending` (net 0, path change only) — its rows drop the SAS/
        // confirmation code (never shown outside the out-of-band compare
        // the approve step preserves). `node.pair.approve`'s `<id>` becomes
        // optional when exactly one request is pending (no new path).
        // Net: 81 - 1 - 1 + 1 = 80.
        //
        // Bumped by 2 for `config` and `config.set` (task #135 P-C) — the
        // portable runtime config file (`$AOIDE_ROOT/config.toml`,
        // `aoide_storage::config`): core is cargo-buildable on any host, so
        // a core command's configuration cannot live in a NixOS option —
        // reached 82.
        //
        // Task #135 P3' collapses the pairing surface AGAIN, net 82 -> 79
        // (the User: "the command set can just be aoide pair"): `node.pair`,
        // `node.pair.approve`, `node.pair.reject`, `node.pair.watch` and
        // `node.pending` all DIE — hard cutover, no aliases, same as
        // `node.invite` before them. Bare `pair` (already registered)
        // becomes the ONE command, routed by what already exists (approve an
        // inbound match, resume an outbound one, else request), plus
        // `pair.reject` (+1) and `pair.watch` (+1). The `node` family keeps
        // the ROSTER (add/list/allow/hub/spawn/pull/status/discover/
        // advertise); `pair` mints the verified records those operate on.
        // Net: 82 - 5 + 2 = 79.
        //
        // Task #135 P4 adds `mesh` (+1) — a read-only drift report
        // comparing every declared `[mesh.<name>]` in config.toml against
        // the live node registry (`aoide_client::mesh`); writes neither
        // side. Net: 79 + 1 = 80.
        //
        // Task #135 P5 adds `mesh.pair` (+1) — the converge: the same
        // `mesh::drift` selects the declared nodes with no verified record
        // (missing/unverified) and drives `commands::run_pair_request` over
        // each, one ordinary pairwise ceremony apiece. A verified node is
        // never modified, so a second run is all-skipped. Net: 80 + 1 = 81.
        //
        // The peer -> node vocabulary rename (User ruling, 2026-09-07)
        // renames all ten `peer.*` paths to `node.*` in place — hard
        // cutover, no aliases, same shape `node.invite`'s own retirement
        // set. Net: 81 (unchanged).
        //
        // Messaging plan P-M1 (docs/architecture/MAIL.md) retires
        // `inbox.clear`/`inbox.list`/`inbox.read` (-3) and adds the
        // addressed, signed, append-only mailbase's six commands: bare
        // `mail`, `mail.mark`, `mail.read`, `mail.rm`, `mail.send`,
        // `mail.show` (+6) — same alphabetical slot the retired `inbox.*`
        // trio held, between `identity` and `make`. Net: 81 - 3 + 6 = 84.
        //
        // P-M2 adds the outbox spool's own two commands, `mail.outbox` and
        // `mail.outbox.rm` (+2) — sorting between `mail.mark` and
        // `mail.read`, same mailbase family. Net: 84 + 2 = 86.
        //
        // Bumped by 1 for `project.edit` (multi-root projects) — the
        // exact-replacement editor for a project's root list, the
        // `project edit` that `records.rs`'s `Project.auto_resume` doc
        // used to say did not exist.
        let mut expected: Vec<&str> = vec![
            "a2a.serve",
            "adapter.melete",
            "conduct",
            "conductor",
            "config",
            "config.set",
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
            "mail",
            "mail.mark",
            "mail.outbox",
            "mail.outbox.rm",
            "mail.read",
            "mail.ring",
            "mail.rm",
            "mail.send",
            "mail.show",
            "make",
            "mcp.serve",
            "melete.call",
            "melete.graph",
            "melete.status",
            "mesh",
            "mesh.pair",
            "node.add",
            "node.advertise",
            "node.allow",
            "node.discover",
            "node.hub",
            "node.list",
            "node.pull",
            "node.remove",
            "node.spawn",
            "node.status",
            "onboard",
            "pair",
            "pair.reject",
            "pair.watch",
            "project.add",
            "project.edit",
            "project.list",
            "project.remove",
            "resurrect",
            "schema",
            "secrets.add",
            "secrets.allow-remote-origin",
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
            "session",
            "session.bind",
            "session.kill",
            "session.project",
            "session.end",
            "session.grant",
            "session.hook",
            "session.pending.approve",
            "session.pending.deny",
            "session.pending.list",
            "session.permit",
            "session.phase",
            "session.prune",
            "session.reap",
            "session.start",
            "context",
            "soundcheck",
            "spawn",
            "update",
            "usage",
        ];
        expected.sort();

        assert_eq!(got, expected, "command path set drifted from the golden snapshot");
    }
}
