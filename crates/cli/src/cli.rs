//! CLI arg-parsing — resolves argv into an [`Invocation`] against the schema.
//!
//! The parser itself moved to `aoide_protocol::door` (Phase 3 restructure,
//! docs/architecture/PACKAGE-LAYOUT.md) so a second binary (lyra, P-A4) can
//! reuse it against its own registry without duplicating the parser; this
//! module is a thin delegation that supplies the crate-global registry so
//! every existing `crate::cli::*` caller is untouched.

use crate::daemon::Door;
use crate::dispatch::{self, Invocation};
use crate::output::Outcome;

/// Parse argv (excluding the program name) into an [`Invocation`].
///
/// Returns `Err(Outcome)` for a usage error (`--help`, unknown command) so the
/// caller can render it as JSON or text uniformly.
pub fn parse(argv: &[String], door: Door) -> Result<(Invocation, bool), Outcome> {
    aoide_protocol::door::parse(argv, door, "aoide", dispatch::registry())
}

/// Exit code for a usage error surfaced during parsing.
pub const USAGE_EXIT: i32 = aoide_protocol::door::USAGE_EXIT;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::{exit, Status};

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn help_flag_prints_subcommand_usage_at_exit_zero() {
        // Bare `graph` (ex-`graph view`, task #101 R1) is the DAG render.
        let err = parse(&argv(&["graph", "--help"]), Door::Cli).unwrap_err();
        assert_eq!(err.status, Status::Ok, "--help is informational, exit 0");
        assert_eq!(err.render(false).1, exit::OK);
        assert!(
            err.message.contains("usage: aoide graph"),
            "usage names the subcommand: {}",
            err.message
        );
        assert!(err.message.contains("--focus"), "lists the command's flags");
    }

    #[test]
    fn short_dash_h_is_also_help() {
        // `rice lint` moved to lyra at P-A5 — core no longer parses it;
        // `content approve` is a stub that stayed in core and still exists
        // for this same assertion (arg-parsing/usage don't care whether a
        // command is implemented).
        let err = parse(&argv(&["content", "approve", "-h"]), Door::Cli).unwrap_err();
        assert_eq!(err.status, Status::Ok);
        assert!(err.message.contains("usage: aoide content approve"));
    }

    #[test]
    fn unknown_flag_is_a_usage_error_naming_the_offender() {
        let err = parse(&argv(&["graph", "--bogus"]), Door::Cli).unwrap_err();
        assert_eq!(err.status, Status::Usage, "unknown flag → exit 2");
        assert_eq!(err.render(false).1, exit::USAGE);
        assert!(
            err.message.contains("--bogus"),
            "the offending flag is named: {}",
            err.message
        );
    }

    #[test]
    fn a_valued_unknown_flag_is_still_rejected() {
        // `--nope value` — the value is consumed by the heuristic, but the flag
        // is still unrecognised and must fail loudly.
        let err = parse(&argv(&["graph", "--nope", "x"]), Door::Cli).unwrap_err();
        assert_eq!(err.status, Status::Usage);
        assert!(err.message.contains("--nope"));
    }

    #[test]
    fn known_flags_still_parse() {
        let (inv, _) = parse(&argv(&["graph", "--focus", "session:x"]), Door::Cli).unwrap();
        assert_eq!(inv.path, vec!["graph"]);
        assert_eq!(inv.flags.get("focus").map(String::as_str), Some("session:x"));

        // `--json` and the universal `--audit-log` are always accepted.
        let (inv, json) = parse(
            &argv(&["daemon", "--json", "--audit-log", "/tmp/l"]),
            Door::Cli,
        )
        .unwrap();
        assert!(json);
        assert_eq!(inv.flags.get("audit-log").map(String::as_str), Some("/tmp/l"));
    }

    #[test]
    fn double_dash_ends_flag_parsing_for_the_wrapped_command() {
        // `conduct --agent codex -- codex --model x`: aoide takes --agent,
        // the child keeps --model untouched (and even a --json after -- is
        // the CHILD's, not ours).
        let (inv, json) = parse(
            &argv(&[
                "conduct", "--agent", "codex", "--", "codex", "--model", "x", "--json",
            ]),
            Door::Cli,
        )
        .unwrap();
        assert!(!json);
        assert_eq!(inv.path, vec!["conduct"]);
        assert_eq!(inv.flags.get("agent").map(String::as_str), Some("codex"));
        assert_eq!(inv.args, vec!["codex", "--model", "x", "--json"]);
        assert!(!inv.flags.contains_key("model"));
    }

    // Regression (khoa, 2026-08-15): `--agent shell -- <program>` broke every
    // terminal on this desktop for real — `is_command_token` (below) treats
    // any bare token matching a REGISTERED command's first path segment as
    // the start of a new subcommand rather than a flag's value, and a
    // command named `shell` briefly existed (the Quickshell IPC reload
    // trigger), colliding with `--agent shell`, the value `graph
    // conduct`/kitty's shell wrapper have used for a long time. The command
    // was renamed to `quickshell` to end THIS collision, but at the time
    // `is_command_token` itself was still collision-prone by construction —
    // it did not consider that the token immediately follows a flag
    // expecting a value. This test guards the specific incident (a bare
    // `shell` value must be consumed by `--agent`, not treated as a
    // subcommand). The general class it warned about above DID recur (every
    // `a2a message/send` spawn, `--agent a2a` colliding with the `a2a`
    // group — see `do_spawn` in server/src/a2a.rs) and `is_command_token` is
    // now flag-position-aware using `prior`; see the tests directly below
    // this one for the general-case coverage.
    #[test]
    fn agent_value_shell_is_consumed_as_a_flag_value_not_treated_as_a_command() {
        let (inv, _) = parse(
            &argv(&["conduct", "--agent", "shell", "--", "bash", "-c", "true"]),
            Door::Cli,
        )
        .unwrap();
        assert_eq!(inv.flags.get("agent").map(String::as_str), Some("shell"));
        assert_eq!(inv.args, vec!["bash", "-c", "true"]);
    }

    // The general class the comment above flagged (khoa, 2026-08-20): every
    // `a2a message/send` spawn was silently failing. `do_spawn`
    // (server/src/a2a.rs) execs the aoide binary itself with
    // `["conduct", "--agent", "a2a", "--id", <id>, "--", <agent command>]` —
    // `"a2a"` is a registered command GROUP (`a2a.serve`, `a2a.agent.*`), so
    // the old position-blind `is_command_token` treated it as the start of a
    // new subcommand, leaving `--agent` a bare boolean and pushing `"a2a"`
    // onto `positionals` instead. That corrupted the whole downstream parse:
    // `conduct`'s `command` arg ended up trying to exec the literal program
    // `"a2a"`, which doesn't exist — spawn dies, but `a2a serve` had already
    // returned `{"status":"submitted"}` to the client and logged `ok`, so the
    // failure was invisible outside a process list. This is the exact argv
    // `do_spawn` builds; it must parse into a real `conduct` invocation.
    #[test]
    fn agent_value_a2a_is_consumed_as_a_flag_value_not_treated_as_a_command() {
        let (inv, _) = parse(
            &argv(&["conduct", "--agent", "a2a", "--id", "X", "--", "claude", "-p"]),
            Door::Cli,
        )
        .unwrap();
        assert_eq!(inv.path, vec!["conduct"]);
        assert_eq!(inv.flags.get("agent").map(String::as_str), Some("a2a"));
        assert_eq!(inv.flags.get("id").map(String::as_str), Some("X"));
        assert_eq!(inv.args, vec!["claude", "-p"]);
    }

    // The collision is with ANY registered group's first segment, not just
    // `a2a` — `is_command_token` used to fire on `graph`, `node`, `rice`,
    // `screen`, ... every top-level group name, whenever it happened to be a
    // flag's value. Two more, to prove the fix is general rather than an
    // `a2a`-shaped patch.
    #[test]
    fn agent_value_colliding_with_other_registered_groups_is_still_consumed_as_a_value() {
        for group in ["graph", "node", "rice"] {
            let (inv, _) = parse(
                &argv(&["conduct", "--agent", group, "--id", "Y", "--", "true"]),
                Door::Cli,
            )
            .unwrap_or_else(|e| panic!("`--agent {group}` failed to parse: {}", e.message));
            assert_eq!(
                inv.flags.get("agent").map(String::as_str),
                Some(group),
                "--agent {group} must be consumed as the flag's value"
            );
            assert_eq!(inv.args, vec!["true"]);
        }
    }

    // The bug wasn't special to `--agent` — ANY flag whose value happens to
    // collide with a registered group's first segment is corrupted the same
    // way. `--id graph` on `conduct` (a completely different flag, on the
    // same command) must consume `graph` as its value, not treat it as the
    // start of a new command path.
    #[test]
    fn a_non_agent_flags_value_colliding_with_a_group_name_is_still_consumed() {
        let (inv, _) = parse(
            &argv(&[
                "conduct", "--id", "graph", "--agent", "codex", "--", "claude", "-p",
            ]),
            Door::Cli,
        )
        .unwrap();
        assert_eq!(inv.path, vec!["conduct"]);
        assert_eq!(inv.flags.get("id").map(String::as_str), Some("graph"));
        assert_eq!(inv.flags.get("agent").map(String::as_str), Some("codex"));
        assert_eq!(inv.args, vec!["claude", "-p"]);
    }

    // The position-aware check has a converse hazard (#48): a flag placed
    // BEFORE the final path segment, whose value collides with that segment's
    // name. `session --id start` used to parse SILENTLY (pre-R1, this was
    // `graph session --id start`) as path=`session.start`, flags={id:"true"}
    // — the value swallowed as a path segment, the flag mis-booleaned —
    // because `start` really is the next segment of `session start`. The
    // token reads both ways, so the parser refuses the ordering loudly
    // instead of guessing. Internal self-exec sites (`do_spawn` in
    // server/src/a2a.rs, graph/spawn.rs, graph/permit.rs) always spell the
    // full leaf path before any flag, so none of them can reach this error.
    #[test]
    fn a_flag_before_the_full_path_colliding_with_a_leaf_name_fails_loudly() {
        let err = parse(&argv(&["session", "--id", "start"]), Door::Cli).unwrap_err();
        assert_eq!(err.status, Status::Usage, "ambiguous ordering → exit 2");
        assert!(err.message.contains("`--id start`"), "names the flag+value: {}", err.message);
        assert!(
            err.message.contains("aoide session start --id <value>"),
            "suggests the flags-after-path spelling: {}",
            err.message
        );
    }

    // No CLI-internal aliases (khoa, 2026-08-14): each command has exactly one
    // spelling. Retired names are plain unknown commands, same as a typo.
    #[test]
    fn rice_new_is_not_an_alias_it_is_an_unknown_command() {
        let err = parse(&argv(&["rice", "new", "dusk"]), Door::Cli).unwrap_err();
        assert_eq!(err.status, Status::Usage);
        assert!(err.message.contains("unknown command"), "{}", err.message);
    }

    #[test]
    fn rice_preview_is_not_an_alias_it_is_an_unknown_command() {
        let err = parse(&argv(&["rice", "preview", "dusk"]), Door::Cli).unwrap_err();
        assert_eq!(err.status, Status::Usage);
        assert!(err.message.contains("unknown command"), "{}", err.message);
    }

    #[test]
    fn root_help_lists_commands_at_exit_zero() {
        let err = parse(&argv(&["--help"]), Door::Cli).unwrap_err();
        assert_eq!(err.status, Status::Ok);
        assert!(err.message.contains("commands:"));
    }

    #[test]
    fn root_help_groups_commands_and_carries_summaries() {
        let err = parse(&argv(&["--help"]), Door::Cli).unwrap_err();
        // Grouped by first path segment, each line carrying its summary.
        // `project` promoted out from under `graph` at R1 — its own group now.
        assert!(err.message.contains("project —"), "grouped with a blurb: {}", err.message);
        assert!(
            err.message.contains("project add <name> [<path>]"),
            "arg signature on the line: {}",
            err.message
        );
        assert!(
            err.message.contains("Register or update a project anchor root"),
            "the summary rides along: {}",
            err.message
        );
        assert!(
            err.message.contains("aoide guide' prints the tier map"),
            "the guide pointer is the footer: {}",
            err.message
        );
    }

    #[test]
    fn a_partial_path_lists_its_subgroup_instead_of_crying_unknown() {
        // `project` (ex-`graph project`) has no bare command of its own, only
        // the three children below — `project` alone must list the group.
        let err = parse(&argv(&["project"]), Door::Cli).unwrap_err();
        assert_eq!(err.status, Status::Usage);
        assert!(
            err.message.contains("is a command group"),
            "names it a group: {}",
            err.message
        );
        for command in ["project add", "project remove", "project list"] {
            assert!(err.message.contains(command), "lists {command}: {}", err.message);
        }
        assert!(err.message.contains("aoide --help"), "{}", err.message);
    }

    #[test]
    fn root_help_is_terse_detail_lives_behind_per_command_help() {
        // `session reap`'s (ex-`graph reap`) summary tail never reaches the
        // root list…
        let root = parse(&argv(&["--help"]), Door::Cli).unwrap_err();
        assert!(
            !root.message.contains("pid-only liveness"),
            "the root list stays GNU-terse: {}",
            root.message
        );
        // …but `session reap --help` keeps the full prose.
        let full = parse(&argv(&["session", "reap", "--help"]), Door::Cli).unwrap_err();
        assert!(
            full.message.contains("pid-only liveness"),
            "per-command --help keeps the full prose: {}",
            full.message
        );
    }

    // The R1 graph-prefix cutover left a bare `graph` (the render) alongside
    // `graph link` — a typo of `link` (`graph lnk`) exercises the SAME
    // did-you-mean path the old `graph vie` regression covered, and doubles
    // as a boundary proof: `graph lnk` must not silently resolve as the
    // zero-arg bare `graph` render with `lnk` as an ignored stray arg (see
    // `aoide_protocol::door`'s zero-arg-overflow check) — it must reach the
    // unknown-command/did-you-mean path instead.
    #[test]
    fn a_typo_gets_a_did_you_mean_suggestion() {
        let err = parse(&argv(&["graph", "lnk"]), Door::Cli).unwrap_err();
        assert_eq!(err.status, Status::Usage);
        assert!(err.message.contains("unknown command: `graph lnk`"), "{}", err.message);
        assert!(
            err.message.contains("did you mean:\n  aoide graph link"),
            "suggests the nearest command: {}",
            err.message
        );
        assert!(err.message.contains("aoide --help"), "{}", err.message);
    }

    #[test]
    fn help_on_a_command_with_examples_shows_them() {
        let err = parse(&argv(&["project", "add", "--help"]), Door::Cli).unwrap_err();
        assert_eq!(err.status, Status::Ok);
        assert!(
            err.message.contains("examples:\n  aoide project add aoide ~/Aoide"),
            "the examples section renders: {}",
            err.message
        );
        // A command WITHOUT examples carries no empty section.
        let bare = parse(&argv(&["session", "prune", "--help"]), Door::Cli).unwrap_err();
        assert!(!bare.message.contains("examples:"), "{}", bare.message);
    }
}
