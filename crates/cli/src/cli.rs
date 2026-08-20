//! CLI arg-parsing — resolves argv into an [`Invocation`] against the schema.
//!
//! Hand-rolled (no clap) to keep the offline cargo lock tiny and the build
//! pure. The command tree is read from `schema.rs`, so the parser and the
//! schema can never disagree about what commands exist.

use crate::daemon::Door;
use crate::dispatch::{self, Invocation};
use crate::output::{exit, Outcome};
use crate::registry;
use std::collections::BTreeMap;

/// All known command paths (from the registry), longest-first for greedy match.
fn known_paths() -> Vec<Vec<String>> {
    let mut paths: Vec<Vec<String>> = dispatch::registry()
        .commands()
        .map(|c| c.path.iter().map(|s| s.to_string()).collect())
        .collect();
    paths.sort_by_key(|p| std::cmp::Reverse(p.len()));
    paths
}

/// Parse argv (excluding the program name) into an [`Invocation`].
///
/// Returns `Err(Outcome)` for a usage error (`--help`, unknown command) so the
/// caller can render it as JSON or text uniformly.
pub fn parse(argv: &[String], door: Door) -> Result<(Invocation, bool), Outcome> {
    // First split off flags anywhere; positionals keep order.
    let mut positionals: Vec<String> = Vec::new();
    let mut flags: BTreeMap<String, String> = BTreeMap::new();
    let mut json = false;
    let mut help = false;

    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        // A bare `--` ends flag parsing: everything after it is positional,
        // verbatim — the wrapped-command seam (`graph wrap -- codex --model x`
        // must not have the child's flags eaten as aoide's).
        if a == "--" {
            positionals.extend(argv[i + 1..].iter().cloned());
            break;
        }
        // `--help`/`-h` anywhere is a request for usage, never a command flag.
        if a == "--help" || a == "-h" {
            help = true;
            i += 1;
            continue;
        }
        if let Some(name) = a.strip_prefix("--") {
            // `--flag=value` or `--flag value` or bare boolean `--flag`.
            if let Some((k, v)) = name.split_once('=') {
                if k == "json" {
                    json = true;
                }
                flags.insert(k.to_string(), v.to_string());
            } else if name == "json" {
                json = true;
                flags.insert("json".into(), "true".into());
            } else {
                // Peek: if the next token is a value (not a flag), consume it.
                if i + 1 < argv.len()
                    && !argv[i + 1].starts_with("--")
                    && !is_command_token(&argv[i + 1], &positionals)
                {
                    flags.insert(name.to_string(), argv[i + 1].clone());
                    i += 1;
                } else {
                    flags.insert(name.to_string(), "true".into());
                }
            }
        } else {
            positionals.push(a.clone());
        }
        i += 1;
    }

    if positionals.is_empty() {
        // `aoide --help` (no command) → the root usage at exit 0; bare `aoide`
        // is still the usage error (exit 2).
        return if help {
            Err(help_outcome("aoide", usage_root().message))
        } else {
            Err(usage_root())
        };
    }

    // Greedy longest-prefix match of positionals against known command paths.
    let paths = known_paths();
    let matched = paths
        .iter()
        .find(|p| p.len() <= positionals.len() && p.iter().zip(&positionals).all(|(a, b)| a == b))
        .cloned();

    let path = match matched {
        Some(p) => p,
        None => {
            // A `--help` on a partial/unknown path still surfaces the command
            // list rather than a bare "unknown command".
            if help {
                return Err(help_outcome(&positionals.join("."), usage_root().message));
            }
            return Err(unknown_command_outcome(&positionals));
        }
    };

    // `--help`/`-h` on a known subcommand → that subcommand's usage (exit 0).
    if help {
        return Err(help_outcome(&path.join("."), command_usage(&path)));
    }

    // Reject an unrecognised flag by name (exit 2) — never silently swallow it.
    if let Some(bad) = unknown_flag(&path, &flags) {
        return Err(Outcome::usage(
            path.join("."),
            format!(
                "unrecognized flag `--{bad}` for `aoide {}`\n{}",
                path.join(" "),
                command_usage(&path)
            ),
        ));
    }

    let args = positionals[path.len()..].to_vec();

    Ok((
        Invocation {
            path,
            args,
            flags,
            door,
        },
        json,
    ))
}

/// The registry entry for a matched command path (name-for-name).
fn command_for(path: &[String]) -> Option<&'static registry::Command> {
    dispatch::registry().get(path)
}

/// The usage error for an unresolvable invocation. Two shapes, by intent:
///
/// * The input is a strict PREFIX of ≥1 known paths (`graph project`) — the
///   caller found a real group, just not a leaf: list the subgroup's commands
///   instead of crying "unknown command".
/// * Anything else is probably a typo — suggest the closest known commands by
///   edit distance (`graph vie` → `graph view`).
///
/// Either way the message ends with the `aoide --help` pointer.
fn unknown_command_outcome(positionals: &[String]) -> Outcome {
    let sub: Vec<&registry::Command> = dispatch::registry()
        .commands()
        .filter(|c| {
            c.path.len() > positionals.len()
                && c.path.iter().zip(positionals).all(|(a, b)| *a == b)
        })
        .collect();
    let message = if !sub.is_empty() {
        let width = sub
            .iter()
            .map(|c| c.path.join(" ").len() + signature(c).len())
            .max()
            .unwrap_or(0);
        let mut m = format!("`{}` is a command group, not a command:\n", positionals.join(" "));
        for c in &sub {
            m.push_str(&command_line(c, width));
            m.push('\n');
        }
        m.pop();
        m
    } else {
        let mut m = format!("unknown command: `{}`", positionals.join(" "));
        let suggestions = did_you_mean(positionals);
        if !suggestions.is_empty() {
            m.push_str("\n\ndid you mean:");
            for s in suggestions {
                m.push_str(&format!("\n  aoide {s}"));
            }
        }
        m
    };
    Outcome::usage(
        positionals.join("."),
        format!("{message}\n\nrun 'aoide --help' for the full command list"),
    )
}

/// The closest known command paths to a typo'd input, nearest first, at most
/// two. The cutoff scales with the target's length: a one-edit miss on a
/// short path is worth suggesting, a three-edit miss on anything reads as a
/// different intent entirely, not a typo.
fn did_you_mean(positionals: &[String]) -> Vec<String> {
    let target = positionals.join(".");
    let cutoff = (target.len() / 4).max(2);
    let mut scored: Vec<(usize, String)> = dispatch::registry()
        .commands()
        .map(|c| (levenshtein(&target, &c.dotted()), c.path.join(" ")))
        .filter(|(d, _)| *d <= cutoff)
        .collect();
    // Stable sort: ties keep registration order (the schema's own order).
    scored.sort_by_key(|(d, _)| *d);
    scored.into_iter().take(2).map(|(_, p)| p).collect()
}

/// Classic two-row Levenshtein over chars. Hand-rolled (no `strsim` dep) to
/// keep the hand-rolled-parser ethos of this crate: the lockfile stays
/// offline-vendored and tiny, and ~70 short paths never justify a crate.
fn levenshtein(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr = vec![0usize; b.len() + 1];
    for (i, ca) in a.chars().enumerate() {
        curr[0] = i + 1;
        for (j, &cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            curr[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(curr[j] + 1);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}

/// Flags accepted for a command: the schema-declared ones (which already
/// include `--json`) plus `--audit-log`, which the dispatcher honours on every
/// command as the audit-log override.
fn allowed_flags(path: &[String]) -> Vec<String> {
    let mut names: Vec<String> = vec!["json".into(), "audit-log".into()];
    if let Some(c) = command_for(path) {
        names.extend(c.flags.iter().map(|f| f.name.to_string()));
    }
    names
}

/// The first flag present that the matched command does not accept, if any.
fn unknown_flag(path: &[String], flags: &BTreeMap<String, String>) -> Option<String> {
    let allowed = allowed_flags(path);
    flags
        .keys()
        .find(|k| !allowed.iter().any(|a| a == *k))
        .cloned()
}

/// An Ok-status outcome carrying a raw usage block. `run_cli` prints an
/// Ok-status parse result to stdout and exits 0 — the `--help` path.
fn help_outcome(cmd: &str, message: String) -> Outcome {
    Outcome::ok(cmd, message)
}

/// The per-subcommand usage block printed for `--help`/`-h`, built from the
/// schema so it can never drift from the real arg/flag set.
fn command_usage(path: &[String]) -> String {
    let Some(c) = command_for(path) else {
        return usage_root().message;
    };
    let mut s = format!(
        "usage: aoide {}{} [--json]\n\n{}",
        path.join(" "),
        signature(c),
        c.summary
    );
    if !c.args.is_empty() {
        s.push_str("\n\nargs:");
        for a in c.args {
            let req = if a.required { "required" } else { "optional" };
            s.push_str(&format!("\n  <{}>  ({req}) {}", a.name, a.description));
        }
    }
    s.push_str("\n\nflags:");
    for f in c.flags {
        s.push_str(&format!("\n  --{}  {}", f.name, f.description));
    }
    if !c.examples.is_empty() {
        s.push_str("\n\nexamples:");
        for ex in c.examples {
            s.push_str(&format!("\n  aoide {ex}"));
        }
    }
    s
}

/// The arg signature shared by `command_usage` and the root help's per-command
/// lines — one builder, so both can never disagree about `<req>`/`[<opt>]`.
fn signature(c: &registry::Command) -> String {
    let mut sig = String::new();
    for a in c.args {
        if a.required {
            sig.push_str(&format!(" <{}>", a.name));
        } else {
            sig.push_str(&format!(" [<{}>]", a.name));
        }
    }
    sig
}

/// Is this token part of a command path (so a preceding `--flag` should be
/// treated as a bare boolean rather than consuming it)?
///
/// Flag-position-aware (khoa, 2026-08-20): `prior` is the positionals already
/// collected by the time the parser reaches this token — i.e. how much of a
/// command path has been built so far, interleaved with whatever flags came
/// before it. A token only continues a command path if some REGISTERED path
/// agrees with `prior` exactly up to `prior.len()` and has `tok` as its very
/// next segment. This is a strict refinement of the old "does `tok` match
/// ANY command's first segment" check, which ignored position entirely: a
/// value like `a2a` (a real group's first segment) or `shell` collided with
/// `--agent a2a` / `--agent shell` no matter where in argv it sat, because
/// nothing about the check depended on what came before it. Requiring `tok`
/// to be the exact next segment of a path that already agrees with `prior`
/// means a flag's value can never be mistaken for a command token unless the
/// invocation is ACTUALLY still mid-way through spelling out a longer
/// command path — which a flag's value never is, by construction (a flag
/// always trails the command path it belongs to, never sits inside it).
fn is_command_token(tok: &str, prior: &[String]) -> bool {
    dispatch::registry().commands().any(|c| {
        c.path.len() > prior.len()
            && c.path[..prior.len()].iter().zip(prior).all(|(a, b)| *a == b)
            && c.path[prior.len()] == tok
    })
}

/// One-line blurbs for the KNOWN command groups, keyed by first path
/// segment. Deliberately a static table rather than a registry field: a
/// future group simply renders without a blurb (no drift failure mode, no
/// amendment needed to add a group).
fn group_blurb(group: &str) -> Option<&'static str> {
    Some(match group {
        "rice" => "the self-ricing loop: compose → mode stage → mode draft → declare",
        "graph" => "the project/session DAG — conducting other terminals",
        "screen" => "screen capture, OCR, and pointer control",
        "a2a" => "Agent-to-Agent server and agent registry",
        "peer" => "same-network host federation",
        "livery" => "the design-token engine: resolve, lint, and emit a song's livery",
        "cover" => "cover-art staging",
        "mcp" => "the per-session stdio MCP façade",
        "hooks" => "agent-harness hook installer",
        _ => return None,
    })
}

/// GNU-style terseness for list output: the first sentence of a command's
/// summary, hard-capped so a chatty opener can't blow out the column. The
/// registry summaries are deliberate multi-sentence prose; that prose still
/// lives behind `aoide <cmd> --help` — the root list is a list, not the docs.
fn short_desc(summary: &str) -> String {
    const CAP: usize = 60; // chars, not bytes — multibyte-safe by construction
    let end = summary
        .find(". ")
        .map(|i| i + 1) // keep the period
        .or_else(|| summary.find('\n'))
        .unwrap_or(summary.len());
    let s = summary[..end].trim_end();
    if s.chars().count() <= CAP {
        return s.to_string();
    }
    // Truncate at the last word boundary inside the cap — never mid-word,
    // never mid-char (chars(), not byte indexing).
    let prefix: String = s.chars().take(CAP).collect();
    let cut = prefix.rfind(char::is_whitespace).unwrap_or(prefix.len());
    format!("{}…", prefix[..cut].trim_end())
}

/// The aligned `  <path + signature>  <short description>` line used by both
/// the root help and the partial-path subgroup listing.
fn command_line(c: &registry::Command, width: usize) -> String {
    let lhs = format!("{}{}", c.path.join(" "), signature(c));
    format!("  {lhs:<width$}  {}", short_desc(c.summary))
}

fn usage_root() -> Outcome {
    // Group by first path segment, preserving registration order inside each
    // group (the registry's own order is load-bearing — registry.rs module
    // docs). Group order is first-appearance order: no sorting, so a newly
    // appended group lands at the bottom rather than reshuffling the list.
    let mut groups: Vec<(&str, Vec<&registry::Command>)> = Vec::new();
    for c in dispatch::registry().commands() {
        let head = c.path[0];
        match groups.iter_mut().find(|(g, _)| *g == head) {
            Some((_, cs)) => cs.push(c),
            None => groups.push((head, vec![c])),
        }
    }
    let width = dispatch::registry()
        .commands()
        .map(|c| c.path.join(" ").len() + signature(c).len())
        .max()
        .unwrap_or(0);

    let mut s = String::from("usage: aoide <command> [args] [--json]\n\ncommands:");
    for (group, cmds) in &groups {
        s.push('\n');
        if let Some(blurb) = group_blurb(group) {
            s.push_str(&format!("{group} — {blurb}\n"));
        } else {
            s.push_str(&format!("{group}\n"));
        }
        for c in cmds {
            s.push_str(&command_line(c, width));
            s.push('\n');
        }
    }
    // Drop the trailing newline of the last group before the footer.
    s.pop();
    s.push_str(
        "\n\nRun 'aoide <command> --help' for args, flags, and examples. \
         'aoide guide' prints the tier map.",
    );
    Outcome::usage("aoide", s)
}

/// Exit code for a usage error surfaced during parsing.
pub const USAGE_EXIT: i32 = exit::USAGE;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::Status;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn help_flag_prints_subcommand_usage_at_exit_zero() {
        let err = parse(&argv(&["graph", "view", "--help"]), Door::Cli).unwrap_err();
        assert_eq!(err.status, Status::Ok, "--help is informational, exit 0");
        assert_eq!(err.render(false).1, exit::OK);
        assert!(
            err.message.contains("usage: aoide graph view"),
            "usage names the subcommand: {}",
            err.message
        );
        assert!(err.message.contains("--focus"), "lists the command's flags");
    }

    #[test]
    fn short_dash_h_is_also_help() {
        let err = parse(&argv(&["rice", "lint", "-h"]), Door::Cli).unwrap_err();
        assert_eq!(err.status, Status::Ok);
        assert!(err.message.contains("usage: aoide rice lint"));
    }

    #[test]
    fn unknown_flag_is_a_usage_error_naming_the_offender() {
        let err = parse(&argv(&["graph", "view", "--bogus"]), Door::Cli).unwrap_err();
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
        let err = parse(&argv(&["graph", "view", "--nope", "x"]), Door::Cli).unwrap_err();
        assert_eq!(err.status, Status::Usage);
        assert!(err.message.contains("--nope"));
    }

    #[test]
    fn known_flags_still_parse() {
        let (inv, _) =
            parse(&argv(&["graph", "view", "--focus", "session:x"]), Door::Cli).unwrap();
        assert_eq!(inv.path, vec!["graph", "view"]);
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
        // `graph wrap --agent codex -- codex --model x`: aoide takes --agent,
        // the child keeps --model untouched (and even a --json after -- is
        // the CHILD's, not ours).
        let (inv, json) = parse(
            &argv(&[
                "graph", "wrap", "--agent", "codex", "--", "codex", "--model", "x", "--json",
            ]),
            Door::Cli,
        )
        .unwrap();
        assert!(!json);
        assert_eq!(inv.path, vec!["graph", "wrap"]);
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
            &argv(&["graph", "wrap", "--agent", "shell", "--", "bash", "-c", "true"]),
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
    // `a2a` — `is_command_token` used to fire on `graph`, `peer`, `rice`,
    // `screen`, ... every top-level group name, whenever it happened to be a
    // flag's value. Two more, to prove the fix is general rather than an
    // `a2a`-shaped patch.
    #[test]
    fn agent_value_colliding_with_other_registered_groups_is_still_consumed_as_a_value() {
        for group in ["graph", "peer", "rice"] {
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
    fn short_desc_keeps_the_first_sentence_only() {
        assert_eq!(short_desc("One sentence. Two sentences."), "One sentence.");
        // A newline also ends the "sentence"; no dangling whitespace.
        assert_eq!(short_desc("First line\nsecond line"), "First line");
        // Short summaries pass through whole.
        assert_eq!(short_desc("Terse."), "Terse.");
    }

    #[test]
    fn short_desc_truncates_a_chatty_opener_at_a_word_boundary() {
        let long = "This opener runs on and on well past the cap without a single period to stop it anywhere at all.";
        let out = short_desc(long);
        assert!(out.ends_with('…'), "ellipsis marks the cut: {out}");
        assert!(out.chars().count() <= 61, "cap + ellipsis: {}", out.len());
        let body = out.trim_end_matches('…');
        assert!(long.starts_with(body), "never invents text: {out}");
        // Word-boundary cut: the next char in the source after the kept body
        // is whitespace (nothing half-swallowed).
        let next = long[body.len()..].chars().next();
        assert!(next.is_none_or(|ch| ch.is_whitespace()), "mid-word cut: {out}");
    }

    #[test]
    fn short_desc_is_multibyte_safe_at_the_cap() {
        // ▶ is 3 bytes — byte-naive truncation at the cap would panic; the
        // char-based cut must not.
        let s = format!("{} watch the ▶ marker glide past the truncation cap without a panic.", "x".repeat(50));
        let out = short_desc(&s);
        assert!(out.ends_with('…'));
        // And a short string containing ▶ passes through untouched.
        assert_eq!(short_desc("Highlight ▶ node."), "Highlight ▶ node.");
    }

    #[test]
    fn root_help_groups_commands_and_carries_summaries() {
        let err = parse(&argv(&["--help"]), Door::Cli).unwrap_err();
        // Grouped by first path segment, each line carrying its summary.
        assert!(err.message.contains("graph —"), "grouped with a blurb: {}", err.message);
        assert!(
            err.message.contains("graph project add <name> [<path>]"),
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
        let err = parse(&argv(&["graph", "project"]), Door::Cli).unwrap_err();
        assert_eq!(err.status, Status::Usage);
        assert!(
            err.message.contains("is a command group"),
            "names it a group: {}",
            err.message
        );
        for verb in ["graph project add", "graph project remove", "graph project list"] {
            assert!(err.message.contains(verb), "lists {verb}: {}", err.message);
        }
        assert!(err.message.contains("aoide --help"), "{}", err.message);
    }

    #[test]
    fn root_help_is_terse_detail_lives_behind_per_command_help() {
        // `graph reap`'s summary tail never reaches the root list…
        let root = parse(&argv(&["--help"]), Door::Cli).unwrap_err();
        assert!(
            !root.message.contains("pid-only liveness"),
            "the root list stays GNU-terse: {}",
            root.message
        );
        // …but `graph reap --help` keeps the full prose.
        let full = parse(&argv(&["graph", "reap", "--help"]), Door::Cli).unwrap_err();
        assert!(
            full.message.contains("pid-only liveness"),
            "per-command --help keeps the full prose: {}",
            full.message
        );
    }

    #[test]
    fn a_typo_gets_a_did_you_mean_suggestion() {
        let err = parse(&argv(&["graph", "vie"]), Door::Cli).unwrap_err();
        assert_eq!(err.status, Status::Usage);
        assert!(err.message.contains("unknown command: `graph vie`"), "{}", err.message);
        assert!(
            err.message.contains("did you mean:\n  aoide graph view"),
            "suggests the nearest command: {}",
            err.message
        );
        assert!(err.message.contains("aoide --help"), "{}", err.message);
    }

    #[test]
    fn help_on_a_command_with_examples_shows_them() {
        let err = parse(&argv(&["graph", "project", "add", "--help"]), Door::Cli).unwrap_err();
        assert_eq!(err.status, Status::Ok);
        assert!(
            err.message.contains("examples:\n  aoide graph project add aoide ~/Aoide"),
            "the examples section renders: {}",
            err.message
        );
        // A command WITHOUT examples carries no empty section.
        let bare = parse(&argv(&["graph", "prune", "--help"]), Door::Cli).unwrap_err();
        assert!(!bare.message.contains("examples:"), "{}", bare.message);
    }
}
