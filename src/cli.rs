//! CLI arg-parsing — resolves argv into an [`Invocation`] against the schema.
//!
//! Hand-rolled (no clap) to keep the offline cargo lock tiny and the build
//! pure. The command tree is read from `schema.rs`, so the parser and the
//! schema can never disagree about what commands exist.

use crate::daemon::Door;
use crate::dispatch::Invocation;
use crate::output::{exit, Outcome};
use crate::schema;
use std::collections::BTreeMap;

/// All known command paths (from the schema), longest-first for greedy match.
fn known_paths() -> Vec<Vec<String>> {
    let mut paths: Vec<Vec<String>> = schema::commands()
        .iter()
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

    // `aoide rice new …` is a pure parse alias for `aoide rice mint …` —
    // there is only ONE registry entry (`rice.mint`, schema.rs); canonicalize
    // here so schema, dispatch, and the audit log only ever see that one path.
    if positionals.len() >= 2 && positionals[0] == "rice" && positionals[1] == "new" {
        positionals[1] = "mint".to_string();
    }

    // Greedy longest-prefix match of positionals against known command paths.
    let paths = known_paths();
    let matched = paths
        .into_iter()
        .find(|p| p.len() <= positionals.len() && p.iter().zip(&positionals).all(|(a, b)| a == b));

    let path = match matched {
        Some(p) => p,
        None => {
            // A `--help` on a partial/unknown path still surfaces the command
            // list rather than a bare "unknown command".
            if help {
                return Err(help_outcome(&positionals.join("."), usage_root().message));
            }
            return Err(Outcome::usage(
                positionals.join("."),
                format!("unknown command: `{}`", positionals.join(" ")),
            ));
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

/// The schema entry for a matched command path (name-for-name).
fn command_for(path: &[String]) -> Option<schema::Command> {
    schema::commands()
        .into_iter()
        .find(|c| c.path.len() == path.len() && c.path.iter().zip(path).all(|(a, b)| *a == b))
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
    let mut sig = String::new();
    for a in c.args {
        if a.required {
            sig.push_str(&format!(" <{}>", a.name));
        } else {
            sig.push_str(&format!(" [<{}>]", a.name));
        }
    }
    let mut s = format!(
        "usage: aoide {}{sig} [--json]\n\n{}",
        path.join(" "),
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
    s
}

/// Heuristic: is this token part of a command path (so a preceding `--flag`
/// should be treated as a bare boolean rather than consuming it)?
fn is_command_token(tok: &str, _prior: &[String]) -> bool {
    schema::commands()
        .iter()
        .any(|c| c.path.first() == Some(&tok))
}

fn usage_root() -> Outcome {
    let cmds: Vec<String> = schema::commands()
        .iter()
        .map(|c| c.path.join(" "))
        .collect();
    Outcome::usage(
        "aoide",
        format!(
            "usage: aoide <command> [args] [--json]\ncommands:\n  {}",
            cmds.join("\n  ")
        ),
    )
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

    #[test]
    fn rice_new_is_a_parse_alias_for_rice_mint() {
        let (inv, _) = parse(
            &argv(&["rice", "new", "dusk", "--from", "default"]),
            Door::Cli,
        )
        .unwrap();
        assert_eq!(inv.path, vec!["rice", "mint"]);
        assert_eq!(inv.args, vec!["dusk"]);
        assert_eq!(inv.flags.get("from").map(String::as_str), Some("default"));
    }

    #[test]
    fn root_help_lists_commands_at_exit_zero() {
        let err = parse(&argv(&["--help"]), Door::Cli).unwrap_err();
        assert_eq!(err.status, Status::Ok);
        assert!(err.message.contains("commands:"));
    }
}
