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

    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
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
        return Err(usage_root());
    }

    // Greedy longest-prefix match of positionals against known command paths.
    let paths = known_paths();
    let matched = paths
        .into_iter()
        .find(|p| p.len() <= positionals.len() && p.iter().zip(&positionals).all(|(a, b)| a == b));

    let path = match matched {
        Some(p) => p,
        None => {
            return Err(Outcome::usage(
                positionals.join("."),
                format!("unknown command: `{}`", positionals.join(" ")),
            ))
        }
    };

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
