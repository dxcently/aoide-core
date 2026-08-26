//! The CLI arg-parser and the parse -> dispatch -> render run loop, shared by
//! every aoide binary (Phase 3 restructure, docs/architecture/PACKAGE-LAYOUT.md).
//!
//! Hand-rolled (no clap) to keep the offline cargo lock tiny and the build
//! pure. The command tree is read from a caller-supplied [`Registry`], so the
//! parser and the schema can never disagree about what commands exist.
//!
//! [`run`] drives the standard loop (parse, render a parse error uniformly,
//! else dispatch the matched command and render its [`Outcome`]) — but a
//! command tree always has a handful of commands that are NOT one-shot dispatch:
//! a raw-stdout tool, a long-running server launch, anything that needs to
//! bypass the `Outcome` envelope entirely. Those are per-binary — the core
//! `aoide` binary launches `mcp serve --stdio`/`a2a serve`/`conductor`,
//! lyra (P-A4) launches its own smaller set and never touches `a2a serve` or
//! `conductor` — so `run` takes a `special` hook: a closure given the parsed
//! [`Invocation`] and the `--json` flag, run AFTER a successful parse and
//! BEFORE the generic dispatch. `Some(code)` short-circuits with that exit
//! code; `None` falls through to the uniform dispatch+render path. This is
//! how one parser + one run loop serves binaries with different special-case
//! command sets without duplicating either.

use crate::audit::Door;
use crate::invocation::Invocation;
use crate::output::{exit, Outcome};
use crate::registry::{Command, Registry};
use std::collections::BTreeMap;

/// All known command paths (from the registry), longest-first for greedy match.
fn known_paths(registry: &Registry) -> Vec<Vec<String>> {
    let mut paths: Vec<Vec<String>> = registry
        .commands()
        .map(|c| c.path.iter().map(|s| s.to_string()).collect())
        .collect();
    paths.sort_by_key(|p| std::cmp::Reverse(p.len()));
    paths
}

/// Parse argv (excluding the program name) into an [`Invocation`].
///
/// `bin_name` is the invoking binary's name (`"aoide"` for core, `"lyra"`
/// for the graphical binary, P-A5 of the binary-split workstream) — every
/// usage/help/did-you-mean string below names it instead of a hardcoded
/// `"aoide"`, so lyra's own usage errors say `lyra`, not `aoide`.
///
/// Returns `Err(Outcome)` for a usage error (`--help`, unknown command) so the
/// caller can render it as JSON or text uniformly.
pub fn parse(argv: &[String], door: Door, bin_name: &str, registry: &Registry) -> Result<(Invocation, bool), Outcome> {
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
                    && !is_command_token(&argv[i + 1], &positionals, registry)
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
            Err(help_outcome(bin_name, usage_root(registry, bin_name).message))
        } else {
            Err(usage_root(registry, bin_name))
        };
    }

    // Greedy longest-prefix match of positionals against known command paths.
    let paths = known_paths(registry);
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
                return Err(help_outcome(&positionals.join("."), usage_root(registry, bin_name).message));
            }
            return Err(unknown_command_outcome(&positionals, registry, bin_name));
        }
    };

    // `--help`/`-h` on a known subcommand → that subcommand's usage (exit 0).
    if help {
        return Err(help_outcome(&path.join("."), command_usage(&path, registry, bin_name)));
    }

    // Reject an unrecognised flag by name (exit 2) — never silently swallow it.
    if let Some(bad) = unknown_flag(&path, &flags, registry) {
        return Err(Outcome::usage(
            path.join("."),
            format!(
                "unrecognized flag `--{bad}` for `{bin_name} {}`\n{}",
                path.join(" "),
                command_usage(&path, registry, bin_name)
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
fn command_for<'a>(path: &[String], registry: &'a Registry) -> Option<&'a Command> {
    registry.get(path)
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
fn unknown_command_outcome(positionals: &[String], registry: &Registry, bin_name: &str) -> Outcome {
    let sub: Vec<&Command> = registry
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
        let suggestions = did_you_mean(positionals, registry);
        if !suggestions.is_empty() {
            m.push_str("\n\ndid you mean:");
            for s in suggestions {
                m.push_str(&format!("\n  {bin_name} {s}"));
            }
        }
        m
    };
    Outcome::usage(
        positionals.join("."),
        format!("{message}\n\nrun '{bin_name} --help' for the full command list"),
    )
}

/// The closest known command paths to a typo'd input, nearest first, at most
/// two. The cutoff scales with the target's length: a one-edit miss on a
/// short path is worth suggesting, a three-edit miss on anything reads as a
/// different intent entirely, not a typo.
fn did_you_mean(positionals: &[String], registry: &Registry) -> Vec<String> {
    let target = positionals.join(".");
    let cutoff = (target.len() / 4).max(2);
    let mut scored: Vec<(usize, String)> = registry
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
fn allowed_flags(path: &[String], registry: &Registry) -> Vec<String> {
    let mut names: Vec<String> = vec!["json".into(), "audit-log".into()];
    if let Some(c) = command_for(path, registry) {
        names.extend(c.flags.iter().map(|f| f.name.to_string()));
    }
    names
}

/// The first flag present that the matched command does not accept, if any.
fn unknown_flag(path: &[String], flags: &BTreeMap<String, String>, registry: &Registry) -> Option<String> {
    let allowed = allowed_flags(path, registry);
    flags
        .keys()
        .find(|k| !allowed.iter().any(|a| a == *k))
        .cloned()
}

/// An Ok-status outcome carrying a raw usage block. `run` prints an
/// Ok-status parse result to stdout and exits 0 — the `--help` path.
fn help_outcome(cmd: &str, message: String) -> Outcome {
    Outcome::ok(cmd, message)
}

/// The per-subcommand usage block printed for `--help`/`-h`, built from the
/// registry so it can never drift from the real arg/flag set.
fn command_usage(path: &[String], registry: &Registry, bin_name: &str) -> String {
    let Some(c) = command_for(path, registry) else {
        return usage_root(registry, bin_name).message;
    };
    let mut s = format!(
        "usage: {bin_name} {}{} [--json]\n\n{}",
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
            s.push_str(&format!("\n  {bin_name} {ex}"));
        }
    }
    s
}

/// The arg signature shared by `command_usage` and the root help's per-command
/// lines — one builder, so both can never disagree about `<req>`/`[<opt>]`.
fn signature(c: &Command) -> String {
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
fn is_command_token(tok: &str, prior: &[String], registry: &Registry) -> bool {
    registry.commands().any(|c| {
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
fn command_line(c: &Command, width: usize) -> String {
    let lhs = format!("{}{}", c.path.join(" "), signature(c));
    format!("  {lhs:<width$}  {}", short_desc(c.summary))
}

fn usage_root(registry: &Registry, bin_name: &str) -> Outcome {
    // Group by first path segment, preserving registration order inside each
    // group (the registry's own order is load-bearing — registry.rs module
    // docs). Group order is first-appearance order: no sorting, so a newly
    // appended group lands at the bottom rather than reshuffling the list.
    let mut groups: Vec<(&str, Vec<&Command>)> = Vec::new();
    for c in registry.commands() {
        let head = c.path[0];
        match groups.iter_mut().find(|(g, _)| *g == head) {
            Some((_, cs)) => cs.push(c),
            None => groups.push((head, vec![c])),
        }
    }
    let width = registry
        .commands()
        .map(|c| c.path.join(" ").len() + signature(c).len())
        .max()
        .unwrap_or(0);

    let mut s = format!("usage: {bin_name} <command> [args] [--json]\n\ncommands:");
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
    s.push_str(&format!(
        "\n\nRun '{bin_name} <command> --help' for args, flags, and examples. \
         '{bin_name} guide' prints the tier map."
    ));
    Outcome::usage(bin_name, s)
}

/// Exit code for a usage error surfaced during parsing.
pub const USAGE_EXIT: i32 = exit::USAGE;

/// Did argv contain `--json` anywhere? (used before full parse for errors).
fn wants_json(argv: &[String]) -> bool {
    argv.iter().any(|a| a == "--json" || a == "--json=true")
}

/// Run one invocation end-to-end: parse against `registry`, offer the result
/// to `special` first, else dispatch generically through `dispatch` and
/// render the [`Outcome`]. Returns the process exit code.
///
/// `special` is called with the parsed [`Invocation`] and the `--json` flag
/// AFTER a successful parse — see the module doc for why it exists.
/// `Some(code)` short-circuits `run` with that exit code (the special case
/// already did its own printing); `None` falls through to the uniform
/// dispatch+render path below, unchanged from every other command.
pub fn run(
    argv: &[String],
    door: Door,
    bin_name: &str,
    registry: &Registry,
    dispatch: fn(&Invocation) -> Outcome,
    special: impl FnOnce(&Invocation, bool) -> Option<i32>,
) -> i32 {
    let (inv, json) = match parse(argv, door, bin_name, registry) {
        Ok(v) => v,
        Err(o) => {
            let json = wants_json(argv);
            let (body, code) = o.render(json);
            if code == exit::OK {
                // Informational (a `--help`/`-h` usage block): to stdout, exit 0.
                // Text mode prints the raw usage; `--json` still emits the
                // envelope so a tool reading `--help --json` gets structure.
                if json {
                    println!("{body}");
                } else {
                    println!("{}", o.message);
                }
            } else {
                eprintln!("{body}");
            }
            return code;
        }
    };

    if let Some(code) = special(&inv, json) {
        return code;
    }

    let outcome = dispatch(&inv);
    let (body, code) = outcome.render(json);
    if code == exit::OK {
        println!("{body}");
    } else {
        eprintln!("{body}");
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::Status;
    use crate::registry::{Arg, Flag, JSON_FLAG};

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    fn noop(_inv: &Invocation) -> Outcome {
        Outcome::ok("noop", "ok")
    }

    /// A tiny hand-built registry standing in for a real crate's
    /// `commands::all()` — protocol cannot depend on the domain crates that
    /// register the real command tree, so these tests exercise the parser's
    /// own logic (greedy match, flags, `--help`) against a minimal tree
    /// rather than the golden 87/41 paths (those are covered by the cli/lyra
    /// crates' own tests, which call through to this same code).
    fn test_registry() -> Registry {
        let mut r = Registry::new();
        r.insert(Command {
            path: &["graph", "view"],
            summary: "View the project/session graph.",
            args: &[],
            flags: &[JSON_FLAG, Flag { name: "focus", ty: "string", description: "Focus a node." }],
            gated: false,
            implemented: true,
            exit_codes: (),
            examples: &[],
            handler: noop,
            available: || true,
        });
        r.insert(Command {
            path: &["graph", "project", "add"],
            summary: "Register a project anchor root.",
            args: &[Arg { name: "name", ty: "string", required: true, description: "Anchor name." }],
            flags: &[JSON_FLAG],
            gated: false,
            implemented: true,
            exit_codes: (),
            examples: &[],
            handler: noop,
            available: || true,
        });
        r
    }

    #[test]
    fn help_flag_prints_subcommand_usage_at_exit_zero() {
        let reg = test_registry();
        let err = parse(&argv(&["graph", "view", "--help"]), Door::Cli, "aoide", &reg).unwrap_err();
        assert_eq!(err.status, Status::Ok, "--help is informational, exit 0");
        assert_eq!(err.render(false).1, exit::OK);
        assert!(err.message.contains("usage: aoide graph view"));
        assert!(err.message.contains("--focus"), "lists the command's flags");
    }

    #[test]
    fn unknown_flag_is_a_usage_error_naming_the_offender() {
        let reg = test_registry();
        let err = parse(&argv(&["graph", "view", "--bogus"]), Door::Cli, "aoide", &reg).unwrap_err();
        assert_eq!(err.status, Status::Usage, "unknown flag → exit 2");
        assert_eq!(err.render(false).1, exit::USAGE);
        assert!(err.message.contains("--bogus"));
    }

    #[test]
    fn known_flags_still_parse() {
        let reg = test_registry();
        let (inv, _) = parse(&argv(&["graph", "view", "--focus", "session:x"]), Door::Cli, "aoide", &reg).unwrap();
        assert_eq!(inv.path, vec!["graph", "view"]);
        assert_eq!(inv.flags.get("focus").map(String::as_str), Some("session:x"));
    }

    #[test]
    fn a_typo_gets_a_did_you_mean_suggestion() {
        let reg = test_registry();
        let err = parse(&argv(&["graph", "vie"]), Door::Cli, "aoide", &reg).unwrap_err();
        assert_eq!(err.status, Status::Usage);
        assert!(err.message.contains("unknown command: `graph vie`"));
        assert!(err.message.contains("did you mean:\n  aoide graph view"));
    }

    /// `bin_name` is not cosmetic: a second binary (lyra, P-A5) must see its
    /// own name in every usage/help/did-you-mean string, never `aoide`'s.
    #[test]
    fn bin_name_names_the_invoking_binary_everywhere() {
        let reg = test_registry();

        let root = parse(&argv(&[]), Door::Cli, "lyra", &reg).unwrap_err();
        assert!(root.message.contains("usage: lyra <command>"), "{}", root.message);
        assert!(!root.message.contains("aoide"), "{}", root.message);

        let sub = parse(&argv(&["graph", "view", "--help"]), Door::Cli, "lyra", &reg).unwrap_err();
        assert!(sub.message.contains("usage: lyra graph view"), "{}", sub.message);

        let unknown = parse(&argv(&["graph", "vie"]), Door::Cli, "lyra", &reg).unwrap_err();
        assert!(
            unknown.message.contains("did you mean:\n  lyra graph view"),
            "{}",
            unknown.message
        );
        assert!(unknown.message.contains("run 'lyra --help'"), "{}", unknown.message);
    }

    #[test]
    fn run_falls_through_to_dispatch_when_special_declines() {
        let reg = test_registry();
        let code = run(&argv(&["graph", "view"]), Door::Cli, "aoide", &reg, noop, |_inv, _json| None);
        assert_eq!(code, exit::OK);
    }

    #[test]
    fn run_short_circuits_when_special_claims_the_invocation() {
        let reg = test_registry();
        let code = run(&argv(&["graph", "view"]), Door::Cli, "aoide", &reg, noop, |_inv, _json| Some(exit::NOT_IMPLEMENTED));
        assert_eq!(code, exit::NOT_IMPLEMENTED);
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
}
