//! `hooks install` — the generic hook-installer command: wire an agent harness
//! to Aoide, driven by the harness's profile (`aoide_protocol::agents`). It
//! writes three things:
//!
//! 1. The `session hook` entries — one per hook event — into the
//!    profile's settings file (`SettingsSpec` — path + format).
//! 2. The `SessionStart` onboarding pointer ([`POINTER_CMD`], the same bare
//!    `printf` one-liner the repo's own `.claude/settings.json` carries),
//!    keyed independently of the graph entries.
//! 3. A symlink of the repo's skill directory (`.claude/skills/aoide`, found
//!    by walking up from the cwd — the invoking checkout IS the source) into
//!    the profile's `skills_dir`. A profile with no skills directory skips
//!    with a taught message; an existing non-matching file/link is a refusal,
//!    never an overwrite.
//!
//! The merge is text/structure-level and NEVER a clobber (the kimi
//! config holds providers/credentials; the claude settings are hand-written).
//! It is content-aware: an existing entry is identified as OURS by a stable
//! marker (`aoide` AND `session hook` both present — see `matches_mode` for
//! why both are required — crossed with the capture-log marker for mode),
//! then its actual command text is compared against what would be written
//! now. A match is left untouched (zero rewrite, zero churn); a
//! mismatch — a pre-rename spelling, a retired path baked into a `--capture`
//! wrap, any stale text — is REWRITTEN in place to the current text. So the
//! second run of an unchanged config reports zero added AND zero updated,
//! while a run after a command/wrap change converges the on-disk entry
//! instead of silently leaving it stale (a prior presence-only check missed
//! exactly this: a renamed-away command or an old capture path kept matching
//! the marker forever and was never rewritten). Reports exactly what
//! changed. `--capture` is temporary debugging: the same graph entries with
//! the command wrapped to tee raw payloads to `$AOIDE_ROOT/state/<agent>-hooks.jsonl`
//! (NOT `~/Aoide/log` — that path is the audit log FILE) — a DISTINCT
//! idempotency key, so capture entries coexist with plain ones
//! (installing without `--capture` replaces nothing) and are removed manually.
//! The pointer and skill link are mode-independent: a `--capture` run neither
//! duplicates nor replaces them.

use aoide_protocol::Invocation;
use aoide_protocol::output::Outcome;
use aoide_protocol::agents::{agent_profile, known_agents, AgentProfile, SettingsFormat};
use aoide_protocol::registry::{arg, cmd, flag, Registry};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["hooks", "install"],
        summary: "Wire an agent harness's settings file to pipe its hooks into `session hook`, and symlink the repo's skill directory into the harness's skills dir when it has one (idempotent merge; never clobbers existing config or an unrelated file at the link path).",
        args: [arg!("agent", "string", true, "Agent harness to wire up (claude | kimi | pi).")],
        flags: [flag!("capture", "bool", "TEMPORARY debugging: wrap the hook command to tee raw payloads to $AOIDE_ROOT/state/<agent>-hooks.jsonl. Capture entries coexist with the plain ones (installing without --capture replaces nothing); remove them manually when done.")],
        gated: false,
        implemented: true,
        handler: hooks_install,
    ));
}

/// The SessionStart onboarding pointer — byte-for-byte the one-liner the
/// repo's own `.claude/settings.json` carries: a bare `printf` that exits 0
/// with no `aoide` on PATH, pointing a fresh session at the onboarding route
/// (the skill, `AGENTS.md`, `docs/agent/`, `aoide guide`). Shared as ONE
/// constant so the installed entry can never drift from the repo's wording
/// by a retype.
const POINTER_CMD: &str = "printf 'Aoide onboarding: run `aoide guide`; read AGENTS.md, then docs/agent/README.md (read order) and docs/agent/session.md (session checklist). Command ground truth: `aoide schema --json`.\\n'";

/// The pointer's idempotency key: any SessionStart entry whose command
/// carries this marker counts as the pointer, whatever its exact wording —
/// so a hand-edited pointer is respected, never duplicated or clobbered.
const POINTER_MARKER: &str = "Aoide onboarding:";

/// The pointer's label in the `added`/`present` report arrays (the graph
/// entries are labelled by event name).
const POINTER_LABEL: &str = "onboarding-pointer";

/// The skill directory shipped in the repo, relative to the checkout root.
const SKILL_REPO_PATH: &str = ".claude/skills/aoide";

/// The hook events wired per harness: the nine core events both profiles map,
/// plus kimi's dedicated needs-input event (claude signals that via
/// Notification instead).
fn events_for(profile: &AgentProfile) -> Vec<&'static str> {
    let mut evts = vec![
        "SessionStart",
        "UserPromptSubmit",
        "PreToolUse",
        "PostToolUse",
        "Stop",
        "SubagentStart",
        "SubagentStop",
        "SessionEnd",
        "Notification",
    ];
    if profile.name == "kimi" {
        evts.push("PermissionRequest");
    }
    evts
}

/// The command a new hook entry runs. Plain kimi entries call the door
/// directly; plain claude entries use the defensive wrapper the hand-written
/// settings already carry (a missing aoide is a silent no-op, and the door
/// never exits non-zero inside a hook). `--capture` tees the raw payload to
/// `$AOIDE_ROOT/state/<agent>-hooks.jsonl` first (`~/Aoide/log` is the audit
/// log FILE, not a directory) — its `-hooks.jsonl` marker is what makes
/// capture a distinct idempotency key. The path is baked as a SHELL
/// expression, not an install-time-resolved absolute path: this command runs
/// later, in the agent harness's own shell, at hook-fire time — so it
/// expands `$AOIDE_ROOT` there (falling back to `$HOME/.aoide` unset), the
/// same precedence `aoide_storage::fs::state_dir()`'s default branch
/// resolves in Rust, rather than baking in whatever root happened to be
/// configured on the installing host.
///
/// The claude wrapper unmuffles stdout for `SessionStart` and
/// `UserPromptSubmit` ONLY (task #139). Stdout is the one PIPE a `session
/// hook` `Outcome` message ever reaches the harness through at all
/// (confirmed against `protocol::door::run`, which `println!`s an `Ok`
/// outcome's rendered body) — but reaching the harness is not reaching the
/// model. Which events Claude Code actually folds a successful hook's
/// stdout into the model's own context is
/// `docs/Aoide-Wiki/protocol/dev/HARNESS-CLAUDE-CODE.md`'s call (its
/// "Traps" section is the one authority for this fact, not restated here in
/// full): exactly `SessionStart`/`UserPromptSubmit`; every other event's
/// stdout (`PreToolUse`, `PostToolUse`, `Stop`, `SubagentStart`/`Stop`,
/// `SessionEnd`, `Notification`) lands in Claude Code's own debug log,
/// never the transcript, never the model, so unmuffling them would only
/// leak routine chatter nobody reads.
///
/// **`Stop` itself stays swallowed, deliberately — never a blocking exit
/// code.** `checklane::on_stop`'s own delta note is computed and folded
/// into `session hook`'s `Outcome` at Stop (`data.checkLane`,
/// `graph/send.rs`), but reaching the model FROM Stop itself would require
/// the blocking `exit 2`/`decision:"block"` contract Claude Code offers for
/// that one event — rejected on design grounds: it FORCES continuation,
/// turning a report into a command, exactly what "do not fix unless asked"
/// exists to prevent (same page, same section). This wrapper's own
/// `2>/dev/null; exit 0` (stderr suppressed, exit forced 0, unconditionally)
/// is part of what forecloses that channel on purpose, not by omission. A
/// deferred-delivery mechanism — carrying the Stop-computed note forward
/// onto a later context-reaching event instead — is a separate, not-yet-
/// landed change to `aoide-upkeep`/`send.rs`; this wrapper's own live-event
/// set already matches what that mechanism will need and does not change
/// again when it lands.
///
/// Stderr stays suppressed on every event (a panic's backtrace has no
/// business in an agent's transcript); the trailing `; exit 0` is
/// unconditional regardless, so a future nonzero exit still never breaks the
/// hook.
fn door_command(profile: &AgentProfile, capture: bool, event: &str) -> String {
    if capture {
        format!(
            "sh -c 'tee -a \"${{AOIDE_ROOT:-$HOME/.aoide}}/state/{}-hooks.jsonl\" | aoide session hook --agent {}'",
            profile.name, profile.name
        )
    } else {
        match profile.hook_settings.format {
            SettingsFormat::Json if event == "SessionStart" || event == "UserPromptSubmit" => {
                r#"a=$(command -v aoide) || exit 0; "$a" session hook 2>/dev/null; exit 0"#
                    .to_string()
            }
            SettingsFormat::Json => {
                r#"a=$(command -v aoide) || exit 0; "$a" session hook >/dev/null 2>&1; exit 0"#
                    .to_string()
            }
            // kimi's own door_command output never varies by event (no
            // context-injection distinction to make on this door at all),
            // so callers for this format pass event-invariant text and
            // `event` goes unread here.
            SettingsFormat::Toml => format!("aoide session hook --agent {}", profile.name),
            // Unreachable for the declarative profiles — `hooks_install`
            // short-circuits before any door command is built.
            SettingsFormat::Declarative => format!("aoide session hook --agent {}", profile.name),
        }
    }
}

/// Identify an existing entry as OURS for this install mode — the
/// content-comparison step below only ever REWRITES an entry this returns
/// `true` for, so a false positive here is no longer harmless (pre-#109 a
/// false positive just meant "reported present"; post-#109 it means
/// "command overwritten"). Two independent substrings, both required:
/// `aoide` (the door binary name every real spelling invokes) and
/// `session hook` (the verb every real spelling names). Neither alone is
/// safe — `session hook` alone matches a user's own prose (`echo "logging
/// session hook state" >> audit.log`), and `aoide` alone would match any
/// unrelated hook that happens to shell out to the binary. Checked as two
/// separate `contains` calls, not one joined phrase, because they are NOT
/// contiguous in the pre-rename spelling (`aoide graph session hook
/// --agent kimi` — `graph` sits between them); `--agent` was considered and
/// rejected as a candidate third token because the claude/JSON door command
/// (`"$a" session hook`) never carries it, old or new (verified against the
/// actual pre-rename text, commit 5dac2d2). Plain and `--capture` entries
/// are further distinguished by the capture log marker, so the two coexist
/// and neither install clobbers the other. Identification is separate from
/// freshness — once an entry is identified as ours, its text is compared
/// against the current `door_command` and rewritten if it differs, so a
/// stale spelling (a renamed door invocation, an old capture path) is
/// exactly the case this is meant to catch, not exclude.
fn matches_mode(command: &str, capture: bool) -> bool {
    command.contains("aoide")
        && command.contains("session hook")
        && command.contains("-hooks.jsonl") == capture
}

/// Resolve the settings file to merge into: kimi honours `KIMI_CODE_HOME` (its
/// config root), else the profile's relative path under `$HOME`.
fn settings_path(profile: &AgentProfile) -> Result<PathBuf, String> {
    if profile.name == "kimi" {
        if let Some(root) = std::env::var_os("KIMI_CODE_HOME").filter(|v| !v.is_empty()) {
            return Ok(PathBuf::from(root).join("config.toml"));
        }
    }
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    Ok(PathBuf::from(home).join(profile.hook_settings.relative_path))
}

/// What one install pass did: which events got a new entry, which already had
/// one for this mode with matching text, and which had one identified as ours
/// but with STALE text — rewritten in place to converge on the current
/// `door_command`.
struct InstallReport {
    added: Vec<&'static str>,
    present: Vec<&'static str>,
    updated: Vec<&'static str>,
}

/// What the skill-link pass did (or why it didn't).
enum SkillLink {
    /// Created the symlink: (link, source).
    Linked(PathBuf, PathBuf),
    /// The link already exists and resolves to the repo skill — a no-op.
    Present(PathBuf),
    /// The profile has no skills directory (kimi) — skipped with a taught
    /// message, exactly like the Declarative settings short-circuit.
    NoSkillsDir,
    /// Not invoked from inside an Aoide checkout, so there is no source to
    /// link — hooks still install; the skill is skipped with a taught message.
    NoSource,
    /// Something else already sits at the link path — a refusal (taught
    /// message), never an overwrite.
    Conflict(PathBuf, String),
}

/// Locate the invoking checkout's skill directory: walk up from the cwd to
/// the first directory holding `.claude/skills/aoide/SKILL.md`. `hooks
/// install` has no repo-locating pattern to reuse (its door commands resolve
/// `aoide` from PATH), so the invoking checkout IS the source — the
/// documented assumption; run the command from inside the repo to link.
///
/// `pub`, not `pub(crate)` (crates/AGENTS.md's "widen it, don't fork it"):
/// `onboard`'s own from-a-checkout refusal (ONBOARD.md decision 10) reaches
/// this exact walk-up rather than duplicating it — the only repo-root
/// detector in the tree, so `onboard` climbs three parents off its result
/// (`aoide/skills/.claude` back to the checkout root) instead of a second
/// probe.
pub fn skill_source() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let cand = dir.join(SKILL_REPO_PATH);
        if cand.join("SKILL.md").is_file() {
            return Some(cand);
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// Link the repo's skill directory into the profile's skills directory as
/// `<skills_dir>/aoide`. Idempotent (an existing correct link is a no-op) and
/// never-clobbering (anything else at the path is a refusal).
fn link_skill(profile: &AgentProfile) -> Result<SkillLink, String> {
    let Some(rel) = profile.skills_dir else {
        return Ok(SkillLink::NoSkillsDir);
    };
    let Some(source) = skill_source() else {
        return Ok(SkillLink::NoSource);
    };
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    let link = PathBuf::from(home).join(rel).join("aoide");
    match std::fs::symlink_metadata(&link) {
        Ok(meta) if meta.file_type().is_symlink() => {
            // Canonicalize both sides so `Present` means "resolves to the
            // same directory", however the link was spelled. A dangling link
            // canonicalizes to Err and lands in the conflict arm.
            let resolves = matches!(
                (std::fs::canonicalize(&link), std::fs::canonicalize(&source)),
                (Ok(l), Ok(s)) if l == s
            );
            if resolves {
                Ok(SkillLink::Present(link))
            } else {
                let target = std::fs::read_link(&link)
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "<unreadable>".to_string());
                Ok(SkillLink::Conflict(
                    link.clone(),
                    format!(
                        "{} is already a symlink to {target}, not to {} — refusing to overwrite it; remove it yourself to relink",
                        link.display(),
                        source.display()
                    ),
                ))
            }
        }
        Ok(_) => Ok(SkillLink::Conflict(
            link.clone(),
            format!(
                "{} already exists and is not a symlink to the repo skill — refusing to overwrite it; move it aside to let `hooks install` link {}",
                link.display(),
                source.display()
            ),
        )),
        Err(_) => {
            if let Some(parent) = link.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
            }
            std::os::unix::fs::symlink(&source, &link).map_err(|e| {
                format!("cannot link {} -> {}: {e}", link.display(), source.display())
            })?;
            Ok(SkillLink::Linked(link, source))
        }
    }
}

/// Escape a value for a TOML basic string (the capture command embeds `"`).
fn toml_basic(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// TOML (kimi): text-level merge — never parse-rewrite (the file holds
/// providers/credentials). An event is identified as ours when a `[[hooks]]`
/// block names it AND its command matches this mode (`matches_mode`); its
/// `command` line is then compared to the current `door_command` — a match
/// is left untouched, a mismatch is rewritten in place (event/timeout lines
/// untouched, so nothing else in that block moves). Missing events append
/// `[[hooks]]` blocks at EOF (valid TOML after any preceding table). The entry
/// carries ONLY `event`/`command`/`timeout` — extra fields make kimi's config
/// fail to load. A missing file is created (parents included).
fn install_toml(path: &Path, profile: &AgentProfile, capture: bool) -> Result<InstallReport, String> {
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let mut report = InstallReport { added: Vec::new(), present: Vec::new(), updated: Vec::new() };
    // TOML's own `door_command` output never varies by event — passed empty
    // since only the JSON (claude) branch reads it (see that function's doc).
    let wanted = door_command(profile, capture, "");
    let wanted_line = format!("command = \"{}\"", toml_basic(&wanted));

    // Split into the preamble (index 0) and each `[[hooks]]` block's body —
    // `split` drops the marker itself, re-added on rejoin — so a stale
    // block's `command` line can be rewritten in place without disturbing
    // its `event`/`timeout` lines or any other block.
    let mut blocks: Vec<String> = existing.split("[[hooks]]").map(str::to_string).collect();
    let mut missing: Vec<&'static str> = Vec::new();
    for evt in events_for(profile) {
        let hit = blocks.iter().enumerate().skip(1).find_map(|(i, block)| {
            let is_ours = block.contains(&format!("event = \"{evt}\""))
                && block
                    .lines()
                    .find(|l| l.trim_start().starts_with("command"))
                    .map(|l| matches_mode(l, capture))
                    .unwrap_or(false);
            is_ours.then_some(i)
        });
        match hit {
            None => {
                report.added.push(evt);
                missing.push(evt);
            }
            Some(i) => {
                let current_line = blocks[i]
                    .lines()
                    .find(|l| l.trim_start().starts_with("command"))
                    .expect("matched by the same predicate above")
                    .to_string();
                if current_line.trim() == wanted_line {
                    report.present.push(evt);
                } else {
                    report.updated.push(evt);
                    blocks[i] = blocks[i].replacen(current_line.as_str(), &wanted_line, 1);
                }
            }
        }
    }
    let mut out = blocks.join("[[hooks]]");
    for evt in &missing {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&format!(
            "[[hooks]]\nevent = \"{evt}\"\ncommand = \"{}\"\ntimeout = 5\n",
            toml_basic(&wanted)
        ));
    }
    // The onboarding pointer: one SessionStart entry, keyed on its marker —
    // mode-independent, so plain and `--capture` runs share the one entry.
    let has_pointer = out.split("[[hooks]]").skip(1).any(|block| {
        block.contains("event = \"SessionStart\"") && block.contains(POINTER_MARKER)
    });
    if has_pointer {
        report.present.push(POINTER_LABEL);
    } else {
        report.added.push(POINTER_LABEL);
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&format!(
            "[[hooks]]\nevent = \"SessionStart\"\ncommand = \"{}\"\ntimeout = 5\n",
            toml_basic(POINTER_CMD)
        ));
    }
    if !report.added.is_empty() || !report.updated.is_empty() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        std::fs::write(path, &out).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    }
    Ok(report)
}

/// JSON (claude): parse → converge the hooks map → serialize, preserving the
/// rest of the document. An invalid file is an error, never a clobber. An
/// event's entry is identified as ours by `matches_mode` on its `command`
/// string; when found, its text is compared to the current `door_command` —
/// a match is left untouched, a mismatch is rewritten in place (same group,
/// same `type`, only `command` changes). A missing event gets a new entry in
/// the existing shape: a matcher-less group wrapping one
/// `{"type":"command","command":…}` hook. Nothing is written when nothing
/// was added or updated (a fully-wired, up-to-date file stays byte-identical).
fn install_json(path: &Path, profile: &AgentProfile, capture: bool) -> Result<InstallReport, String> {
    let mut doc: Value = match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).map_err(|e| {
            format!("{} is not valid JSON (refusing to clobber): {e}", path.display())
        })?,
        Err(_) => json!({}),
    };
    let root = doc
        .as_object_mut()
        .ok_or_else(|| format!("{}: top level is not a JSON object", path.display()))?;
    if root.contains_key("hooks") && !root["hooks"].is_object() {
        return Err(format!("{}: `hooks` is not a JSON object", path.display()));
    }
    let hooks = root.entry("hooks").or_insert_with(|| json!({}));
    let hooks = hooks.as_object_mut().expect("hooks is an object");
    let mut report = InstallReport { added: Vec::new(), present: Vec::new(), updated: Vec::new() };
    for evt in events_for(profile) {
        let wanted = door_command(profile, capture, evt);
        let mut found = false;
        if let Some(groups) = hooks.get_mut(evt).and_then(Value::as_array_mut) {
            'groups: for g in groups.iter_mut() {
                let Some(hs) = g.get_mut("hooks").and_then(Value::as_array_mut) else {
                    continue;
                };
                for h in hs.iter_mut() {
                    let is_ours = h
                        .get("command")
                        .and_then(Value::as_str)
                        .map(|c| matches_mode(c, capture))
                        .unwrap_or(false);
                    if !is_ours {
                        continue;
                    }
                    found = true;
                    let current = h.get("command").and_then(Value::as_str).unwrap_or("");
                    if current == wanted {
                        report.present.push(evt);
                    } else {
                        report.updated.push(evt);
                        h["command"] = json!(wanted);
                    }
                    break 'groups;
                }
            }
        }
        if !found {
            report.added.push(evt);
            let group = json!({ "hooks": [ {
                "type": "command",
                "command": wanted,
            } ] });
            hooks
                .entry(evt)
                .or_insert_with(|| json!([]))
                .as_array_mut()
                .expect("event entry is an array")
                .push(group);
        }
    }
    // The onboarding pointer: one SessionStart entry, keyed on its marker —
    // mode-independent, so plain and `--capture` runs share the one entry.
    let has_pointer = hooks
        .get("SessionStart")
        .and_then(Value::as_array)
        .map(|groups| {
            groups.iter().any(|g| {
                g.get("hooks")
                    .and_then(Value::as_array)
                    .map(|hs| {
                        hs.iter().any(|h| {
                            h.get("command")
                                .and_then(Value::as_str)
                                .map(|c| c.contains(POINTER_MARKER))
                                .unwrap_or(false)
                        })
                    })
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);
    if has_pointer {
        report.present.push(POINTER_LABEL);
    } else {
        report.added.push(POINTER_LABEL);
        let group = json!({ "hooks": [ {
            "type": "command",
            "command": POINTER_CMD,
        } ] });
        hooks
            .entry("SessionStart")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .expect("event entry is an array")
            .push(group);
    }
    if !report.added.is_empty() || !report.updated.is_empty() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        let mut text = serde_json::to_string_pretty(&doc)
            .map_err(|e| format!("cannot serialise {}: {e}", path.display()))?;
        text.push('\n');
        std::fs::write(path, text).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    }
    Ok(report)
}

/// `aoide hooks install <agent> [--capture]` — idempotent merge of aoide's
/// hook wiring into the agent harness's settings file.
fn hooks_install(inv: &Invocation) -> Outcome {
    let cmd = "hooks.install";
    let Some(agent) = inv.args.first() else {
        return Outcome::usage(cmd, "usage: aoide hooks install <agent> [--capture]");
    };
    let Some(profile) = agent_profile(agent) else {
        return Outcome::error(
            cmd,
            format!("unknown agent `{agent}` (known: {})", known_agents().join(", ")),
        )
        .with_data(json!({ "reason": "unknown-agent", "agent": agent, "known": known_agents() }));
    };
    let capture = inv.flag_present("capture");
    // A declaratively-wired harness (pi: the ~/.pi/agent/extensions/ file the
    // NixOS dendrite manages) has no settings file for this command to write —
    // report it as already wired instead of minting a file the harness never
    // reads.
    if profile.hook_settings.format == SettingsFormat::Declarative {
        let message = format!(
            "{}'s hooks are wired declaratively ({}); nothing to install here (capture is N/A)",
            profile.name, profile.hook_settings.relative_path
        );
        return Outcome::ok(cmd, message).with_data(json!({
            "agent": profile.name,
            "reason": "declarative",
            "settings": profile.hook_settings.relative_path,
            "changed": false,
        }));
    }
    let path = match settings_path(profile) {
        Ok(p) => p,
        Err(e) => {
            return Outcome::error(cmd, e).with_data(json!({ "reason": "no-settings-path" }))
        }
    };
    let result = match profile.hook_settings.format {
        SettingsFormat::Toml => install_toml(&path, profile, capture),
        SettingsFormat::Json => install_json(&path, profile, capture),
        SettingsFormat::Declarative => unreachable!("short-circuited in hooks_install"),
    };
    let report = match result {
        Ok(r) => r,
        Err(e) => {
            return Outcome::error(cmd, e).with_data(
                json!({ "reason": "settings-unwritable", "settings": path.to_string_lossy() }),
            )
        }
    };
    // The capture wrap tees into `$AOIDE_ROOT/state` — make sure it exists.
    // Resolved here via `state_dir()` (the installing host's OWN
    // `$AOIDE_ROOT`/`$AOIDE_STATE_DIR`) purely so the directory pre-exists;
    // the wrap baked into the settings file itself re-derives the same
    // default at hook-fire time in its own shell (see `door_command`), so a
    // later host with a different `$AOIDE_ROOT` still resolves correctly.
    if capture {
        let _ = std::fs::create_dir_all(aoide_storage::fs::state_dir());
    }
    // The skill link, after the settings merge (a skill refusal must not
    // block the hook wiring, and the report below carries both outcomes).
    let skill = match link_skill(profile) {
        Ok(s) => s,
        Err(e) => {
            return Outcome::error(cmd, e).with_data(json!({
                "reason": "skill-unlinkable",
                "agent": profile.name,
                "added": report.added,
                "present": report.present,
                "updated": report.updated,
            }))
        }
    };
    if let SkillLink::Conflict(link, taught) = &skill {
        return Outcome::error(cmd, taught.clone()).with_data(json!({
            "reason": "skill-link-conflict",
            "agent": profile.name,
            "skill_link": link.to_string_lossy(),
            "added": report.added,
            "present": report.present,
            "updated": report.updated,
        }));
    }
    let (skill_status, skill_note): (&str, String) = match &skill {
        SkillLink::Linked(link, source) => (
            "linked",
            format!("skill linked: {} -> {}", link.display(), source.display()),
        ),
        SkillLink::Present(link) => (
            "present",
            format!("skill already linked ({})", link.display()),
        ),
        SkillLink::NoSkillsDir => (
            "no-skills-dir",
            format!(
                "{} has no skills directory; skill not linked",
                profile.name
            ),
        ),
        SkillLink::NoSource => (
            "no-source",
            format!(
                "not inside an Aoide checkout (no {SKILL_REPO_PATH} above the cwd); skill not linked — run from the repo to link it"
            ),
        ),
        SkillLink::Conflict(..) => unreachable!("returned above"),
    };
    let skill_linked = matches!(skill, SkillLink::Linked(..));
    let changed = !report.added.is_empty() || !report.updated.is_empty() || skill_linked;
    let message = if report.added.is_empty() && report.updated.is_empty() {
        format!(
            "all {} hooks already installed for {} ({}); {skill_note}",
            report.present.len(),
            profile.name,
            path.display()
        )
    } else {
        let mut counts = Vec::new();
        if !report.added.is_empty() {
            counts.push(format!("installed {}", report.added.len()));
        }
        if !report.updated.is_empty() {
            counts.push(format!("updated {} (stale text converged)", report.updated.len()));
        }
        format!(
            "{} hook(s) for {} → {}; {skill_note}",
            counts.join(", "),
            profile.name,
            path.display()
        )
    };
    let out = Outcome::ok(cmd, message);
    let out = if changed {
        let mut changes: Vec<String> = report
            .added
            .iter()
            .map(|e| format!("hook installed: {e} ({})", profile.name))
            .collect();
        changes.extend(
            report
                .updated
                .iter()
                .map(|e| format!("hook updated: {e} ({})", profile.name)),
        );
        if skill_linked {
            changes.push(format!("skill linked ({})", profile.name));
        }
        out.changed(changes)
    } else {
        out
    };
    out.with_data(json!({
        "agent": profile.name,
        "settings": path.to_string_lossy(),
        "added": report.added,
        "present": report.present,
        "updated": report.updated,
        "skill": skill_status,
        "capture": capture,
        "changed": changed,
    }))
}

#[cfg(test)]
mod tests {
    // Env-mutating tests here hold `crate::env_lock()` — the ONE mutex every
    // test module in this crate serializes process-global env through (see
    // its doc in lib.rs for the P-D6/P-D8 floors it also stamps). A second
    // lock (`aoide_test_support::env_lock()`) does not exclude against it.
    use super::*;
    use aoide_test_support::{unique_tmp, EnvSaver};
    use std::collections::BTreeMap;

    fn install_inv(agent: &str, capture: bool) -> Invocation {
        let mut flags = BTreeMap::new();
        if capture {
            flags.insert("capture".to_string(), "true".to_string());
        }
        Invocation {
            path: vec!["hooks".into(), "install".into()],
            args: vec![agent.to_string()],
            flags,
            door: aoide_protocol::Door::Cli,
        }
    }

    #[test]
    fn kimi_install_creates_merges_and_is_idempotent() {
        let _g = crate::env_lock().lock().unwrap();
        let _env = EnvSaver::capture(&["KIMI_CODE_HOME", "HOME"]);
        let root = unique_tmp("hooks-kimi");
        std::env::set_var("KIMI_CODE_HOME", root.join("kimi"));
        let path = root.join("kimi/config.toml");
        // A pre-existing config with user content — the merge must keep it.
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "default_model = \"kimi-code/k3-256k\"\n\n[providers.\"managed:kimi-code\"]\ntype = \"kimi\"\n").unwrap();

        let out = hooks_install(&install_inv("kimi", false));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.unwrap();
        assert_eq!(data["changed"], true);
        // 10 graph events + the onboarding pointer.
        assert_eq!(data["added"].as_array().unwrap().len(), 11);
        assert_eq!(data["settings"], json!(path.to_string_lossy()));
        // kimi has no skills directory — the skill pass short-circuits.
        assert_eq!(data["skill"], "no-skills-dir");
        assert!(out.message.contains("kimi has no skills directory"), "msg: {}", out.message);

        let text = std::fs::read_to_string(&path).unwrap();
        // The user's content survived, above the appended blocks.
        assert!(text.starts_with("default_model = \"kimi-code/k3-256k\""));
        assert_eq!(text.matches("[[hooks]]").count(), 11);
        for evt in ["SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop",
                    "SubagentStart", "SubagentStop", "SessionEnd", "Notification", "PermissionRequest"] {
            assert!(text.contains(&format!("event = \"{evt}\"")), "event: {evt}");
        }
        assert!(text.contains("command = \"aoide session hook --agent kimi\""));
        // Exactly one pointer entry.
        assert_eq!(text.matches(POINTER_MARKER).count(), 1);
        // ONLY the three fields per entry — a `matcher` would break kimi's load.
        assert!(!text.contains("matcher"));

        // Second run: nothing added, everything present, file byte-identical.
        let out2 = hooks_install(&install_inv("kimi", false));
        let data2 = out2.data.unwrap();
        assert_eq!(data2["changed"], false);
        assert_eq!(data2["added"], json!([]));
        assert_eq!(data2["present"].as_array().unwrap().len(), 11);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn kimi_capture_entries_coexist_with_plain_and_are_idempotent() {
        let _g = crate::env_lock().lock().unwrap();
        // This test asserts `state_dir()`'s $HOME fallback, so both overrides
        // that outrank $HOME (the crate lock's own AOIDE_STATE_DIR floor
        // included) are cleared for its duration.
        let _env = EnvSaver::capture(&["KIMI_CODE_HOME", "HOME", "AOIDE_ROOT", "AOIDE_STATE_DIR"]);
        std::env::remove_var("AOIDE_ROOT");
        std::env::remove_var("AOIDE_STATE_DIR");
        let root = unique_tmp("hooks-kimi-cap");
        std::env::set_var("KIMI_CODE_HOME", root.join("kimi"));
        std::env::set_var("HOME", &root);

        hooks_install(&install_inv("kimi", false)); // plain first (adds the pointer too)
        let out = hooks_install(&install_inv("kimi", true)); // capture is a distinct key
        let data = out.data.unwrap();
        assert_eq!(data["changed"], true);
        // The 10 capture events only — the pointer is mode-independent and
        // already present from the plain run, so `--capture` left it alone.
        assert_eq!(data["added"].as_array().unwrap().len(), 10);
        let text = std::fs::read_to_string(root.join("kimi/config.toml")).unwrap();
        assert_eq!(text.matches("[[hooks]]").count(), 21, "plain + pointer + capture coexist");
        assert_eq!(text.matches(POINTER_MARKER).count(), 1);
        assert!(text.contains(
            "tee -a \\\"${AOIDE_ROOT:-$HOME/.aoide}/state/kimi-hooks.jsonl\\\" | aoide session hook --agent kimi"
        ));
        // The capture log dir was created — under `$HOME/.aoide/state` here
        // since `AOIDE_ROOT` is unset for this test (the installing host's
        // `state_dir()` default), NOT under the retired `$HOME/Aoide`.
        assert!(root.join(".aoide/state").is_dir());
        assert!(!root.join("Aoide/state").exists());

        // Re-running EITHER mode adds nothing.
        let plain_again = hooks_install(&install_inv("kimi", false));
        assert_eq!(plain_again.data.unwrap()["changed"], false);
        let capture_again = hooks_install(&install_inv("kimi", true));
        assert_eq!(capture_again.data.unwrap()["changed"], false);
        assert_eq!(std::fs::read_to_string(root.join("kimi/config.toml")).unwrap(), text);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn kimi_reinstall_converges_a_stale_command_spelling_and_preserves_user_hook() {
        // The real yomi incident this fix targets: a pre-rename spelling
        // (`graph session hook`) still carries the `session hook` marker, so
        // the presence-only check called it "already installed" forever and
        // never rewrote it — the kimi harness kept running a dead command.
        let _g = crate::env_lock().lock().unwrap();
        let _env = EnvSaver::capture(&["KIMI_CODE_HOME", "HOME"]);
        let root = unique_tmp("hooks-kimi-stale-cmd");
        std::env::set_var("KIMI_CODE_HOME", root.join("kimi"));
        let path = root.join("kimi/config.toml");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // The stale SessionStart entry, plus the user's OWN unrelated
        // automation hook — it must survive the reinstall untouched.
        std::fs::write(
            &path,
            "default_model = \"kimi-code/k3-256k\"\n\n\
             [[hooks]]\n\
             event = \"SessionStart\"\n\
             command = \"aoide graph session hook --agent kimi\"\n\
             timeout = 5\n\n\
             [[hooks]]\n\
             event = \"MyOwnAutomation\"\n\
             command = \"my-own-script.sh\"\n\
             timeout = 5\n",
        )
        .unwrap();

        let out = hooks_install(&install_inv("kimi", false));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.unwrap();
        assert_eq!(data["changed"], true);
        // Identified as ours (still carries the marker) and REWRITTEN, not
        // silently left alone.
        assert_eq!(data["updated"], json!(["SessionStart"]));
        // Every other graph event plus the pointer was missing and got added.
        assert_eq!(data["added"].as_array().unwrap().len(), 10);

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("command = \"aoide session hook --agent kimi\""),
            "stale spelling was not converged: {text}"
        );
        assert!(
            !text.contains("graph session hook"),
            "stale spelling still present after reinstall: {text}"
        );
        // The user's own unrelated hook, untouched, exactly once.
        assert!(text.contains("event = \"MyOwnAutomation\""));
        assert!(text.contains("command = \"my-own-script.sh\""));
        assert_eq!(text.matches("MyOwnAutomation").count(), 1);

        // Reinstalling again over the now-correct text is a true no-op.
        let out2 = hooks_install(&install_inv("kimi", false));
        let data2 = out2.data.unwrap();
        assert_eq!(data2["changed"], false);
        assert_eq!(data2["added"], json!([]));
        assert_eq!(data2["updated"], json!([]));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn kimi_capture_reinstall_converges_a_stale_state_path_wrap() {
        // The other real incident this fix targets: #113 moved the capture
        // wrap from the retired `~/Aoide/state` to `${AOIDE_ROOT:-...}`, but
        // both spellings carry the same `-hooks.jsonl` marker — so a
        // presence-only check kept the retired path installed forever.
        let _g = crate::env_lock().lock().unwrap();
        let _env = EnvSaver::capture(&["KIMI_CODE_HOME", "HOME"]);
        let root = unique_tmp("hooks-kimi-stale-wrap");
        std::env::set_var("KIMI_CODE_HOME", root.join("kimi"));
        std::env::set_var("HOME", &root);
        let path = root.join("kimi/config.toml");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            "[[hooks]]\n\
             event = \"UserPromptSubmit\"\n\
             command = \"sh -c 'tee -a \\\"$HOME/Aoide/state/kimi-hooks.jsonl\\\" | aoide session hook --agent kimi'\"\n\
             timeout = 5\n",
        )
        .unwrap();

        let out = hooks_install(&install_inv("kimi", true));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.unwrap();
        assert_eq!(data["changed"], true);
        assert_eq!(data["updated"], json!(["UserPromptSubmit"]));

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("${AOIDE_ROOT:-$HOME/.aoide}/state/kimi-hooks.jsonl"),
            "stale capture wrap was not converged: {text}"
        );
        assert!(!text.contains("Aoide/state"), "retired path still present: {text}");

        // Idempotent on the converged text.
        let out2 = hooks_install(&install_inv("kimi", true));
        let data2 = out2.data.unwrap();
        assert_eq!(data2["changed"], false);
        assert_eq!(data2["updated"], json!([]));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn kimi_a_prose_hook_that_merely_mentions_session_hook_is_never_identified_as_ours() {
        // The near-miss the loose pre-tightening marker missed: a user's own
        // hook whose command TEXT happens to contain the literal phrase
        // "session hook" (in prose, not an invocation) must never be
        // identified as ours — post-#109 that identification means an
        // in-place OVERWRITE, not just a `present` report.
        let _g = crate::env_lock().lock().unwrap();
        let _env = EnvSaver::capture(&["KIMI_CODE_HOME", "HOME"]);
        let root = unique_tmp("hooks-kimi-nearmiss");
        std::env::set_var("KIMI_CODE_HOME", root.join("kimi"));
        let path = root.join("kimi/config.toml");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let prose_line = "command = \"echo \\\"logging session hook state\\\" >> audit.log\"";
        std::fs::write(
            &path,
            format!(
                "[[hooks]]\nevent = \"SessionStart\"\n{prose_line}\ntimeout = 5\n"
            ),
        )
        .unwrap();
        let before = std::fs::read_to_string(&path).unwrap();

        let out = hooks_install(&install_inv("kimi", false));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.unwrap();
        // Not identified as ours, so never rewritten...
        assert!(
            !data["updated"].as_array().unwrap().contains(&json!("SessionStart")),
            "the prose hook was clobbered: {data}"
        );
        // ...and our own SessionStart entry is added alongside it (kimi's
        // format allows multiple `[[hooks]]` blocks per event, same as the
        // plain/`--capture` coexistence above).
        assert!(data["added"].as_array().unwrap().contains(&json!("SessionStart")));

        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.starts_with(&before), "the user's own block was not left untouched at its original spot: {after}");
        assert_eq!(after.matches(prose_line).count(), 1, "the prose command line survives verbatim, exactly once: {after}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn capture_wrap_expands_aoide_root_at_hook_fire_time_not_install_time() {
        // The wrap is a SHELL snippet baked into the installed hook config,
        // not a path resolved in Rust at install time — so `door_command`
        // must emit the `${AOIDE_ROOT:-...}` expansion form literally,
        // whatever this process's own env happens to be, and never a
        // hardcoded `~/Aoide` or an install-time-resolved absolute path.
        let profile = agent_profile("kimi").unwrap();
        let cmd = door_command(&profile, true, "SessionStart");
        assert!(
            cmd.contains("${AOIDE_ROOT:-$HOME/.aoide}/state/kimi-hooks.jsonl"),
            "wrap did not carry the AOIDE_ROOT-with-fallback expansion: {cmd}"
        );
        assert!(!cmd.contains("Aoide/state"), "wrap still names the retired ~/Aoide root: {cmd}");
    }

    #[test]
    fn claude_json_wrapper_unmuffles_stdout_for_session_start_and_prompt_submit_only() {
        // Task #139 (docs/Aoide-Wiki/protocol/dev/HARNESS-CLAUDE-CODE.md's
        // "Traps" section is the authority for this rule): SessionStart and
        // UserPromptSubmit are the two events Claude Code itself folds a
        // hook's stdout into the model's context for —
        // UserPromptSubmit is the eventual delivery channel for a Stop-
        // computed delta note (a later, not-yet-landed change). Every OTHER
        // event — including Stop — keeps the original full swallow, or
        // routine hook chatter leaks into events that can never usefully
        // speak.
        let profile = agent_profile("claude").unwrap();
        for evt in ["SessionStart", "UserPromptSubmit"] {
            let cmd = door_command(&profile, false, evt);
            assert!(cmd.contains("2>/dev/null"), "{evt}: {cmd}");
            assert!(!cmd.contains(">/dev/null 2>&1"), "{evt}: {cmd}");
        }

        for evt in [
            "PreToolUse",
            "PostToolUse",
            "Stop",
            "SubagentStart",
            "SubagentStop",
            "SessionEnd",
            "Notification",
        ] {
            let cmd = door_command(&profile, false, evt);
            assert!(cmd.contains(">/dev/null 2>&1"), "{evt}: {cmd}");
        }
    }

    #[test]
    fn capture_install_creates_the_log_dir_under_a_configured_aoide_root() {
        // Install-time, the capture log dir is pre-created via
        // `aoide_storage::fs::state_dir()` — proving it tracks a CONFIGURED
        // `AOIDE_ROOT` (a scratch path here), not the retired `~/Aoide`.
        let _g = crate::env_lock().lock().unwrap();
        let _env = EnvSaver::capture(&["KIMI_CODE_HOME", "HOME", "AOIDE_ROOT", "AOIDE_STATE_DIR"]);
        std::env::remove_var("AOIDE_STATE_DIR");
        let root = unique_tmp("hooks-kimi-cap-root");
        let home = root.join("home");
        let aoide_root = root.join("configured-root");
        std::env::set_var("KIMI_CODE_HOME", home.join("kimi"));
        std::env::set_var("HOME", &home);
        std::env::set_var("AOIDE_ROOT", &aoide_root);

        hooks_install(&install_inv("kimi", true));

        assert!(aoide_root.join("state").is_dir());
        assert!(!home.join("Aoide/state").exists());
        assert!(!home.join(".aoide/state").exists());

        let _ = std::fs::remove_dir_all(&root);
    }

    // ── The three claude tests below exercise the skill-link pass, which
    // ── resolves the LINK SOURCE by walking up from the cwd to the repo's
    // ── own `.claude/skills/aoide` (`skill_source`). The package build's
    // ── sandbox unpacks only `pkgs/aoide`, so no checkout exists above the
    // ── cwd there — each probes and skips with a note, the same
    // ── capability-probe pattern `aoide-secrets`' age-binary tests hold.
    // ── Production needs no gate: `link_skill` already reports the
    // ── condition as its taught `no-source` outcome. ─────────────────────

    #[test]
    fn claude_install_reports_present_and_preserves_the_document() {
        if skill_source().is_none() {
            eprintln!("skipping claude_install_reports_present_and_preserves_the_document: not inside an Aoide checkout (no .claude/skills/aoide above the cwd)");
            return;
        }
        let _g = crate::env_lock().lock().unwrap();
        let _env = EnvSaver::capture(&["HOME"]);
        let root = unique_tmp("hooks-claude");
        std::env::set_var("HOME", &root);
        let path = root.join(".claude/settings.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // Mirror the real hand-written file: the defensive wrapper per event —
        // `door_command` itself builds each entry's expected text, since
        // SessionStart/UserPromptSubmit's `2>/dev/null` and every other
        // event's `>/dev/null 2>&1` swallow now differ (task #139) and a
        // hardcoded literal here drifts the moment that scoping changes
        // again — plus unrelated keys that must survive untouched.
        let events = ["SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse",
                      "Notification", "SubagentStart", "SubagentStop", "Stop", "SessionEnd"];
        let claude_profile = agent_profile("claude").unwrap();
        let mut hooks = serde_json::Map::new();
        for evt in events {
            hooks.insert(evt.to_string(), json!([{ "hooks": [ {
                "type": "command",
                "command": door_command(&claude_profile, false, evt)
            } ] } ]));
        }
        // The pointer entry too (the real hand-written file carries it), so a
        // fully-wired file stays byte-identical below.
        hooks.get_mut("SessionStart").unwrap().as_array_mut().unwrap().push(
            json!({ "hooks": [ { "type": "command", "command": POINTER_CMD } ] }),
        );
        let doc = json!({ "model": "sonnet", "hooks": hooks, "theme": "auto" });
        std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
        let before = std::fs::read_to_string(&path).unwrap();
        // And the skill already correctly linked.
        let skills = root.join(".claude/skills");
        std::fs::create_dir_all(&skills).unwrap();
        std::os::unix::fs::symlink(skill_source().unwrap(), skills.join("aoide")).unwrap();

        let out = hooks_install(&install_inv("claude", false));
        let data = out.data.unwrap();
        assert_eq!(data["changed"], false, "msg: {}", out.message);
        assert_eq!(data["added"], json!([]));
        // 9 graph events + the pointer.
        assert_eq!(data["present"].as_array().unwrap().len(), 10);
        assert_eq!(data["skill"], "present");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before, "untouched when complete");

        // A missing event gets exactly one new entry, in the existing shape,
        // with the rest of the document preserved.
        let mut doc2: Value = serde_json::from_str(&before).unwrap();
        doc2["hooks"].as_object_mut().unwrap().remove("Stop");
        std::fs::write(&path, serde_json::to_string_pretty(&doc2).unwrap()).unwrap();
        let out2 = hooks_install(&install_inv("claude", false));
        let data2 = out2.data.unwrap();
        assert_eq!(data2["changed"], true);
        assert_eq!(data2["added"], json!(["Stop"]));
        let merged: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(merged["model"], "sonnet");
        assert_eq!(merged["theme"], "auto");
        let stop_cmd = &merged["hooks"]["Stop"][0]["hooks"][0];
        assert_eq!(stop_cmd["type"], "command");
        assert!(stop_cmd["command"].as_str().unwrap().contains("session hook"));
        // And the full set is present again on a third run.
        let out3 = hooks_install(&install_inv("claude", false));
        assert_eq!(out3.data.unwrap()["changed"], false);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn claude_reinstall_converges_a_stale_command_and_preserves_user_hook() {
        if skill_source().is_none() {
            eprintln!("skipping claude_reinstall_converges_a_stale_command_and_preserves_user_hook: not inside an Aoide checkout (no .claude/skills/aoide above the cwd)");
            return;
        }
        let _g = crate::env_lock().lock().unwrap();
        let _env = EnvSaver::capture(&["HOME"]);
        let root = unique_tmp("hooks-claude-stale");
        std::env::set_var("HOME", &root);
        let path = root.join(".claude/settings.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // A stale pre-rename PreToolUse entry (still carries the `session
        // hook` marker, so a presence-only check would call it installed
        // forever) sharing its group array with the user's OWN unrelated
        // PreToolUse hook, which must survive the reinstall untouched.
        let doc = json!({ "hooks": { "PreToolUse": [
            { "hooks": [ { "type": "command",
                "command": "a=$(command -v aoide) || exit 0; \"$a\" graph session hook >/dev/null 2>&1; exit 0" } ] },
            { "hooks": [ { "type": "command", "command": "my-own-lint-check.sh" } ] },
        ] } });
        std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();

        let out = hooks_install(&install_inv("claude", false));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.unwrap();
        assert_eq!(data["changed"], true, "msg: {}", out.message);
        assert_eq!(data["updated"], json!(["PreToolUse"]));

        let merged: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let groups = merged["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(groups.len(), 2, "no duplicate entry -- the stale one was rewritten in place");
        // PreToolUse converges to the swallow form, not the unmuffled one —
        // that variant is scoped to SessionStart/UserPromptSubmit only
        // (task #139); a stale PreToolUse entry rewrites to the same
        // `>/dev/null 2>&1` every other non-unmuffled event gets.
        assert_eq!(
            groups[0]["hooks"][0]["command"],
            "a=$(command -v aoide) || exit 0; \"$a\" session hook >/dev/null 2>&1; exit 0"
        );
        // The user's own unrelated hook, untouched.
        assert_eq!(groups[1]["hooks"][0]["command"], "my-own-lint-check.sh");

        // Idempotent on the converged text.
        let before = std::fs::read_to_string(&path).unwrap();
        let out2 = hooks_install(&install_inv("claude", false));
        let data2 = out2.data.unwrap();
        assert_eq!(data2["updated"], json!([]));
        assert!(!data2["added"].as_array().unwrap().contains(&json!("PreToolUse")));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn claude_a_prose_hook_that_merely_mentions_session_hook_is_never_identified_as_ours() {
        // The JSON counterpart of the TOML near-miss above: a user's own
        // PreToolUse hook whose command is prose containing the literal
        // phrase "session hook" (no `aoide` invocation at all) must never
        // be identified as ours and so never rewritten.
        if skill_source().is_none() {
            eprintln!("skipping claude_a_prose_hook_that_merely_mentions_session_hook_is_never_identified_as_ours: not inside an Aoide checkout (no .claude/skills/aoide above the cwd)");
            return;
        }
        let _g = crate::env_lock().lock().unwrap();
        let _env = EnvSaver::capture(&["HOME"]);
        let root = unique_tmp("hooks-claude-nearmiss");
        std::env::set_var("HOME", &root);
        let path = root.join(".claude/settings.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let prose_command = "echo \"logging session hook state\" >> audit.log";
        let doc = json!({ "hooks": { "PreToolUse": [
            { "hooks": [ { "type": "command", "command": prose_command } ] },
        ] } });
        std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();

        let out = hooks_install(&install_inv("claude", false));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.unwrap();
        // Not identified as ours, so never rewritten...
        assert!(
            !data["updated"].as_array().unwrap().contains(&json!("PreToolUse")),
            "the prose hook was clobbered: {data}"
        );
        // ...and our own PreToolUse group is added alongside it.
        assert!(data["added"].as_array().unwrap().contains(&json!("PreToolUse")));

        let merged: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let groups = merged["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(groups.len(), 2, "the user's group survives, ours is added alongside it");
        assert_eq!(
            groups[0]["hooks"][0]["command"], prose_command,
            "the prose command must survive byte-identical"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn claude_pointer_and_skill_install_and_are_idempotent() {
        if skill_source().is_none() {
            eprintln!("skipping claude_pointer_and_skill_install_and_are_idempotent: not inside an Aoide checkout (no .claude/skills/aoide above the cwd)");
            return;
        }
        let _g = crate::env_lock().lock().unwrap();
        let _env = EnvSaver::capture(&["HOME"]);
        let root = unique_tmp("hooks-claude-skill");
        std::env::set_var("HOME", &root);
        let path = root.join(".claude/settings.json");

        // Fresh install: 9 graph events + the pointer, and the skill linked.
        let out = hooks_install(&install_inv("claude", false));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.unwrap();
        assert_eq!(data["changed"], true);
        assert_eq!(data["added"].as_array().unwrap().len(), 10);
        assert!(data["added"].as_array().unwrap().contains(&json!(POINTER_LABEL)));
        assert_eq!(data["skill"], "linked");

        // The pointer entry is the shared constant, in its own group.
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let session_start = doc["hooks"]["SessionStart"].as_array().unwrap();
        assert_eq!(session_start.len(), 2, "graph entry + pointer entry");
        assert_eq!(session_start[1]["hooks"][0]["command"], POINTER_CMD);

        // The symlink resolves to the invoking checkout's skill directory.
        let link = root.join(".claude/skills/aoide");
        assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        assert_eq!(
            std::fs::canonicalize(&link).unwrap(),
            std::fs::canonicalize(skill_source().unwrap()).unwrap()
        );
        assert!(link.join("SKILL.md").is_file());

        // Second run: zero added, pointer and link reported present, settings
        // byte-identical.
        let before = std::fs::read_to_string(&path).unwrap();
        let out2 = hooks_install(&install_inv("claude", false));
        let data2 = out2.data.unwrap();
        assert_eq!(data2["changed"], false);
        assert_eq!(data2["added"], json!([]));
        assert_eq!(data2["present"].as_array().unwrap().len(), 10);
        assert_eq!(data2["skill"], "present");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn claude_skill_conflict_is_a_taught_refusal_never_an_overwrite() {
        if skill_source().is_none() {
            eprintln!("skipping claude_skill_conflict_is_a_taught_refusal_never_an_overwrite: not inside an Aoide checkout (no .claude/skills/aoide above the cwd)");
            return;
        }
        let _g = crate::env_lock().lock().unwrap();
        let _env = EnvSaver::capture(&["HOME"]);
        let root = unique_tmp("hooks-claude-conflict");
        std::env::set_var("HOME", &root);
        let link = root.join(".claude/skills/aoide");
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();

        // A regular file where the link belongs: refuse, teach, leave it.
        std::fs::write(&link, "someone else's skill").unwrap();
        let out = hooks_install(&install_inv("claude", false));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert!(out.message.contains("refusing to overwrite"), "msg: {}", out.message);
        assert!(out.message.contains(&link.display().to_string()), "msg: {}", out.message);
        let data = out.data.unwrap();
        assert_eq!(data["reason"], "skill-link-conflict");
        // The hooks themselves DID merge before the refusal — reported.
        assert_eq!(data["added"].as_array().unwrap().len(), 10);
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "someone else's skill");

        // A symlink to somewhere else: same refusal, naming both targets.
        std::fs::remove_file(&link).unwrap();
        let elsewhere = root.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &link).unwrap();
        let out2 = hooks_install(&install_inv("claude", false));
        assert_eq!(out2.status, aoide_protocol::output::Status::Error);
        assert!(out2.message.contains("already a symlink to"), "msg: {}", out2.message);
        assert_eq!(std::fs::read_link(&link).unwrap(), elsewhere, "link untouched");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pi_install_is_declarative_and_writes_nothing() {
        let _g = crate::env_lock().lock().unwrap();
        let _env = EnvSaver::capture(&["HOME"]);
        let root = unique_tmp("hooks-pi");
        std::env::set_var("HOME", &root);

        let out = hooks_install(&install_inv("pi", false));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let data = out.data.unwrap();
        assert_eq!(data["reason"], "declarative");
        assert_eq!(data["changed"], false);
        assert_eq!(data["settings"], ".pi/agent/extensions/aoide-pi-session.ts");
        // No settings file was minted anywhere under the fake home.
        assert!(!root.join(".pi").exists());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn install_unknown_agent_is_a_structured_error() {
        let out = hooks_install(&install_inv("bogus", false));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert_eq!(out.render(false).1, aoide_protocol::output::exit::ERROR);
        let data = out.data.unwrap();
        assert_eq!(data["reason"], "unknown-agent");
        assert_eq!(data["agent"], "bogus");
        assert_eq!(data["known"], json!(["claude", "kimi", "pi"]));
    }
}
