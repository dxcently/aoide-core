//! `hooks install` — the generic hook-installer command: wire an agent harness
//! to Aoide, driven by the harness's profile (`aoide_protocol::agents`). It
//! writes three things:
//!
//! 1. The `graph session hook` entries — one per hook event — into the
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
//! config holds providers/credentials; the claude settings are hand-written),
//! idempotent (the second run reports zero added), and reports exactly what
//! changed. `--capture` is temporary debugging: the same graph entries with
//! the command wrapped to tee raw payloads to `~/Aoide/state/<agent>-hooks.jsonl`
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
        summary: "Wire an agent harness's settings file to pipe its hooks into `graph session hook` (idempotent merge; never clobbers existing config).",
        args: [arg!("agent", "string", true, "Agent harness to wire up (claude | kimi | pi).")],
        flags: [flag!("capture", "bool", "TEMPORARY debugging: wrap the hook command to tee raw payloads to ~/Aoide/state/<agent>-hooks.jsonl. Capture entries coexist with the plain ones (installing without --capture replaces nothing); remove them manually when done.")],
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
/// `~/Aoide/state/<agent>-hooks.jsonl` first (`~/Aoide/log` is the audit log
/// FILE, not a directory) — its `-hooks.jsonl` marker is what makes capture a
/// distinct idempotency key.
fn door_command(profile: &AgentProfile, capture: bool) -> String {
    if capture {
        format!(
            "sh -c 'tee -a \"$HOME/Aoide/state/{}-hooks.jsonl\" | aoide graph session hook --agent {}'",
            profile.name, profile.name
        )
    } else {
        match profile.hook_settings.format {
            SettingsFormat::Json => {
                r#"a=$(command -v aoide) || exit 0; "$a" graph session hook >/dev/null 2>&1; exit 0"#
                    .to_string()
            }
            SettingsFormat::Toml => format!("aoide graph session hook --agent {}", profile.name),
            // Unreachable for the declarative profiles — `hooks_install`
            // short-circuits before any door command is built.
            SettingsFormat::Declarative => format!("aoide graph session hook --agent {}", profile.name),
        }
    }
}

/// Does an existing entry's command belong to this install mode? Plain and
/// `--capture` entries are distinguished by the capture log marker, so the two
/// coexist and neither install clobbers the other.
fn matches_mode(command: &str, capture: bool) -> bool {
    command.contains("graph session hook") && command.contains("-hooks.jsonl") == capture
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
/// one for this mode.
struct InstallReport {
    added: Vec<&'static str>,
    present: Vec<&'static str>,
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
fn skill_source() -> Option<PathBuf> {
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
/// providers/credentials). An event counts as installed when a `[[hooks]]`
/// block names it AND its command matches this mode; missing events append
/// `[[hooks]]` blocks at EOF (valid TOML after any preceding table). The entry
/// carries ONLY `event`/`command`/`timeout` — extra fields make kimi's config
/// fail to load. A missing file is created (parents included).
fn install_toml(path: &Path, profile: &AgentProfile, capture: bool) -> Result<InstallReport, String> {
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let mut report = InstallReport { added: Vec::new(), present: Vec::new() };
    let mut out = existing;
    for evt in events_for(profile) {
        let has = out.split("[[hooks]]").skip(1).any(|block| {
            block.contains(&format!("event = \"{evt}\""))
                && block
                    .lines()
                    .find(|l| l.trim_start().starts_with("command"))
                    .map(|l| matches_mode(l, capture))
                    .unwrap_or(false)
        });
        if has {
            report.present.push(evt);
            continue;
        }
        report.added.push(evt);
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&format!(
            "[[hooks]]\nevent = \"{evt}\"\ncommand = \"{}\"\ntimeout = 5\n",
            toml_basic(&door_command(profile, capture))
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
    if !report.added.is_empty() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        std::fs::write(path, &out).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    }
    Ok(report)
}

/// JSON (claude): parse → add missing entries to the hooks map → serialize,
/// preserving the rest of the document. An invalid file is an error, never a
/// clobber. New entries match the existing shape exactly: a matcher-less group
/// wrapping one `{"type":"command","command":…}` hook. Nothing is written when
/// nothing was added (a fully-wired file stays byte-identical).
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
    let mut report = InstallReport { added: Vec::new(), present: Vec::new() };
    for evt in events_for(profile) {
        let has = hooks
            .get(evt)
            .and_then(Value::as_array)
            .map(|groups| {
                groups.iter().any(|g| {
                    g.get("hooks")
                        .and_then(Value::as_array)
                        .map(|hs| {
                            hs.iter().any(|h| {
                                h.get("command")
                                    .and_then(Value::as_str)
                                    .map(|c| matches_mode(c, capture))
                                    .unwrap_or(false)
                            })
                        })
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);
        if has {
            report.present.push(evt);
            continue;
        }
        report.added.push(evt);
        let group = json!({ "hooks": [ {
            "type": "command",
            "command": door_command(profile, capture),
        } ] });
        hooks
            .entry(evt)
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .expect("event entry is an array")
            .push(group);
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
    if !report.added.is_empty() {
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
    // The capture wrap tees into ~/Aoide/state — make sure it exists.
    if capture {
        if let Some(home) = std::env::var_os("HOME") {
            let _ = std::fs::create_dir_all(PathBuf::from(home).join("Aoide/state"));
        }
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
    let changed = !report.added.is_empty() || skill_linked;
    let message = if report.added.is_empty() {
        format!(
            "all {} hooks already installed for {} ({}); {skill_note}",
            report.present.len(),
            profile.name,
            path.display()
        )
    } else {
        format!(
            "installed {} hook(s) for {} → {}; {skill_note}",
            report.added.len(),
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
        "skill": skill_status,
        "capture": capture,
        "changed": changed,
    }))
}

#[cfg(test)]
mod tests {
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
        let _g = aoide_test_support::env_lock().lock().unwrap();
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
        assert!(text.contains("command = \"aoide graph session hook --agent kimi\""));
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
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _env = EnvSaver::capture(&["KIMI_CODE_HOME", "HOME"]);
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
        assert!(text.contains("tee -a \\\"$HOME/Aoide/state/kimi-hooks.jsonl\\\" | aoide graph session hook --agent kimi"));
        // The capture log dir was created.
        assert!(root.join("Aoide/state").is_dir());

        // Re-running EITHER mode adds nothing.
        let plain_again = hooks_install(&install_inv("kimi", false));
        assert_eq!(plain_again.data.unwrap()["changed"], false);
        let capture_again = hooks_install(&install_inv("kimi", true));
        assert_eq!(capture_again.data.unwrap()["changed"], false);
        assert_eq!(std::fs::read_to_string(root.join("kimi/config.toml")).unwrap(), text);

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
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _env = EnvSaver::capture(&["HOME"]);
        let root = unique_tmp("hooks-claude");
        std::env::set_var("HOME", &root);
        let path = root.join(".claude/settings.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // Mirror the real hand-written file: the defensive wrapper per event,
        // plus unrelated keys that must survive untouched.
        let events = ["SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse",
                      "Notification", "SubagentStart", "SubagentStop", "Stop", "SessionEnd"];
        let mut hooks = serde_json::Map::new();
        for evt in events {
            hooks.insert(evt.to_string(), json!([{ "hooks": [ {
                "type": "command",
                "command": "a=$(command -v aoide) || exit 0; \"$a\" graph session hook >/dev/null 2>&1; exit 0"
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
        assert!(stop_cmd["command"].as_str().unwrap().contains("graph session hook"));
        // And the full set is present again on a third run.
        let out3 = hooks_install(&install_inv("claude", false));
        assert_eq!(out3.data.unwrap()["changed"], false);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn claude_pointer_and_skill_install_and_are_idempotent() {
        if skill_source().is_none() {
            eprintln!("skipping claude_pointer_and_skill_install_and_are_idempotent: not inside an Aoide checkout (no .claude/skills/aoide above the cwd)");
            return;
        }
        let _g = aoide_test_support::env_lock().lock().unwrap();
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
        let _g = aoide_test_support::env_lock().lock().unwrap();
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
        let _g = aoide_test_support::env_lock().lock().unwrap();
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
