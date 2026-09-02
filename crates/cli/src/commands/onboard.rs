//! `onboard` — the first-boot install-script flow (docs/architecture/
//! ONBOARD.md), core's shell-only half.
//!
//! CLI-only (ONBOARD.md's flow diagram: "Door::Cli only, from a checkout") —
//! an interactive install flow that shells out to a child process makes no
//! sense over MCP/A2A/the daemon, the same reasoning `events tail` already
//! carries for its own foreground-follow shape. From a checkout only
//! (decision 10): the clone IS what gets registered, and the skill link
//! `hooks install` performs needs the repo (the package never ships the
//! skill dir). Registers the clone, seeds the songbook, asks which
//! harnesses to wire and runs the already-registered `hooks install` for
//! each, probes for `lyra` and delegates the nix half to `lyra onboard` as a
//! child process when it resolves (core never speaks nix itself — root
//! `AGENTS.md`'s core/lyra split), then prints the same `aoide guide` output
//! the stub's schema summary always promised.
//!
//! Root-coupled like `meta`/`stubs`/`infra` (this crate's own README/
//! AGENTS): it reads the fully-assembled registry twice — to call the
//! already-registered `hooks.install` handler directly (never reimplemented,
//! crates/AGENTS.md's "no cross-crate copying") and to render the closing
//! guide — neither reachable without depending on this crate, so onboard
//! lives here rather than in a domain crate.

use crate::dispatch::Invocation;
use crate::output::{Outcome, Status};
use crate::registry::{cmd, flag, Registry};
use aoide_protocol::agents::{agent_profile, known_agents, on_path};
use aoide_protocol::{aoide_home, choose_many, interactive, Door};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["onboard"],
        summary: "First-boot flow: register the clone, seed songbook, wire harness hooks, delegate the nix half to `lyra onboard` when lyra is available, print the guide.",
        args: [],
        flags: [
            flag!("harness", "string", "Comma-separated harnesses to wire (claude,kimi,pi); given at all, skips the interactive ask and wires exactly this list (default: ask on a tty, else every harness found on PATH)."),
            flag!("yes", "bool", "Skip every interactive prompt end to end, including the lyra delegate step: use --harness if given, else every harness found on PATH."),
            flag!("out", "string", "Forwarded to `lyra onboard` as its own --out (default: lyra's own default, ./aoide.nix); omitted unless given here."),
        ],
        gated: false,
        implemented: true,
        handler: handle_onboard,
    ));
}

fn handle_onboard(inv: &Invocation) -> Outcome {
    let cmd = "onboard";
    if inv.door != Door::Cli {
        return Outcome::usage(
            cmd,
            "onboard is an interactive install flow; run `aoide onboard` from a terminal (not over this door)",
        );
    }

    let quiet = inv.flag_present("json");
    let say = |s: &str| {
        if !quiet {
            println!("{s}");
        }
    };

    let Some(root) = checkout_root() else {
        return Outcome::error(
            cmd,
            "aoide onboard must run from inside an Aoide checkout (no .claude/skills/aoide/SKILL.md found walking up from the cwd) -- clone the repo (`git clone <upstream> ~/Aoide`) and run onboard from inside it",
        )
        .with_data(json!({ "reason": "no-checkout" }));
    };

    let mut changed: Vec<String> = Vec::new();

    say(&format!("onboard: registering the clone ({})...", root.display()));
    let (clone_changed, clone_notes) = register_clone(&root, inv.door);
    for n in &clone_notes {
        say(&format!("  {n}"));
    }
    changed.extend(clone_changed);

    say("onboard: seeding the songbook...");
    let (seeded, seed_note) = seed_songbook(&root);
    say(&format!("  {seed_note}"));
    if seeded {
        changed.push(seed_note.clone());
    }

    let harnesses = match resolve_harnesses(inv) {
        Ok(h) => h,
        Err(out) => return out,
    };
    let mut hook_reports: Vec<serde_json::Value> = Vec::new();
    if harnesses.is_empty() {
        say("onboard: no harnesses selected -- nothing to wire");
    } else {
        say(&format!("onboard: wiring hooks for {}...", harnesses.join(", ")));
        for h in &harnesses {
            let out = run_hooks_install(h, inv.door);
            say(&format!("  {}", out.message));
            hook_reports.push(json!({
                "agent": h,
                "ok": out.status == Status::Ok,
                "message": out.message,
            }));
            changed.extend(out.changed.clone());
        }
    }

    say("onboard: probing for lyra...");
    let lyra_note = probe_and_delegate_lyra(inv);
    say(&format!("  {lyra_note}"));

    if !quiet {
        println!("{}", crate::guide::render(crate::dispatch::registry()));
    }

    let message = format!("onboard: clone registered, {} harness(es) wired -- {lyra_note}", harnesses.len());
    Outcome::ok(cmd, message).changed(changed).with_data(json!({
        "root": root.display().to_string(),
        "harnesses": harnesses,
        "hooks": hook_reports,
        "lyra": lyra_note,
    }))
}

/// The invoking checkout's root: `hooks::skill_source()`'s own walk-up (the
/// only repo-root detector in the tree, ONBOARD.md decision 10) returns
/// `<root>/.claude/skills`; two `.parent()` calls strip `skills`/`.claude`
/// back to `<root>`.
fn checkout_root() -> Option<PathBuf> {
    let skills_dir = crate::conduct::commands::hooks::skill_source()?;
    skills_dir.parent()?.parent().map(Path::to_path_buf)
}

/// "register the clone" (ONBOARD.md's stub-summary contract, decision 1):
/// two shell-only, idempotent acts the wiki already documents as onboard's
/// job. `project.add`'s own schema example (`project add aoide
/// ~/Aoide`) is the existing "register X as known" mechanism this reuses
/// rather than inventing a new marker file or state format; Song-Anatomy.md/
/// Song-Vocabulary.md/Clone-and-Run.md all separately state "onboard links
/// `~/song` -> `~/Aoide/song`", so the second act is the symlink they
/// already document, made real. Never a clobber: an existing correct link
/// is a no-op, anything else at either path is left alone with a note.
fn register_clone(root: &Path, door: Door) -> (Vec<String>, Vec<String>) {
    let mut changed = Vec::new();
    let mut notes = Vec::new();

    let out = crate::graph::project_add(&Invocation {
        path: vec!["project".into(), "add".into()],
        args: vec!["aoide".into(), root.display().to_string()],
        flags: BTreeMap::new(),
        door,
    });
    notes.push(out.message.clone());
    changed.extend(out.changed);

    let home_song = aoide_home().join("song");
    let root_song = root.join("song");
    match std::fs::symlink_metadata(&home_song) {
        Ok(meta) if meta.file_type().is_symlink() => {
            // The exact-path compare catches a symlink correctly aimed at
            // `root_song` whose target doesn't (yet) exist -- canonicalize
            // fails on a dangling target, which would otherwise misreport a
            // correctly-targeted link as "elsewhere" just because the read
            // happened before `root/song` existed. The canonicalize fallback
            // still catches an equivalent but differently-spelled target
            // (relative vs absolute, a symlink chain) once it resolves.
            let same_target = std::fs::read_link(&home_song).map(|t| t == root_song).unwrap_or(false);
            let resolves = same_target
                || matches!(
                    (std::fs::canonicalize(&home_song), std::fs::canonicalize(&root_song)),
                    (Ok(l), Ok(s)) if l == s
                );
            if resolves {
                notes.push(format!("~/song already links to {}", root_song.display()));
            } else {
                let target = std::fs::read_link(&home_song)
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "<unreadable>".to_string());
                notes.push(format!(
                    "{} is already a symlink to {target}, not to {} -- leaving it (remove it yourself to relink)",
                    home_song.display(),
                    root_song.display()
                ));
            }
        }
        Ok(_) => notes.push(format!(
            "{} already exists and is not a symlink -- leaving it (move it aside to let onboard link it)",
            home_song.display()
        )),
        Err(_) => match std::os::unix::fs::symlink(&root_song, &home_song) {
            Ok(()) => {
                notes.push(format!("linked {} -> {}", home_song.display(), root_song.display()));
                changed.push(format!("~/song -> {}", root_song.display()));
            }
            Err(e) => notes.push(format!("could not link {}: {e}", home_song.display())),
        },
    }

    (changed, notes)
}

/// "seed songbook" (ONBOARD.md's stub-summary contract, decision 1):
/// `song/songbook/` travels committed with the clone itself
/// (`learnings.md`/`update-playbook.md` are already there on any fresh
/// checkout) — the one root file Song-Anatomy.md documents as part of the
/// songbook's cross-cutting trio that a fresh clone still lacks is
/// `preferences.md`. Idempotent: only ever created, never overwritten.
fn seed_songbook(root: &Path) -> (bool, String) {
    let path = root.join("song/songbook/preferences.md");
    if path.exists() {
        return (false, format!("{} already present", path.display()));
    }
    let body = "\
# Songbook Preferences

Cross-cutting preferences that apply across songs, not any one song's
`design/` folder -- the sibling of `learnings.md`. Sparse today; the agent
reads this before every ricing iteration and appends after declare/reject
decisions, the same write-back discipline `learnings.md` already holds.
";
    match std::fs::write(&path, body) {
        Ok(()) => (true, format!("seeded {}", path.display())),
        Err(e) => (false, format!("could not seed {}: {e}", path.display())),
    }
}

/// Which harnesses to wire. `--harness` (comma-separated -- the repo's
/// established stand-in for a repeatable flag over this registry's flat
/// `BTreeMap<String,String>` flag model, `events tail --class`'s own
/// convention) skips the ask outright and wires exactly that list;
/// otherwise `--yes` or a non-tty invocation silently takes every harness
/// found on PATH; otherwise the interactive multi-select (ONBOARD.md
/// decision 7) asks, preselected by the same PATH probe.
fn resolve_harnesses(inv: &Invocation) -> Result<Vec<&'static str>, Outcome> {
    if let Some(raw) = inv.flags.get("harness") {
        let names: Vec<&str> = raw.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
        let mut chosen = Vec::new();
        for name in names {
            match known_agents().iter().find(|k| **k == name) {
                Some(k) => chosen.push(*k),
                None => {
                    return Err(Outcome::usage(
                        "onboard",
                        format!("unknown harness `{name}` (known: {})", known_agents().join(", ")),
                    ))
                }
            }
        }
        return Ok(chosen);
    }

    let known = known_agents();
    let on_path_idx: Vec<usize> = (0..known.len())
        .filter(|&i| agent_profile(known[i]).is_some_and(on_path))
        .collect();

    let non_interactive = inv.flag_present("yes") || !interactive(inv.door);
    if non_interactive {
        return Ok(on_path_idx.iter().map(|&i| known[i]).collect());
    }

    let rows: Vec<String> = known.iter().map(|n| n.to_string()).collect();
    match choose_many("which harnesses should onboard wire?", &rows, &on_path_idx) {
        Some(sel) => Ok(sel.into_iter().filter_map(|i| known.get(i).copied()).collect()),
        None => Ok(Vec::new()),
    }
}

/// Call the already-registered `hooks install <agent>` handler directly off
/// the assembled registry -- never reimplemented (crates/AGENTS.md's "no
/// cross-crate copying"), the exact entry point a plain `aoide hooks install
/// <agent>` invocation would reach (including its skill-symlink pass).
fn run_hooks_install(agent: &str, door: Door) -> Outcome {
    let path = vec!["hooks".to_string(), "install".to_string()];
    match crate::dispatch::registry().get(&path) {
        Some(entry) => (entry.handler)(&Invocation {
            path,
            args: vec![agent.to_string()],
            flags: BTreeMap::new(),
            door,
        }),
        None => Outcome::error("onboard", "hooks.install is not registered (unexpected)"),
    }
}

/// ONBOARD.md decision 3: "lyra enabled" = `rice_bin()` resolves. The env
/// tier is trusted unconditionally (`rice_bin`'s own contract) and the
/// sibling tier is only ever RETURNED after `rice_bin` already ran its own
/// `exists()` check -- both show up as a path containing `/`. Only the bare
/// name (`"lyra"`, tier 3, deliberately left by `rice_bin` for
/// `Command::spawn` to resolve at exec time) needs a PATH probe of our own.
fn lyra_bin_if_resolved() -> Option<String> {
    let bin = aoide_protocol::bin::rice_bin();
    let resolved = bin.contains('/') || aoide_protocol::bin::on_path(&bin);
    resolved.then_some(bin)
}

/// Steps 2-3 of the flow (ONBOARD.md): probe for lyra, and when it
/// resolves, delegate the whole nix half to `lyra onboard` as a child
/// process with inherited stdio so its own prompts/output reach this same
/// terminal directly (`--harness` is deliberately NOT forwarded -- harness
/// wiring is core's own job, decision 7, and lyra's half has no use for it).
/// A spawn failure (e.g. `ENOENT`) OR a nonzero exit both fall to the same
/// tolerant note rather than a hard onboard failure -- either could mean the
/// resolved lyra binary predates this aoide and genuinely lacks `onboard`,
/// OR a real failure inside `lyra onboard` itself; the note names the exit
/// code (or spawn error) and states plainly that the desktop half was
/// skipped, without guessing which case it was. If lyra isn't found at all,
/// the returned line names no nix-shaped detail whatsoever (ONBOARD.md
/// decision 3's "nothing nix-shaped is ever spoken").
fn probe_and_delegate_lyra(inv: &Invocation) -> String {
    let Some(bin) = lyra_bin_if_resolved() else {
        return "lyra: not found (no AOIDE_RICE_BIN, no sibling binary, not on PATH) -- skipping the desktop half; core setup is complete".to_string();
    };

    let mut cmd = Command::new(&bin);
    cmd.arg("onboard");
    if let Some(out) = inv.flags.get("out") {
        cmd.arg("--out").arg(out);
    }
    if inv.flag_present("yes") {
        cmd.arg("--yes");
    }
    cmd.stdin(Stdio::inherit()).stdout(Stdio::inherit()).stderr(Stdio::inherit());

    match cmd.status() {
        Ok(status) if status.success() => format!("lyra onboard: done ({bin})"),
        Ok(status) => format!(
            "lyra onboard failed (exited {}) -- the resolved lyra binary may be older than this aoide and lack the `onboard` subcommand, or the command itself failed; skipping the desktop half",
            status.code().map(|c| c.to_string()).unwrap_or_else(|| "via signal".to_string())
        ),
        Err(e) => format!(
            "lyra onboard could not be run ({e}) -- the resolved lyra binary may be older than this aoide and lack the `onboard` subcommand, or spawning it failed; skipping the desktop half"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aoide_test_support::{env_lock, unique_tmp, EnvSaver};

    // ── register_clone: the ~/song symlink's never-clobber contract ─────

    #[test]
    fn register_clone_links_song_when_absent_and_is_idempotent_on_rerun() {
        let _g = env_lock().lock().unwrap();
        let _env = EnvSaver::capture(&["HOME", "AOIDE_STAGE_DIR"]);
        let root = unique_tmp("onboard-clone-fresh");
        std::fs::create_dir_all(root.join("song")).unwrap();
        let home = unique_tmp("onboard-clone-fresh-home");
        std::env::set_var("HOME", &home);
        std::env::set_var("AOIDE_STAGE_DIR", home.join("Aoide/song/stage"));
        let home_song = home.join("song");

        let (changed, notes) = register_clone(&root, Door::Cli);
        let meta = std::fs::symlink_metadata(&home_song).unwrap();
        assert!(meta.file_type().is_symlink(), "~/song was not created as a symlink");
        assert_eq!(
            std::fs::canonicalize(&home_song).unwrap(),
            std::fs::canonicalize(root.join("song")).unwrap()
        );
        assert!(notes.iter().any(|n| n.contains("linked") && n.contains("song")), "notes: {notes:?}");
        assert!(changed.iter().any(|c| c.starts_with("~/song ->")), "changed: {changed:?}");

        // Re-run: no-op, reported present, never re-listed as changed.
        let (changed2, notes2) = register_clone(&root, Door::Cli);
        assert!(notes2.iter().any(|n| n.contains("already links to")), "notes2: {notes2:?}");
        assert!(
            !changed2.iter().any(|c| c.starts_with("~/song ->")),
            "a second run must not re-report the symlink as changed: {changed2:?}"
        );

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn register_clone_leaves_a_wrong_target_symlink_alone_with_a_note() {
        let _g = env_lock().lock().unwrap();
        let _env = EnvSaver::capture(&["HOME", "AOIDE_STAGE_DIR"]);
        let root = unique_tmp("onboard-clone-wrong");
        std::fs::create_dir_all(root.join("song")).unwrap();
        let home = unique_tmp("onboard-clone-wrong-home");
        std::env::set_var("HOME", &home);
        std::env::set_var("AOIDE_STAGE_DIR", home.join("Aoide/song/stage"));
        let home_song = home.join("song");
        let elsewhere = unique_tmp("onboard-clone-wrong-elsewhere");
        std::os::unix::fs::symlink(&elsewhere, &home_song).unwrap();

        let (changed, notes) = register_clone(&root, Door::Cli);
        assert!(
            notes.iter().any(|n| n.contains("is already a symlink to") && n.contains(&elsewhere.display().to_string())),
            "notes: {notes:?}"
        );
        assert!(!changed.iter().any(|c| c.starts_with("~/song ->")));
        assert_eq!(std::fs::read_link(&home_song).unwrap(), elsewhere, "the wrong link must survive untouched");

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&elsewhere);
    }

    #[test]
    fn register_clone_leaves_a_regular_file_alone_with_a_note() {
        let _g = env_lock().lock().unwrap();
        let _env = EnvSaver::capture(&["HOME", "AOIDE_STAGE_DIR"]);
        let root = unique_tmp("onboard-clone-file");
        std::fs::create_dir_all(root.join("song")).unwrap();
        let home = unique_tmp("onboard-clone-file-home");
        std::env::set_var("HOME", &home);
        std::env::set_var("AOIDE_STAGE_DIR", home.join("Aoide/song/stage"));
        let home_song = home.join("song");
        std::fs::write(&home_song, "not a symlink").unwrap();

        let (changed, notes) = register_clone(&root, Door::Cli);
        assert!(
            notes.iter().any(|n| n.contains("already exists and is not a symlink")),
            "notes: {notes:?}"
        );
        assert!(!changed.iter().any(|c| c.starts_with("~/song ->")));
        assert_eq!(std::fs::read_to_string(&home_song).unwrap(), "not a symlink", "the file must survive untouched");

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn register_clone_reports_a_dangling_but_correctly_targeted_link_as_already_linked() {
        // The cosmetic fix: a symlink aimed at the RIGHT path whose target
        // doesn't exist yet must not be misreported as "elsewhere" just
        // because `canonicalize` can't resolve a dangling target.
        let _g = env_lock().lock().unwrap();
        let _env = EnvSaver::capture(&["HOME", "AOIDE_STAGE_DIR"]);
        let root = unique_tmp("onboard-clone-dangling");
        // Deliberately no `root/song` directory yet -- the link below points
        // at a path that does not exist on disk.
        let home = unique_tmp("onboard-clone-dangling-home");
        std::env::set_var("HOME", &home);
        std::env::set_var("AOIDE_STAGE_DIR", home.join("Aoide/song/stage"));
        let home_song = home.join("song");
        std::os::unix::fs::symlink(root.join("song"), &home_song).unwrap();

        let (_changed, notes) = register_clone(&root, Door::Cli);
        assert!(notes.iter().any(|n| n.contains("already links to")), "notes: {notes:?}");

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&home);
    }

    // ── seed_songbook: create-once, never overwrite ──────────────────────

    #[test]
    fn seed_songbook_creates_preferences_once_then_leaves_it_untouched() {
        let root = unique_tmp("onboard-seed");
        std::fs::create_dir_all(root.join("song/songbook")).unwrap();
        let path = root.join("song/songbook/preferences.md");

        let (seeded, note) = seed_songbook(&root);
        assert!(seeded);
        assert!(note.contains("seeded"), "note: {note}");
        let first = std::fs::read_to_string(&path).unwrap();
        assert!(first.contains("Songbook Preferences"));

        let (seeded2, note2) = seed_songbook(&root);
        assert!(!seeded2);
        assert!(note2.contains("already present"), "note2: {note2}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), first, "a second run must never overwrite");

        let _ = std::fs::remove_dir_all(&root);
    }

    // ── resolve_harnesses: --harness parsing ─────────────────────────────

    fn onboard_inv(flags: &[(&str, &str)]) -> Invocation {
        Invocation {
            path: vec!["onboard".to_string()],
            args: vec![],
            flags: flags.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            door: Door::Cli,
        }
    }

    #[test]
    fn resolve_harnesses_from_explicit_flag_preserves_given_order() {
        let inv = onboard_inv(&[("harness", "kimi,claude")]);
        assert_eq!(resolve_harnesses(&inv).unwrap(), vec!["kimi", "claude"]);
    }

    #[test]
    fn resolve_harnesses_trims_whitespace_and_drops_empty_tokens() {
        let inv = onboard_inv(&[("harness", " claude ,, kimi ")]);
        assert_eq!(resolve_harnesses(&inv).unwrap(), vec!["claude", "kimi"]);
    }

    #[test]
    fn resolve_harnesses_rejects_an_unknown_name() {
        let inv = onboard_inv(&[("harness", "claude,bogus")]);
        let err = resolve_harnesses(&inv).unwrap_err();
        assert_eq!(err.status, Status::Usage);
        assert!(err.message.contains("unknown harness `bogus`"), "message: {}", err.message);
        assert!(err.message.contains("claude, kimi, pi"), "message: {}", err.message);
    }

    // ── checkout_root: the from-a-checkout detector ──────────────────────

    #[test]
    fn checkout_root_finds_the_repo_root_by_walking_up_to_the_skill_marker() {
        let _g = env_lock().lock().unwrap();
        let root = unique_tmp("onboard-checkout-found");
        std::fs::create_dir_all(root.join(".claude/skills/aoide")).unwrap();
        std::fs::write(root.join(".claude/skills/aoide/SKILL.md"), "").unwrap();
        let nested = root.join("pkgs/aoide/crates/cli");
        std::fs::create_dir_all(&nested).unwrap();

        let saved_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&nested).unwrap();
        let found = checkout_root();
        std::env::set_current_dir(&saved_cwd).unwrap();

        assert_eq!(
            found.map(|p| std::fs::canonicalize(p).unwrap()),
            Some(std::fs::canonicalize(&root).unwrap())
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn checkout_root_is_none_outside_a_checkout() {
        let _g = env_lock().lock().unwrap();
        let root = unique_tmp("onboard-checkout-missing");

        let saved_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&root).unwrap();
        let found = checkout_root();
        std::env::set_current_dir(&saved_cwd).unwrap();

        assert!(found.is_none(), "found a checkout root where there is none: {found:?}");
        let _ = std::fs::remove_dir_all(&root);
    }
}
