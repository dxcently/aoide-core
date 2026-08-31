//! The check lane — connecting `aoide soundcheck`'s report-only sweep and
//! `nix flake check`'s committed-tree half to the agent LOOP itself, through
//! `aoide session hook`'s SessionStart/Stop wiring (task #139).
//!
//! **The problem this closes.** Both halves already existed as commands an
//! agent could run by hand; neither was ever WIRED to fire on its own. An
//! agent that hits a red mid-task and was never told assumes it caused the
//! red, then reverts its own good work chasing an inherited fault.
//!
//! **Nix appears as DATA, never as source.** This crate (like every core
//! crate) cannot shell out to `nix` directly — `checks.nix-independence`
//! (`lib/checks.nix`) fails the build if `nix eval|build|flake|…` appears on
//! a line that spawns a process. So [`run_verify`] runs whatever command
//! [`crate::config`] hands it — [`aoide_storage::config::Upkeep::
//! verify_command`], a free-form string an operator points at `nix flake
//! check <checks…>` on a nix host, `cargo test`/`make check`/anything else on
//! a non-nix host, or leaves empty to disable the lane outright. This module
//! never parses that command's own output — the module doc on
//! [`aoide_storage::config::ValueKind::Scalar`] says why: core cannot judge
//! what "clean" means on every host, only whether the command it was handed
//! exited zero.
//!
//! **Two triggers.** [`on_session_start`] runs the lane, records its result
//! as this session's BASELINE, and — when that baseline is already red, or
//! already carries an untracked `.nix` file — returns a message pairing the
//! fact with the scope constraint in the same breath ("inherited, not yours
//! — do not fix unless asked"): recognition is the load-bearing part, an
//! agent about to edit a file needs to know it is already failing or it will
//! misread its own diff. [`on_stop`] re-runs the lane and diffs it against
//! that recorded baseline ([`diff`]), so attribution — did THIS turn make
//! something newly red — is a fact rather than a guess, then the fresh run
//! becomes the baseline for the next delta. **`on_stop`'s note is correct
//! and computed, but not yet LIVE** (`data.checkLane` in `session hook`'s
//! own `Outcome` carries it, inspectable via `--json`): under Claude Code's
//! real hook contract, `Stop`'s stdout never reaches the model, only a debug
//! log (`docs/Aoide-Wiki/protocol/dev/HARNESS-CLAUDE-CODE.md`'s "Traps"
//! section). The decided fix is deferred delivery — `on_stop` records, and
//! the next context-reaching event (`UserPromptSubmit`) speaks the note on
//! its behalf — not yet landed here (`aoide-conduct`'s `graph/send.rs`, a
//! separate change); see `commands/hooks.rs::door_command`'s own doc for
//! the full contract this was checked against.
//!
//! **A baseline is a snapshot, not a ledger of turns.** [`on_session_start`]
//! unconditionally overwrites the previous baseline on every call, including
//! a mid-session `SessionStart` fired by a harness-side compaction/resume
//! with no intervening [`on_stop`] — so a regression introduced earlier in
//! the SAME session can be re-baselined as "inherited" if a compaction lands
//! between the edit and the next `Stop`. Known, not yet fixed: distinguishing
//! a fresh session from a mid-session resume needs the hook payload's own
//! `source` field threaded down from `graph/send.rs`, and is entangled with
//! the channel question above (what a baseline should even mean depends on
//! how/whether Stop ever becomes live).
//!
//! **Untracked `.nix` files are invisible to flake checks, so this lane
//! reports them itself.** `nix flake check` evaluates the git-filtered
//! store copy — an untracked file was never copied in, so a brand-new,
//! grossly-unformatted module draws zero complaint from it. Since creating a
//! new module is exactly what an agent does most, [`untracked_nix_files`]
//! answers this independently of whatever [`run_verify`] reports.
//!
//! **Cost.** Both entry points run synchronously inside the hook (the fast
//! lane this connects to batches to roughly 259ms warm / 1.6s cold-eval,
//! per the check-lane design) — no backgrounding, no polling. The slow
//! attributes (vm-boot, pkg-*, portability) are deliberately NOT this lane's
//! concern; they stay manual.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The wording every inherited-red message carries alongside the fact — the
/// load-bearing half, per the module doc: stating the fact WITHOUT this
/// reads as "go fix it" and turns a recognition into a yak-shave.
const INHERITED_NOTE: &str = "inherited, not yours — do not fix unless asked";

// ── Pure: one run, and the delta between two ────────────────────────────────

/// One lane run's result. `Eq`+`Serialize`/`Deserialize` so it can be
/// compared and persisted as a session's baseline without a second shape.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LaneRun {
    /// Did the configured verify command exit non-zero?
    #[serde(default)]
    pub verify_red: bool,
    /// Untracked `.nix` file paths, repo-relative, sorted.
    #[serde(default)]
    pub untracked_nix: Vec<String>,
}

/// What changed between a recorded baseline and a fresh run — the only
/// question [`on_stop`] answers. Every field defaults to "nothing changed",
/// so [`LaneDelta::is_empty`] is the single gate a caller needs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LaneDelta {
    pub verify_newly_red: bool,
    pub verify_newly_green: bool,
    pub newly_untracked_nix: Vec<String>,
}

impl LaneDelta {
    pub fn is_empty(&self) -> bool {
        !self.verify_newly_red && !self.verify_newly_green && self.newly_untracked_nix.is_empty()
    }
}

/// Pure: the delta between a recorded baseline and a fresh run. No I/O — the
/// entire attribution question ("is this red inherited, or did THIS turn
/// make it") is one comparison, testable without a filesystem or a
/// subprocess.
pub fn diff(baseline: &LaneRun, current: &LaneRun) -> LaneDelta {
    LaneDelta {
        verify_newly_red: current.verify_red && !baseline.verify_red,
        verify_newly_green: baseline.verify_red && !current.verify_red,
        newly_untracked_nix: current
            .untracked_nix
            .iter()
            .filter(|p| !baseline.untracked_nix.contains(p))
            .cloned()
            .collect(),
    }
}

/// Pure: pick the `.nix` paths out of `git status --porcelain`'s untracked
/// (`??`) lines. Split from its git-spawning caller ([`untracked_nix_files`])
/// so the parsing rule is testable on a literal string — the same separation
/// `scan.rs`'s `slug` holds against ITS git-sourced callers.
pub fn parse_untracked_nix(porcelain: &str) -> Vec<String> {
    let mut files: Vec<String> = porcelain
        .lines()
        .filter_map(|l| l.strip_prefix("?? "))
        .filter(|p| p.ends_with(".nix"))
        .map(str::to_string)
        .collect();
    files.sort();
    files
}

/// Pure: message [`on_session_start`] builds off one [`LaneRun`]. `None`
/// when there is nothing to flag (a clean baseline) — a quiet SessionStart
/// stays quiet.
pub fn session_start_message(run: &LaneRun) -> Option<String> {
    if !run.verify_red && run.untracked_nix.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    if run.verify_red {
        parts.push(format!("the verify command is already red ({INHERITED_NOTE})"));
    }
    if !run.untracked_nix.is_empty() {
        parts.push(format!(
            "untracked .nix file(s) invisible to flake checks ({INHERITED_NOTE}): {}",
            run.untracked_nix.join(", ")
        ));
    }
    Some(format!("check lane: {}", parts.join("; ")))
}

/// Pure: message [`on_stop`] builds off a [`LaneDelta`]. `None` when nothing
/// changed since the recorded baseline — attribution is a fact, and "nothing
/// changed" is a fact worth staying silent about, not narrating.
pub fn stop_message(delta: &LaneDelta) -> Option<String> {
    if delta.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    if delta.verify_newly_red {
        parts.push("the verify command turned red during this turn".to_string());
    }
    if delta.verify_newly_green {
        parts.push("the verify command turned green during this turn".to_string());
    }
    if !delta.newly_untracked_nix.is_empty() {
        parts.push(format!(
            "new untracked .nix file(s) this turn: {}",
            delta.newly_untracked_nix.join(", ")
        ));
    }
    Some(format!("check lane: {}", parts.join("; ")))
}

// ── Impure: run the command, read the tree, persist the baseline ───────────

/// `git status --porcelain --untracked-files=all` scoped at `root` —
/// `all`, not the default `normal` C1 uses: a brand-new NESTED directory
/// (exactly what a new dendrite/facet looks like) collapses to one line
/// under `normal` and would hide every `.nix` file inside it.
pub fn untracked_nix_files(root: &Path) -> Vec<String> {
    crate::scan::run_git(root, &["status", "--porcelain", "--untracked-files=all"])
        .map(|s| parse_untracked_nix(&s))
        .unwrap_or_default()
}

/// Run the configured verify command at `root`, `sh -c`'d so the operator's
/// TOML string can be anything a shell accepts (a bare binary, a pipeline, a
/// `&&` chain) — exactly like `soundcheck`'s own C4-C6 shell-outs will. A
/// command that cannot even launch is not this lane's finding to make (best-
/// effort, the same degrade-to-nothing stance `scan::run_git` holds).
///
/// Both `stdout`/`stderr` are explicitly `Stdio::null()` — NOT inherited
/// (review finding: `.status()` with no `Stdio` call inherits the calling
/// hook process's own streams). A real verify command's own output (a `nix
/// flake check` eval/build log, easily many KB) would otherwise ride
/// straight through to `session hook`'s own stdout, ahead of its one-line
/// summary — and on `SessionStart` specifically, that stdout is exactly the
/// channel Claude Code folds into the model's context (`commands/
/// hooks.rs::door_command`'s doc), so an unredirected verify command would
/// dump its whole build log into context on every session. This module
/// reports red/green only, never the command's own words — the redirection
/// is what actually keeps that promise, not just the absence of a parser.
fn run_verify(root: &Path, command: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(command)
        .current_dir(root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| !s.success())
        .unwrap_or(false)
}

/// Run the whole lane once: the verify command (if any) plus the untracked-
/// `.nix` scan, always — the scan is cheap and answers a question the verify
/// command structurally cannot.
pub fn run_lane(root: &Path, command: &str) -> LaneRun {
    LaneRun {
        verify_red: !command.trim().is_empty() && run_verify(root, command),
        untracked_nix: untracked_nix_files(root),
    }
}

/// The configured verify command, or `None` when the lane is off (empty
/// string — [`aoide_storage::config::Upkeep`]'s default). A config that
/// fails to load degrades to "lane off" rather than failing the hook — this
/// module never fails a hook, the same best-effort stance every other
/// session-hook action already holds.
fn configured_command() -> Option<String> {
    let cmd = aoide_storage::config::load().ok()?.config.upkeep.verify_command;
    (!cmd.trim().is_empty()).then_some(cmd)
}

/// Where this session's baseline [`LaneRun`] is persisted — one small file
/// per session, under the state dir the rest of this crate already writes
/// beneath (`aoide_storage::fs::state_dir()`), NOT the conduct session store:
/// this lane's own state, not a conducted session's.
fn baseline_path(session_id: &str) -> PathBuf {
    aoide_storage::fs::state_dir().join("checklane").join(format!("{session_id}.json"))
}

fn load_baseline(session_id: &str) -> Option<LaneRun> {
    let text = std::fs::read_to_string(baseline_path(session_id)).ok()?;
    serde_json::from_str(&text).ok()
}

/// Best-effort: a failed write never fails the hook (same stance as every
/// other write in this crate's `commands`/`scan` — soundcheck never repairs,
/// and this lane never blocks a session over its own bookkeeping).
fn store_baseline(session_id: &str, run: &LaneRun) {
    let path = baseline_path(session_id);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(text) = serde_json::to_string(run) {
        let _ = aoide_storage::fs::atomic_write(&path, &text);
    }
}

/// Delete this session's baseline, if any (review finding: nothing ever
/// deleted these — one file accreted forever per session, an effect with no
/// inverse). Called from the two places that already know a session is
/// truly over — `aoide-conduct`'s `do_session_end` and `reap`'s own prune
/// pass — never a new sweep of its own; a missing file is not an error
/// (`remove_file`'s `NotFound` is swallowed the same way every other
/// best-effort cleanup in this crate is).
pub fn forget_baseline(session_id: &str) {
    let _ = std::fs::remove_file(baseline_path(session_id));
}

// ── The two hook entry points ───────────────────────────────────────────────

/// `SessionStart`: run the lane, record it as this session's baseline, and
/// flag an already-red or already-.nix-carrying baseline — `None` when the
/// lane is disabled or the baseline is clean.
pub fn on_session_start(session_id: &str, root: &Path) -> Option<String> {
    let command = configured_command()?;
    let run = run_lane(root, &command);
    let message = session_start_message(&run);
    store_baseline(session_id, &run);
    message
}

/// `Stop`: re-run the lane and report only the DELTA against the baseline
/// [`on_session_start`] recorded — `None` when the lane is disabled, no
/// baseline was ever recorded (the lane turned on mid-session), or nothing
/// changed. This run becomes the new baseline either way, so the NEXT Stop's
/// delta is against THIS turn, not the session's original start.
pub fn on_stop(session_id: &str, root: &Path) -> Option<String> {
    let command = configured_command()?;
    let current = run_lane(root, &command);
    let message = load_baseline(session_id).map(|baseline| diff(&baseline, &current)).and_then(
        |delta| stop_message(&delta),
    );
    store_baseline(session_id, &current);
    message
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Pure: parse_untracked_nix ───────────────────────────────────────────

    #[test]
    fn parse_untracked_nix_keeps_only_dot_nix_paths_from_untracked_lines() {
        let porcelain = "?? modules/dendrites/newthing/rice.nix\n?? README.md\n M tracked.nix\n?? another/deep/one.nix\n";
        assert_eq!(
            parse_untracked_nix(porcelain),
            vec!["another/deep/one.nix".to_string(), "modules/dendrites/newthing/rice.nix".to_string()]
        );
    }

    #[test]
    fn parse_untracked_nix_is_empty_on_a_clean_or_all_tracked_status() {
        assert!(parse_untracked_nix("").is_empty());
        assert!(parse_untracked_nix(" M tracked.nix\nA  other.nix\n").is_empty());
    }

    // ── Pure: diff — this is the one that PROVES it bites ───────────────────

    #[test]
    fn diff_reports_nothing_when_the_run_is_unchanged() {
        let run = LaneRun { verify_red: true, untracked_nix: vec!["a.nix".to_string()] };
        let delta = diff(&run, &run);
        assert!(delta.is_empty(), "{delta:?}");
    }

    #[test]
    fn diff_flags_a_newly_red_verify_command_and_nothing_else() {
        let baseline = LaneRun { verify_red: false, untracked_nix: vec![] };
        let current = LaneRun { verify_red: true, untracked_nix: vec![] };
        let delta = diff(&baseline, &current);
        assert!(delta.verify_newly_red);
        assert!(!delta.verify_newly_green);
        assert!(delta.newly_untracked_nix.is_empty());
    }

    #[test]
    fn diff_flags_a_newly_green_verify_command() {
        let baseline = LaneRun { verify_red: true, untracked_nix: vec![] };
        let current = LaneRun { verify_red: false, untracked_nix: vec![] };
        let delta = diff(&baseline, &current);
        assert!(delta.verify_newly_green);
        assert!(!delta.verify_newly_red);
    }

    #[test]
    fn diff_flags_only_the_nix_files_the_baseline_did_not_already_carry() {
        let baseline = LaneRun { verify_red: false, untracked_nix: vec!["old.nix".to_string()] };
        let current = LaneRun {
            verify_red: false,
            untracked_nix: vec!["new.nix".to_string(), "old.nix".to_string()],
        };
        let delta = diff(&baseline, &current);
        assert_eq!(delta.newly_untracked_nix, vec!["new.nix".to_string()]);
        assert!(!delta.verify_newly_red);
        assert!(!delta.verify_newly_green);
    }

    /// Bites-the-thing-it-pins proof: a delta that reports a file already
    /// present in the baseline as "new" would make the Stop lane cry wolf on
    /// every single turn of a session that started dirty — the exact
    /// regression this test exists to catch. Broken deliberately below,
    /// confirmed to fail, then restored (see the report for the transcript).
    #[test]
    fn diff_never_reclaims_a_baseline_file_as_newly_untracked() {
        let baseline = LaneRun { verify_red: false, untracked_nix: vec!["carried.nix".to_string()] };
        let current = LaneRun { verify_red: false, untracked_nix: vec!["carried.nix".to_string()] };
        assert!(diff(&baseline, &current).newly_untracked_nix.is_empty());
    }

    // ── Pure: message builders ──────────────────────────────────────────────

    #[test]
    fn session_start_message_is_none_on_a_clean_baseline() {
        assert!(session_start_message(&LaneRun::default()).is_none());
    }

    #[test]
    fn session_start_message_states_the_fact_and_the_scope_constraint_together() {
        let run = LaneRun { verify_red: true, untracked_nix: vec![] };
        let msg = session_start_message(&run).unwrap();
        assert!(msg.contains("already red"), "{msg}");
        assert!(
            msg.contains("inherited, not yours"),
            "the fact without the scope constraint is exactly the yak-shave this wording avoids: {msg}"
        );
    }

    #[test]
    fn session_start_message_names_every_untracked_nix_file() {
        let run = LaneRun {
            verify_red: false,
            untracked_nix: vec!["a.nix".to_string(), "b/c.nix".to_string()],
        };
        let msg = session_start_message(&run).unwrap();
        assert!(msg.contains("a.nix"), "{msg}");
        assert!(msg.contains("b/c.nix"), "{msg}");
    }

    #[test]
    fn stop_message_is_none_on_an_empty_delta() {
        assert!(stop_message(&LaneDelta::default()).is_none());
    }

    #[test]
    fn stop_message_names_the_delta_only_never_the_whole_state() {
        let delta = LaneDelta {
            verify_newly_red: true,
            verify_newly_green: false,
            newly_untracked_nix: vec!["fresh.nix".to_string()],
        };
        let msg = stop_message(&delta).unwrap();
        assert!(msg.contains("turned red"), "{msg}");
        assert!(msg.contains("fresh.nix"), "{msg}");
        assert!(!msg.contains("turned green"), "{msg}");
    }

    // ── Impure: the git-sourced scan ─────────────────────────────────────────

    fn run_git_cmd(root: &Path, args: &[&str]) {
        let status = Command::new("git").arg("-C").arg(root).args(args).status().unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    #[test]
    fn untracked_nix_files_sees_a_nix_file_inside_a_brand_new_nested_directory() {
        let root = aoide_test_support::unique_tmp("checklane-untracked-nix");
        std::fs::create_dir_all(&root).unwrap();
        run_git_cmd(&root, &["init", "-q"]);
        run_git_cmd(&root, &["config", "user.email", "test@example.invalid"]);
        run_git_cmd(&root, &["config", "user.name", "test"]);
        std::fs::write(root.join("README.md"), "committed\n").unwrap();
        run_git_cmd(&root, &["add", "README.md"]);
        run_git_cmd(&root, &["commit", "-q", "-m", "init"]);

        // A WHOLLY NEW nested directory — the exact shape `git status
        // --porcelain` (no `--untracked-files=all`) would collapse to one
        // line and hide the `.nix` file inside, per this module's doc.
        std::fs::create_dir_all(root.join("modules/dendrites/newthing")).unwrap();
        std::fs::write(root.join("modules/dendrites/newthing/rice.nix"), "{ }\n").unwrap();
        std::fs::write(root.join("modules/dendrites/newthing/notes.md"), "x").unwrap();

        let files = untracked_nix_files(&root);
        assert_eq!(files, vec!["modules/dendrites/newthing/rice.nix".to_string()], "{files:?}");

        let _ = std::fs::remove_dir_all(&root);
    }

    // ── Impure: run_lane / run_verify ────────────────────────────────────────

    #[test]
    fn run_lane_with_an_empty_command_never_runs_anything_but_still_scans_the_tree() {
        let root = aoide_test_support::unique_tmp("checklane-empty-cmd");
        std::fs::create_dir_all(&root).unwrap();
        let run = run_lane(&root, "");
        assert!(!run.verify_red, "an empty command must never read as red");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn run_lane_reflects_the_configured_commands_own_exit_code() {
        let root = aoide_test_support::unique_tmp("checklane-verify");
        std::fs::create_dir_all(&root).unwrap();
        assert!(!run_lane(&root, "true").verify_red);
        assert!(run_lane(&root, "false").verify_red);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn run_lane_completes_promptly_on_a_verify_command_with_a_large_stdout_write() {
        // Review finding: `.status()` with no `Stdio` call inherits the
        // CALLING process's own stdout/stderr — for a real hook that pipe is
        // read by the harness, but nothing guarantees it is read PROMPTLY or
        // AT ALL for a plain `cargo test` run, and a write past the OS pipe
        // buffer (~64KB) with nobody draining it blocks forever. `run_verify`
        // now redirects both streams to `Stdio::null()`, which never blocks
        // regardless of volume — this proves a command that writes several
        // times past that buffer still returns, deterministically, on a
        // bounded timeout, and reads back as the "clean" exit it actually is.
        let root = aoide_test_support::unique_tmp("checklane-large-stdout");
        std::fs::create_dir_all(&root).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let cwd = root.clone();
        std::thread::spawn(move || {
            let run = run_lane(&cwd, "yes | head -c 2000000");
            let _ = tx.send(run);
        });
        let run = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("run_lane hung — the verify command's own stdout was not redirected");
        assert!(!run.verify_red, "a pipeline exiting 0 must read as green regardless of its own output volume");
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── The two entry points, end to end ────────────────────────────────────

    #[test]
    fn on_session_start_then_on_stop_report_only_what_changed_between_them() {
        let _g = crate::env_lock().lock().unwrap();
        let _env = aoide_test_support::EnvSaver::capture(&["AOIDE_ROOT", "AOIDE_CONFIG"]);
        let state_root = aoide_test_support::unique_tmp("checklane-e2e-state");
        std::env::set_var("AOIDE_ROOT", &state_root);
        std::env::remove_var("AOIDE_CONFIG");
        aoide_storage::config::set("upkeep.verifyCommand", "false").unwrap();

        let tree = aoide_test_support::unique_tmp("checklane-e2e-tree");
        std::fs::create_dir_all(&tree).unwrap();
        run_git_cmd(&tree, &["init", "-q"]);
        run_git_cmd(&tree, &["config", "user.email", "test@example.invalid"]);
        run_git_cmd(&tree, &["config", "user.name", "test"]);
        std::fs::write(tree.join("README.md"), "committed\n").unwrap();
        run_git_cmd(&tree, &["add", "README.md"]);
        run_git_cmd(&tree, &["commit", "-q", "-m", "init"]);

        let session_id = "checklane-e2e-session";
        // SessionStart: the command is `false`, so the baseline is red —
        // flagged, inherited, with the scope constraint attached.
        let start = on_session_start(session_id, &tree).unwrap();
        assert!(start.contains("already red"), "{start}");
        assert!(start.contains("inherited"), "{start}");

        // Stop, nothing changed: same red command, same tree — silent.
        assert!(on_stop(session_id, &tree).is_none());

        // The agent drops a fresh, ungrossly-formatted .nix file — Stop
        // reports exactly that, and does NOT re-report the already-known red.
        std::fs::write(tree.join("new-module.nix"), "{ }\n").unwrap();
        let stop = on_stop(session_id, &tree).unwrap();
        assert!(stop.contains("new-module.nix"), "{stop}");
        assert!(!stop.contains("turned red"), "the red was already the baseline, not new: {stop}");

        let _ = std::fs::remove_dir_all(&state_root);
        let _ = std::fs::remove_dir_all(&tree);
    }

    #[test]
    fn on_session_start_and_on_stop_are_both_none_when_the_lane_is_disabled() {
        let _g = crate::env_lock().lock().unwrap();
        let _env = aoide_test_support::EnvSaver::capture(&["AOIDE_ROOT", "AOIDE_CONFIG"]);
        let state_root = aoide_test_support::unique_tmp("checklane-disabled-state");
        std::env::set_var("AOIDE_ROOT", &state_root);
        std::env::remove_var("AOIDE_CONFIG");
        // No `config set` at all — the default is the empty string, lane off.

        let tree = aoide_test_support::unique_tmp("checklane-disabled-tree");
        std::fs::create_dir_all(&tree).unwrap();

        assert!(on_session_start("disabled-session", &tree).is_none());
        assert!(on_stop("disabled-session", &tree).is_none());

        let _ = std::fs::remove_dir_all(&state_root);
        let _ = std::fs::remove_dir_all(&tree);
    }
}
