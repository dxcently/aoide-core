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
//! **Three triggers, one relay: Stop records, the next context-reaching
//! event speaks.** Claude Code's hook contract folds a hook's stdout into
//! the model's own context on exactly `SessionStart` and `UserPromptSubmit`
//! — every other event, `Stop` included, lands in a debug log nobody reads
//! (`docs/Aoide-Wiki/protocol/dev/HARNESS-CLAUDE-CODE.md`'s "Traps" section
//! is the authority for this). So [`on_stop`] never returns anything to the
//! harness: it re-runs the lane, diffs it against the recorded baseline
//! ([`diff`]) so attribution — did THIS turn make something newly red — is a
//! fact rather than a guess, rolls the fresh run forward as the new
//! baseline, and persists the rendered delta as a PENDING note instead.
//! [`on_prompt_submit`] is the drain: read the pending note and delete it,
//! exactly once, no config load, no subprocess — the normal case, since a
//! prompt follows every Stop. [`on_session_start`] drains it too, for the
//! session-was-closed-and-resumed case, before running its own settled-start
//! logic (below). Delivery is one event later than the fact was measured, so
//! every note's wording is turn-relative AT DELIVERY ("turned red **last
//! turn**"), not "during this turn".
//!
//! **A baseline means the tree at the last SETTLED boundary — a moment no
//! turn was in flight.** [`on_stop`] always rolls it forward (the next delta
//! is against this turn's end). [`on_session_start`] takes a `mid_turn` flag
//! — `graph/send.rs`'s Start arm derives it from the stored phase in
//! `hooks.json` (`working` ⇔ mid-turn), read BEFORE that arm's own mutating
//! calls change it, never from the payload's own `source` field (a manual
//! between-turns `/compact` also says `source: "compact"` but IS a settled
//! boundary; phase-based detection gets both cases right). Settled
//! (`startup`, resume-from-stopped, a between-turns manual compact): drain
//! the pending note, run the lane, overwrite the baseline, report the
//! inherited state — exactly what this function always did, plus the drain.
//! Mid-turn (an auto-compact firing between a prompt and its `Stop`, or a
//! resume that lands back in `working`): no lane run, no baseline write —
//! just replay [`session_start_message`] off the STORED baseline, the
//! inherited-state warning the compaction just erased from context. Without
//! this split, a regression introduced earlier in the SAME turn would
//! re-baseline as "inherited" the instant a compaction landed before the
//! next `Stop` — the exact misattribution this pairing closes.
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
/// `deny_unknown_fields`: a persisted shape that drives attribution must
/// fail loudly on a stranger key, never silently drop it and default the
/// field beside it (review finding Q7 — see [`SessionLane`]'s own doc for
/// why this specific struct is where the guard actually has to live).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// Pure: the note [`on_stop`] persists as this session's PENDING note off a
/// [`LaneDelta`]. `None` when nothing changed since the recorded baseline —
/// attribution is a fact, and "nothing changed" is a fact worth staying
/// silent about, not narrating. Worded turn-relative AT DELIVERY ("last
/// turn") rather than "during this turn": this note is rendered at `Stop`
/// but read one event later, by [`on_prompt_submit`] or a settled
/// [`on_session_start`] — by the time anyone sees it, the turn it describes
/// has already ended.
pub fn stop_message(delta: &LaneDelta) -> Option<String> {
    if delta.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    if delta.verify_newly_red {
        parts.push("the verify command turned red last turn".to_string());
    }
    if delta.verify_newly_green {
        parts.push("the verify command turned green last turn".to_string());
    }
    if !delta.newly_untracked_nix.is_empty() {
        parts.push(format!(
            "new untracked .nix file(s) last turn: {}",
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

/// What this session's checklane state holds between hook calls: the
/// baseline [`on_stop`]/settled [`on_session_start`] roll forward, and a
/// PENDING note — the relay `on_stop` has no other way to speak (its stdout
/// never reaches the model), waiting for the next context-reaching event to
/// drain it. Same path, one file, atomic write — nothing has shipped against
/// the old bare-`LaneRun` shape, so this is free to change without a
/// migration.
///
/// `deny_unknown_fields` belongs HERE, on the struct [`load_lane`] actually
/// parses — not only on the nested [`LaneRun`] (review finding Q7). Task
/// #139 phase 1 persisted a BARE `LaneRun` (`{"verify_red":…,"untracked_nix":…}`,
/// no wrapper); those keys are unknown to `SessionLane` at the TOP level, so
/// the guard on this struct is what actually rejects that file — a guard on
/// `LaneRun` alone would never fire, because `baseline`'s own `#[serde(
/// default)]` means the deserializer never even attempts to build a
/// `LaneRun` from that JSON at all; it just defaults the field, same as a
/// missing key. Deliberately no migration: nothing has shipped, so an old
/// file is not a shape to preserve — refusing it and falling back to "no
/// baseline recorded" (safe: the next settled `SessionStart` computes a
/// fresh one) is correct, where silently parsing it as a clean baseline
/// would launder an inherited red exactly the way this whole phase exists
/// to stop.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionLane {
    #[serde(default)]
    pub baseline: LaneRun,
    #[serde(default)]
    pub pending: Option<String>,
}

/// Where this session's [`SessionLane`] is persisted — one small file per
/// session, under the state dir the rest of this crate already writes
/// beneath (`aoide_storage::fs::state_dir()`), NOT the conduct session store:
/// this lane's own state, not a conducted session's.
fn lane_path(session_id: &str) -> PathBuf {
    aoide_storage::fs::state_dir().join("checklane").join(format!("{session_id}.json"))
}

fn load_lane(session_id: &str) -> Option<SessionLane> {
    let text = std::fs::read_to_string(lane_path(session_id)).ok()?;
    serde_json::from_str(&text).ok()
}

/// Best-effort: a failed write never fails the hook (same stance as every
/// other write in this crate's `commands`/`scan` — soundcheck never repairs,
/// and this lane never blocks a session over its own bookkeeping).
fn store_lane(session_id: &str, lane: &SessionLane) {
    let path = lane_path(session_id);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(text) = serde_json::to_string(lane) {
        let _ = aoide_storage::fs::atomic_write(&path, &text);
    }
}

/// Delete this session's checklane state, if any (review finding: nothing
/// ever deleted these — one file accreted forever per session, an effect
/// with no inverse). Called from the two places that already know a session
/// is truly over — `aoide-conduct`'s `do_session_end` and `reap`'s own prune
/// pass — never a new sweep of its own; a missing file is not an error
/// (`remove_file`'s `NotFound` is swallowed the same way every other
/// best-effort cleanup in this crate is).
pub fn forget_baseline(session_id: &str) {
    let _ = std::fs::remove_file(lane_path(session_id));
}

// ── The three hook entry points ─────────────────────────────────────────────

/// `SessionStart`: settled, run the lane, drain any pending note, prepend it
/// to the fresh inherited-state message and overwrite the baseline. Mid-turn
/// (`mid_turn: true` — the stored `hooks.json` phase read `working` before
/// this arm's own mutating calls, `graph/send.rs`'s Start arm), do none of
/// that: no lane run, no overwrite, just replay [`session_start_message`]
/// off the STORED baseline — the inherited-state warning a mid-turn
/// compaction just erased from context, recomputed from what was actually
/// recorded so a red the agent caused mid-turn is never relabeled
/// "inherited" (see the module doc's baseline/settled-boundary rule).
/// `None` when the lane is disabled (settled path) or nothing was ever
/// recorded for this session (mid-turn path, e.g. the lane turned on
/// mid-session).
pub fn on_session_start(session_id: &str, root: &Path, mid_turn: bool) -> Option<String> {
    if mid_turn {
        // No config load, no subprocess — cheaper than the settled path by
        // construction, per the module doc's budget note.
        return load_lane(session_id).and_then(|lane| session_start_message(&lane.baseline));
    }
    let command = configured_command()?;
    let drained = load_lane(session_id).and_then(|lane| lane.pending);
    let run = run_lane(root, &command);
    let fresh = session_start_message(&run);
    store_lane(session_id, &SessionLane { baseline: run, pending: None });
    prepend(drained, fresh)
}

/// `Stop`: re-run the lane, diff it against the recorded baseline, and
/// persist the rendered delta as this session's PENDING note — never
/// returned, since `Stop`'s own stdout never reaches the model (module
/// doc). A missing baseline (the lane turned on mid-session) means there is
/// nothing to diff against, so no note is rendered, matching
/// [`on_session_start`]'s own "nothing to flag yet" stance. This run becomes
/// the new baseline either way, so the NEXT `Stop`'s delta is against THIS
/// turn, not the session's original start.
pub fn on_stop(session_id: &str, root: &Path) {
    let Some(command) = configured_command() else { return };
    let current = run_lane(root, &command);
    let pending = load_lane(session_id)
        .and_then(|lane| stop_message(&diff(&lane.baseline, &current)));
    store_lane(session_id, &SessionLane { baseline: current, pending });
}

/// `UserPromptSubmit`: drain this session's pending note — read and delete,
/// exactly once. No config load, no subprocess: `on_stop` already ran the
/// lane and rendered the note, this only relays it onto the one event
/// Claude Code is documented to fold into the model's context alongside
/// `SessionStart` (module doc). A second call with nothing newly pending
/// reads `None`, same as a session with the lane disabled.
pub fn on_prompt_submit(session_id: &str) -> Option<String> {
    let mut lane = load_lane(session_id)?;
    let pending = lane.pending.take()?;
    store_lane(session_id, &lane);
    Some(pending)
}

/// Join a drained pending note (last turn's fact) ahead of this call's own
/// message (this moment's fact) — `None` only when both are.
fn prepend(pending: Option<String>, own: Option<String>) -> Option<String> {
    match (pending, own) {
        (Some(p), Some(o)) => Some(format!("{p}\n{o}")),
        (Some(p), None) => Some(p),
        (None, Some(o)) => Some(o),
        (None, None) => None,
    }
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

    // ── The three entry points, end to end ──────────────────────────────────

    /// Sets up an isolated config root + a real git tree the lane can scan,
    /// shared by the two end-to-end tests below. Returns `(state_root, tree)`
    /// — both temp dirs the caller must remove.
    fn e2e_fixture(state_prefix: &str, tree_prefix: &str, verify_command: &str) -> (PathBuf, PathBuf) {
        let state_root = aoide_test_support::unique_tmp(state_prefix);
        std::env::set_var("AOIDE_ROOT", &state_root);
        std::env::remove_var("AOIDE_CONFIG");
        aoide_storage::config::set("upkeep.verifyCommand", verify_command).unwrap();

        let tree = aoide_test_support::unique_tmp(tree_prefix);
        std::fs::create_dir_all(&tree).unwrap();
        run_git_cmd(&tree, &["init", "-q"]);
        run_git_cmd(&tree, &["config", "user.email", "test@example.invalid"]);
        run_git_cmd(&tree, &["config", "user.name", "test"]);
        std::fs::write(tree.join("README.md"), "committed\n").unwrap();
        run_git_cmd(&tree, &["add", "README.md"]);
        run_git_cmd(&tree, &["commit", "-q", "-m", "init"]);
        (state_root, tree)
    }

    /// The delivery sequence itself (module doc + decision record §6):
    /// start → prompt (silent) → a new `.nix` appears → stop (silent to the
    /// harness, `on_stop` returns nothing) → prompt (note delivered, naming
    /// the file) → prompt (silent, drained exactly once).
    #[test]
    fn the_delivery_sequence_speaks_once_at_the_next_prompt_and_never_again() {
        let _g = crate::env_lock().lock().unwrap();
        let _env = aoide_test_support::EnvSaver::capture(&["AOIDE_ROOT", "AOIDE_CONFIG"]);
        let (state_root, tree) = e2e_fixture("checklane-delivery-state", "checklane-delivery-tree", "true");
        let session_id = "checklane-delivery-session";

        // Settled start: the command is `true`, so the baseline is green —
        // nothing to flag.
        assert!(on_session_start(session_id, &tree, false).is_none());

        // A prompt with nothing pending yet: silent.
        assert!(on_prompt_submit(session_id).is_none());

        // The agent drops a fresh, untracked `.nix` file mid-turn.
        std::fs::write(tree.join("new-module.nix"), "{ }\n").unwrap();

        // Stop: computes the delta, persists it as pending, returns nothing —
        // there is nothing for the harness to even discard here.
        on_stop(session_id, &tree);

        // The next prompt drains it, naming the file, worded turn-relative.
        let delivered = on_prompt_submit(session_id).unwrap();
        assert!(delivered.contains("new-module.nix"), "{delivered}");
        assert!(delivered.contains("last turn"), "{delivered}");

        // A further prompt with nothing new pending: silent — drained exactly
        // once, not re-delivered.
        assert!(on_prompt_submit(session_id).is_none());

        let _ = std::fs::remove_dir_all(&state_root);
        let _ = std::fs::remove_dir_all(&tree);
    }

    /// The compaction regression, end to end (decision record F5/§6): a
    /// settled start on a green baseline, the tree turns red mid-turn, an
    /// auto-compact fires a mid-turn `SessionStart` — which must NOT
    /// re-baseline the red as "inherited" — then `Stop` computes the delta
    /// against the STILL-green recorded baseline, so the pending note
    /// attributes the red to last turn, correctly, not to "always been this
    /// way". The baseline file itself must be byte-identical across the
    /// mid-turn call — proof that it truly took no write path at all.
    #[test]
    fn a_mid_turn_session_start_never_launders_this_turns_own_regression() {
        let _g = crate::env_lock().lock().unwrap();
        let _env = aoide_test_support::EnvSaver::capture(&["AOIDE_ROOT", "AOIDE_CONFIG"]);
        let (state_root, tree) =
            e2e_fixture("checklane-compaction-state", "checklane-compaction-tree", "true");
        let session_id = "checklane-compaction-session";

        // Settled start: green baseline, nothing to flag.
        assert!(on_session_start(session_id, &tree, false).is_none());
        let baseline_bytes_before = std::fs::read(lane_path(session_id)).unwrap();

        // Mid-turn: the agent's own edit turns the verify command red.
        aoide_storage::config::set("upkeep.verifyCommand", "false").unwrap();

        // An auto-compact fires SessionStart mid-turn. Must run no lane, write
        // nothing, and replay the (still-green) recorded baseline's own
        // message — which is `None`, since that baseline was clean.
        assert!(on_session_start(session_id, &tree, true).is_none());
        let baseline_bytes_after = std::fs::read(lane_path(session_id)).unwrap();
        assert_eq!(
            baseline_bytes_before, baseline_bytes_after,
            "a mid-turn SessionStart must not write the baseline file at all"
        );

        // Stop: diffs the NOW-red run against the still-green recorded
        // baseline — the newly-red fact is attributed to THIS turn, not
        // laundered into "inherited" by the compaction that just happened.
        on_stop(session_id, &tree);
        let pending = on_prompt_submit(session_id).unwrap();
        assert!(pending.contains("turned red"), "{pending}");
        assert!(pending.contains("last turn"), "{pending}");

        let _ = std::fs::remove_dir_all(&state_root);
        let _ = std::fs::remove_dir_all(&tree);
    }

    #[test]
    fn on_session_start_and_on_prompt_submit_are_both_none_when_the_lane_is_disabled() {
        let _g = crate::env_lock().lock().unwrap();
        let _env = aoide_test_support::EnvSaver::capture(&["AOIDE_ROOT", "AOIDE_CONFIG"]);
        let state_root = aoide_test_support::unique_tmp("checklane-disabled-state");
        std::env::set_var("AOIDE_ROOT", &state_root);
        std::env::remove_var("AOIDE_CONFIG");
        // No `config set` at all — the default is the empty string, lane off.

        let tree = aoide_test_support::unique_tmp("checklane-disabled-tree");
        std::fs::create_dir_all(&tree).unwrap();

        assert!(on_session_start("disabled-session", &tree, false).is_none());
        on_stop("disabled-session", &tree);
        assert!(on_prompt_submit("disabled-session").is_none());
        // Mid-turn with nothing ever recorded reads `None` too.
        assert!(on_session_start("disabled-session", &tree, true).is_none());

        let _ = std::fs::remove_dir_all(&state_root);
        let _ = std::fs::remove_dir_all(&tree);
    }

    /// Review finding Q7: the persisted shape changed (bare `LaneRun` →
    /// `SessionLane { baseline, pending }`) with neither struct denying
    /// unknown fields. A phase-1-shaped file's keys (`verify_red`,
    /// `untracked_nix`) don't match `SessionLane`'s own (`baseline`,
    /// `pending`), so without the guard they're silently dropped and both
    /// `#[serde(default)]` fields fall back — a previously-RED, `.nix`-
    /// carrying baseline reads back as a clean one, no error, no signal.
    /// That is the laundering bug in a different hat: the next `Stop` would
    /// diff the real (still-red) tree against this false-clean baseline and
    /// report the inherited red as "turned red during this turn". A wrong
    /// baseline is unsafe; no baseline is safe (the next settled
    /// `SessionStart` computes a fresh one, and a baseline-less `Stop` says
    /// nothing) — so `load_lane` must refuse this file outright, not parse
    /// it into a plausible-looking default.
    #[test]
    fn load_lane_refuses_a_phase_1_shaped_file_rather_than_reading_it_as_a_clean_baseline() {
        let _g = crate::env_lock().lock().unwrap();
        let _env = aoide_test_support::EnvSaver::capture(&["AOIDE_ROOT"]);
        let state_root = aoide_test_support::unique_tmp("checklane-old-shape-state");
        std::env::set_var("AOIDE_ROOT", &state_root);

        let session_id = "checklane-old-shape-session";
        let path = lane_path(session_id);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // Byte-for-byte the bare `LaneRun` shape task #139 phase 1 actually
        // persisted — no `baseline`/`pending` wrapper, a red + `.nix`-carrying
        // run.
        std::fs::write(&path, r#"{"verify_red":true,"untracked_nix":["carried.nix"]}"#).unwrap();

        assert!(
            load_lane(session_id).is_none(),
            "a phase-1-shaped file must fail to parse — reading it as a default-valued \
             SessionLane silently launders an inherited red into a clean baseline"
        );

        let _ = std::fs::remove_dir_all(&state_root);
    }
}
