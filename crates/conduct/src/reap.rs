//! Liveness reaping: mark KILLED sessions done so they cannot haunt forever.
//!
//! A terminal killed with SUPER+Q / SIGKILL cannot run its own cleanup — the
//! `conduct`/`wrap` process is torn down uncatchably, so `do_session_end` never
//! fires and the record is stranded `running` forever (22 dead `conduct-*` piled
//! up in ~8 minutes of use). The reaper detects such orphans out-of-band and
//! resolves them, so conduct-by-default is viable. A FALSE reap of a LIVE session
//! is worse than a stale record, so the predicate never guesses.
//!
//! A third case sits outside both signals: a hook-only Claude Code (UUID)
//! session that never picked up a `windowAddress`/`pid` mapping. Such a session
//! carries neither the window nor the pid signal, so it used to be left `idle`
//! forever (absence of evidence is never evidence of death — see
//! [`is_session_dead`]). But an at-rest (`idle`/`stopped`) hook-only session
//! whose last evidence of life is many hours stale is no longer "absence of
//! evidence" — the staleness itself IS positive evidence of abandonment. The
//! third signal reaps exactly that case, conservatively (see
//! [`REAP_IDLE_STALE_SECS`]).
//!
//! Extracted from `graph.rs` (which had grown past 5800 lines) — a self-contained
//! cluster with no external callers but the CLI dispatch. It leans on a handful of
//! `pub(crate)` stage helpers still owned by `graph.rs`.

use aoide_protocol::Invocation;
use aoide_protocol::agents::{agent_profile, AgentProfile, CLAUDE_PROFILE};
use crate::graph::{
    canonical_state, hooks_path, hyprctl_clients, load_stage, normalize_addr, now_iso_utc,
    prune_done, restage_graph, sessions_path, stage_error, upsert_hook,
    write_stage, HookRecord, HooksFile, SessionRecord, SessionsFile, STAGE_GRAPH_VERSION,
};
use aoide_protocol::output::Outcome;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

/// Does `/proc/<pid>` still exist? The real liveness probe for [`is_session_dead`]
/// (injected as a closure in tests so the predicate stays pure).
fn proc_exists(pid: u32) -> bool {
    std::path::Path::new("/proc").join(pid.to_string()).exists()
}

/// How long a hook-only session (no `windowAddress`, no `pid`) may sit at rest
/// (`idle`/`stopped`) before its own silence becomes the third liveness signal
/// — see [`is_session_dead`]. 72h (~3 days) is conservative on purpose:
/// comfortably longer than any ordinary idle gap (an overnight, a weekend) a
/// LIVE hook-only session might sit through, so a session that is merely quiet
/// is never touched. Only a session stranded well past any plausible "still
/// working on it" window qualifies — the two cleared-by-hand orphans that
/// motivated this had been `idle` for days, so 72h loses nothing on the
/// cleanup side while giving a wide berth to a quiet-but-live weekend session.
pub const REAP_IDLE_STALE_SECS: i64 = 72 * 3600; // 72 hours (~3 days)

/// Is a session DEAD — orphaned so that NO process will ever clean it up? Pure
/// and unit-tested (feed a fake live-address set, a fake `proc_exists`, and a
/// fake `last_seen`).
///
/// DEAD when ANY of three signals fires:
///   * **window gone** — a non-empty `windowAddress` that is NOT among the live
///     `hyprctl clients -j` addresses (the SUPER+Q kill: the window vanished), OR
///   * **process gone** — a recorded `pid` whose `/proc/<pid>` no longer exists
///     (the process-killed case), OR
///   * **stale hook-only at-rest** — NO window evidence (empty `windowAddress`,
///     so the window signal can't apply either way) AND NO pid (so the pid
///     signal can't apply either) AND the canonical state is `idle` or
///     `stopped` (never `working`/`awaiting`/`needsSudo` — a hook-only session
///     mid-turn is not dead) AND `last_seen` reports evidence of life older
///     than [`REAP_IDLE_STALE_SECS`].
///
/// The never-false-reap guards:
///   * `live_addresses` is an `Option`: `None` means the compositor could not be
///     queried (no Hyprland, hyprctl missing/failed) — the window signal is then
///     UNKNOWN and contributes nothing, so we never reap a windowed session we
///     merely failed to see. Only a `Some(live)` we actually gathered can fire it.
///   * A session with NEITHER the window NOR the pid signal (e.g. a hook-only
///     session that has not yet discovered a window/pid) is left alone UNLESS
///     the third signal's own positive evidence (a stale `last_seen`) fires:
///     absence of evidence is never evidence of death, but STALENESS is
///     evidence, not absence — `last_seen` returning `None` (no transcript, no
///     parseable `startedAt`) is itself absence of evidence and never counts as
///     stale, so the guard holds. A just-started hook-only session has a recent
///     `last_seen` and sits far under the threshold, so it is never touched.
pub fn is_session_dead(
    rec: &SessionRecord,
    live_addresses: Option<&HashSet<String>>,
    proc_exists: impl Fn(u32) -> bool,
    now_epoch: i64,
    last_seen: impl Fn(&SessionRecord) -> Option<i64>,
) -> bool {
    let window_signal = match live_addresses {
        Some(live) => {
            !rec.window_address.is_empty()
                && !live.contains(&normalize_addr(&rec.window_address))
        }
        None => false, // compositor not queried — window liveness is unknown.
    };
    let pid_signal = matches!(rec.pid, Some(p) if !proc_exists(p));
    let stale_idle_signal = rec.window_address.is_empty()
        && rec.pid.is_none()
        && matches!(canonical_state(&rec.state), "idle" | "stopped")
        && last_seen(rec)
            .map(|seen| now_epoch.saturating_sub(seen) > REAP_IDLE_STALE_SECS)
            .unwrap_or(false); // no last-seen evidence at all → not stale, not dead.
    window_signal || pid_signal || stale_idle_signal
}

/// Gather the normalised live window addresses from `hyprctl clients -j`.
/// Returns `None` (→ pid-only liveness) whenever the compositor cannot be
/// consulted authoritatively (see [`crate::graph::hyprctl_clients`]). This is the
/// seam that keeps the reaper safe off-Hyprland — it degrades to the pid signal
/// instead of blindly reaping every windowed session it could not see.
fn live_window_addresses() -> Option<HashSet<String>> {
    Some(
        hyprctl_clients()?
            .iter()
            .filter_map(|c| c.get("address").and_then(Value::as_str))
            .filter(|a| !a.is_empty())
            .map(normalize_addr)
            .collect(),
    )
}

/// The reaper's transient-read grace (pure, unit-tested). Given the set of live
/// window addresses the compositor just reported and the current sessions,
/// decide the window-liveness set this reap pass should actually trust.
///
/// During a reload/restart (a quickshell restart, `hyprctl reload`, a nixos
/// switch) `hyprctl clients -j` can momentarily answer SUCCESS with ZERO windows
/// while the terminals are in fact alive — the compositor is mid-reload. Reaping
/// the whole windowed roster off that snapshot is exactly the transient drop this
/// fix targets, so an EMPTY gathered set against a roster that still holds
/// windowed, not-`done` sessions is treated as degenerate and DOWNGRADED to
/// `None` (pid-only liveness) for the pass — a vanished `/proc/<pid>` is still
/// authoritative, so a genuinely-closed terminal (its owning pid gone too) is
/// still reaped, while a live-but-momentarily-unlisted window is spared. A
/// non-empty set, or an empty set with nothing windowed to protect, passes
/// through unchanged.
///
/// Bounded edge (acceptable): a not-`done`, windowed, PID-LESS session whose
/// terminal genuinely closed while the desktop is at zero windows carries neither
/// a pid signal nor — under this downgrade — a window signal, so it is NOT reaped
/// on that pass. It self-heals the moment ANY window exists (the snapshot is no
/// longer empty, the stale address is then absent from a real set, and the window
/// signal fires as normal). A lone stale record briefly lingering is the right
/// trade for never mass-sweeping a live roster off a mid-reload read.
pub(crate) fn effective_live_addresses(
    gathered: Option<HashSet<String>>,
    sessions: &[SessionRecord],
) -> Option<HashSet<String>> {
    match &gathered {
        Some(set)
            if set.is_empty()
                && sessions
                    .iter()
                    .any(|s| s.state != "done" && !s.window_address.is_empty()) =>
        {
            None
        }
        _ => gathered,
    }
}

// ── Same-window agent dedup: retire a superseded / phantom re-registration ──
//
// One kitty window hosts one conducted shell + one foreground claude, and that
// claude's `pid` field (from the window listener) is the TERMINAL's pid — shared
// by the shell and every claude that ever ran in it. So when a session-id changes
// (compact/resume) and the old record is never `SessionEnd`ed, it orphans as
// `working` with a still-alive pid, and the liveness sweep above can never reap
// it. Two "claude" rows for one terminal result — and the stale one masks `say`
// in the Terminals merge. A terminal hosts ONE foreground agent, so this collapses
// same-window agent duplicates down to the real one.

/// Is this a top-level AGENT session (a claude), vs a shell or a synthetic
/// sub-agent node? A conducted PTY host (`conductable` — the control-socket
/// owner) is a HOST, never an agent-duplicate candidate, whatever kind it
/// published (`upsert_session` classifies a `conduct -- kimi` wrapper as
/// "agent" from its child's basename, and the wrapper is not a second
/// foreground agent). Otherwise published `kind` wins; absent, fall back to
/// "not a shell and not a conducted PTY". Sub-nodes (`sub:*`) carry no
/// `windowAddress`, so they never enter a window group regardless.
///
/// `pub`, not `pub(crate)` (pre-Phase-3b visibility): root's
/// `graph::session_store::do_session_start_inner` (same-window agent
/// eviction) called this at `crate::reap::is_agent_kind` before the move —
/// that call site travelled INTO this crate too, so it's now purely
/// same-crate; kept `pub` (rather than narrowed) because root's own
/// `reap.rs` shim also re-exports it onward at the old path.
pub fn is_agent_kind(rec: &SessionRecord) -> bool {
    if rec.conductable == Some(true) {
        return false; // a conducted PTY host — never an agent duplicate
    }
    match rec.kind.as_deref() {
        Some("agent") => true,
        Some(_) => false, // "shell" | "subagent" | any other explicit kind
        None => rec.agent != "shell",
    }
}

/// The profile a record's transcript probes dispatch through: its own agent's
/// when the bridge has one registered, else the claude layout — exactly what
/// every record used before the seam (a profile-less harness simply has no
/// transcript for the locator to find).
fn profile_for(rec: &SessionRecord) -> &'static AgentProfile {
    agent_profile(&rec.agent).unwrap_or(&CLAUDE_PROFILE)
}

/// Among not-`done` agent records sharing one non-empty `windowAddress`, at most
/// one is real; return the ids to RETIRE (the superseded duplicates). Pure and
/// unit-testable: `is_recent` and `has_transcript` are injected as closures.
///
/// Keeper rank (descending): a real on-disk transcript (`has_transcript` — the
/// ground-truth "this is a live claude" signal) → carries `say` → classified
/// `kind=="agent"` → newest `startedAt` → lexically-greatest `sessionId` (stable
/// final tiebreak). A group of one is never touched; a group with ANY member
/// still inside the grace (`is_recent`) is left entirely alone — a just-born pair
/// is let settle until the real one writes its transcript, so we never drop the
/// wrong twin at t≈0.
fn superseded_agent_duplicates(
    sessions: &[SessionRecord],
    is_recent: impl Fn(&SessionRecord) -> bool,
    has_transcript: impl Fn(&SessionRecord) -> bool,
) -> Vec<String> {
    let mut by_window: HashMap<&str, Vec<&SessionRecord>> = HashMap::new();
    for s in sessions {
        if s.state == "done" || s.window_address.is_empty() || !is_agent_kind(s) {
            continue;
        }
        by_window
            .entry(s.window_address.as_str())
            .or_default()
            .push(s);
    }
    let mut losers = Vec::new();
    for group in by_window.values() {
        if group.len() < 2 || group.iter().any(|s| is_recent(s)) {
            continue;
        }
        let rank = |s: &SessionRecord| {
            (
                has_transcript(s),
                s.say.is_some(),
                s.kind.as_deref() == Some("agent"),
                s.started_at.clone(),
                s.session_id.clone(),
            )
        };
        let keeper = group.iter().max_by(|a, b| rank(a).cmp(&rank(b))).unwrap();
        for s in group {
            if s.session_id != keeper.session_id {
                losers.push(s.session_id.clone());
            }
        }
    }
    losers
}

// ── `stopped` → `idle` decay: the warm/cold split of "at rest" ──────────────
//
// `Stop` (the turn ended, the agent is at its prompt) lands `stopped`, NOT
// `idle`: a session you just finished talking to is a different thing from one
// that has been sitting untouched all afternoon. Nothing in the hook stream ever
// fires again for a session that is simply left alone, so the transition out of
// `stopped` cannot be event-driven — it is an AGE. The reaper already ticks every
// ~12s under the stage lock with both stage files loaded, so it is where the
// clock is read; the threshold decision itself stays pure below.

/// How long a `stopped` session stays warm before it settles to plain `idle`.
/// `pub` (not `pub(crate)`, pre-Phase-3b visibility): root's `graph.rs` shim
/// re-exports this onward at the old `crate::reap::STOPPED_IDLE_AFTER_SECS`
/// path, so it now crosses the aoide-conduct → aoide crate boundary.
pub const STOPPED_IDLE_AFTER_SECS: i64 = 3600; // 1 hour

/// Has a `stopped` session been at rest long enough to be plain `idle`? PURE —
/// both instants are parameters (no clock read in here), so the 1h boundary is
/// deterministically testable from either side.
///
/// `stopped_at` is `None` when the session carries no parseable stop instant (no
/// hook record, or an unreadable `updatedAt`). There is then no evidence it
/// stopped RECENTLY, and `stopped` is the claim that needs the evidence — so it
/// decays. `idle` is the safe resting state; a warm badge invented from a missing
/// timestamp would never expire.
pub(crate) fn stopped_has_decayed(now_epoch: i64, stopped_at: Option<i64>) -> bool {
    match stopped_at {
        Some(t) => now_epoch.saturating_sub(t) >= STOPPED_IDLE_AFTER_SECS,
        None => true,
    }
}

/// Age every `stopped` session past the threshold down to `idle`, in BOTH stage
/// files, and return the ids that moved. Pure over the loaded records (the caller
/// owns the I/O and passes `now`).
///
/// The stop INSTANT is the session's rolling hook record's `updatedAt` — the one
/// `upsert_hook` rewrites on every phase change, so for a session sitting in
/// `stopped` it is exactly when `Stop` fired. No new `SessionRecord` field is
/// needed, and nothing has to migrate.
///
/// hooks.json is rewritten alongside sessions.json because `merged_sessions`
/// OVERLAYS the latest hook phase onto the roster state: decaying only
/// sessions.json would be undone by the very next merge.
pub(crate) fn decay_stopped_sessions(
    sessions: &mut [SessionRecord],
    hooks: &mut Vec<HookRecord>,
    now_epoch: i64,
    now: &str,
) -> Vec<String> {
    let stop_instant: HashMap<&str, Option<i64>> = hooks
        .iter()
        .map(|h| {
            (
                h.session_id.as_str(),
                aoide_storage::time::parse_iso_utc(&h.updated_at),
            )
        })
        .collect();
    let mut decayed: Vec<String> = Vec::new();
    for s in sessions.iter_mut() {
        if canonical_state(&s.state) != "stopped" {
            continue;
        }
        let at = stop_instant.get(s.session_id.as_str()).copied().flatten();
        if stopped_has_decayed(now_epoch, at) {
            s.state = "idle".to_string();
            decayed.push(s.session_id.clone());
        }
    }
    for id in &decayed {
        upsert_hook(hooks, id, "idle", now);
    }
    decayed
}

/// `graph reap` — the automatic liveness sweep. Marks every DEAD (killed,
/// orphaned) session `done` (and its hook record), then reuses [`prune_done`] to
/// drop them + clear orphaned parent links, re-staging `graph.json` atomically.
/// Cheap: one `hyprctl` call + a stage read, and a stage WRITE only when
/// something was actually reaped. NEVER errors non-zero on "nothing to reap" and
/// NEVER on an unavailable compositor (it falls back to pid-only liveness).
pub fn reap(inv: &Invocation) -> Outcome {
    aoide_storage::fs::with_stage_lock(|| reap_inner(inv))
}
fn reap_inner(_inv: &Invocation) -> Outcome {
    let cmd = "graph.reap";
    let mut s_file: SessionsFile = match load_stage(&sessions_path()) {
        Ok(f) => f,
        Err(e) => return stage_error(cmd, e),
    };
    let mut h_file: HooksFile = match load_stage(&hooks_path()) {
        Ok(f) => f,
        Err(e) => return stage_error(cmd, e),
    };

    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let gathered = live_window_addresses();
    let hyprctl_available = gathered.is_some();
    // Apply the transient-read grace: a degenerate empty snapshot during a reload
    // window falls back to pid-only liveness so we never sweep the live roster off
    // a momentary "zero windows" answer.
    let live = effective_live_addresses(gathered, &s_file.sessions);
    // This session's hook record's `updatedAt` — the exact timestamp
    // `decay_stopped_sessions` below reads for the `stopped` clock, mirrored
    // here as evidence for the third signal too: a foreign-harness/headless
    // session (no window, no pid, no transcript — the `graph session start`
    // recipe) that fires hooks on its own cadence is proven alive by THIS
    // timestamp even when its `startedAt` is old and no transcript exists.
    let hook_seen: HashMap<&str, Option<i64>> = h_file
        .hooks
        .iter()
        .map(|h| {
            (
                h.session_id.as_str(),
                aoide_storage::time::parse_iso_utc(&h.updated_at),
            )
        })
        .collect();
    // The third signal's evidence-of-life probe: the MAX of every timestamp we
    // have reason to trust — the on-disk transcript's mtime (if a transcript
    // exists), this session's hook `updatedAt` (see above), and the record's
    // own `startedAt` (the floor — at least this recently the session came
    // into being). `None` only when NONE of the three resolve — genuine
    // absence of evidence, which `is_session_dead` treats as "not stale, not
    // dead", never as staleness itself.
    let last_seen = |s: &SessionRecord| -> Option<i64> {
        let transcript_mtime = (profile_for(s).transcript.locate)(&s.session_id, Some(s.cwd.as_str()), None)
            .and_then(|p| std::fs::metadata(p).ok())
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64);
        let hook_updated_at = hook_seen.get(s.session_id.as_str()).copied().flatten();
        let started = aoide_storage::time::parse_iso_utc(&s.started_at);
        [transcript_mtime, hook_updated_at, started]
            .into_iter()
            .flatten()
            .max()
    };
    // Only STILL-live records can be dead-by-liveness; an already-`done` session
    // is prune's job, not a reap. This is the set the liveness predicate killed.
    let mut reaped: Vec<String> = s_file
        .sessions
        .iter()
        .filter(|s| s.state != "done")
        .filter(|s| is_session_dead(s, live.as_ref(), proc_exists, now_epoch, last_seen))
        .map(|s| s.session_id.clone())
        .collect();

    // Also retire superseded same-window agent duplicates (a phantom re-id whose
    // pid is the terminal's, invisible to the liveness predicate above). Grace:
    // ~60s off startedAt so a just-born pair settles; keeper = the one with a real
    // transcript on disk (see `superseded_agent_duplicates`).
    const DEDUP_GRACE_SECS: i64 = 60;
    let is_recent = |s: &SessionRecord| {
        aoide_storage::time::parse_iso_utc(&s.started_at)
            .map(|t| now_epoch - t < DEDUP_GRACE_SECS)
            .unwrap_or(false) // an unparseable/empty startedAt is treated as old
    };
    let has_transcript = |s: &SessionRecord| {
        (profile_for(s).transcript.locate)(&s.session_id, Some(s.cwd.as_str()), None).is_some()
    };
    for id in superseded_agent_duplicates(&s_file.sessions, is_recent, has_transcript) {
        if !reaped.contains(&id) {
            reaped.push(id);
        }
    }

    // Age out the warm `stopped` badge: a turn that ended more than an hour ago is
    // just `idle` now. This is the one transition no hook can ever deliver (a
    // session left alone emits nothing), so the periodic pass owns it — and it runs
    // on EVERY tick, independent of whether anything was reaped.
    let now = now_iso_utc();
    let decayed = decay_stopped_sessions(&mut s_file.sessions, &mut h_file.hooks, now_epoch, &now);

    if reaped.is_empty() && decayed.is_empty() {
        return Outcome::ok(cmd, "nothing to reap (all sessions live)").with_data(json!({
            "reaped": [],
            "decayed": [],
            "hyprctlAvailable": hyprctl_available,
        }));
    }

    // Mark each reaped session done in BOTH files, then let prune_done drop them
    // (and any pre-existing `done`) + clear orphaned parentSessionIds.
    let dead: HashSet<&str> = reaped.iter().map(String::as_str).collect();
    for s in s_file.sessions.iter_mut() {
        if dead.contains(s.session_id.as_str()) {
            s.state = "done".to_string();
        }
    }
    for id in &reaped {
        upsert_hook(&mut h_file.hooks, id, "done", &now);
    }

    // Prune only when something was actually reaped — a decay-only pass must not
    // start sweeping pre-existing `done` records out from under the widgets (that
    // stays `graph prune`'s job, on its own schedule).
    let (removed, cleared) = if reaped.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        let (kept_s, kept_h, removed, cleared) = prune_done(
            std::mem::take(&mut s_file.sessions),
            std::mem::take(&mut h_file.hooks),
        );
        s_file.sessions = kept_s;
        h_file.hooks = kept_h;
        (removed, cleared)
    };
    if s_file.schema_version.is_empty() {
        s_file.schema_version = STAGE_GRAPH_VERSION.to_string();
    }
    if h_file.schema_version.is_empty() {
        h_file.schema_version = STAGE_GRAPH_VERSION.to_string();
    }
    if let Err(e) = write_stage(&sessions_path(), &s_file) {
        return stage_error(cmd, e);
    }
    if let Err(e) = write_stage(&hooks_path(), &h_file) {
        return stage_error(cmd, e);
    }

    let mut changed: Vec<String> = reaped
        .iter()
        .map(|id| format!("reaped dead session {id} (killed; running → done → dropped)"))
        .collect();
    changed.extend(
        decayed
            .iter()
            .map(|id| format!("session {id} at rest > 1h (stopped → idle)")),
    );
    changed.extend(
        cleared
            .iter()
            .map(|id| format!("cleared parentSessionId of {id}")),
    );
    match restage_graph() {
        Ok(g) => changed.push(g.to_string_lossy().into_owned()),
        Err(e) => return stage_error(cmd, e),
    }
    Outcome::ok(
        cmd,
        format!(
            "reaped {} dead session(s); dropped {} total; decayed {} stopped → idle; cleared {} orphaned parent link(s)",
            reaped.len(),
            removed.len(),
            decayed.len(),
            cleared.len()
        ),
    )
    .changed(changed)
    .with_data(json!({
        "reaped": reaped,
        "removed": removed,
        "decayed": decayed,
        "clearedParents": cleared,
        "hyprctlAvailable": hyprctl_available,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(id: &str, win: &str, started: &str) -> SessionRecord {
        SessionRecord {
            session_id: id.into(),
            agent: "claude".into(),
            window_address: win.into(),
            state: "working".into(),
            started_at: started.into(),
            ..Default::default()
        }
    }

    /// A hook-only session: no `windowAddress`, no `pid` — exactly the UUID
    /// sessions that used to strand `idle` forever (the third-signal target).
    fn hook_only(id: &str, state: &str) -> SessionRecord {
        SessionRecord {
            session_id: id.into(),
            agent: "claude".into(),
            window_address: String::new(),
            state: state.into(),
            pid: None,
            ..Default::default()
        }
    }

    #[test]
    fn stale_hook_only_at_rest_session_is_reaped() {
        // No window, no pid, `idle`, last evidence of life 100h ago (> the 72h
        // threshold) — the exact stranded-UUID-orphan case this signal exists
        // for. Live-address/proc-exists probes are irrelevant here (neither
        // window nor pid signal can fire), so wire up dummies.
        let now = 1_800_000_000_i64;
        let stale = |_: &SessionRecord| Some(now - 100 * 3600);
        assert!(is_session_dead(
            &hook_only("orphan-idle", "idle"),
            None,
            |_| true,
            now,
            stale,
        ));
        // `stopped` is equally "at rest" and equally reapable once stale.
        assert!(is_session_dead(
            &hook_only("orphan-stopped", "stopped"),
            None,
            |_| true,
            now,
            stale,
        ));
    }

    #[test]
    fn fresh_hook_only_idle_session_is_not_reaped() {
        // Same shape (no window, no pid, idle) but last seen only 1h ago — well
        // under the 72h threshold. A just-started hook-only session must never
        // be swept.
        let now = 1_800_000_000_i64;
        let one_hour_ago = |_: &SessionRecord| Some(now - 3600);
        assert!(!is_session_dead(
            &hook_only("fresh", "idle"),
            None,
            |_| true,
            now,
            one_hour_ago,
        ));
    }

    #[test]
    fn hook_only_working_session_is_never_reaped_even_if_stale() {
        // No window, no pid, but `working` (mid-turn) with a 100h-stale
        // last-seen: the state gate must block the third signal outright — a
        // hook-only session mid-startup/mid-turn is not dead, no matter how old
        // its last transcript write looks.
        let now = 1_800_000_000_i64;
        let stale = |_: &SessionRecord| Some(now - 100 * 3600);
        let mut rec = hook_only("busy", "working");
        rec.state = "working".into();
        assert!(!is_session_dead(&rec, None, |_| true, now, stale));
        // Same for `awaiting` — waiting on a permission prompt is not at rest.
        rec.state = "awaiting".into();
        assert!(!is_session_dead(&rec, None, |_| true, now, stale));
    }

    #[test]
    fn headless_session_kept_alive_by_hook_updated_at_survives_stale_started_at() {
        // THE BLOCKER regression (Fable review): a foreign-harness/headless
        // session (no window, no pid, no on-disk transcript — the `graph
        // session start` recipe) can have an ANCIENT `startedAt` yet still be
        // firing hooks on its own cadence. Its hook record's `updatedAt` is
        // proof of life that must win over the stale `startedAt` — this is the
        // pure-predicate half of the fix: feed `is_session_dead` a `last_seen`
        // that (correctly) folds in a fresh hook timestamp, and the record must
        // NOT be dead despite a `startedAt` far past the 72h threshold.
        let now = 1_800_000_000_i64;
        let mut rec = hook_only("headless", "idle");
        rec.started_at = "2020-01-01T00:00:00Z".into(); // ancient birth time
        let fresh_hook_updated_at = now - 60; // this session's hook fired 1 minute ago
        let last_seen = move |s: &SessionRecord| -> Option<i64> {
            // Mirrors the real `last_seen` in `reap_inner`: MAX of transcript
            // mtime (none here), hook `updatedAt` (fresh), and `startedAt`
            // (ancient) — the fold that closes the false-reap hole.
            [
                None, // no transcript
                Some(fresh_hook_updated_at),
                aoide_storage::time::parse_iso_utc(&s.started_at),
            ]
            .into_iter()
            .flatten()
            .max()
        };
        assert!(!is_session_dead(&rec, None, |_| true, now, last_seen));
    }

    /// THE BLOCKER regression, end-to-end through `reap()`: a headless session
    /// with an ancient `startedAt`, no transcript, no window, no pid, but a
    /// FRESH hook `updatedAt` in `hooks.json` must survive a real reap pass —
    /// proving `reap_inner`'s `last_seen` closure actually performs the fold
    /// (not just the pure predicate above).
    #[test]
    fn reap_spares_a_headless_session_kept_alive_by_a_fresh_hook_updated_at() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env =
            crate::graph::testutil::EnvVars::save(&["AOIDE_STAGE_DIR", "HYPRLAND_INSTANCE_SIGNATURE"]);
        std::env::remove_var("HYPRLAND_INSTANCE_SIGNATURE"); // pid-only/no-window liveness
        let stage = crate::graph::testutil::unique_stage("reap-hookfold");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let mut rec = hook_only("headless", "idle");
        rec.started_at = "2020-01-01T00:00:00Z".into(); // ancient — no transcript exists for it
        rec.cwd = "/nonexistent/nowhere".into();
        write_stage(
            &sessions_path(),
            &SessionsFile {
                schema_version: "0".into(),
                sessions: vec![rec],
            },
        )
        .unwrap();
        let mut hooks = Vec::new();
        upsert_hook(&mut hooks, "headless", "idle", &now_iso_utc()); // fired seconds ago
        write_stage(
            &hooks_path(),
            &HooksFile {
                schema_version: "0".into(),
                hooks,
            },
        )
        .unwrap();

        let out = reap(&crate::graph::testutil::invocation(&["graph", "reap"], &[]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        assert_eq!(
            out.data.unwrap()["reaped"],
            json!([]),
            "a headless session kept alive by a fresh hook updatedAt must survive despite an ancient startedAt"
        );
        let s2: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert!(
            s2.sessions.iter().any(|s| s.session_id == "headless"),
            "the headless session survives the reaper pass"
        );

        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn windowed_session_is_unaffected_by_the_stale_idle_signal() {
        // A session WITH a live window is never touched by the third signal
        // regardless of staleness — condition 1 (no window evidence) fails, so
        // only the pre-existing window/pid signals can ever apply to it.
        let live: HashSet<String> = ["aaa"].iter().map(|s| s.to_string()).collect();
        let now = 1_800_000_000_i64;
        let ancient = |_: &SessionRecord| Some(now - 100 * 3600);
        let mut rec = agent("windowed", "0xAAA", "2026-07-30T00:00:00Z");
        rec.state = "idle".into();
        rec.pid = None;
        assert!(!is_session_dead(&rec, Some(&live), |_| true, now, ancient));
    }

    #[test]
    fn pid_dead_signal_is_unchanged_by_the_new_third_signal() {
        // The pre-existing pid-gone signal still fires exactly as before — the
        // third signal only ADDS a case, it never masks or weakens signal (b).
        let now = 1_800_000_000_i64;
        let fresh = |_: &SessionRecord| Some(now);
        let mut rec = hook_only("pid-dead", "working");
        rec.pid = Some(42);
        assert!(is_session_dead(&rec, None, |_| false, now, fresh));
    }

    #[test]
    fn superseded_agent_duplicates_keeps_the_real_one() {
        // The live diagnosis: one window (0xW) holds the real claude (transcript,
        // kind=agent, say), a phantom re-id (none of those), plus the conducted
        // shell that hosts them. A second window (0xZ) holds a lone claude.
        let mut real = agent("efdc", "0xW", "2026-07-30T07:29:57Z");
        real.kind = Some("agent".into());
        real.say = Some("hi".into());
        let phantom = agent("e711", "0xW", "2026-07-30T07:29:57Z");
        let lone = agent("solo", "0xZ", "2026-07-30T07:29:57Z");
        let mut shell = agent("sh", "0xW", "2026-07-30T01:00:00Z");
        shell.agent = "shell".into();
        shell.kind = Some("shell".into());
        let sessions = vec![real, phantom, lone, shell];

        let none_recent = |_: &SessionRecord| false;
        let has_tx = |s: &SessionRecord| s.session_id == "efdc"; // only the real one

        // The phantom is retired; the real one, the lone agent, and the shell stay.
        let losers = superseded_agent_duplicates(&sessions, none_recent, has_tx);
        assert_eq!(losers, vec!["e711".to_string()]);

        // Grace: if EITHER twin is still fresh, the whole group is left alone (so a
        // just-born pair is never resolved before the real one writes a transcript).
        let all_recent = |_: &SessionRecord| true;
        assert!(superseded_agent_duplicates(&sessions, all_recent, has_tx).is_empty());
    }

    #[test]
    fn stopped_decays_to_idle_only_past_the_one_hour_boundary() {
        // The threshold predicate is pure — `now` and the stop instant are both
        // parameters, so both sides of the boundary are exact, not flaky.
        let now = 1_800_000_000_i64;
        let minutes = |m: i64| Some(now - m * 60);
        assert!(!stopped_has_decayed(now, minutes(0)), "just stopped");
        assert!(
            !stopped_has_decayed(now, minutes(59)),
            "59m → still stopped"
        );
        assert!(
            !stopped_has_decayed(now, Some(now - STOPPED_IDLE_AFTER_SECS + 1)),
            "one second short of the hour → still stopped"
        );
        assert!(
            stopped_has_decayed(now, Some(now - STOPPED_IDLE_AFTER_SECS)),
            "exactly an hour → idle"
        );
        assert!(stopped_has_decayed(now, minutes(61)), "61m → idle");
        // A clock skew that puts the stop in the FUTURE is not an hour of rest.
        assert!(!stopped_has_decayed(now, Some(now + 600)));
        // No parseable stop instant → no evidence of recency → settle to idle,
        // rather than wearing a warm badge that could never expire.
        assert!(stopped_has_decayed(now, None));
    }

    #[test]
    fn decay_pass_ages_stopped_sessions_in_both_stage_files() {
        // now = 2026-07-30T12:00:00Z
        let now = "2026-07-30T12:00:00Z";
        let now_epoch = aoide_storage::time::parse_iso_utc(now).unwrap();

        let stopped = |id: &str| SessionRecord {
            session_id: id.into(),
            agent: "claude".into(),
            state: "stopped".into(),
            ..Default::default()
        };
        let mut sessions = vec![
            stopped("cold"),   // stopped 2h ago → idle
            stopped("warm"),   // stopped 10m ago → untouched
            stopped("orphan"), // no hook record at all → idle
            SessionRecord {
                session_id: "busy".into(),
                state: "working".into(),
                ..Default::default()
            },
            SessionRecord {
                session_id: "asking".into(),
                state: "awaiting".into(),
                ..Default::default()
            },
        ];
        let hook = |id: &str, at: &str| HookRecord {
            session_id: id.into(),
            phase: "stopped".into(),
            updated_at: at.into(),
            extra: Default::default(),
        };
        let mut hooks = vec![
            hook("cold", "2026-07-30T10:00:00Z"),
            hook("warm", "2026-07-30T11:50:00Z"),
            HookRecord {
                session_id: "busy".into(),
                phase: "working".into(),
                updated_at: "2026-07-30T09:00:00Z".into(), // old, but NOT stopped
                extra: Default::default(),
            },
        ];

        let mut decayed = decay_stopped_sessions(&mut sessions, &mut hooks, now_epoch, now);
        decayed.sort();
        assert_eq!(decayed, vec!["cold".to_string(), "orphan".to_string()]);

        let state = |id: &str| {
            sessions
                .iter()
                .find(|s| s.session_id == id)
                .unwrap()
                .state
                .clone()
        };
        assert_eq!(state("cold"), "idle");
        assert_eq!(state("orphan"), "idle");
        assert_eq!(state("warm"), "stopped", "10m of rest is still warm");
        // A long-running turn is never aged out — only `stopped` decays.
        assert_eq!(state("busy"), "working");
        assert_eq!(state("asking"), "awaiting");

        // hooks.json moves in lockstep: `merged_sessions` overlays the hook phase,
        // so a decay that skipped it would be undone by the very next merge.
        let phase = |id: &str| {
            hooks
                .iter()
                .find(|h| h.session_id == id)
                .map(|h| h.phase.clone())
        };
        assert_eq!(phase("cold").as_deref(), Some("idle"));
        assert_eq!(phase("orphan").as_deref(), Some("idle"));
        assert_eq!(phase("warm").as_deref(), Some("stopped"));
        assert_eq!(phase("busy").as_deref(), Some("working"));
        assert_eq!(
            crate::graph::merged_sessions(&sessions, &hooks)
                .iter()
                .find(|s| s.session_id == "cold")
                .unwrap()
                .state,
            "idle"
        );

        // Idempotent: a second pass over the settled roster moves nothing.
        assert!(decay_stopped_sessions(&mut sessions, &mut hooks, now_epoch, now).is_empty());
    }

    #[test]
    fn is_agent_kind_excludes_shells_and_subagents() {
        let mut a = agent("a", "0xW", "t");
        a.kind = Some("agent".into());
        assert!(is_agent_kind(&a));
        // classified shell / subagent → not an agent for dedup
        let mut sh = agent("sh", "0xW", "t");
        sh.kind = Some("shell".into());
        assert!(!is_agent_kind(&sh));
        let mut sub = agent("s", "0xW", "t");
        sub.kind = Some("subagent".into());
        assert!(!is_agent_kind(&sub));
        // unclassified: a conducted PTY (conductable) is a shell; a bare claude is not
        let mut conducted = agent("c", "0xW", "t");
        conducted.kind = None;
        conducted.agent = "shell".into();
        conducted.conductable = Some(true);
        assert!(!is_agent_kind(&conducted));
        // a conducted wrapper OF an agent (`conduct -- kimi`): upsert_session
        // classifies it kind="agent" from the child's basename, yet the
        // control-socket owner is a HOST, never a duplicate candidate — the
        // conductable clause precedes the published-kind match
        let mut host = agent("h", "0xW", "t");
        host.kind = Some("agent".into());
        host.agent = "kimi".into();
        host.conductable = Some(true);
        assert!(!is_agent_kind(&host));
        let mut bare = agent("b", "0xW", "t");
        bare.kind = None; // agent="claude", not conductable → agent
        assert!(is_agent_kind(&bare));
    }
}
