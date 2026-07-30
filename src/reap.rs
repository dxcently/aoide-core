//! Liveness reaping: mark KILLED sessions done so they cannot haunt forever.
//!
//! A terminal killed with SUPER+Q / SIGKILL cannot run its own cleanup — the
//! `conduct`/`wrap` process is torn down uncatchably, so `do_session_end` never
//! fires and the record is stranded `running` forever (22 dead `conduct-*` piled
//! up in ~8 minutes of use). The reaper detects such orphans out-of-band and
//! resolves them, so conduct-by-default is viable. A FALSE reap of a LIVE session
//! is worse than a stale record, so the predicate never guesses.
//!
//! Extracted from `graph.rs` (which had grown past 5800 lines) — a self-contained
//! cluster with no external callers but the CLI dispatch. It leans on a handful of
//! `pub(crate)` stage helpers still owned by `graph.rs`.

use crate::dispatch::Invocation;
use crate::graph::{
    hooks_path, hyprctl_clients, load_stage, normalize_addr, now_iso_utc, prune_done,
    restage_graph, sessions_path, stage_error, transcript_path_for, upsert_hook, write_stage,
    HooksFile, SessionRecord, SessionsFile, STAGE_GRAPH_VERSION,
};
use crate::output::Outcome;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

/// Does `/proc/<pid>` still exist? The real liveness probe for [`is_session_dead`]
/// (injected as a closure in tests so the predicate stays pure).
fn proc_exists(pid: u32) -> bool {
    std::path::Path::new("/proc").join(pid.to_string()).exists()
}

/// Is a session DEAD — orphaned so that NO process will ever clean it up? Pure
/// and unit-tested (feed a fake live-address set + a fake `proc_exists`).
///
/// DEAD when EITHER independent signal fires:
///   * **window gone** — a non-empty `windowAddress` that is NOT among the live
///     `hyprctl clients -j` addresses (the SUPER+Q kill: the window vanished), OR
///   * **process gone** — a recorded `pid` whose `/proc/<pid>` no longer exists
///     (the process-killed case).
///
/// The never-false-reap guards:
///   * `live_addresses` is an `Option`: `None` means the compositor could not be
///     queried (no Hyprland, hyprctl missing/failed) — the window signal is then
///     UNKNOWN and contributes nothing, so we never reap a windowed session we
///     merely failed to see. Only a `Some(live)` we actually gathered can fire it.
///   * A session with NEITHER signal (empty `windowAddress` AND no `pid` — e.g. a
///     hook-only session that has not yet discovered a window/pid) is left alone:
///     absence of evidence is never evidence of death.
pub fn is_session_dead(
    rec: &SessionRecord,
    live_addresses: Option<&HashSet<String>>,
    proc_exists: impl Fn(u32) -> bool,
) -> bool {
    let window_signal = match live_addresses {
        Some(live) => {
            !rec.window_address.is_empty()
                && !live.contains(&normalize_addr(&rec.window_address))
        }
        None => false, // compositor not queried — window liveness is unknown.
    };
    let pid_signal = matches!(rec.pid, Some(p) if !proc_exists(p));
    window_signal || pid_signal
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
/// sub-agent node? Published `kind` wins; absent, fall back to "not a shell and
/// not a conducted PTY". Sub-nodes (`sub:*`) carry no `windowAddress`, so they
/// never enter a window group regardless.
fn is_agent_kind(rec: &SessionRecord) -> bool {
    match rec.kind.as_deref() {
        Some("agent") => true,
        Some(_) => false, // "shell" | "subagent" | any other explicit kind
        None => rec.agent != "shell" && rec.conductable != Some(true),
    }
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

/// `graph reap` — the automatic liveness sweep. Marks every DEAD (killed,
/// orphaned) session `done` (and its hook record), then reuses [`prune_done`] to
/// drop them + clear orphaned parent links, re-staging `graph.json` atomically.
/// Cheap: one `hyprctl` call + a stage read, and a stage WRITE only when
/// something was actually reaped. NEVER errors non-zero on "nothing to reap" and
/// NEVER on an unavailable compositor (it falls back to pid-only liveness).
pub fn reap(inv: &Invocation) -> Outcome {
    crate::shellbridge::with_stage_lock(|| reap_inner(inv))
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

    let gathered = live_window_addresses();
    let hyprctl_available = gathered.is_some();
    // Apply the transient-read grace: a degenerate empty snapshot during a reload
    // window falls back to pid-only liveness so we never sweep the live roster off
    // a momentary "zero windows" answer.
    let live = effective_live_addresses(gathered, &s_file.sessions);
    // Only STILL-live records can be dead-by-liveness; an already-`done` session
    // is prune's job, not a reap. This is the set the liveness predicate killed.
    let mut reaped: Vec<String> = s_file
        .sessions
        .iter()
        .filter(|s| s.state != "done")
        .filter(|s| is_session_dead(s, live.as_ref(), proc_exists))
        .map(|s| s.session_id.clone())
        .collect();

    // Also retire superseded same-window agent duplicates (a phantom re-id whose
    // pid is the terminal's, invisible to the liveness predicate above). Grace:
    // ~60s off startedAt so a just-born pair settles; keeper = the one with a real
    // transcript on disk (see `superseded_agent_duplicates`).
    const DEDUP_GRACE_SECS: i64 = 60;
    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let is_recent = |s: &SessionRecord| {
        crate::baton::theme::parse_iso_utc(&s.started_at)
            .map(|t| now_epoch - t < DEDUP_GRACE_SECS)
            .unwrap_or(false) // an unparseable/empty startedAt is treated as old
    };
    let has_transcript =
        |s: &SessionRecord| transcript_path_for(&s.session_id, Some(s.cwd.as_str()), None).is_some();
    for id in superseded_agent_duplicates(&s_file.sessions, is_recent, has_transcript) {
        if !reaped.contains(&id) {
            reaped.push(id);
        }
    }

    if reaped.is_empty() {
        return Outcome::ok(cmd, "nothing to reap (all sessions live)").with_data(json!({
            "reaped": [],
            "hyprctlAvailable": hyprctl_available,
        }));
    }

    // Mark each reaped session done in BOTH files, then let prune_done drop them
    // (and any pre-existing `done`) + clear orphaned parentSessionIds.
    let dead: HashSet<&str> = reaped.iter().map(String::as_str).collect();
    let now = now_iso_utc();
    for s in s_file.sessions.iter_mut() {
        if dead.contains(s.session_id.as_str()) {
            s.state = "done".to_string();
        }
    }
    for id in &reaped {
        upsert_hook(&mut h_file.hooks, id, "done", &now);
    }

    let (kept_s, kept_h, removed, cleared) = prune_done(
        std::mem::take(&mut s_file.sessions),
        std::mem::take(&mut h_file.hooks),
    );
    s_file.sessions = kept_s;
    h_file.hooks = kept_h;
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
            "reaped {} dead session(s); dropped {} total; cleared {} orphaned parent link(s)",
            reaped.len(),
            removed.len(),
            cleared.len()
        ),
    )
    .changed(changed)
    .with_data(json!({
        "reaped": reaped,
        "removed": removed,
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
        let mut bare = agent("b", "0xW", "t");
        bare.kind = None; // agent="claude", not conductable → agent
        assert!(is_agent_kind(&bare));
    }
}
