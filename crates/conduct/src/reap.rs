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
//! Hardened against the two ghost classes a still-live window/pid used to
//! shield forever:
//!   * an AGENT killed inside its still-open terminal or parent session: the
//!     recorded pid is the TERMINAL's (it outlives the agent), the window is
//!     live — every old signal blind. The staleness evidence now also judges
//!     agent records whose window/pid are live, discriminated by the
//!     window-owner map: a live pid that is NOT its window's owner is the
//!     agent's own process (the payload-pid seam) and vetoes the signal;
//!   * a HEADLESS record stuck mid-turn (`working`/`awaiting`) whose process
//!     is gone: silence past a week-long band (see
//!     [`REAP_WORKING_STALE_SECS`]) condemns it, while a live harness firing
//!     hooks on its own cadence is proven alive by its fresh hook `updatedAt`.
//! And three ghosts that answer NO to every signal above and are dead anyway:
//! a record whose evidence all predates the machine's own boot instant (see
//! [`pre_boot_ghosts`] — the case a recycled pid shields forever), a dependent
//! node whose parent has left the roster entirely (see [`orphaned_subagents`]),
//! and the control socket a killed `conduct` left in `$XDG_RUNTIME_DIR` (see
//! [`sweep_orphan_sockets`] — not a session record at all, but this sweep's
//! leavings and nobody else's job).
//!
//! A fourth kind of leaving sits alongside the socket: the ssh tunnel a
//! cross-box call opened for a session that never got to close it itself
//! (see [`sweep_orphan_tunnels`], ssh-transport lane P-S5). Same shape as
//! the socket sweep — a roster-less, settled record is collected — plus one
//! extra step the socket never needed: the tunnel is a live `ssh -N` child,
//! not just a leftover file, so a still-answering pid is signaled
//! (`aoide_client::tunnel::kill_if_still_our_ssh`) before its record is
//! unlinked. `do_session_end`'s own clean-exit path already closes a
//! session's tunnels on the fast path (`graph/session_store.rs`); this sweep
//! is the SUPER+Q/SIGKILL backstop, so an ssh child can never outlive its
//! session and become a resident daemon.
//!
//! Last and narrowest: the worker shell an agent's own `aoide spawn` left
//! running and never came back to (see [`abandoned_spawned_shells`]) — the
//! one carve-out into the kind gate that otherwise keeps every shell out of
//! staleness judgment, and the only sweep here with two speeds. The
//! unattended pass waits out [`REAP_SPAWNED_SHELL_STALE_SECS`]; a human
//! gesture (`--now`) waives the band and takes every idle spawned shell on
//! the spot.
//!
//! A false reap of a merely-quiet live session self-heals: the hook door
//! re-registers the record on the session's next event.
//!
//! Extracted from `graph.rs` (which had grown past 5800 lines) — a self-contained
//! cluster with no external callers but the CLI dispatch. It leans on a handful of
//! `pub(crate)` stage helpers still owned by `graph.rs`.

use aoide_protocol::Invocation;
use aoide_protocol::agents::{agent_profile, AgentProfile, CLAUDE_PROFILE};
use crate::graph::{
    canonical_state, drop_sessions, hooks_path, hyprctl_clients, ledger_session_exit, lineage_of,
    load_stage, normalize_addr, now_iso_utc, prune_done, refresh_subagent_says,
    refresh_transcript_fields, restage_graph, sessions_path, stage_error, upsert_hook,
    write_stage, HookRecord, HooksFile, SessionRecord, SessionsFile, STAGE_GRAPH_VERSION,
};
use aoide_protocol::output::Outcome;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

/// Does `/proc/<pid>` still exist? The real liveness probe for [`is_session_dead`]
/// (injected as a closure in tests so the predicate stays pure).
///
/// `pub` (task #33): `aoide-server`'s A2A `tasks/get` resolution feeds this
/// SAME probe into `is_session_dead` at read time, so a session that died
/// after its spawn ack reads `failed` instead of stale `submitted` —
/// widened rather than forked (`crates/AGENTS.md` "no cross-crate copying").
pub fn proc_exists(pid: u32) -> bool {
    std::path::Path::new("/proc").join(pid.to_string()).exists()
}

/// How long an AT-REST (`idle`/`stopped`) record that staleness may judge (see
/// [`is_session_dead`]) may go without any evidence of life before its own
/// silence becomes the abandonment signal. 72h (~3 days) is conservative on
/// purpose: comfortably longer than any ordinary idle gap (an overnight, a
/// weekend) a LIVE session might sit through, so a session that is merely quiet
/// is never touched. Only a session stranded well past any plausible "still
/// working on it" window qualifies — the two cleared-by-hand orphans that
/// motivated this had been `idle` for days, so 72h loses nothing on the
/// cleanup side while giving a wide berth to a quiet-but-live weekend session.
pub const REAP_IDLE_STALE_SECS: i64 = 72 * 3600; // 72 hours (~3 days)

/// How long a MID-TURN (`working`/`awaiting`) record may go without any
/// evidence of life before its own silence becomes the abandonment signal —
/// see [`is_session_dead`]. Deliberately LONGER than the at-rest band: a
/// legitimate long-running headless turn (a multi-day build/training whose
/// harness fires hooks only at start and end) can be silent for days while
/// very much alive. 168h (a full week) gives that case a wide berth; silence
/// past it is not plausibly "still working" — the process is gone and the
/// record is a ghost.
pub const REAP_WORKING_STALE_SECS: i64 = 7 * 24 * 3600; // 7 days (~168 hours)

/// How long a MID-TURN (`working`/`awaiting`) **`subagent`-kind** record may
/// go without any evidence of life before its own silence becomes the
/// abandonment signal — see [`is_session_dead`]. Overrides
/// [`REAP_WORKING_STALE_SECS`] for that one kind specifically, and is FAR
/// shorter: a subagent record is spawned by its parent session's own
/// Task-tool call and lives entirely inside that single call (see
/// `doomed_subagent_descendants` in `graph/doc.rs` — the cascade is its
/// PRIMARY cleanup path when the parent ends; this band is only the slow
/// backstop for a subagent stranded while its parent lives on). There is no
/// scenario where a subagent is still genuinely "working" long after that —
/// unlike an independent long-running headless agent (the case
/// [`REAP_WORKING_STALE_SECS`] protects), which can legitimately go
/// hook-silent for days. 2h sits comfortably clear on both sides: well past
/// an ordinary subagent turn (real multi-tool work running 20-30 minutes is
/// normal) and well short of the multi-hour staleness that actually strands
/// one — the two ghost records that motivated this constant were still
/// `working` 11+ hours after their parent's Task call had already returned.
pub const REAP_SUBAGENT_STALE_SECS: i64 = 2 * 3600; // 2 hours

/// How long a SPAWNED worker shell (see [`abandoned_spawned_shells`]) may sit
/// idle with its pty log untouched before the UNATTENDED sweep calls it
/// leftover. Its own constant rather than a share of
/// [`REAP_IDLE_STALE_SECS`], because the two answer different questions: that
/// band guards a session that might still be someone's, so it has to clear a
/// whole weekend, while this one judges a terminal an agent created and
/// walked away from. Being early there costs a shell that keeps running
/// untracked (no signal in this file ever kills a process); being late costs
/// a roster that fills with worker terminals nobody will ever type in again.
/// Two days sits past any turn an agent legitimately returns to and short of
/// the pile-up.
///
/// The band belongs to the unattended sweep alone — the ~12s timer and the
/// daemon's own tick. A human gesture waives it outright (`--now`; see
/// [`with_human_gesture`] for what resolves to one, and
/// [`abandoned_spawned_shells`]'s `band` parameter for what waiving does).
pub const REAP_SPAWNED_SHELL_STALE_SECS: i64 = 48 * 3600; // 48 hours (2 days)

/// Is a session DEAD — orphaned so that NO process will ever clean it up? Pure
/// and unit-tested (feed a fake live-address set + window-owner map, a fake
/// `proc_exists`, and a fake `last_seen`).
///
/// DEAD when ANY of three signals fires:
///   * **window gone** — a non-empty `windowAddress` that is NOT among the live
///     `hyprctl clients -j` addresses (the SUPER+Q kill: the window vanished), OR
///   * **process gone** — a recorded `pid` whose `/proc/<pid>` no longer exists
///     (the process-killed case), OR
///   * **stale abandonment** — every evidence stream (`last_seen` — the MAX of
///     transcript mtime, hook `updatedAt`, and `startedAt`) has been silent
///     past a state-dependent band, for a record staleness may judge:
///       - **at rest** (`idle`/`stopped`), silent past
///         [`REAP_IDLE_STALE_SECS`] (72h), OR
///       - **mid-turn** (`working`/`awaiting`), silent past
///         [`REAP_WORKING_STALE_SECS`] (7 days) — except a `subagent`-kind
///         record, which judges mid-turn silence against
///         [`REAP_SUBAGENT_STALE_SECS`] (2h) instead: it cannot legitimately
///         outlive its parent's own Task-tool call, so it needs no week-long
///         grace.
///     Eligible records: a HEADLESS one (no window AND no pid — the classic
///     hook-only shape; every `subagent` record is shaped this way) or an
///     AGENT one ([`is_agent_kind`]). The agent arm is
///     the hardening: an agent killed inside its still-open terminal/parent
///     keeps a live window and a live TERMINAL pid forever, so only the
///     silence of every evidence stream can condemn it. The kind gate keeps
///     SHELLS out — a shell record's pid IS its terminal, so a live pid means
///     the shell is alive and staleness must never overrule it. One veto on
///     top: a live pid that is NOT its window's owning pid is the agent's OWN
///     process (the payload-pid seam) — positive proof of life, governed by
///     the pid signal alone.
///   One more veto, orthogonal to all of the above: `rec.exempt` (task #20,
///   `aoide session grant exempt on|off`) vetoes `stale_abandoned` alone —
///   window-gone and pid-gone still fire on an exempt record, since only
///   staleness can ever take a LIVE session and that is exactly what the
///   exemption promises against.
///
/// The never-false-reap guards:
///   * `live_addresses` is an `Option`: `None` means the compositor could not be
///     queried (no Hyprland, hyprctl missing/failed) — the window signal is then
///     UNKNOWN and contributes nothing, so we never reap a windowed session we
///     merely failed to see. Only a `Some(live)` we actually gathered can fire it.
///   * Absence of evidence is never evidence of death, but STALENESS is
///     evidence, not absence — `last_seen` returning `None` (no transcript, no
///     parseable `startedAt`, no hook record) never counts as stale, so the
///     guard holds. A just-started session has a recent `last_seen` and sits
///     far under every band.
///   * A false reap of a merely-quiet live session is recoverable: the hook
///     door re-registers the record on the session's next event
///     (`hook_ensure_session`), so the cost is a temporarily missing row,
///     never a lost session.
pub fn is_session_dead(
    rec: &SessionRecord,
    live_addresses: Option<&HashSet<String>>,
    window_owners: Option<&HashMap<String, u32>>,
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
    let state = canonical_state(&rec.state);
    let at_rest = matches!(state, "idle" | "stopped");
    let mid_turn = matches!(state, "working" | "awaiting");
    let stale_beyond = |secs: i64| {
        last_seen(rec)
            .map(|seen| now_epoch.saturating_sub(seen) > secs)
            .unwrap_or(false)
    };
    // A LIVE pid that is NOT its window's owning pid is the agent's OWN process
    // (the payload-pid seam) — positive proof of life: the pid signal alone
    // governs that record and staleness must never fire over it. A pid equal to
    // the window's owner is the TERMINAL's, which outlives the agent, so it
    // cannot veto. No owner map (compositor unqueried) reads a live pid
    // conservatively as the agent's own.
    let live_agent_pid = rec.pid.is_some_and(|p| {
        proc_exists(p)
            && !window_owners
                .and_then(|m| m.get(&normalize_addr(&rec.window_address)).copied())
                .is_some_and(|owner| owner == p)
    });
    // WHO staleness may judge: a headless record (no window AND no pid — the
    // classic hook-only shape) or an AGENT record (the hardened arm — see the
    // doc above for why shells are excluded).
    let stale_eligible =
        (rec.window_address.is_empty() && rec.pid.is_none()) || is_agent_kind(rec);
    // A subagent cannot legitimately outlive its parent's own Task-tool call
    // (see REAP_SUBAGENT_STALE_SECS), so its mid-turn silence is judged
    // against a far shorter band than the general working/awaiting case.
    let working_band = if rec.kind.as_deref() == Some("subagent") {
        REAP_SUBAGENT_STALE_SECS
    } else {
        REAP_WORKING_STALE_SECS
    };
    let stale_abandoned = stale_eligible
        && !live_agent_pid
        && !rec.exempt
        && ((at_rest && stale_beyond(REAP_IDLE_STALE_SECS))
            || (mid_turn && stale_beyond(working_band)));
    window_signal || pid_signal || stale_abandoned
}

/// Gather the live windows from `hyprctl clients -j` — BOTH the normalised
/// addresses (for the window-liveness signal and the transient-read grace)
/// and each window's OWNING pid (for the staleness veto in
/// [`is_session_dead`]: a record's pid equal to its window's owner is the
/// TERMINAL's pid, which outlives the agent — the owners map is how that is
/// told apart from an agent's self-reported pid). Returns `None` whenever the
/// compositor cannot be consulted authoritatively (see
/// [`crate::graph::hyprctl_clients`]). This is the seam that keeps the reaper
/// safe off-Hyprland — it degrades to the pid signal instead of blindly
/// reaping every windowed session it could not see.
fn live_windows() -> Option<(HashSet<String>, HashMap<String, u32>)> {
    let clients = hyprctl_clients()?;
    let mut addrs = HashSet::new();
    let mut owners = HashMap::new();
    for c in &clients {
        let Some(addr) = c.get("address").and_then(Value::as_str) else {
            continue;
        };
        if addr.is_empty() {
            continue;
        }
        let addr = normalize_addr(addr);
        addrs.insert(addr.clone());
        if let Some(pid) = c
            .get("pid")
            .and_then(Value::as_i64)
            .and_then(|p| u32::try_from(p).ok())
        {
            owners.insert(addr, pid);
        }
    }
    Some((addrs, owners))
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
/// Keeper rank (descending): newest `startedAt` → a real on-disk transcript
/// (`has_transcript`) → carries `say` → classified `kind=="agent"` →
/// lexically-greatest `sessionId` (stable final tiebreak). A group of one is
/// never touched; a group with ANY member still inside the grace (`is_recent`)
/// is left entirely alone — a just-born pair is let settle until the real one
/// writes its transcript, so we never drop the wrong twin at t≈0.
///
/// `startedAt` leads, not `has_transcript`: the case this function exists for
/// (compact/resume mints a NEW sessionId in the same window; the OLD one never
/// gets a clean `SessionEnd`) mints the new record STRICTLY after the old one,
/// so newest-first always keeps it. Ranking on `has_transcript` first used to
/// pick the OLD record instead whenever the fresh session hadn't said anything
/// yet — the transcript file doesn't exist until the first turn, while the old
/// session's transcript (and `say`) are still sitting there from before the
/// compact/resume. That silently reaped the LIVE session out of the roster
/// (self-heals only once the user's next hook re-registers it) and left the
/// stale twin standing in its place — exactly the "reap doesn't clear the
/// ghost claude in this terminal" symptom. `has_transcript`/`say` still decide
/// a tie: the one real scenario left for them is a same-instant registration
/// race, where `startedAt` cannot tell the pair apart at all.
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
                s.started_at.clone(),
                has_transcript(s),
                s.say.is_some(),
                s.kind.as_deref() == Some("agent"),
                s.session_id.clone(),
            )
        };
        let keeper = group.iter().max_by(|a, b| rank(a).cmp(&rank(b))).unwrap();
        // Defense in depth (task #89, review round 2): never retire a member
        // of the KEEPER's own lineage as a "duplicate" — the same carve-out
        // `session_store`'s registration-time eviction applies, reused here
        // via the SAME `lineage_of` (ancestors + descendants), never a
        // second computation. By design a windowless-by-construction nested
        // session never shares a real window with its own launching agent
        // in the first place (the fix this whole task landed), so this
        // should be a no-op on a healthy roster — it only matters if
        // something upstream still manages to stamp a stray shared window
        // onto a lineage-related pair.
        let keeper_lineage = lineage_of(&keeper.session_id, sessions);
        for s in group {
            if s.session_id != keeper.session_id && !keeper_lineage.contains(&s.session_id) {
                losers.push(s.session_id.clone());
            }
        }
    }
    losers
}

/// Among agent records sharing one non-empty `windowAddress`, return the ids of
/// the SUPERSEDED `done` ones — the tombstones a terminal piles up as its
/// foreground agent is re-identified. One terminal, one agent row.
///
/// The live shape this closes (four `claude` rows for ONE kitty window): every
/// `/clear`, compact or resume mints a NEW sessionId, and the outgoing session
/// ends cleanly — so unlike the phantoms [`superseded_agent_duplicates`]
/// retires, these records are legitimately `done`, invisible to the liveness
/// predicate (which only judges not-`done` records) and skipped by the dedup
/// above (which only groups not-`done` ones). Nothing in a reap pass collected
/// them: [`prune_done`] runs only when something else was already reaped, so on
/// a quiet desktop the tombstones sat in `sessions.json` indefinitely — one
/// Conductor card each, and (before the widget's own rank fix) the Terminals
/// row for that window rendered a DEAD agent, because the shared-window merge
/// took the first agent record it saw.
///
/// A terminal hosts ONE foreground agent, so the window's history is never the
/// roster's business — only its present:
///   * a window with a LIVE agent keeps that one; every `done` predecessor in
///     it is superseded outright (the roster shows what is running NOW), and
///   * a window with only tombstones keeps exactly the NEWEST (`startedAt`,
///     then the id as a stable final tiebreak) — the agent that actually just
///     finished, whose done pose the widgets deliberately show until
///     `session prune` sweeps it. Its predecessors are as superseded as they
///     would be beside a live one.
/// So this never empties a window's roster entry, and never leaves two.
///
/// [`prune_done`]: crate::graph::prune_done
fn superseded_done_siblings(sessions: &[SessionRecord]) -> Vec<String> {
    let mut by_window: HashMap<&str, Vec<&SessionRecord>> = HashMap::new();
    for s in sessions {
        if s.window_address.is_empty() || !is_agent_kind(s) {
            continue;
        }
        by_window
            .entry(s.window_address.as_str())
            .or_default()
            .push(s);
    }
    let mut losers = Vec::new();
    for group in by_window.values() {
        let mut tombs: Vec<&&SessionRecord> =
            group.iter().filter(|s| s.state == "done").collect();
        if !group.iter().any(|s| s.state != "done") {
            // No live agent here — the newest tombstone is the one still owed a
            // done pose, so it is spared and only its predecessors are dropped.
            let keeper = tombs
                .iter()
                .max_by_key(|s| (&s.started_at, &s.session_id))
                .map(|s| s.session_id.clone());
            tombs.retain(|s| Some(&s.session_id) != keeper.as_ref());
        }
        losers.extend(tombs.into_iter().map(|s| s.session_id.clone()));
    }
    losers
}

// ── Three ghosts every signal above walks past ──────────────────────────────
//
// The liveness predicate asks "is this record's process/window gone, or has it
// been silent past its band". Each of the three below is a record that answers
// NO to all of that and is dead anyway: one because the machine rebooted under
// it, one because the node it hangs off no longer exists, and one because it is
// not a session record at all but the file a dead session left in /run.

/// Grace on the boot-instant comparison, absorbing early-boot clock skew: a
/// record can be written before NTP steps the clock, landing a timestamp a
/// little BEHIND the `btime` recorded moments earlier. Five minutes is far
/// wider than any plausible step and far narrower than the hours a real
/// pre-boot ghost sits at.
const BOOT_SKEW_GRACE_SECS: i64 = 300; // 5 minutes

/// How long a control socket must have sat untouched before the sweep will
/// consider unlinking it. `conduct` binds its socket a moment BEFORE its
/// `session start` lands in sessions.json, so an infant socket is briefly
/// roster-less through no fault of its own; 60s is the same settle window the
/// duplicate dedup uses.
const SOCKET_SETTLE_SECS: i64 = 60;

/// How long a tunnel record must have sat untouched before
/// [`sweep_orphan_tunnels`] will consider it. Same value, same reasoning as
/// [`SOCKET_SETTLE_SECS`]: `aoide-client::tunnel::open_or_reuse` writes the
/// record a moment AFTER the forward already answers, so an infant record is
/// briefly roster-less through no fault of its own the instant a session
/// starts opening its first tunnel.
const TUNNEL_SETTLE_SECS: i64 = 60;

/// The instant this machine booted, epoch seconds — `btime` out of
/// `/proc/stat`. `None` whenever it cannot be read or parsed (no `/proc`, a
/// stripped container): the pre-boot signal then never fires at all, which is
/// the safe direction.
///
/// `pub`, not `pub(crate)` (P-D8): `aoide-server`'s `daemon.rs` reuses this
/// EXACT read for its own boot-epoch-guarded auto-resume trigger
/// (`docs/architecture/AOIDED.md`'s "Open knobs" — "using the boot-epoch
/// read the reaper already has") rather than re-deriving `/proc/stat`
/// parsing a second time (`pkgs/aoide/crates/AGENTS.md`'s "no cross-crate
/// copying").
pub fn boot_epoch() -> Option<i64> {
    let stat = std::fs::read_to_string("/proc/stat").ok()?;
    stat.lines()
        .find_map(|l| l.strip_prefix("btime "))
        .and_then(|v| v.trim().parse::<i64>().ok())
}

/// Sessions whose every evidence of life predates the current boot. PURE —
/// both the boot instant and `last_seen` are injected.
///
/// A reboot is a hard fact about the world: no process, no window address and
/// no pty survives one. A record that has shown no sign of life since the
/// machine came up therefore cannot be attached to anything running, and all
/// three existing signals can miss it:
///   * the window signal only fires when `hyprctl` answers, and a compositor
///     that also restarted may not be up yet on the first passes;
///   * the pid signal reads a RECYCLED pid as alive — on a busy box (22 dead
///     `conduct-*` in eight minutes of use) a fresh process lands on the old
///     number and `/proc/<pid>` exists again, shielding the ghost forever;
///   * the staleness bands hold their fire for 72h / 7 days, and the live-pid
///     veto can stop them firing at all.
/// This collapses that wait to the one thing already known for certain: the
/// box rebooted, and this record never woke up.
///
/// Absence of evidence is still never evidence of death — an unreadable
/// `/proc/stat` (`boot_epoch` `None`) and a record with no parseable evidence
/// (`last_seen` `None`) both leave the record alone.
///
/// Known caveat, deliberately accepted: on a kernel that recomputes `btime`
/// across a long suspend, the boot instant can drift FORWARD past a live
/// session's last hook, and a quiet-but-live record is then reaped. It
/// self-heals on that session's next event exactly like every other false
/// reap (`hook_ensure_session` re-registers it), and the grace above absorbs
/// the small drifts.
fn pre_boot_ghosts(
    sessions: &[SessionRecord],
    boot_epoch: Option<i64>,
    last_seen: impl Fn(&SessionRecord) -> Option<i64>,
) -> Vec<String> {
    let Some(boot) = boot_epoch else {
        return Vec::new();
    };
    sessions
        .iter()
        .filter(|s| s.state != "done")
        .filter(|s| last_seen(s).is_some_and(|seen| seen + BOOT_SKEW_GRACE_SECS < boot))
        .map(|s| s.session_id.clone())
        .collect()
}

/// Dependent records whose parent is gone from the roster entirely. PURE —
/// `is_recent` is injected.
///
/// A `subagent` node exists only inside its parent's Task-tool call: its id is
/// minted from that call, and it owns no process, window or transcript of its
/// own. `doomed_subagent_descendants` (in `graph/doc.rs`) is the primary
/// cleanup and takes the sub-agents down with a parent that ends HERE — but a
/// parent that left through another door (`session prune` on its own schedule,
/// or an earlier pass that cleared the dangling link) leaves the sub-agent as
/// a parentless root node, and there it sits for its full staleness band
/// (2h mid-turn, 72h at rest) still claiming to be working.
///
/// The same blind spot swallows a HOOK-ONLY top-level agent (no pid, no
/// windowAddress — every liveness signal blind by construction) whose host
/// terminal's record has left the roster: the host is reaped only once its
/// window AND its pid are both gone, so a gone parent means a dead terminal,
/// and a dead terminal's claude is dead with it. That case is taken here too —
/// but only on a PRESENT-but-gone parent link: an absent parent is the normal
/// project-anchored shape for a top-level agent, never evidence of death.
///
/// Narrow on purpose: for sub-agents, only a record whose parent id is EMPTY
/// or names a session that is not in the roster AT ALL. A parent that is
/// present but `done` is the cascade's business and is left to it. `is_recent`
/// spares an infant, since a reap racing the hook door's own write would
/// otherwise judge a record whose parent link is a moment away.
fn orphaned_subagents(
    sessions: &[SessionRecord],
    is_recent: impl Fn(&SessionRecord) -> bool,
) -> Vec<String> {
    let known: HashSet<&str> = sessions.iter().map(|s| s.session_id.as_str()).collect();
    sessions
        .iter()
        .filter(|s| s.state != "done")
        .filter(|s| !is_recent(s))
        .filter(|s| {
            let parent = s
                .parent_session_id
                .as_deref()
                .map(str::trim)
                .filter(|p| !p.is_empty());
            if s.kind.as_deref() == Some("subagent") || s.session_id.starts_with("sub:") {
                // A sub-agent owns nothing — parentless is parentless.
                parent.is_none_or(|p| !known.contains(p))
            } else if is_agent_kind(s) && s.pid.is_none() && s.window_address.is_empty() {
                // The hook-only agent: signal-blind without its host terminal.
                parent.is_some_and(|p| !known.contains(p))
            } else {
                false
            }
        })
        .map(|s| s.session_id.clone())
        .collect()
}

/// A SPAWNED conducted SHELL — the worker terminal `aoide spawn` leaves
/// running once whatever an agent launched inside it has finished, in
/// EITHER launch mode — that nobody has come back to. PURE — `log_mtime` is
/// injected (the real caller reads the log file's own mtime off disk),
/// exactly like every other staleness probe in this file.
///
/// `band` is how long that terminal's pty log may have gone untouched before
/// the record counts as leftover: `Some(secs)` —
/// [`REAP_SPAWNED_SHELL_STALE_SECS`] — for the unattended sweep, and `None`
/// for a human gesture, which waives the wait outright. A person pressing
/// `[ reap ]` IS the "nobody came back to this" evidence the band otherwise
/// sits two days to infer, so making them wait for it adds nothing they have
/// not already said. Waiving drops ONLY the staleness clause; all three
/// guards below still have to hold.
///
/// The one new carve-out into the kind gate [`is_session_dead`] otherwise
/// holds absolute (`is_agent_kind`'s own doc: "a shell record's pid IS its
/// terminal", so a live pid alone must never be overruled by staleness) —
/// and it stays narrow on purpose, because a shell has no self-heal: an
/// agent's hook door re-registers a falsely-reaped AGENT on its very next
/// event ([`is_session_dead`]'s own "never-false-reap" doc), but nothing
/// ever re-registers a shell mid-life, so a false positive here is
/// unrecoverable in a way this file's other signals are not. Four guards
/// keep it to exactly the shape an agent-spawned, unattended worker
/// terminal has, and never a human's:
///   * `spawned` — a PERMANENT registration fact stamped once inside the
///     spawned child at its own registration and never cleared. This is the
///     whole "left over by an agent, not opened by a human" test, and it is
///     decidable precisely because `aoide spawn` is the only thing that ever
///     sets it: a terminal the User opened themselves can never carry it,
///     whatever its log evidence says. It deliberately does NOT read
///     `headless` — a `spawn --windowed` worker terminal is abandoned the
///     same way a headless one is — nor `parentSessionId`, which `graph/
///     doc.rs` clears when the parent is removed and so is empty exactly
///     when a shell has become leftover.
///   * `restore.is_some()` — stamped ONLY by `conduct`'s P-C5 tick
///     (`graph/conduct.rs::conduct_refresh_shell`), which itself only runs
///     when the wrapped command's own basename is `bash`/`zsh`/`fish`/`sh`
///     (`captures_like_a_shell`) — the same `restore.is_some()` proxy
///     `resurrect.rs`'s own terminal-candidate arm already uses for
///     "was this actually ticked as a shell". An agent or a one-shot
///     command spawned headless never sets this field at all, so this
///     signal structurally can never reach either.
///   * `state == "idle"` (the bare prompt) — never `working` (a live
///     foreground command, however quiet) or `awaiting` (a sudo prompt
///     mid-conversation). Only a terminal doing NOTHING right now is even
///     considered.
///   * `!exempt` (task #20, `aoide session grant exempt on|off`) — an agent
///     that wants ITS OWN spawned worker terminal safe from this arm marks
///     it after spawn; the veto holds banded AND waived alike, so `--now`
///     cannot take an exempt shell either.
///
/// The touch signal is the per-session pty LOG FILE's own mtime
/// (`state/sessions/<id>.log`, `log_path`): every byte that crosses this
/// pty appends to it — the spawned command's own original output, AND any
/// LATER injected `aoide send` (an agent's own follow-up, or a human's —
/// the injection door cannot tell the two apart, `graph/send.rs`'s own
/// `resolve_sender` doc: attribution there is self-reported and never
/// enforced at the receiving socket, so it is never a trust boundary).
/// "Silent past the band" therefore means exactly "nothing has happened in
/// this terminal, from anyone, in over [`REAP_SPAWNED_SHELL_STALE_SECS`]" —
/// the only decidable meaning of "unused" this codebase can stand behind. The moment
/// anything is sent into it — the spawning agent's own follow-up, a
/// different agent, or a human who found and used it — the log grows and
/// the clock resets, which is what keeps a human's later use of an
/// agent-spawned terminal safe from this signal without this file ever
/// needing to know WHO touched it.
///
/// No log evidence at all (`log_mtime` returns `None`) never counts as
/// staleness: absence of evidence is never evidence of death, the same
/// guard [`is_session_dead`] holds for `last_seen`. **That is the reach of
/// the unattended band today, and it is narrower than the three guards
/// above:** only a HEADLESS conduct opens `state/sessions/<id>.log` at all
/// (`graph/conduct.rs`'s log block sits inside its own `if headless`), so a
/// `spawn --windowed` worker terminal has no `log_path`, no touch signal,
/// and is never reaped by the timer however long it sits. It is reached by
/// the human gesture instead, which needs no touch signal to waive a band it
/// isn't applying — and it comes under the band for free the day interactive
/// conduct tees its own pty to the same per-session log (the session
/// streaming lane). Nothing here changes when it does: the probe already
/// reads `log_path`, whoever wrote it.
///
/// This never KILLS the underlying process — the same posture every other
/// signal in this file takes toward a still-alive pid (the one exception,
/// [`sweep_orphan_tunnels`], only ever signals a live process once its
/// OWNING session is already gone, never as the primary death signal
/// itself). A record this catches drops off the roster; a still-running
/// shell behind it keeps running, untracked, until its own natural exit.
///
/// `rec.exempt` (task #20) vetoes this arm too — an exempt worker terminal
/// is never abandoned-shell candidacy, banded or waived alike. Shared with
/// [`spared_exempt_spawned_shells`] below via [`spawned_shell_shape`], the
/// ONE definition of "shaped like a leftover spawned shell" both read, so a
/// record can never be both reaped and reported spared, or neither.
fn abandoned_spawned_shells(
    sessions: &[SessionRecord],
    now_epoch: i64,
    log_mtime: impl Fn(&SessionRecord) -> Option<i64>,
    band: Option<i64>,
) -> Vec<String> {
    spawned_shell_shape(sessions, now_epoch, log_mtime, band)
        .filter(|s| !s.exempt)
        .map(|s| s.session_id.clone())
        .collect()
}

/// The staleness/idle/spawned shape [`abandoned_spawned_shells`] looks for
/// — WITHOUT the `exempt` veto, so both that function and
/// [`spared_exempt_spawned_shells`] read the exact same candidacy test and
/// differ only in which side of `exempt` they keep. See
/// `abandoned_spawned_shells`'s own doc for what each clause means.
fn spawned_shell_shape<'a>(
    sessions: &'a [SessionRecord],
    now_epoch: i64,
    log_mtime: impl Fn(&SessionRecord) -> Option<i64>,
    band: Option<i64>,
) -> impl Iterator<Item = &'a SessionRecord> {
    sessions
        .iter()
        .filter(|s| s.state != "done")
        .filter(|s| s.spawned && s.restore.is_some() && canonical_state(&s.state) == "idle")
        .filter(move |s| match band {
            Some(secs) => {
                log_mtime(s).is_some_and(|seen| now_epoch.saturating_sub(seen) > secs)
            }
            None => true,
        })
}

/// The exempt idle spawned shells the waived arm (`band: None`, a human
/// gesture) skipped — reported by `reap_inner` on `--now` only (module doc:
/// "Sweep visibility"), never on the unattended pass, which would otherwise
/// name them on every ~12s tick forever. `band` is always `None` here: the
/// unattended pass never waives, so it has nothing waived to report.
fn spared_exempt_spawned_shells(
    sessions: &[SessionRecord],
    now_epoch: i64,
    log_mtime: impl Fn(&SessionRecord) -> Option<i64>,
) -> Vec<String> {
    spawned_shell_shape(sessions, now_epoch, log_mtime, None)
        .filter(|s| s.exempt)
        .map(|s| s.session_id.clone())
        .collect()
}

/// Unlink the control sockets left behind by sessions that are no longer on
/// the roster, and return the ids swept.
///
/// `conduct` binds `$XDG_RUNTIME_DIR/aoide/session-<id>.sock` at start and
/// unlinks it on exit — but the sessions this whole module exists for are
/// precisely the ones that never got to run their exit path (SUPER+Q,
/// SIGKILL), so every reap leaves a socket file behind it. Nothing else ever
/// collects them, and the reaper is already the sweep that knows who is gone.
///
/// Three guards, so this can never take a live session's socket:
///   * only `session-*.sock` names are candidates, so the shellbridge's own
///     socket sharing that directory is never one whatever the roster says;
///   * a candidate whose id IS on the roster is skipped outright;
///   * a candidate nothing is listening on is the only one unlinked — a
///     successful `connect` is positive proof of a live `conduct` accept loop,
///     and outranks a roster that merely fails to mention it. (This is also
///     what keeps the unit tests honest: they run against a temp stage whose
///     roster knows none of the desktop's real sessions, and every one of
///     those sockets answers.)
/// Plus [`SOCKET_SETTLE_SECS`] off the file's mtime, for the moment between
/// `bind` and `listen` where an infant socket would refuse a connection.
fn sweep_orphan_sockets(live_ids: &HashSet<&str>, now_epoch: i64) -> Vec<String> {
    use std::os::unix::net::UnixStream;
    let Some(dir) = crate::graph::conduct_socket_path("probe")
        .parent()
        .map(|d| d.to_path_buf())
    else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut swept = Vec::new();
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(id) = name
            .to_str()
            .and_then(|n| n.strip_prefix("session-"))
            .and_then(|n| n.strip_suffix(".sock"))
        else {
            continue;
        };
        if id.is_empty() || live_ids.contains(id) {
            continue;
        }
        let settled = e
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .is_some_and(|d| now_epoch.saturating_sub(d.as_secs() as i64) >= SOCKET_SETTLE_SECS);
        if !settled || UnixStream::connect(e.path()).is_ok() {
            continue;
        }
        if std::fs::remove_file(e.path()).is_ok() {
            swept.push(id.to_string());
        }
    }
    swept.sort();
    swept
}

/// GATHER phase of the ssh tunnel sweep — the half that runs INSIDE
/// `with_stage_lock`, alongside `reap_inner`'s other roster reads. Decides
/// WHICH tunnel records qualify as orphans (roster-less and settled) and
/// returns them for [`sweep_orphan_tunnels`] to act on; touches only
/// already-loaded state and a handful of file stats, nothing that can block
/// for any real duration — see that function's own doc for why the KILL
/// half must never run in here.
///
/// Two guards, mirroring [`sweep_orphan_sockets`]:
///   * a record whose `sessionId` IS on the roster is skipped outright,
///     whatever its pid probe would later say — a live session's tunnel is
///     never this sweep's business;
///   * [`TUNNEL_SETTLE_SECS`] off the record FILE's own mtime spares an
///     infant record from the moment between the forward answering and
///     `open_or_reuse` finishing its write.
/// A record whose file cannot be resolved or stat'd (a mid-write,
/// torn-directory, or permission edge) is skipped, never treated as a hard
/// error — `aoide_storage::tunnel::list_records` already holds this same
/// tolerate-and-continue discipline for a record that fails to parse at
/// all, and this pass must never abort the rest of the directory over one
/// unreadable entry.
fn orphan_tunnel_candidates(
    live_ids: &HashSet<&str>,
    now_epoch: i64,
) -> Vec<aoide_storage::tunnel::TunnelRecord> {
    let mut candidates = Vec::new();
    for rec in aoide_storage::tunnel::list_records() {
        if live_ids.contains(rec.session_id.as_str()) {
            continue;
        }
        let Ok(path) = aoide_storage::tunnel::record_path(&rec.session_id, &rec.key) else {
            continue;
        };
        let settled = std::fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .is_some_and(|d| now_epoch.saturating_sub(d.as_secs() as i64) >= TUNNEL_SETTLE_SECS);
        if !settled {
            continue;
        }
        candidates.push(rec);
    }
    candidates
}

/// KILL phase of the ssh tunnel sweep — unlink (and, when still alive,
/// kill) every candidate [`orphan_tunnel_candidates`] gathered, and return
/// the `<sessionId>/<key>` pairs actually swept.
///
/// **Deliberately called OUTSIDE `with_stage_lock`, unlike
/// [`sweep_orphan_sockets`].** A candidate's pid may still be a live `ssh`
/// child, and `kill_if_still_our_ssh` → `terminate_pid` does a bounded
/// `SIGTERM` + `waitpid`/`/proc` poll that can take up to ~1s PER kill —
/// the exact cost `do_session_end` (`graph/session_store.rs`) already
/// avoids paying under the lock for its own tunnel close. `.stage.lock` is
/// a cross-process flock every other stage writer (hooks, the ~1Hz conduct
/// ticks, the window listener, `session start`/`end`, `send`) blocks on;
/// running N of these kills inside it would serialize the whole desktop
/// for up to N seconds. The socket sweep never faces this because unlinking
/// a leftover file has no comparable cost — a real asymmetry between the
/// two sweeps, not an inconsistency. `orphan_tunnel_candidates` above is
/// the only part that needs the lock (reading the roster mid-sweep), so
/// that is all `reap_inner` runs under it; `reap` calls this function
/// afterward, once the lock is already released.
///
/// A dead pid costs nothing extra: `kill_if_still_our_ssh`'s own liveness
/// check already makes the call a no-op for one, so the dead-pid and the
/// confirmed-dead-after-signaling alive-pid candidates converge on the same
/// unlink below. A candidate that is STILL alive and still ours once
/// `kill_if_still_our_ssh`'s bounded wait elapses (a stubborn or hung
/// child) is left on disk instead — the same "never drop what a kill only
/// ATTEMPTED to clear" rule `aoide_client::tunnel::close` holds: unlinking
/// it here regardless would re-orphan a live child this very sweep just
/// tried to collect, with no further backstop behind it. A record kept
/// this way simply reappears as a candidate on
/// the next sweep pass and gets another try — `orphan_tunnel_candidates`
/// re-gathers from disk every time, so no separate retry bookkeeping is
/// needed. A candidate whose record fails to remove (already gone, a
/// permission edge) is simply not reported swept — never a hard error, and
/// never counted as removed when it wasn't.
fn sweep_orphan_tunnels(candidates: Vec<aoide_storage::tunnel::TunnelRecord>) -> Vec<String> {
    let mut swept = Vec::new();
    for rec in candidates {
        if !aoide_client::tunnel::kill_if_still_our_ssh(rec.pid, rec.local_port, rec.remote_port) {
            continue;
        }
        if aoide_storage::tunnel::remove(&rec.session_id, &rec.key).is_ok() {
            swept.push(format!("{}/{}", rec.session_id, rec.key));
        }
    }
    swept.sort();
    swept
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

/// `session reap` — the automatic liveness sweep. Marks every DEAD (killed,
/// orphaned) session `done` (and its hook record), then reuses [`prune_done`] to
/// drop them + clear orphaned parent links, re-staging `graph.json` atomically.
/// Cheap: one `hyprctl` call + a stage read, and a stage WRITE only when
/// something was actually reaped. NEVER errors non-zero on "nothing to reap" and
/// NEVER on an unavailable compositor (it falls back to pid-only liveness).
///
/// `hyprctl clients -j` is gathered BEFORE the stage lock is taken, not inside
/// it: it is a subprocess call (real wall-clock cost, and a hung `hyprctl`
/// would otherwise hang indefinitely) that touches no stage file, so it needs
/// none of the lock's atomicity — holding the lock across it would block
/// every other stage writer (`send`, session-start/end, hook updates,
/// …) for as long as it runs. The window-liveness signal is already treated
/// as a best-effort, racy-by-nature snapshot throughout this module (see
/// `effective_live_addresses`'s transient-read grace), so gathering it a
/// moment before the lock rather than inside it changes nothing about
/// correctness — only the sessions/hooks read-decide-write below needs the
/// lock, and that still happens entirely inside it.
pub fn reap(inv: &Invocation) -> Outcome {
    let (gathered_addrs, window_owners) = match live_windows() {
        Some((addrs, owners)) => (Some(addrs), Some(owners)),
        None => (None, None),
    };
    let (mut outcome, tunnel_candidates) =
        aoide_storage::fs::with_stage_lock(move || reap_inner(inv, gathered_addrs, window_owners));
    // Finish the ssh tunnel sweep OUTSIDE the stage lock — `reap_inner` only
    // GATHERED the candidates under it (`orphan_tunnel_candidates`); this is
    // the KILL half (`sweep_orphan_tunnels`'s own doc has the full reasoning
    // for why it must never run inside `with_stage_lock`). Folded into
    // `changed` here, same as the reaped/dropped/decayed lines, so a
    // tunnel-only pass still toasts on `reap_and_announce`'s "did anything
    // change" check.
    let swept_tunnels = sweep_orphan_tunnels(tunnel_candidates);
    if !swept_tunnels.is_empty() {
        outcome.message = format!(
            "{}; unlinked {} orphaned tunnel(s)",
            outcome.message,
            swept_tunnels.len()
        );
        outcome.changed.extend(
            swept_tunnels
                .iter()
                .map(|id| format!("unlinked orphaned ssh tunnel {id} (session gone)")),
        );
        if let Some(data) = outcome.data.as_mut() {
            data["orphanTunnels"] = json!(swept_tunnels);
        }
    }
    // The refresh is reported but deliberately NOT folded into `changed`: that
    // vec is the sweep's ledger (what entered or left the roster), and it is
    // what decides whether the timer toasts. An agent merely speaking must not
    // ring the desktop every twelve seconds.
    let refreshed = refresh_live_agents();
    if !refreshed.is_empty() {
        outcome.message = format!(
            "{}; refreshed {} live agent(s)",
            outcome.message,
            refreshed.len()
        );
        if let Some(data) = outcome.data.as_mut() {
            data["refreshed"] = json!(refreshed);
        }
    }
    outcome
}

/// Resolve "a person asked for this" AT THE DOOR and normalize it onto the
/// invocation as `--now`, before anything is dispatched or swept. Pure over
/// its input (the tty probe aside) and returns the invocation to use.
///
/// Two gestures mean the same thing and both land here as one flag:
///   * the dock's `[ reap ]` control, which passes `--now` itself
///     (`shellbridge.rs`'s `dispatch_recheck_sessions`) — it runs as a
///     detached child with no tty, so nothing could infer it after the fact;
///   * `aoide session reap` typed at a real terminal, which
///     [`aoide_protocol::pick::interactive`] recognises — this repo's one
///     probe for "a person is at a keyboard", the same one the pickers gate
///     on, door-checked first so no non-CLI door can ever read as a human.
/// Everything else — the ~12s systemd timer, the daemon's own tick, an
/// agent's piped shell — is the unattended sweep and keeps the band.
///
/// It has to happen HERE rather than inside the sweep. `daemon_dispatch`
/// forwards path/args/FLAGS to a resident `aoided` and the sweep then runs
/// over there, with no tty and a `Door::Daemon` invocation: a probe made on
/// the far side would answer false for every gesture, and the button's
/// behaviour would silently depend on whether the daemon happened to be up.
/// The flag is the fact; this probe is only how the CLI door computes it.
///
/// `--announce` is deliberately NOT a second way in. It means "toast even on
/// a quiet pass", which is a display concern, and a caller that wants the
/// answer without the sweeping it now would have no way to say so if the two
/// were welded together.
fn with_human_gesture(inv: &Invocation) -> Invocation {
    let mut inv = inv.clone();
    if aoide_protocol::pick::interactive(inv.door) {
        inv.flags.insert("now".to_string(), "true".to_string());
    }
    inv
}

/// The `session reap` COMMAND — [`reap`], plus the desktop toast that says what it
/// did. Registered as the command handler while `reap` itself stays toast-free,
/// so every in-crate caller (and every unit test) gets the sweep without
/// spawning notifiers.
///
/// Two callers, one rule each:
///   * the ~12s timer sweeps unannounced and toasts only when it CHANGED
///     something (`outcome.changed` — the reaped/dropped/decayed lines). A
///     death is worth a toast; a quiet pass twelve seconds later is not, and
///     the transcript refresh never counts (it moves no session in or out of
///     the roster, and would toast every time an agent spoke).
///   * `--announce` toasts unconditionally: it marks a HUMAN gesture (the dock's
///     `[ reap ]` control, via shellbridge), and a pressed button must answer
///     even when the answer is "nothing to reap".
///
/// [`with_human_gesture`] runs FIRST, before the daemon hop: a bare
/// `aoide session reap` typed at a terminal is a person asking, and picks up
/// `--now` (the abandoned-shell band waived) on the way past.
///
/// Whether the toast was actually handed off lands in `data.announced`, so the
/// shellbridge's audit log answers "did the button ring the daemon" on its own
/// — a missing notifier is otherwise an `eprintln` into a systemd child's
/// stderr, i.e. invisible exactly when someone is asking why nothing appeared.
///
/// P-D6 graph residency (`docs/architecture/AOIDED.md`'s "L4"/"Liveness"):
/// tries the resident daemon's `dispatch` op first — daemon up, the sweep
/// (and its toast) run IN the daemon against its own roster; daemon down,
/// this falls back to the direct sweep below byte-identically. The ~12s
/// systemd timer keeps firing `aoide session reap` either way; once a daemon
/// is resident this makes the timer a redundant backstop rather than the
/// mechanism (the daemon's own tick also runs this same reap internally —
/// `aoide_server::daemon::run_loop`).
pub fn reap_and_announce(inv: &Invocation) -> Outcome {
    let inv = &with_human_gesture(inv);
    if let Some(outcome) = aoide_client::daemon::daemon_dispatch(inv) {
        return outcome;
    }
    let mut outcome = reap(inv);
    if inv.flag_present("announce") || !outcome.changed.is_empty() {
        let announced = announce_reap(&outcome.message);
        if let Some(data) = outcome.data.as_mut() {
            data["announced"] = json!(announced);
        }
    }
    outcome
}

/// Raise the reap toast through the stock freedesktop client, detached: spawned
/// and collected on its own thread so a slow/hung `notify-send` can never delay
/// the sweep's own exit (the reaper is a `oneshot` on a 12s timer — a wedged
/// child would stack units). A missing/failed notifier is an eprintln, never an
/// error: the sweep already happened, and losing the toast must not turn a
/// successful reap into a failed one. Same idiom as shellbridge's
/// `dispatch_rice_mode_toggle`.
///
/// Returns whether the notifier was handed the toast at all (the spawn
/// succeeded) — never whether the daemon drew it, which is dunst's business
/// and the herald's after that.
fn announce_reap(message: &str) -> bool {
    match std::process::Command::new("notify-send")
        // No `--icon`: dunst stacks the icon slot on TOP of the stele at up to
        // 48px, and a picture is not what a one-line sweep report needs. The
        // sweep's mark is a GLYPH in the summary instead — 𓌳 (U+13333, the
        // Egyptian sickle), which costs no layout slot at all and reads as
        // this command and no other in the herald ledger. U+13333 and not its
        // neighbour U+13334: the two are the same sign, and 13334 is the
        // variant drawn as a bare blade — 13333 is the one that keeps the
        // upright shaft, and a scythe with no handle is a knife. The shaft
        // survives down to 18px, well under the herald title's size.
        // Covered by the rig's
        // own font set: `noto-fonts` (modules/dendrites/fonts.nix) ships
        // NotoSansEgyptianHieroglyphs, so pango's and Qt's fontconfig
        // fallback both resolve it rather than drawing tofu.
        //
        // The word leads and the sickle follows: the herald card already
        // carries `aoide` in its own header row, so the summary owes no app
        // name — it says what happened, and the glyph closes the line.
        .args(["--app-name=aoide", "reaped 𓌳"])
        .arg(message)
        .spawn()
    {
        Ok(mut child) => {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            true
        }
        Err(e) => {
            eprintln!("[aoide/reap] notify-send failed (the sweep itself succeeded): {e}");
            false
        }
    }
}

/// Re-read every SURVIVING agent's transcript and publish what changed — its
/// `say`, `tool`, `model` and context fill (and the same for its sub-agents).
///
/// Those fields are otherwise only refreshed when a hook fires, so an agent
/// whose harness has no hooks wired (or which is mid-turn between boundaries)
/// shows whatever it last said an hour ago. The reaper already runs every ~12s
/// and is what BOTH dock refresh buttons invoke, so this is where "make the
/// roster current" belongs: reaping decides who is alive, this decides what the
/// living are doing.
///
/// Runs AFTER `reap_inner`'s lock is released, never inside it: each refresh
/// takes the stage lock itself (they are the same functions the hook path
/// calls), so doing this under the reap lock would deadlock. That means it acts
/// on the post-sweep roster — the dead are already gone and never get a read.
///
/// Best-effort throughout: a session whose transcript can't be located is
/// silently skipped, and every write is change-only, so a quiet desktop does no
/// stage writes at all. Sub-agents are refreshed through their PARENT (their
/// `sub:<tuid>` id has no transcript of its own to locate); shells and a2a
/// records have no transcript at all and are skipped outright.
/// Returns the ids of the agents whose records actually MOVED, so the sweep can
/// report (and toast) how many it brought current — an empty vec on a desktop
/// where nothing has been said since the last pass.
fn refresh_live_agents() -> Vec<String> {
    let Ok(file) = load_stage::<SessionsFile>(&sessions_path()) else {
        return Vec::new();
    };
    let live: Vec<&SessionRecord> = file
        .sessions
        .iter()
        .filter(|s| s.state != "done" && is_agent_kind(s))
        .collect();
    let mut refreshed = Vec::new();
    for s in live {
        let profile = profile_for(s);
        let cwd = (!s.cwd.is_empty()).then_some(s.cwd.as_str());
        let own = refresh_transcript_fields(profile, &s.session_id, cwd, None, None);
        let subs = refresh_subagent_says(profile, &s.session_id, cwd);
        if own || subs {
            refreshed.push(s.session_id.clone());
        }
    }
    refreshed
}
/// Returns the sweep's `Outcome` PLUS the ssh tunnel candidates gathered
/// under the stage lock (`orphan_tunnel_candidates`) — this function never
/// kills or unlinks any of them itself. `reap` (the only caller) finishes
/// that work AFTER `with_stage_lock` returns; see `sweep_orphan_tunnels`'s
/// own doc for why the kill phase must never run in here.
fn reap_inner(
    inv: &Invocation,
    gathered_addrs: Option<HashSet<String>>,
    window_owners: Option<HashMap<String, u32>>,
) -> (Outcome, Vec<aoide_storage::tunnel::TunnelRecord>) {
    let cmd = "session.reap";
    let mut s_file: SessionsFile = match load_stage(&sessions_path()) {
        Ok(f) => f,
        Err(e) => return (stage_error(cmd, e), Vec::new()),
    };
    let mut h_file: HooksFile = match load_stage(&hooks_path()) {
        Ok(f) => f,
        Err(e) => return (stage_error(cmd, e), Vec::new()),
    };

    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let hyprctl_available = gathered_addrs.is_some();
    // Apply the transient-read grace: a degenerate empty snapshot during a reload
    // window falls back to pid-only liveness so we never sweep the live roster off
    // a momentary "zero windows" answer.
    let live = effective_live_addresses(gathered_addrs, &s_file.sessions);
    // This session's hook record's `updatedAt` — the exact timestamp
    // `decay_stopped_sessions` below reads for the `stopped` clock, mirrored
    // here as evidence for the third signal too: a foreign-harness/headless
    // session (no window, no pid, no transcript — the `session start`
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
        .filter(|s| is_session_dead(
            s,
            live.as_ref(),
            window_owners.as_ref(),
            proc_exists,
            now_epoch,
            last_seen,
        ))
        .map(|s| s.session_id.clone())
        .collect();

    // Also retire superseded same-window agent duplicates (a phantom re-id whose
    // pid is the terminal's, invisible to the liveness predicate above). Grace:
    // ~60s off startedAt so a just-born pair settles; keeper = the newest-started
    // one, transcript/say only tiebreaking a same-instant tie (see
    // `superseded_agent_duplicates`).
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

    // The pre-boot ghosts: a record whose every evidence stream is older than
    // the machine's own boot instant cannot be attached to anything running —
    // the case a recycled pid otherwise shields forever (see
    // `pre_boot_ghosts`). Reads `/proc/stat` once per pass; unreadable there
    // means the signal simply does not fire.
    for id in pre_boot_ghosts(&s_file.sessions, boot_epoch(), last_seen) {
        if !reaped.contains(&id) {
            reaped.push(id);
        }
    }

    // And the parentless dependents — nodes hanging off a Task call whose
    // parent is no longer in the roster at all, and hook-only agents whose
    // host terminal's record has left the same way (see `orphaned_subagents`).
    // Same settle grace as the dedup above, so an infant awaiting its own
    // parent link is never judged.
    for id in orphaned_subagents(&s_file.sessions, is_recent) {
        if !reaped.contains(&id) {
            reaped.push(id);
        }
    }

    // And the abandoned worker shells: a conducted shell `aoide spawn`
    // created and no one returned to, sitting idle with its pty log
    // untouched past `REAP_SPAWNED_SHELL_STALE_SECS` (see
    // `abandoned_spawned_shells`). The log-mtime probe mirrors `last_seen`'s
    // transcript-mtime read above — a per-session file, read fresh off disk
    // every pass, never cached.
    //
    // `--now` waives that band: the flag marks a human gesture, already
    // resolved at the door by `with_human_gesture` (never re-probed here —
    // this code also runs inside `aoided`, where there is no tty to probe).
    // The other bands in this pass are untouched by it; a person asking for
    // the leftover worker terminals is not asking to judge their agents.
    let log_mtime = |s: &SessionRecord| -> Option<i64> {
        s.log_path
            .as_deref()
            .and_then(|p| std::fs::metadata(p).ok())
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
    };
    let spawned_shell_band = (!inv.flag_present("now")).then_some(REAP_SPAWNED_SHELL_STALE_SECS);
    for id in abandoned_spawned_shells(&s_file.sessions, now_epoch, log_mtime, spawned_shell_band) {
        if !reaped.contains(&id) {
            reaped.push(id);
        }
    }

    // The exempt idle spawned shells the waived arm just skipped — a human
    // gesture only (`spawned_shell_band.is_none()` iff `--now`); the
    // unattended pass reports nothing here (module doc's "Sweep
    // visibility" — it would otherwise name them on every ~12s tick
    // forever). Folded into `message`/`data.spared` below, NEVER `changed`:
    // nothing moves on the roster, so this must not toast the timer.
    let spared: Vec<String> = if spawned_shell_band.is_none() {
        spared_exempt_spawned_shells(&s_file.sessions, now_epoch, log_mtime)
    } else {
        Vec::new()
    };

    // And the tombstones a re-identified terminal leaves behind: `done` agent
    // records whose window already holds a LIVE agent (see
    // `superseded_done_siblings`). Kept OUT of `reaped` deliberately — these
    // records are already `done`, so there is nothing to reap, and folding them
    // in would trip the `prune_done` call below into sweeping every unrelated
    // `done` record on the desktop, which stays `session prune`'s job.
    let superseded_done = superseded_done_siblings(&s_file.sessions);

    // Orphaned hook records: a `hooks.json` entry whose sessionId matches NO
    // session record anywhere in the roster. The hook door always writes the
    // session record before (or with) its hook — `hook_ensure_session`
    // re-creates one on ANY later non-`sub:` event, and a `sub:` phase never
    // upserts a hook at all — so in a lock-consistent snapshot a hook with no
    // session is pure cruft. Neither existing collector reaches it: the liveness
    // predicate above only iterates `sessions.json`, and `prune_done` only drops
    // the hooks of *done sessions*. Left alone it accretes forever (observed
    // live: a `sub:testT1` fixture weeks stale, plus two `stopped` UUID
    // leftovers). Computed against the FULL roster (every state), so it is
    // invariant under the reap-mark / decay / prune that follow — a done
    // session's hook is prune's job and is never miscounted here. A false drop
    // self-heals exactly like a false reap: the hook door re-upserts the record
    // on the session's next event.
    let live_ids: HashSet<&str> =
        s_file.sessions.iter().map(|s| s.session_id.as_str()).collect();
    let orphan_hooks: Vec<String> = h_file
        .hooks
        .iter()
        .filter(|h| !live_ids.contains(h.session_id.as_str()))
        .map(|h| h.session_id.clone())
        .collect();

    // The control sockets dead sessions left in `$XDG_RUNTIME_DIR/aoide`
    // (see `sweep_orphan_sockets`). Computed against the roster MINUS what
    // this pass is about to reap, so a session dropped now has its socket
    // collected on the same pass rather than the next one. Runs BEFORE the
    // quiet-pass early return below on purpose: like the orphaned hooks, the
    // steady state these accumulate in is exactly the pass where nothing else
    // happened.
    let orphan_sockets = {
        let dead: HashSet<&str> = reaped.iter().map(String::as_str).collect();
        let surviving: HashSet<&str> = s_file
            .sessions
            .iter()
            .map(|s| s.session_id.as_str())
            .filter(|id| !dead.contains(id))
            .collect();
        sweep_orphan_sockets(&surviving, now_epoch)
    };

    // The ssh tunnels dead sessions left in `$XDG_RUNTIME_DIR/aoide/tunnel`
    // — GATHERED only (`orphan_tunnel_candidates`), against a roster built
    // the same way the socket sweep's is (minus what THIS pass is about to
    // reap), for the same "collected on the pass that reaped it, not the
    // next one" reason — PLUS one narrowing the socket sweep does not
    // share: a session already `done` (a clean `session end` that ran its
    // own fast-path close, `aoide_client::tunnel::close_all_for_session`)
    // is excluded from "surviving" for TUNNEL candidacy specifically. A
    // `done` session's tunnels have no owner left to close them, but the
    // session RECORD itself stays present until `prune_done` — which only
    // runs on a pass that reaped something — so without this narrowing a
    // record `close` had to keep (its child survived the fast path's own
    // bounded kill) could wait unbounded on an otherwise quiet desktop.
    // Socket sweeping and `prune_done` are untouched by
    // this — a `done` session's control socket is already gone by the time
    // `do_session_end` returns, and pruning `done` records at all remains
    // this pass's own reaped-something gate. The kill phase
    // (`sweep_orphan_tunnels`) runs AFTER this whole function returns and
    // the stage lock is released — see that function's doc for why.
    let tunnel_candidates = {
        let dead: HashSet<&str> = reaped.iter().map(String::as_str).collect();
        let surviving: HashSet<&str> = s_file
            .sessions
            .iter()
            .filter(|s| canonical_state(&s.state) != "done")
            .map(|s| s.session_id.as_str())
            .filter(|id| !dead.contains(id))
            .collect();
        orphan_tunnel_candidates(&surviving, now_epoch)
    };

    // Age out the warm `stopped` badge: a turn that ended more than an hour ago is
    // just `idle` now. This is the one transition no hook can ever deliver (a
    // session left alone emits nothing), so the periodic pass owns it — and it runs
    // on EVERY tick, independent of whether anything was reaped.
    let now = now_iso_utc();
    let decayed = decay_stopped_sessions(&mut s_file.sessions, &mut h_file.hooks, now_epoch, &now);

    if reaped.is_empty()
        && decayed.is_empty()
        && orphan_hooks.is_empty()
        && superseded_done.is_empty()
        && orphan_sockets.is_empty()
        && tunnel_candidates.is_empty()
    {
        // A pressed button that spares something says so, even on an
        // otherwise quiet pass — the whole point of `--now` sparing an
        // exempt shell is invisible to the operator if a quiet pass says
        // nothing at all (module doc's "Sweep visibility").
        let message = if spared.is_empty() {
            "nothing to reap (all sessions live)".to_string()
        } else {
            format!(
                "nothing to reap (all sessions live); spared {} exempt idle spawned shell(s)",
                spared.len()
            )
        };
        return (
            Outcome::ok(cmd, message).with_data(json!({
                "reaped": [],
                "decayed": [],
                "orphanHooks": [],
                "supersededDone": [],
                "orphanSockets": [],
                "orphanTunnels": [],
                "hyprctlAvailable": hyprctl_available,
                "spared": spared,
            })),
            Vec::new(),
        );
    }

    // Mark each reaped session done in BOTH files, then let prune_done drop them
    // (and any pre-existing `done`) + clear orphaned parentSessionIds.
    let dead: HashSet<&str> = reaped.iter().map(String::as_str).collect();
    for s in s_file.sessions.iter_mut() {
        if dead.contains(s.session_id.as_str()) {
            s.state = "done".to_string();
            // The ledger write (P-D8): every id `reaped` collected — the
            // liveness kill AND the dedup/pre-boot-ghost/orphaned-subagent
            // folds above that feed into this same set — leaves the roster
            // HERE. The one shared call `do_session_end_inner`'s own clean
            // exit routes through too (`doc.rs`'s `ledger_session_exit`), so
            // the two roster-exit paths can never double-write or diverge.
            ledger_session_exit(s, &now);
        }
    }
    for id in &reaped {
        upsert_hook(&mut h_file.hooks, id, "done", &now);
    }

    // Prune only when something was actually reaped — a decay-only pass must not
    // start sweeping pre-existing `done` records out from under the widgets (that
    // stays `session prune`'s job, on its own schedule).
    let (removed, mut cleared) = if reaped.is_empty() {
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

    // The check lane's own baseline for every id actually leaving the roster
    // here (task #139 review finding: nothing ever deleted
    // `state/checklane/<id>.json` on THIS exit path — `removed` is
    // `prune_done`'s full drop set, a superset of `reaped` since it also
    // sweeps any pre-existing `done` record). Mirrors the same call
    // `graph/session_store.rs::do_session_end` makes on the clean-exit path;
    // this is the SIGKILL/liveness-reap backstop for the sessions that never
    // got to run that path. Best-effort, same posture as that call: a
    // session with no baseline (the lane was never configured, or it
    // already ran `on_stop`'s own compaction) is a no-op.
    for id in &removed {
        aoide_upkeep::checklane::forget_baseline(id);
    }

    // Drop the superseded tombstones, narrowly — only the ids identified above,
    // never the whole `done` set. Runs on a quiet (non-reaping) pass too, which
    // is the steady state they otherwise accumulate in; when a reaping pass
    // already ran `prune_done` they are gone with the rest, and `drop_sessions`
    // no-ops over ids it cannot find. Routed through the same computation prune
    // uses so the subagent cascade and the dangling-parent clearing still apply.
    if !superseded_done.is_empty() {
        let doomed: HashSet<&str> = superseded_done.iter().map(String::as_str).collect();
        let (kept_s, kept_h, _, also_cleared) =
            drop_sessions(&s_file.sessions, &doomed, std::mem::take(&mut h_file.hooks));
        s_file.sessions = kept_s;
        h_file.hooks = kept_h;
        cleared.extend(also_cleared);
    }

    // Drop the orphaned hook records identified above. Independent of prune
    // (which only fires when something was reaped): orphans must be collected on
    // a decay-only or otherwise-quiet pass too — that steady state is exactly
    // where they otherwise sit forever. Whatever `h_file.hooks` now holds —
    // prune's `kept_h` on a reaping pass, or the decay-updated vector on a
    // non-reaping one — the orphan ids are absent from the live roster either
    // way, so this retain is correct against both.
    if !orphan_hooks.is_empty() {
        let orphaned: HashSet<&str> = orphan_hooks.iter().map(String::as_str).collect();
        h_file.hooks.retain(|h| !orphaned.contains(h.session_id.as_str()));
    }

    if s_file.schema_version.is_empty() {
        s_file.schema_version = STAGE_GRAPH_VERSION.to_string();
    }
    if h_file.schema_version.is_empty() {
        h_file.schema_version = STAGE_GRAPH_VERSION.to_string();
    }
    if let Err(e) = write_stage(&sessions_path(), &s_file) {
        return (stage_error(cmd, e), Vec::new());
    }
    if let Err(e) = write_stage(&hooks_path(), &h_file) {
        return (stage_error(cmd, e), Vec::new());
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
    changed.extend(
        orphan_hooks
            .iter()
            .map(|id| format!("dropped orphaned hook record {id} (no session)")),
    );
    changed.extend(
        superseded_done
            .iter()
            .map(|id| format!("dropped superseded session {id} (its terminal has a live agent)")),
    );
    changed.extend(
        orphan_sockets
            .iter()
            .map(|id| format!("unlinked orphaned control socket of {id} (nothing listening)")),
    );
    // No `orphan_tunnels` entry here: the candidates above are only GATHERED
    // at this point, not yet killed/unlinked. `reap` appends the real
    // swept-tunnel lines to `changed` (and the message, and `data.
    // orphanTunnels`) once it has run `sweep_orphan_tunnels` on
    // `tunnel_candidates` OUTSIDE the stage lock this function returns
    // under.
    match restage_graph() {
        Ok(g) => changed.push(g.to_string_lossy().into_owned()),
        Err(e) => return (stage_error(cmd, e), Vec::new()),
    }
    let mut message = format!(
        "reaped {} dead session(s); dropped {} total; decayed {} stopped → idle; cleared {} orphaned parent link(s); dropped {} orphaned hook record(s); dropped {} superseded session(s); unlinked {} orphaned socket(s)",
        reaped.len(),
        removed.len(),
        decayed.len(),
        cleared.len(),
        orphan_hooks.len(),
        superseded_done.len(),
        orphan_sockets.len()
    );
    // A pressed button that spares something says so (module doc's "Sweep
    // visibility") — folded into the message and `data.spared`, never
    // `changed`: nothing moved on the roster for these ids.
    if !spared.is_empty() {
        message = format!("{message}; spared {} exempt idle spawned shell(s)", spared.len());
    }
    let outcome = Outcome::ok(cmd, message)
        .changed(changed)
        .with_data(json!({
            "reaped": reaped,
            "removed": removed,
            "decayed": decayed,
            "clearedParents": cleared,
            "orphanHooks": orphan_hooks,
            "supersededDone": superseded_done,
            "orphanSockets": orphan_sockets,
            "orphanTunnels": Vec::<String>::new(),
            "hyprctlAvailable": hyprctl_available,
            "spared": spared,
        }));
    (outcome, tunnel_candidates)
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

    /// A `kind:"subagent"` Task-tool node: no `windowAddress`, no `pid` —
    /// exactly the shape of the two 11h-stale `working` ghosts
    /// `REAP_SUBAGENT_STALE_SECS` exists for.
    fn subagent(id: &str, state: &str) -> SessionRecord {
        SessionRecord {
            session_id: id.into(),
            agent: "general-purpose".into(),
            window_address: String::new(),
            state: state.into(),
            pid: None,
            kind: Some("subagent".into()),
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
            None,
            |_| true,
            now,
            stale,
        ));
        // `stopped` is equally "at rest" and equally reapable once stale.
        assert!(is_session_dead(
            &hook_only("orphan-stopped", "stopped"),
            None,
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
            None,
            |_| true,
            now,
            one_hour_ago,
        ));
    }

    #[test]
    fn midturn_sessions_reaped_only_past_the_week_band() {
        // No window, no pid, `working` — the headless record stuck mid-turn
        // whose process is gone. 100h of silence is under the 7-day band (a
        // legitimate long-running headless turn can be hook-silent for days);
        // 200h is past it — silence that long IS abandonment.
        let now = 1_800_000_000_i64;
        let hundred_hours = |_: &SessionRecord| Some(now - 100 * 3600);
        let two_hundred_hours = |_: &SessionRecord| Some(now - 200 * 3600);
        assert!(!is_session_dead(
            &hook_only("busy", "working"),
            None,
            None,
            |_| true,
            now,
            hundred_hours,
        ));
        assert!(is_session_dead(
            &hook_only("busy", "working"),
            None,
            None,
            |_| true,
            now,
            two_hundred_hours,
        ));
        // `awaiting` is equally mid-turn.
        assert!(is_session_dead(
            &hook_only("asking", "awaiting"),
            None,
            None,
            |_| true,
            now,
            two_hundred_hours,
        ));
    }

    #[test]
    fn subagent_midturn_sessions_reaped_past_the_subagent_band_not_the_week_band() {
        // A `kind:"subagent"` record cannot outlive its parent's own Task
        // call, so mid-turn silence is judged against the much shorter
        // REAP_SUBAGENT_STALE_SECS (2h) — NOT the general 7-day
        // REAP_WORKING_STALE_SECS band `hook_only` records above use.
        let now = 1_800_000_000_i64;
        let thirty_minutes = |_: &SessionRecord| Some(now - 30 * 60);
        let three_hours = |_: &SessionRecord| Some(now - 3 * 3600);
        let eleven_hours = |_: &SessionRecord| Some(now - 11 * 3600);

        // 30m of silence: comfortably inside a real multi-tool subagent turn.
        assert!(!is_session_dead(
            &subagent("busy-sub", "working"),
            None,
            None,
            |_| true,
            now,
            thirty_minutes,
        ));
        // 3h: past the 2h subagent band (though still nowhere near the 7-day
        // general one) — silence that long is abandonment for a subagent.
        assert!(is_session_dead(
            &subagent("busy-sub", "working"),
            None,
            None,
            |_| true,
            now,
            three_hours,
        ));
        // `awaiting` is equally mid-turn for a subagent.
        assert!(is_session_dead(
            &subagent("asking-sub", "awaiting"),
            None,
            None,
            |_| true,
            now,
            three_hours,
        ));
        // The actual 11h-stale shape of the two live ghosts that motivated
        // this constant is caught, well past the 2h band.
        assert!(is_session_dead(
            &subagent("ghost-sub", "working"),
            None,
            None,
            |_| true,
            now,
            eleven_hours,
        ));
    }

    // ── exempt (task #20): vetoes `stale_abandoned` alone, in every band —
    // window-gone and pid-gone are untouched by it ───────────────────────

    #[test]
    fn exempt_record_survives_stale_abandonment_in_every_band() {
        let now = 1_800_000_000_i64;
        let hundred_hours = |_: &SessionRecord| Some(now - 100 * 3600); // past at-rest (72h) and subagent (2h) bands
        let two_hundred_hours = |_: &SessionRecord| Some(now - 200 * 3600); // past the working band (7d)

        let mut idle = hook_only("shielded-idle", "idle");
        idle.exempt = true;
        assert!(
            !is_session_dead(&idle, None, None, |_| true, now, hundred_hours),
            "the at-rest band must not condemn an exempt record"
        );

        let mut working = hook_only("shielded-working", "working");
        working.exempt = true;
        assert!(
            !is_session_dead(&working, None, None, |_| true, now, two_hundred_hours),
            "the mid-turn band must not condemn an exempt record"
        );

        let mut sub = subagent("shielded-sub", "working");
        sub.exempt = true;
        assert!(
            !is_session_dead(&sub, None, None, |_| true, now, hundred_hours),
            "the subagent band must not condemn an exempt record either"
        );
    }

    #[test]
    fn exempt_record_is_still_reaped_by_the_window_gone_signal() {
        // Staleness is the only signal class the exemption vetoes -- a
        // vanished window is positive proof the session is gone, and the
        // exemption never promises otherwise.
        let now = 1_800_000_000_i64;
        let fresh = |_: &SessionRecord| Some(now); // no staleness in play at all
        let mut rec = agent("shielded", "0xAAA", "2026-07-30T00:00:00Z");
        rec.exempt = true;
        let live: HashSet<String> = HashSet::new(); // the window is NOT among the live set
        assert!(is_session_dead(&rec, Some(&live), None, |_| true, now, fresh));
    }

    #[test]
    fn exempt_record_is_still_reaped_by_the_pid_gone_signal() {
        let now = 1_800_000_000_i64;
        let fresh = |_: &SessionRecord| Some(now);
        let mut rec = hook_only("shielded-pid", "working");
        rec.exempt = true;
        rec.pid = Some(42);
        assert!(is_session_dead(&rec, None, None, |_| false, now, fresh)); // pid 42 gone
    }

    #[test]
    fn subagent_band_does_not_shrink_the_general_headless_working_band() {
        // The short band is SPECIFIC to kind=="subagent" — an ordinary
        // headless `working` record (a real long-running headless agent, no
        // window, no pid, kind neither "agent" nor "subagent") must still get
        // the full week-long grace, not accidentally inherit the short one.
        // 3h is past the subagent band but nowhere near the week-long one.
        let now = 1_800_000_000_i64;
        let three_hours = |_: &SessionRecord| Some(now - 3 * 3600);
        assert!(!is_session_dead(
            &hook_only("busy-headless", "working"),
            None,
            None,
            |_| true,
            now,
            three_hours,
        ));
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
        assert!(!is_session_dead(&rec, None, None, |_| true, now, last_seen));
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

        let out = reap(&crate::graph::testutil::invocation(&["session", "reap"], &[]));
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

    /// The orphan-hook gap, end-to-end through `reap()`: a `hooks.json` record
    /// whose sessionId matches no session anywhere (the `sub:testT1` /
    /// stale-UUID leftovers seen live) is collected by a reap pass — neither the
    /// liveness predicate (it iterates `sessions.json` only) nor `prune_done` (it
    /// drops the hooks of *done sessions* only) ever reached it, so it used to
    /// sit forever, even on an otherwise-quiet pass that reaps and decays
    /// nothing. A live session's own hook is untouched.
    #[test]
    fn reap_drops_orphaned_hook_records_with_no_session() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env =
            crate::graph::testutil::EnvVars::save(&["AOIDE_STAGE_DIR", "HYPRLAND_INSTANCE_SIGNATURE"]);
        std::env::remove_var("HYPRLAND_INSTANCE_SIGNATURE"); // pid-only/no-window liveness
        let stage = crate::graph::testutil::unique_stage("reap-orphan-hooks");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // One live session (fresh hook, so never reaped) plus two orphan hooks
        // whose ids match no session record at all.
        let mut live = hook_only("live-1", "idle");
        live.started_at = now_iso_utc();
        live.cwd = "/nonexistent/nowhere".into();
        write_stage(
            &sessions_path(),
            &SessionsFile {
                schema_version: "0".into(),
                sessions: vec![live],
            },
        )
        .unwrap();
        let mut hooks = Vec::new();
        upsert_hook(&mut hooks, "live-1", "idle", &now_iso_utc()); // matches a session — kept
        upsert_hook(&mut hooks, "sub:testT1", "working", "2026-07-30T15:44:37Z"); // orphan
        upsert_hook(&mut hooks, "ghost-uuid", "stopped", "2026-08-03T08:58:21Z"); // orphan
        write_stage(
            &hooks_path(),
            &HooksFile {
                schema_version: "0".into(),
                hooks,
            },
        )
        .unwrap();

        let out = reap(&crate::graph::testutil::invocation(&["session", "reap"], &[]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let data = out.data.unwrap();
        let mut orphans: Vec<String> = data["orphanHooks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        orphans.sort();
        assert_eq!(
            orphans,
            vec!["ghost-uuid".to_string(), "sub:testT1".to_string()],
            "both session-less hook records are collected"
        );

        let h2: HooksFile = load_stage(&hooks_path()).unwrap();
        let ids: HashSet<&str> = h2.hooks.iter().map(|h| h.session_id.as_str()).collect();
        assert!(ids.contains("live-1"), "the live session's hook survives");
        assert!(!ids.contains("sub:testT1"), "the orphan hook is dropped from the file");
        assert!(!ids.contains("ghost-uuid"), "the orphan hook is dropped from the file");

        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn windowed_agent_at_rest_with_stale_evidence_is_reaped() {
        // THE hardened corpse: an agent killed inside its still-open terminal —
        // live window, live TERMINAL-owner pid, yet every evidence stream 100h
        // stale. Before the hardening, the live pid + live window shielded this
        // record from every signal forever; the staleness bands now condemn it.
        let now = 1_800_000_000_i64;
        let stale = |_: &SessionRecord| Some(now - 100 * 3600);
        let mut rec = agent("ghost", "0xAAA", "2026-07-30T00:00:00Z");
        rec.state = "idle".into();
        rec.pid = Some(42); // the terminal's pid — alive
        let live: HashSet<String> = ["aaa"].iter().map(|s| s.to_string()).collect();
        let mut owners: HashMap<String, u32> = HashMap::new();
        owners.insert("aaa".into(), 42); // the window belongs to pid 42
        assert!(is_session_dead(
            &rec,
            Some(&live),
            Some(&owners),
            |_| true,
            now,
            stale,
        ));
    }

    #[test]
    fn windowed_agent_with_a_live_agent_pid_is_never_staleness_reaped() {
        // Post-payload-pid pi: the record's pid is the AGENT's own process —
        // alive and NOT the window's owner. Positive proof of life: staleness
        // must never fire over it, however stale the evidence — the pid signal
        // alone governs it (and fires the moment that process dies).
        let now = 1_800_000_000_i64;
        let stale = |_: &SessionRecord| Some(now - 100 * 3600);
        let mut rec = agent("p9", "0xAAA", "2026-07-30T00:00:00Z");
        rec.state = "idle".into();
        rec.pid = Some(999); // the agent's own pid — alive
        let live: HashSet<String> = ["aaa"].iter().map(|s| s.to_string()).collect();
        let mut owners: HashMap<String, u32> = HashMap::new();
        owners.insert("aaa".into(), 42); // the window belongs to the terminal
        assert!(!is_session_dead(
            &rec,
            Some(&live),
            Some(&owners),
            |_| true, // pid 999 alive
            now,
            stale,
        ));
        // Its death is caught by the pid signal, exactly as before.
        assert!(is_session_dead(
            &rec,
            Some(&live),
            Some(&owners),
            |p| p != 999, // pid 999 gone
            now,
            stale,
        ));
    }

    #[test]
    fn windowed_shell_with_stale_evidence_is_spared() {
        // The kind gate: a shell record's pid IS its terminal — a live pid
        // means the shell is alive, and staleness must never overrule that.
        let now = 1_800_000_000_i64;
        let stale = |_: &SessionRecord| Some(now - 100 * 3600);
        let mut shell = agent("sh", "0xAAA", "2026-07-30T00:00:00Z");
        shell.agent = "shell".into();
        shell.kind = Some("shell".into());
        shell.state = "idle".into();
        shell.pid = Some(42);
        let live: HashSet<String> = ["aaa"].iter().map(|s| s.to_string()).collect();
        let mut owners: HashMap<String, u32> = HashMap::new();
        owners.insert("aaa".into(), 42);
        assert!(!is_session_dead(
            &shell,
            Some(&live),
            Some(&owners),
            |_| true,
            now,
            stale,
        ));
    }

    #[test]
    fn pid_dead_signal_is_unchanged_by_the_new_third_signal() {
        // The pre-existing pid-gone signal still fires exactly as before — the
        // third signal only ADDS a case, it never masks or weakens signal (b).
        let now = 1_800_000_000_i64;
        let fresh = |_: &SessionRecord| Some(now);
        let mut rec = hook_only("pid-dead", "working");
        rec.pid = Some(42);
        assert!(is_session_dead(&rec, None, None, |_| false, now, fresh));
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
    fn superseded_agent_duplicates_keeps_the_newer_twin_even_transcript_less() {
        // The compact/resume ghost this function exists for: the terminal's
        // claude was compacted, minting a NEW sessionId in the same window
        // while the OLD one never got a clean SessionEnd. The user hasn't said
        // anything to the fresh session yet — no transcript, no `say` — while
        // the stale one still carries both from before the compact. Ranking
        // on `has_transcript` first used to keep the STALE record and reap the
        // live one; `startedAt` must win instead, since the newer id is always
        // the terminal's real current occupant.
        let mut old = agent("old-session", "0xW", "2026-08-17T07:00:00Z");
        old.kind = Some("agent".into());
        old.say = Some("last thing I said before compacting".into());
        let mut fresh = agent("new-session", "0xW", "2026-08-17T08:00:00Z");
        fresh.kind = Some("agent".into());
        // fresh has no `say` yet — matches a session that hasn't spoken.

        let sessions = vec![old, fresh];
        let none_recent = |_: &SessionRecord| false;
        // Ground truth: only the OLD session has an on-disk transcript so far.
        let has_tx = |s: &SessionRecord| s.session_id == "old-session";

        let losers = superseded_agent_duplicates(&sessions, none_recent, has_tx);
        assert_eq!(
            losers,
            vec!["old-session".to_string()],
            "the newer, still-transcript-less session is the real occupant and must survive"
        );
    }

    /// Defense in depth (task #89, review round 2): even if something
    /// upstream still manages to stamp a shared window onto a lineage-
    /// related pair — never the healthy-roster case after this task's fix,
    /// since a windowless-by-construction nested session no longer
    /// re-acquires its launching agent's window at all — the dedup pass
    /// must not retire a member of the KEEPER's own lineage. An UNRELATED
    /// same-window twin with no lineage relation to the keeper still gets
    /// retired exactly as before.
    #[test]
    fn superseded_agent_duplicates_spares_the_keepers_own_lineage_but_not_an_unrelated_twin() {
        let mut claude = agent("claude", "0xW", "2026-08-24T01:00:00Z");
        claude.kind = Some("agent".into());
        let mut nested = agent("nested", "0xW", "2026-08-24T03:00:00Z"); // latest → keeper
        nested.kind = Some("agent".into());
        nested.parent_session_id = Some("claude".into());
        let mut twin = agent("twin", "0xW", "2026-08-24T02:00:00Z"); // no lineage relation
        twin.kind = Some("agent".into());

        let sessions = vec![claude, nested, twin];
        let none_recent = |_: &SessionRecord| false;
        let no_tx = |_: &SessionRecord| false;

        let losers = superseded_agent_duplicates(&sessions, none_recent, no_tx);
        assert_eq!(
            losers,
            vec!["twin".to_string()],
            "claude survives as the keeper's own ancestor; the unrelated twin still retires"
        );
    }

    #[test]
    fn superseded_done_siblings_drops_tombstones_only_beside_a_live_agent() {
        // The live shape: ONE kitty window (0xW) whose claude was re-identified
        // three times — three `done` records plus the working one — beside the
        // conducted shell that hosts them all. A second window (0xZ) holds a
        // lone `done` agent: nothing supersedes it, so that tombstone is the
        // done pose the widgets deliberately show and must survive.
        let done = |id: &str, win: &str, started: &str| {
            let mut r = agent(id, win, started);
            r.kind = Some("agent".into());
            r.state = "done".into();
            r
        };
        let mut live = agent("0f317777", "0xW", "2026-08-17T07:57:00Z");
        live.kind = Some("agent".into());
        let mut shell = agent("conduct-865994", "0xW", "2026-08-17T01:00:00Z");
        shell.agent = "shell".into();
        shell.kind = Some("shell".into());
        shell.conductable = Some(true);
        shell.state = "done".into(); // even a done SHELL is not an agent tombstone
        let sessions = vec![
            done("14bc78ab", "0xW", "2026-08-17T07:56:00Z"),
            done("cc55b87b", "0xW", "2026-08-17T07:56:20Z"),
            done("e0eb7197", "0xW", "2026-08-17T07:56:40Z"),
            live,
            shell,
            done("lonely", "0xZ", "2026-08-17T07:00:00Z"),
        ];

        let mut losers = superseded_done_siblings(&sessions);
        losers.sort();
        assert_eq!(
            losers,
            vec![
                "14bc78ab".to_string(),
                "cc55b87b".to_string(),
                "e0eb7197".to_string()
            ],
            "a live agent supersedes EVERY tombstone in its window; the lone one elsewhere stands"
        );
    }

    #[test]
    fn superseded_done_siblings_keeps_the_newest_tombstone_when_nothing_is_live() {
        // The same terminal one moment later — its last claude has exited too,
        // so the window holds nothing but tombstones. Exactly one survives (the
        // NEWEST — the agent that actually just finished, whose done pose is
        // owed), not all four: a window is never left with two agent rows, and
        // never with none.
        let done = |id: &str, started: &str| {
            let mut r = agent(id, "0xW", started);
            r.kind = Some("agent".into());
            r.state = "done".into();
            r
        };
        let sessions = vec![
            done("14bc78ab", "2026-08-17T07:56:00Z"),
            done("newest", "2026-08-17T07:57:00Z"),
            done("cc55b87b", "2026-08-17T07:56:20Z"),
        ];
        let mut losers = superseded_done_siblings(&sessions);
        losers.sort();
        assert_eq!(losers, vec!["14bc78ab".to_string(), "cc55b87b".to_string()]);

        // A lone tombstone is never touched — nothing supersedes it.
        assert!(superseded_done_siblings(&[done("solo", "2026-08-17T07:56:00Z")]).is_empty());
    }

    #[test]
    fn superseded_done_siblings_ignores_windowless_and_unwindowed_records() {
        // A `sub:` node carries no windowAddress, so it never enters a window
        // group however it is stated — and a done subagent beside a live main
        // agent is the cascade's business, not this one's.
        let mut sub = subagent("sub:x", "done");
        sub.window_address = String::new();
        let mut live = agent("main", "0xW", "2026-08-17T07:57:00Z");
        live.kind = Some("agent".into());
        assert!(superseded_done_siblings(&[sub, live]).is_empty());
    }

    /// End-to-end through `reap()`: the tombstones go, on a pass that reaps
    /// nothing else — the quiet steady state they used to accumulate in,
    /// because `prune_done` fires only when something was actually reaped. The
    /// live sibling and an unrelated lone tombstone both survive.
    #[test]
    fn reap_refreshes_a_live_agents_say_and_tool_from_its_transcript() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = crate::graph::testutil::EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "HYPRLAND_INSTANCE_SIGNATURE",
            "HOME",
        ]);
        std::env::remove_var("HYPRLAND_INSTANCE_SIGNATURE"); // pid-only/no-window liveness
        let stage = crate::graph::testutil::unique_stage("reap-refresh");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // A transcript in a project bucket that does NOT match the session's
        // cwd — the real drift (Claude Code fixes its bucket at launch, the
        // roster's cwd follows the session), and the case the reaper must still
        // find, since it has no hook payload to hint with.
        let home = stage.join("home");
        let bucket = home.join(".claude/projects/-somewhere-else");
        std::fs::create_dir_all(&bucket).unwrap();
        std::fs::write(
            bucket.join("talker.jsonl"),
            concat!(
                r#"{"type":"assistant","message":{"content":[{"type":"text","text":"on it"},"#,
                r#"{"type":"tool_use","name":"Bash","input":{"command":"cargo test"}}]}}"#,
                "\n"
            ),
        )
        .unwrap();
        std::env::set_var("HOME", &home);

        let now = now_iso_utc();
        let mut rec = agent("talker", "0xW", &now);
        rec.kind = Some("agent".into());
        rec.state = "working".into();
        rec.pid = None; // no pid signal — nothing here is liveness-reapable
        rec.cwd = "/some/deep/subdir".into();
        write_stage(
            &sessions_path(),
            &SessionsFile {
                schema_version: "0".into(),
                sessions: vec![rec],
            },
        )
        .unwrap();
        write_stage(
            &hooks_path(),
            &HooksFile {
                schema_version: "0".into(),
                hooks: Vec::new(),
            },
        )
        .unwrap();

        // A QUIET pass — nothing to reap — still refreshes the living.
        let out = reap(&crate::graph::testutil::invocation(&["session", "reap"], &[]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let s2: SessionsFile = load_stage(&sessions_path()).unwrap();
        let got = &s2.sessions[0];
        assert_eq!(got.say.as_deref(), Some("on it"));
        assert_eq!(got.tool.as_deref(), Some("Bash: cargo test"));

        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn reap_drops_superseded_done_siblings_on_an_otherwise_quiet_pass() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env =
            crate::graph::testutil::EnvVars::save(&["AOIDE_STAGE_DIR", "HYPRLAND_INSTANCE_SIGNATURE"]);
        std::env::remove_var("HYPRLAND_INSTANCE_SIGNATURE"); // pid-only/no-window liveness
        let stage = crate::graph::testutil::unique_stage("reap-superseded-done");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let now = now_iso_utc();
        let mk = |id: &str, win: &str, state: &str| {
            let mut r = agent(id, win, &now);
            r.kind = Some("agent".into());
            r.state = state.into();
            r.pid = None; // no pid signal — nothing here is liveness-reapable
            r.cwd = "/nonexistent/nowhere".into();
            r
        };
        write_stage(
            &sessions_path(),
            &SessionsFile {
                schema_version: "0".into(),
                sessions: vec![
                    mk("ghost-1", "0xW", "done"),
                    mk("ghost-2", "0xW", "done"),
                    mk("live", "0xW", "working"),
                    mk("lonely", "0xZ", "done"),
                ],
            },
        )
        .unwrap();
        let mut hooks = Vec::new();
        for id in ["ghost-1", "ghost-2", "live", "lonely"] {
            upsert_hook(&mut hooks, id, "working", &now);
        }
        write_stage(
            &hooks_path(),
            &HooksFile {
                schema_version: "0".into(),
                hooks,
            },
        )
        .unwrap();

        let out = reap(&crate::graph::testutil::invocation(&["session", "reap"], &[]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let data = out.data.unwrap();
        assert_eq!(data["reaped"], json!([]), "nothing here is liveness-dead");
        let mut superseded: Vec<String> = data["supersededDone"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        superseded.sort();
        assert_eq!(
            superseded,
            vec!["ghost-1".to_string(), "ghost-2".to_string()]
        );

        let s2: SessionsFile = load_stage(&sessions_path()).unwrap();
        let ids: HashSet<&str> = s2.sessions.iter().map(|s| s.session_id.as_str()).collect();
        assert_eq!(
            ids,
            ["live", "lonely"].into_iter().collect::<HashSet<&str>>(),
            "the tombstones beside a live agent go; the live one and the lone tombstone stay"
        );
        // Their hook records leave with them (else the next pass reads them as
        // orphans), and the survivors keep theirs.
        let h2: HooksFile = load_stage(&hooks_path()).unwrap();
        let hook_ids: HashSet<&str> = h2.hooks.iter().map(|h| h.session_id.as_str()).collect();
        assert_eq!(
            hook_ids,
            ["live", "lonely"].into_iter().collect::<HashSet<&str>>()
        );

        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn reap_appends_exactly_one_ledger_line_per_reaped_session() {
        // P-D8: the `reaped` half of "clean end and reap each produce one
        // ledger line, never two" — `do_session_end`'s own half lives in
        // `session_store.rs`'s test suite. A pre-boot ghost (every evidence
        // stream predates `boot_epoch()`) is used to guarantee a REAL reap
        // deterministically, with no dependency on a real `/proc/<pid>`
        // probe finding a pid absent.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = crate::graph::testutil::EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "HYPRLAND_INSTANCE_SIGNATURE",
        ]);
        std::env::remove_var("HYPRLAND_INSTANCE_SIGNATURE"); // pid-only/no-window liveness
        let stage = crate::graph::testutil::unique_stage("reap-ledger");
        let state = stage.join("state");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);

        let mut dead = hook_only("dead-1", "idle");
        dead.started_at = "2000-01-01T00:00:00Z".into(); // long before any real boot
        dead.cwd = "/nonexistent/pre-boot-ghost".into();
        write_stage(
            &sessions_path(),
            &SessionsFile { schema_version: "0".into(), sessions: vec![dead] },
        )
        .unwrap();

        let out = reap(&crate::graph::testutil::invocation(&["session", "reap"], &[]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let reaped: Vec<String> = out.data.as_ref().unwrap()["reaped"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert!(reaped.contains(&"dead-1".to_string()), "reaped: {reaped:?}");

        let lines = aoide_storage::ledger::read_ledger().unwrap();
        let mine: Vec<_> = lines.iter().filter(|l| l.session_id == "dead-1").collect();
        assert_eq!(mine.len(), 1, "exactly one ledger line, never two: {lines:?}");
        assert!(!mine[0].ended_at.is_empty());

        let _ = std::fs::remove_dir_all(&stage);
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

    #[test]
    fn pre_boot_ghosts_are_condemned_and_everything_since_the_boot_is_spared() {
        // The signal the recycled pid used to shield: a record whose evidence
        // is all older than the machine's boot instant cannot be attached to
        // anything running, whatever `/proc/<pid>` now says.
        let boot = 1_800_000_000_i64;
        let ghost = hook_only("from-last-boot", "working");
        let live = hook_only("since-boot", "working");
        let sessions = vec![ghost, live, hook_only("already-done", "done")];

        // An hour before boot for the ghost, a minute after it for the live
        // one; the `done` record is never in scope whatever its evidence.
        let seen = |s: &SessionRecord| match s.session_id.as_str() {
            "from-last-boot" | "already-done" => Some(boot - 3600),
            _ => Some(boot + 60),
        };
        assert_eq!(
            pre_boot_ghosts(&sessions, Some(boot), seen),
            vec!["from-last-boot".to_string()],
        );

        // Inside the skew grace: evidence a minute before boot is a clock
        // step, not a previous boot.
        let just_before = |_: &SessionRecord| Some(boot - 60);
        assert!(pre_boot_ghosts(&sessions, Some(boot), just_before).is_empty());

        // Both "no evidence" directions leave everything alone: an unreadable
        // /proc/stat, and a record with nothing parseable to date.
        assert!(pre_boot_ghosts(&sessions, None, seen).is_empty());
        assert!(pre_boot_ghosts(&sessions, Some(boot), |_| None).is_empty());
    }

    #[test]
    fn orphaned_subagents_take_only_the_ones_whose_parent_left_the_roster() {
        let sub = |id: &str, parent: Option<&str>| {
            let mut s = subagent(id, "working");
            s.parent_session_id = parent.map(str::to_string);
            s
        };
        let sessions = vec![
            hook_only("parent-live", "working"),
            hook_only("parent-done", "done"),
            sub("kept-parent-live", Some("parent-live")),
            sub("kept-parent-done", Some("parent-done")), // the cascade's job
            sub("orphan-missing-parent", Some("parent-pruned-away")),
            sub("orphan-no-parent", None),
            sub("orphan-blank-parent", Some("   ")),
            hook_only("not-a-subagent", "working"), // parentless, but not a sub
        ];

        let mut got = orphaned_subagents(&sessions, |_| false);
        got.sort();
        assert_eq!(
            got,
            vec![
                "orphan-blank-parent".to_string(),
                "orphan-missing-parent".to_string(),
                "orphan-no-parent".to_string(),
            ],
        );

        // The settle grace: an infant whose parent link is a moment away is
        // never judged.
        assert!(orphaned_subagents(&sessions, |_| true).is_empty());

        // The `sub:` id prefix classifies too, for a record that published no
        // kind at all.
        let mut bare = hook_only("sub:t1", "working");
        bare.kind = None;
        assert_eq!(
            orphaned_subagents(&[bare], |_| false),
            vec!["sub:t1".to_string()],
        );
    }

    #[test]
    fn orphaned_hook_only_agents_follow_a_gone_host_but_never_an_absent_parent() {
        // The live case this widened for: a hook-only claude (no pid, no
        // window — every signal blind) whose host terminal's record was
        // already reaped out of the roster.
        let agent = |id: &str, parent: Option<&str>| {
            let mut s = hook_only(id, "idle");
            s.kind = Some("agent".into());
            s.parent_session_id = parent.map(str::to_string);
            s
        };
        let mut with_window = agent("kept-has-window", Some("host-reaped-away"));
        with_window.window_address = "0xabc".into();
        let mut with_pid = agent("kept-has-pid", Some("host-reaped-away"));
        with_pid.pid = Some(123);
        let sessions = vec![
            hook_only("host-live", "working"),
            agent("orphan-host-gone", Some("host-reaped-away")),
            agent("kept-host-live", Some("host-live")),
            // An absent/blank parent is the normal project-anchored shape —
            // never evidence of death.
            agent("kept-no-parent", None),
            agent("kept-blank-parent", Some("   ")),
            // A record with its own signal is that signal's business, not the
            // orphan sweep's.
            with_window,
            with_pid,
        ];

        let got = orphaned_subagents(&sessions, |_| false);
        assert_eq!(got, vec!["orphan-host-gone".to_string()]);

        // The settle grace spares an infant here too.
        assert!(orphaned_subagents(&sessions, |_| true).is_empty());
    }

    /// A SPAWNED conducted SHELL that HAS been ticked by `conduct`'s P-C5
    /// refresh (`restore` populated) — the exact shape
    /// `abandoned_spawned_shells` targets. `conductable: Some(true)`
    /// mirrors a real `aoide spawn -- bash` registration and keeps
    /// `is_agent_kind` false, so the end-to-end `reap()` tests below prove
    /// the NEW signal specifically, never a coincidental fold of the
    /// pre-existing one (which this shape is already excluded from, by
    /// `is_session_dead`'s own kind gate).
    ///
    /// `headless` is left FALSE here on purpose: the predicate must key off
    /// `spawned` alone, and a helper that set both would hide a regression
    /// back to the headless gate.
    fn spawned_shell(id: &str, state: &str) -> SessionRecord {
        SessionRecord {
            session_id: id.into(),
            agent: "bash".into(),
            window_address: String::new(),
            state: state.into(),
            started_at: now_iso_utc(),
            pid: Some(std::process::id()),
            conductable: Some(true),
            spawned: true,
            restore: Some(aoide_storage::records::RestoreSnapshot::default()),
            ..Default::default()
        }
    }

    #[test]
    fn abandoned_spawned_shells_reaps_one_stale_and_untouched() {
        let now = 1_800_000_000_i64;
        let rec = spawned_shell("worker", "idle");
        let stale = |_: &SessionRecord| Some(now - 100 * 3600); // 100h silent
        assert_eq!(
            abandoned_spawned_shells(&[rec], now, stale, Some(REAP_SPAWNED_SHELL_STALE_SECS)),
            vec!["worker".to_string()],
        );
    }

    #[test]
    fn abandoned_spawned_shells_spares_one_recently_touched() {
        // The "or touched" half of the rule. Any byte crossing this pty
        // advances the log's mtime, so a human who found this terminal and
        // used it resets the clock — without this file ever needing to know
        // WHO touched it (`graph/send.rs`'s `resolve_sender`: attribution is
        // self-reported and never a trust boundary).
        let now = 1_800_000_000_i64;
        let rec = spawned_shell("worker", "idle");
        let recent = |_: &SessionRecord| Some(now - 3600); // 1h ago, well under the band
        assert!(abandoned_spawned_shells(&[rec], now, recent, Some(REAP_SPAWNED_SHELL_STALE_SECS)).is_empty());
    }

    #[test]
    fn abandoned_spawned_shells_reaps_a_windowed_spawn_too() {
        // The User's rule: a leftover worker terminal is judged the same way
        // whether or not it had a window. `spawn --windowed` execs a real
        // terminal running the same `aoide conduct`, and an agent abandons
        // one exactly as readily as a headless one. The window is not a
        // guard and never becomes one — what a windowed spawn lacks today is
        // the LOG the band reads, not standing here (the function's own doc);
        // the gesture path below reaches it regardless.
        let now = 1_800_000_000_i64;
        let mut rec = spawned_shell("windowed-worker", "idle");
        rec.window_address = "0xAAA".into();
        let stale = |_: &SessionRecord| Some(now - 100 * 3600);
        assert_eq!(
            abandoned_spawned_shells(&[rec], now, stale, Some(REAP_SPAWNED_SHELL_STALE_SECS)),
            vec!["windowed-worker".to_string()],
        );
    }

    #[test]
    fn abandoned_spawned_shells_spares_a_terminal_the_user_opened() {
        // The whole point of the `spawned` gate. Identical stale evidence,
        // identical idle prompt — but nothing spawned it, so it is the
        // User's own terminal and this signal must never reach it. A shell
        // has no self-heal: nothing re-registers it mid-life, so a false
        // positive here is unrecoverable.
        let now = 1_800_000_000_i64;
        let mut rec = spawned_shell("mine", "idle");
        rec.spawned = false;
        rec.window_address = "0xAAA".into();
        let stale = |_: &SessionRecord| Some(now - 100 * 3600);
        assert!(abandoned_spawned_shells(&[rec], now, stale, Some(REAP_SPAWNED_SHELL_STALE_SECS)).is_empty());
    }

    #[test]
    fn abandoned_spawned_shells_spares_a_never_shell_ticked_record() {
        // No `restore` at all — an agent or a one-shot command spawned
        // headless never sets this field, so this signal must never reach
        // either, however stale their log evidence reads.
        let now = 1_800_000_000_i64;
        let mut rec = spawned_shell("agent-headless", "idle");
        rec.restore = None;
        let stale = |_: &SessionRecord| Some(now - 100 * 3600);
        assert!(abandoned_spawned_shells(&[rec], now, stale, Some(REAP_SPAWNED_SHELL_STALE_SECS)).is_empty());
    }

    #[test]
    fn abandoned_spawned_shells_spares_working_and_awaiting_states() {
        // A live foreground command (working), or a sudo prompt mid-
        // conversation (awaiting), is never considered — only a bare,
        // doing-nothing prompt is.
        let now = 1_800_000_000_i64;
        let stale = |_: &SessionRecord| Some(now - 100 * 3600);
        assert!(abandoned_spawned_shells(&[spawned_shell("w", "working")], now, stale, Some(REAP_SPAWNED_SHELL_STALE_SECS)).is_empty());
        assert!(abandoned_spawned_shells(&[spawned_shell("a", "awaiting")], now, stale, Some(REAP_SPAWNED_SHELL_STALE_SECS)).is_empty());
    }

    #[test]
    fn abandoned_spawned_shells_spares_with_no_log_evidence_at_all() {
        // Absence of evidence is never evidence of death — the log was
        // never opened (a failed open degrades to stdout,
        // `graph/conduct.rs`'s own best-effort fallback) or is otherwise
        // unreadable.
        let now = 1_800_000_000_i64;
        let rec = spawned_shell("no-log", "idle");
        assert!(abandoned_spawned_shells(&[rec], now, |_| None, Some(REAP_SPAWNED_SHELL_STALE_SECS)).is_empty());
    }

    #[test]
    fn abandoned_spawned_shells_band_is_two_days() {
        // Pins the constant from both sides, and the strict `>`: exactly at
        // the band is not yet past it.
        let now = 1_800_000_000_i64;
        let band = Some(REAP_SPAWNED_SHELL_STALE_SECS);
        let at = |secs: i64| move |_: &SessionRecord| Some(now - secs);
        assert!(
            abandoned_spawned_shells(&[spawned_shell("w", "idle")], now, at(48 * 3600), band)
                .is_empty(),
            "48h silent is exactly AT the band, not past it"
        );
        assert_eq!(
            abandoned_spawned_shells(&[spawned_shell("w", "idle")], now, at(48 * 3600 + 1), band),
            vec!["w".to_string()],
        );
        // And the move this band exists for: 60h is leftover now, where the
        // at-rest band it used to borrow (72h) would still have spared it.
        assert_eq!(
            abandoned_spawned_shells(&[spawned_shell("w", "idle")], now, at(60 * 3600), band),
            vec!["w".to_string()],
        );
        assert!(60 * 3600 < REAP_IDLE_STALE_SECS, "the 60h case must be under the at-rest band");
    }

    #[test]
    fn abandoned_spawned_shells_waives_the_band_for_a_human_gesture() {
        // `band: None` is what `--now` resolves to. A worker shell touched
        // an hour ago — nowhere near stale — goes on the spot: the person
        // pressing `[ reap ]` IS the evidence the band waits two days for.
        let now = 1_800_000_000_i64;
        let recent = |_: &SessionRecord| Some(now - 3600);
        assert_eq!(
            abandoned_spawned_shells(&[spawned_shell("worker", "idle")], now, recent, None),
            vec!["worker".to_string()],
        );
    }

    #[test]
    fn abandoned_spawned_shells_waived_reaches_a_windowed_spawn_with_no_log_at_all() {
        // The case the unattended band structurally cannot reach: a
        // `spawn --windowed` worker terminal has no `log_path` (only a
        // headless conduct opens one), so `log_mtime` is `None` forever and
        // no silence ever accrues. A waived band needs no touch signal.
        let now = 1_800_000_000_i64;
        let mut rec = spawned_shell("windowed-worker", "idle");
        rec.window_address = "0xAAA".into();
        rec.log_path = None;
        assert_eq!(
            abandoned_spawned_shells(&[rec], now, |_| None, None),
            vec!["windowed-worker".to_string()],
        );
    }

    #[test]
    fn abandoned_spawned_shells_waived_still_holds_all_three_guards() {
        // Waiving drops the staleness clause and NOTHING else. The User's
        // own terminal, an agent/one-shot record that never ticked as a
        // shell, and a shell mid-command are all out of reach of the button.
        let now = 1_800_000_000_i64;
        let recent = |_: &SessionRecord| Some(now - 60);
        let mut mine = spawned_shell("mine", "idle");
        mine.spawned = false;
        let mut agent = spawned_shell("agent", "idle");
        agent.restore = None;
        let busy = spawned_shell("busy", "working");
        assert!(
            abandoned_spawned_shells(&[mine, agent, busy], now, recent, None).is_empty(),
        );
    }

    #[test]
    fn abandoned_spawned_shells_ignores_already_done_records() {
        let now = 1_800_000_000_i64;
        let rec = spawned_shell("gone", "done");
        let stale = |_: &SessionRecord| Some(now - 100 * 3600);
        assert!(abandoned_spawned_shells(&[rec], now, stale, Some(REAP_SPAWNED_SHELL_STALE_SECS)).is_empty());
    }

    // ── exempt (task #20): vetoes abandoned_spawned_shells, banded AND
    // waived alike — never reaped, and spared_exempt_spawned_shells reports
    // it back only on the waived (`--now`) shape ─────────────────────────

    #[test]
    fn abandoned_spawned_shells_spares_an_exempt_shell_under_the_band() {
        let now = 1_800_000_000_i64;
        let mut rec = spawned_shell("worker", "idle");
        rec.exempt = true;
        let stale = |_: &SessionRecord| Some(now - 100 * 3600); // well past the band
        assert!(
            abandoned_spawned_shells(&[rec], now, stale, Some(REAP_SPAWNED_SHELL_STALE_SECS)).is_empty(),
            "an exempt shell must survive the unattended band even 100h silent"
        );
    }

    #[test]
    fn abandoned_spawned_shells_spares_an_exempt_shell_even_waived() {
        // `band: None` is what `--now` resolves to -- a human gesture takes
        // every OTHER idle spawned shell on the spot, but the exemption
        // survives `--now` structurally: it is filtered out of candidacy
        // before any band question is asked.
        let now = 1_800_000_000_i64;
        let mut rec = spawned_shell("worker", "idle");
        rec.exempt = true;
        let recent = |_: &SessionRecord| Some(now - 60);
        assert!(abandoned_spawned_shells(&[rec], now, recent, None).is_empty());
    }

    #[test]
    fn spared_exempt_spawned_shells_reports_the_ones_the_waived_arm_skipped() {
        let now = 1_800_000_000_i64;
        let mut exempt_rec = spawned_shell("shielded", "idle");
        exempt_rec.exempt = true;
        let ordinary = spawned_shell("ordinary", "idle");
        let recent = |_: &SessionRecord| Some(now - 60);
        let spared = spared_exempt_spawned_shells(&[exempt_rec, ordinary], now, recent);
        assert_eq!(spared, vec!["shielded".to_string()], "only the exempt row is spared, never the ordinary one");
    }

    #[test]
    fn spared_exempt_spawned_shells_never_names_a_record_outside_the_shape() {
        // An exempt record that is not even a spawned-shell candidate (still
        // `working`, say) has nothing to be spared FROM -- `spared` must stay
        // empty, not just "not reaped".
        let now = 1_800_000_000_i64;
        let mut busy = spawned_shell("busy", "working");
        busy.exempt = true;
        let recent = |_: &SessionRecord| Some(now - 60);
        assert!(spared_exempt_spawned_shells(&[busy], now, recent).is_empty());
    }

    /// End-to-end through `reap()`: a spawned worker shell whose pty log
    /// has sat untouched past `REAP_SPAWNED_SHELL_STALE_SECS` is reaped — proving
    /// `reap_inner`'s `log_mtime` closure actually reads the real log
    /// file's mtime off disk, not just the pure predicate above.
    #[test]
    fn reap_collects_a_spawned_worker_shell_whose_log_has_gone_stale() {
        use std::os::unix::ffi::OsStrExt;

        let _guard = crate::env_lock().lock().unwrap();
        let _env = crate::graph::testutil::EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "HYPRLAND_INSTANCE_SIGNATURE",
        ]);
        std::env::remove_var("HYPRLAND_INSTANCE_SIGNATURE"); // pid-only/no-window liveness
        let stage = crate::graph::testutil::unique_stage("reap-spawned-shell-stale");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", stage.join("state"));

        let log = stage.join("worker.log");
        std::fs::write(&log, b"$ the last thing that ever ran here\n").unwrap();
        let backdate_secs = REAP_SPAWNED_SHELL_STALE_SECS + 3600; // an hour past the band
        let t = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - backdate_secs) as libc::time_t;
        let tv = [libc::timeval { tv_sec: t, tv_usec: 0 }; 2];
        let c = std::ffi::CString::new(log.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::utimes(c.as_ptr(), tv.as_ptr()) }, 0);

        let mut rec = spawned_shell("worker", "idle");
        rec.log_path = Some(log.to_string_lossy().into_owned());
        write_stage(
            &sessions_path(),
            &SessionsFile { schema_version: "0".into(), sessions: vec![rec] },
        )
        .unwrap();

        let out = reap(&crate::graph::testutil::invocation(&["session", "reap"], &[]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let reaped: Vec<String> = out.data.as_ref().unwrap()["reaped"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert!(reaped.contains(&"worker".to_string()), "reaped: {reaped:?}");

        let _ = std::fs::remove_dir_all(&stage);
    }

    /// The opposite proof, and the literal guarantee the User asked for: a
    /// worker shell whose log was touched RECENTLY — as `aoide send` would
    /// leave it, from an agent's own follow-up or a human's — survives.
    /// Anything that touches the terminal after spawn keeps it off the
    /// reap list. (Deliberately keeps `startedAt` recent, unlike the
    /// hook-fold regression test above: an ancient `startedAt` with no
    /// other evidence would instead trip the UNRELATED pre-boot-ghost
    /// signal — this test isolates `abandoned_spawned_shells` alone.)
    #[test]
    fn reap_spares_a_spawned_worker_shell_whose_log_was_touched_after_spawn() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = crate::graph::testutil::EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "HYPRLAND_INSTANCE_SIGNATURE",
        ]);
        std::env::remove_var("HYPRLAND_INSTANCE_SIGNATURE");
        let stage = crate::graph::testutil::unique_stage("reap-spawned-shell-fresh");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", stage.join("state"));

        let log = stage.join("worker.log");
        // Freshly written — mtime is "now", well under the band, exactly as
        // if a follow-up command had just been sent into it.
        std::fs::write(&log, b"$ someone just ran another command here\n").unwrap();

        let mut rec = spawned_shell("worker", "idle");
        rec.log_path = Some(log.to_string_lossy().into_owned());
        write_stage(
            &sessions_path(),
            &SessionsFile { schema_version: "0".into(), sessions: vec![rec] },
        )
        .unwrap();

        let out = reap(&crate::graph::testutil::invocation(&["session", "reap"], &[]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(
            out.data.unwrap()["reaped"],
            json!([]),
            "a worker shell touched after spawn must survive despite an ancient startedAt"
        );

        let _ = std::fs::remove_dir_all(&stage);
    }

    /// The third leg, end to end: the SAME roster the test above spares —
    /// a worker shell whose log was written a moment ago — is taken once
    /// `--now` is on the invocation. Proves the flag actually reaches
    /// `reap_inner`'s band decision through `reap`, not just the pure
    /// predicate.
    #[test]
    fn reap_now_takes_a_spawned_worker_shell_the_band_would_have_spared() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = crate::graph::testutil::EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "HYPRLAND_INSTANCE_SIGNATURE",
        ]);
        std::env::remove_var("HYPRLAND_INSTANCE_SIGNATURE");
        let stage = crate::graph::testutil::unique_stage("reap-spawned-shell-now");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", stage.join("state"));

        let log = stage.join("worker.log");
        std::fs::write(&log, b"$ someone just ran another command here\n").unwrap();
        let mut rec = spawned_shell("worker", "idle");
        rec.log_path = Some(log.to_string_lossy().into_owned());
        write_stage(
            &sessions_path(),
            &SessionsFile { schema_version: "0".into(), sessions: vec![rec] },
        )
        .unwrap();

        let out = reap(&crate::graph::testutil::flag_invocation(
            &["session", "reap"],
            &[("now", "true")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let reaped: Vec<String> = out.data.as_ref().unwrap()["reaped"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert!(reaped.contains(&"worker".to_string()), "reaped: {reaped:?}");

        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn with_human_gesture_adds_nothing_off_a_tty() {
        // A test harness (and the systemd timer, and the daemon's own tick)
        // has piped stdio, so `pick::interactive` reads false and the
        // invocation goes through untouched — the unattended band holds.
        let inv = with_human_gesture(&crate::graph::testutil::invocation(&["session", "reap"], &[]));
        assert!(!inv.flag_present("now"));
    }

    #[test]
    fn with_human_gesture_never_reads_announce_as_the_gesture() {
        // The two flags stay separate on purpose: `--announce` is about the
        // toast. The dock's control passes `--now` itself (shellbridge);
        // nothing infers one from the other.
        let inv = with_human_gesture(&crate::graph::testutil::flag_invocation(
            &["session", "reap"],
            &[("announce", "true")],
        ));
        assert!(!inv.flag_present("now"));
    }

    #[test]
    fn with_human_gesture_carries_the_invocation_through_intact() {
        // Whatever it decides, it must hand the sweep back the same command
        // — the flags travel over the daemon hop verbatim.
        let inv = with_human_gesture(&crate::graph::testutil::flag_invocation(
            &["session", "reap"],
            &[("announce", "true"), ("json", "true"), ("now", "true")],
        ));
        assert_eq!(inv.path, vec!["session".to_string(), "reap".to_string()]);
        assert!(inv.flag_present("announce") && inv.flag_present("json") && inv.flag_present("now"));
    }

    #[test]
    fn orphan_control_sockets_are_unlinked_only_with_nothing_listening() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::net::UnixListener;

        let _guard = crate::env_lock().lock().unwrap();
        let _env = crate::graph::testutil::EnvVars::save(&["XDG_RUNTIME_DIR"]);
        let runtime = crate::graph::testutil::unique_stage("reap-sockets");
        std::fs::create_dir_all(runtime.join("aoide")).unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", &runtime);
        let dir = runtime.join("aoide");

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        // Backdate past the settle window — the sweep only considers a socket
        // that has sat still for a minute.
        let backdate = |p: &std::path::Path| {
            let t = (now - 600) as libc::time_t;
            let tv = [libc::timeval {
                tv_sec: t,
                tv_usec: 0,
            }; 2];
            let c = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::utimes(c.as_ptr(), tv.as_ptr()) }, 0);
        };

        // Dropping the listener leaves the socket FILE behind with nobody
        // accepting — exactly what a SIGKILLed `conduct` leaves.
        let dead = dir.join("session-killed.sock");
        drop(UnixListener::bind(&dead).unwrap());
        backdate(&dead);
        // Same shape, but its session is still on the roster.
        let on_roster = dir.join("session-alive-record.sock");
        drop(UnixListener::bind(&on_roster).unwrap());
        backdate(&on_roster);
        // A real live conduct: the listener is held for the whole test, so a
        // connect succeeds and outranks a roster that never mentions it.
        let listening = dir.join("session-listening.sock");
        let _held = UnixListener::bind(&listening).unwrap();
        backdate(&listening);
        // Bound a moment ago — inside the settle window between `bind` and the
        // session record reaching sessions.json.
        let infant = dir.join("session-infant.sock");
        drop(UnixListener::bind(&infant).unwrap());
        // Not a session socket at all: the shellbridge shares this directory.
        let bridge = dir.join("shellbridge.sock");
        drop(UnixListener::bind(&bridge).unwrap());
        backdate(&bridge);

        let live: HashSet<&str> = ["alive-record"].into_iter().collect();
        assert_eq!(
            sweep_orphan_sockets(&live, now),
            vec!["killed".to_string()],
            "only the dead, settled, roster-less session socket is swept",
        );
        assert!(!dead.exists(), "the killed session's socket is unlinked");
        for spared in [&on_roster, &listening, &infant, &bridge] {
            assert!(spared.exists(), "spared: {}", spared.display());
        }
        let _ = std::fs::remove_dir_all(&runtime);
    }

    /// Mirrors `orphan_control_sockets_are_unlinked_only_with_nothing_listening`
    /// one crate DAG hop down: fake `TunnelRecord`s (no real `ssh` anywhere —
    /// the P-S3 test seam this sweep leans on is `aoide_client::tunnel`'s own
    /// pid/cmdline checks, exercised here only through pids that either don't
    /// exist or are this very test process, never a spawned child). Exercises
    /// both halves of the GATHER/KILL split (P-S5 review): `orphan_tunnel_
    /// candidates` decides which records qualify with no lock held here
    /// either (this test never touches the stage), and `sweep_orphan_tunnels`
    /// then acts on exactly that candidate list — the same two calls `reap`
    /// makes across its `with_stage_lock` boundary, just with no lock in
    /// between since this test has no stage files to guard.
    #[test]
    fn orphan_ssh_tunnels_are_swept_only_when_roster_less_and_settled() {
        use std::os::unix::ffi::OsStrExt;

        let _guard = crate::env_lock().lock().unwrap();
        let _env = crate::graph::testutil::EnvVars::save(&["XDG_RUNTIME_DIR"]);
        let runtime = crate::graph::testutil::unique_stage("reap-tunnels");
        std::fs::create_dir_all(runtime.join("aoide")).unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", &runtime);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        // Backdate past the settle window — same recipe the socket test uses.
        let backdate = |p: &std::path::Path| {
            let t = (now - 600) as libc::time_t;
            let tv = [libc::timeval {
                tv_sec: t,
                tv_usec: 0,
            }; 2];
            let c = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::utimes(c.as_ptr(), tv.as_ptr()) }, 0);
        };
        let write_record = |session_id: &str, key: &str, pid: u32| {
            let rec = aoide_storage::tunnel::TunnelRecord {
                schema_version: aoide_storage::tunnel::TUNNEL_VERSION.to_string(),
                session_id: session_id.to_string(),
                key: key.to_string(),
                ssh_target: "ssh://user@host".to_string(),
                local_port: 40000,
                remote_host: "127.0.0.1".to_string(),
                remote_port: 8710,
                pid,
                opened_at: aoide_storage::time::now_iso_utc(),
            };
            aoide_storage::tunnel::save(&rec).unwrap();
            aoide_storage::tunnel::record_path(session_id, key).unwrap()
        };

        // Nothing at this pid on any sane machine — a dead-pid orphan.
        let dead_pid = 999_999_999u32;

        // Orphan: session gone, pid dead, settled. Swept.
        let orphan_path = write_record("gone-session", "peer-a", dead_pid);
        backdate(&orphan_path);
        // Live: session still on the roster, pid ALSO reads dead — spared
        // regardless, because the roster check runs before any pid probe.
        let live_path = write_record("alive-session", "peer-b", dead_pid);
        backdate(&live_path);
        // Infant: session gone, pid dead, but bound a moment ago — inside the
        // settle window between the forward answering and `open_or_reuse`
        // finishing its write. Spared.
        let _infant_path = write_record("gone-infant", "peer-c", dead_pid);
        // Orphan with a LIVE pid that is not actually an `ssh` child (this
        // test process itself): `kill_if_still_our_ssh` must no-op on it
        // (never signal a process that isn't its own ssh), and the record is
        // still unlinked — the safety pin proving the guarded kill and the
        // unconditional unlink are two separate steps.
        let my_pid = std::process::id();
        let alive_nonssh_path = write_record("gone-alive-pid", "peer-d", my_pid);
        backdate(&alive_nonssh_path);

        let live: HashSet<&str> = ["alive-session"].into_iter().collect();
        let candidates = orphan_tunnel_candidates(&live, now);
        let mut candidate_ids: Vec<String> = candidates
            .iter()
            .map(|r| format!("{}/{}", r.session_id, r.key))
            .collect();
        candidate_ids.sort();
        assert_eq!(
            candidate_ids,
            vec![
                "gone-alive-pid/peer-d".to_string(),
                "gone-session/peer-a".to_string(),
            ],
            "the GATHER phase alone already excludes the live and infant records",
        );

        let mut swept = sweep_orphan_tunnels(candidates);
        swept.sort();
        assert_eq!(
            swept,
            vec![
                "gone-alive-pid/peer-d".to_string(),
                "gone-session/peer-a".to_string(),
            ],
            "only the dead-pid orphan and the alive-but-not-ours orphan are swept",
        );
        assert!(
            aoide_storage::tunnel::load("gone-session", "peer-a").is_none(),
            "the roster-less, settled, dead-pid record is unlinked",
        );
        assert!(
            aoide_storage::tunnel::load("gone-alive-pid", "peer-d").is_none(),
            "the roster-less, settled, alive-but-foreign-pid record is unlinked too",
        );
        assert!(
            aoide_storage::tunnel::load("alive-session", "peer-b").is_some(),
            "a live session's tunnel is spared even when its pid probe reads dead",
        );
        assert!(
            aoide_storage::tunnel::load("gone-infant", "peer-c").is_some(),
            "an infant record inside the settle window is spared",
        );
        // This test process is very much still alive — the whole point of
        // the safety pin above.
        assert!(std::path::Path::new("/proc").join(my_pid.to_string()).exists());

        let _ = std::fs::remove_dir_all(&runtime);
    }

    /// Independent-review follow-up: `sweep_orphan_tunnels` used to unlink
    /// every candidate regardless of whether `kill_if_still_our_ssh`
    /// actually confirmed the pid dead — a still-alive, still-ours child
    /// (a stubborn or hung `ssh`) was re-orphaned with no further
    /// backstop, since a fresh `session reap` pass is the only thing that
    /// would ever revisit it. Pins the fix at this layer too (not just
    /// `aoide_client::tunnel::close`'s own unit tests): a genuine, killable
    /// process whose cmdline actually matches `looks_like_our_ssh` but
    /// traps `SIGTERM` away survives the sweep with its record intact,
    /// while an ordinary dead-pid candidate is swept exactly as before.
    #[test]
    fn sweep_orphan_tunnels_keeps_a_record_whose_child_survives_the_kill() {
        use std::os::unix::process::CommandExt;

        let _guard = crate::env_lock().lock().unwrap();
        let _env = crate::graph::testutil::EnvVars::save(&["XDG_RUNTIME_DIR"]);
        let runtime = crate::graph::testutil::unique_stage("reap-tunnel-survivor");
        std::fs::create_dir_all(runtime.join("aoide")).unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", &runtime);

        // A genuine child whose `/proc/<pid>/cmdline` reads exactly like an
        // `ssh … -L <port>:<host>:<port> …` (the same `arg0`-override
        // fixture shape `aoide_client::tunnel`'s own tests use) but traps
        // `SIGTERM` away — real `ssh` never does this, but `terminate_pid`
        // only ever sends one bounded `SIGTERM`, so this is the worst case
        // the guard must still survive correctly. `trap`/`:`/`while` are
        // shell builtins, so this stays exec-free the same way the source
        // fixture's own doc explains.
        let local_port = 40002u16;
        let remote_port = 8710u16;
        let spec = format!("{local_port}:127.0.0.1:{remote_port}");
        let child = std::process::Command::new("bash")
            .arg0("ssh")
            .arg("-c")
            .arg("trap '' TERM; while :; do :; done")
            .arg("aoide-test-marker")
            .arg(&spec)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        drop(child);
        // Give the `trap` a moment to actually install before this test's
        // own `sweep_orphan_tunnels` call signals it — a fixed, generous
        // sleep is acceptable here (unlike the `tunnel.rs` unit test this
        // mirrors) since there is no assertion tight enough for the race to
        // realistically flip; the trap is a no-I/O shell builtin that runs
        // in microseconds.
        std::thread::sleep(std::time::Duration::from_millis(200));

        let rec = aoide_storage::tunnel::TunnelRecord {
            schema_version: aoide_storage::tunnel::TUNNEL_VERSION.to_string(),
            session_id: "gone-survivor".to_string(),
            key: "peer-z".to_string(),
            ssh_target: "ssh://user@host".to_string(),
            local_port,
            remote_host: "127.0.0.1".to_string(),
            remote_port,
            pid,
            opened_at: aoide_storage::time::now_iso_utc(),
        };
        aoide_storage::tunnel::save(&rec).unwrap();

        let swept = sweep_orphan_tunnels(vec![rec]);
        assert!(swept.is_empty(), "a still-alive, still-ours candidate must not be reported swept: {swept:?}");
        assert!(
            aoide_storage::tunnel::load("gone-survivor", "peer-z").is_some(),
            "the survivor's record must stay on disk for the next sweep pass to retry"
        );
        assert!(proc_exists(pid), "the fixture traps SIGTERM on purpose — it must still be alive");

        // Cleanup: SIGKILL cannot be trapped; reap with a real, blocking
        // `waitpid` so no zombie is left behind.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        let mut status: libc::c_int = 0;
        unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };

        // A second sweep pass, now that the child is actually gone, finally
        // collects it — the kept record really is retryable, not stuck.
        let rec2 = aoide_storage::tunnel::load("gone-survivor", "peer-z").unwrap();
        let swept2 = sweep_orphan_tunnels(vec![rec2]);
        assert_eq!(swept2, vec!["gone-survivor/peer-z".to_string()]);
        assert!(aoide_storage::tunnel::load("gone-survivor", "peer-z").is_none());

        let _ = std::fs::remove_dir_all(&runtime);
    }

    /// DECIDED (independent review, task #104 follow-up): `orphan_tunnel_
    /// candidates` treats any session still PRESENT in `sessions.json` as
    /// live — but a clean `session end` (`do_session_end_inner`) marks a
    /// session `done` IN PLACE; the record itself is only removed once
    /// `prune_done` runs, which only happens on a pass that reaped
    /// something. Left unnarrowed, a tunnel record `close` had to KEEP (its
    /// child survived the fast path's own bounded kill) could wait
    /// UNBOUNDED on an otherwise quiet desktop, since nothing else ever
    /// prunes a lone `done` session. Pins the narrowed rule: a `done`
    /// session's settled tunnel record is a CANDIDATE even while its
    /// session record still sits in the roster, while a genuinely live
    /// (not-`done`) session's tunnel is still spared exactly as before —
    /// and the `done` session record itself is untouched by this (pruning
    /// it stays `prune_done`'s own job, on its own schedule).
    #[test]
    fn reap_treats_a_done_but_unpruned_sessions_settled_tunnel_as_a_candidate() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = crate::graph::testutil::EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "HYPRLAND_INSTANCE_SIGNATURE",
        ]);
        std::env::remove_var("HYPRLAND_INSTANCE_SIGNATURE"); // pid-only/no-window liveness
        let stage = crate::graph::testutil::unique_stage("reap-done-tunnel-stage");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let runtime = crate::graph::testutil::unique_stage("reap-done-tunnel-runtime");
        std::fs::create_dir_all(runtime.join("aoide")).unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", &runtime);

        let now = now_iso_utc();
        let mut done_sess = agent("done-sess", "", &now);
        done_sess.state = "done".into();
        done_sess.pid = None;
        done_sess.cwd = "/nonexistent/nowhere".into();
        let mut live_sess = agent("live-sess", "", &now);
        live_sess.state = "working".into();
        live_sess.pid = None;
        live_sess.cwd = "/nonexistent/nowhere".into();

        write_stage(
            &sessions_path(),
            &SessionsFile {
                schema_version: "0".into(),
                sessions: vec![done_sess, live_sess],
            },
        )
        .unwrap();
        // A fresh hook record keeps `live-sess` provably alive under the
        // third liveness signal — this test's business is the tunnel
        // carve-out, not the reap-death machinery.
        let mut hooks = Vec::new();
        upsert_hook(&mut hooks, "live-sess", "working", &now);
        write_stage(&hooks_path(), &HooksFile { schema_version: "0".into(), hooks }).unwrap();

        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let backdate = |p: &std::path::Path| {
            use std::os::unix::ffi::OsStrExt;
            let t = (now_epoch - 600) as libc::time_t;
            let tv = [libc::timeval {
                tv_sec: t,
                tv_usec: 0,
            }; 2];
            let c = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::utimes(c.as_ptr(), tv.as_ptr()) }, 0);
        };
        let write_record = |session_id: &str, key: &str| {
            let rec = aoide_storage::tunnel::TunnelRecord {
                schema_version: aoide_storage::tunnel::TUNNEL_VERSION.to_string(),
                session_id: session_id.to_string(),
                key: key.to_string(),
                ssh_target: "ssh://user@host".to_string(),
                local_port: 40003,
                remote_host: "127.0.0.1".to_string(),
                remote_port: 8710,
                pid: 999_999_999u32, // dead on any sane machine
                opened_at: aoide_storage::time::now_iso_utc(),
            };
            aoide_storage::tunnel::save(&rec).unwrap();
            aoide_storage::tunnel::record_path(session_id, key).unwrap()
        };

        let done_tunnel = write_record("done-sess", "peer-x");
        backdate(&done_tunnel);
        let live_tunnel = write_record("live-sess", "peer-y");
        backdate(&live_tunnel);

        let out = reap(&crate::graph::testutil::invocation(&["session", "reap"], &[]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.unwrap();
        let orphan_tunnels: Vec<String> = data["orphanTunnels"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            orphan_tunnels,
            vec!["done-sess/peer-x".to_string()],
            "a done-but-unpruned session's settled tunnel is swept; a live one's is not"
        );
        assert!(
            aoide_storage::tunnel::load("done-sess", "peer-x").is_none(),
            "the done session's tunnel record is gone"
        );
        assert!(
            aoide_storage::tunnel::load("live-sess", "peer-y").is_some(),
            "the live session's tunnel record is untouched"
        );
        let s2: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert!(
            s2.sessions.iter().any(|s| s.session_id == "done-sess"),
            "the done session record itself is not pruned by this — pruning stays prune_done's own job"
        );

        let _ = std::fs::remove_dir_all(&stage);
        let _ = std::fs::remove_dir_all(&runtime);
    }
}
