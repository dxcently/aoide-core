//! Desktop Codex/ChatGPT task association — the pure core of the P-CX design
//! (`docs/architecture/CODEX-INTEGRATION.md`). One `SessionRecord` per NATIVE
//! Codex thread, keyed by the thread's own id verbatim — never a synthetic
//! prefix, never an aoide-minted id, unlike
//! [`super::window::reconcile_untracked_terminals`]'s `win:<addr>` records:
//! a window address is not a stable id on its own, but a Codex thread id
//! already is one.
//!
//! This module holds ONLY the pure reconciler
//! ([`reconcile_codex_app_threads`]) and its input shape ([`CodexThread`]) —
//! no filesystem, no `/proc`, no call site. Discovering live threads from
//! `~/.codex/thread-writer-locks/*.lock` and calling this function under the
//! stage lock is a later slice's `sync_codex_app_threads`; the listener call
//! site and the taught transport/lifecycle refusals (`send`, `session kill`)
//! are later still. Until then this module is reachable only from its own
//! tests.

use super::model::SessionRecord;
use std::collections::{HashMap, HashSet};

/// One live Codex thread, already resolved to its writer-lock holder — the
/// pure-core input for [`reconcile_codex_app_threads`], so the reconciliation
/// is testable without touching `~/.codex` or `/proc` (that I/O belongs to
/// the eventual `sync_codex_app_threads` wrapper).
#[derive(Debug, Clone)]
pub(crate) struct CodexThread {
    /// The native Codex thread id, verbatim (`session_index.jsonl`'s `id`,
    /// the lock filename, the rollout's `session_meta.id`) — becomes
    /// `sessionId` unchanged, so the reaper's `apply_codex_titles`
    /// (`reap.rs:1289`) names the card for free with zero change to the
    /// title invariant.
    pub id: String,
    /// The thread's cwd, read once from its rollout header
    /// (`session_meta.payload.cwd`) at enrolment — never re-read per tick.
    pub cwd: String,
    /// The pid of the `app-server` process holding this thread's writer
    /// lock. Feeds exactly two things downstream: the existing window
    /// sweep's pid-ancestry walk, and the reaper's pid-DEATH signal — NEVER
    /// proof of life. A shared app-server pid backs every thread it holds a
    /// lock for, so the staleness arm must stay closed to it regardless of
    /// this pid's liveness (that's what `kind:"app"` buys, below).
    pub pid: u32,
}

/// Reconcile `kind:"app"` Codex-desktop records against the live thread set —
/// the PURE CORE (fed fake [`CodexThread`]s in tests), mirroring
/// [`super::window::reconcile_untracked_terminals`] rule for rule:
///
///   * A desired thread with no existing record is INSERTED, keyed by its
///     native id verbatim (no synthetic prefix — see the module doc).
///   * An existing `kind:"app"` record for a still-desired thread is upserted
///     IN PLACE, change-only — `changed` flips only on an actual field
///     difference, so a re-scan of an unchanged thread is a no-op.
///   * A `kind:"app"` record whose thread is no longer desired (its lock is
///     gone) is REMOVED — mirrors a closed window dropping its `win:*` row.
///   * A native id already claimed by a NON-`"app"` record (a real tracked
///     session somehow already sitting on that id) is left entirely alone:
///     never inserted, never overwritten, never removed by this function —
///     the tracked record carries the rich state and always wins.
///
/// Every record this function writes carries a fixed identity
/// (`agent:"codex"`, `kind:"app"`, `state:"idle"`), re-applied on every
/// upsert rather than assumed. `kind:"app"` is why `crate::reap::is_agent_kind`
/// reads false for these records — which keeps them out of BOTH
/// `superseded_agent_duplicates` (N threads legitimately share one app
/// window address; that dedup would otherwise retire N−1 of them) and
/// `is_session_dead`'s staleness arm (a shared app-server pid must never
/// stand as proof any one thread is alive). `windowAddress`/`workspace` are
/// left empty here by design — the existing `resolve_pending_session_windows`
/// sweep fills them later; this function has no compositor access and must
/// not invent one.
pub(crate) fn reconcile_codex_app_threads(
    mut sessions: Vec<SessionRecord>,
    threads: &[CodexThread],
) -> (Vec<SessionRecord>, bool) {
    // Native ids already claimed by a TRACKED (non-`"app"`) record — never
    // ours to insert, overwrite, or remove.
    let claimed: HashSet<String> = sessions
        .iter()
        .filter(|s| s.kind.as_deref() != Some("app"))
        .map(|s| s.session_id.clone())
        .collect();

    // The `"app"` roster we WANT: one entry per live thread, keyed by its
    // native id, skipping any id a tracked record already owns.
    let mut desired: HashMap<&str, &CodexThread> = HashMap::new();
    for t in threads {
        if claimed.contains(t.id.as_str()) {
            continue;
        }
        desired.insert(t.id.as_str(), t);
    }

    let mut changed = false;

    // Drop `"app"` records whose thread is no longer desired (lock gone, or
    // a tracked session now claims the id).
    let before = sessions.len();
    sessions.retain(|s| {
        s.kind.as_deref() != Some("app") || desired.contains_key(s.session_id.as_str())
    });
    if sessions.len() != before {
        changed = true;
    }

    // Upsert a record per desired thread.
    for (id, t) in &desired {
        if let Some(rec) = sessions.iter_mut().find(|s| s.session_id.as_str() == *id) {
            if rec.pid != Some(t.pid) {
                rec.pid = Some(t.pid);
                changed = true;
            }
            if rec.cwd != t.cwd {
                rec.cwd = t.cwd.clone();
                changed = true;
            }
            // The fixed identity, re-applied every upsert — never left to
            // drift even if something else touched the record in between.
            if rec.agent != "codex" {
                rec.agent = "codex".to_string();
                changed = true;
            }
            if rec.state != "idle" {
                rec.state = "idle".to_string();
                changed = true;
            }
            if rec.kind.as_deref() != Some("app") {
                rec.kind = Some("app".to_string());
                changed = true;
            }
        } else {
            let petname = aoide_storage::petname::mint_for(&sessions);
            sessions.push(SessionRecord {
                session_id: id.to_string(),
                agent: "codex".to_string(),
                cwd: t.cwd.clone(),
                state: "idle".to_string(),
                kind: Some("app".to_string()),
                pid: Some(t.pid),
                petname: Some(petname),
                ..Default::default()
            });
            changed = true;
        }
    }

    (sessions, changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::testutil::session;

    fn thread(id: &str, cwd: &str, pid: u32) -> CodexThread {
        CodexThread {
            id: id.to_string(),
            cwd: cwd.to_string(),
            pid,
        }
    }

    #[test]
    fn a_live_thread_becomes_one_record_keyed_by_its_native_id() {
        let (out, changed) = reconcile_codex_app_threads(
            vec![],
            &[thread(
                "01a07d89-5f9b-7900-b909-d5eb9457c195",
                "/home/khoa/Aoide",
                2598256,
            )],
        );
        assert!(changed);
        assert_eq!(out.len(), 1);
        let r = &out[0];
        assert_eq!(r.session_id, "01a07d89-5f9b-7900-b909-d5eb9457c195");
        assert_eq!(r.agent, "codex");
        assert_eq!(r.kind.as_deref(), Some("app"));
        assert_eq!(r.state, "idle");
        assert_eq!(r.pid, Some(2598256));
        assert_eq!(r.cwd, "/home/khoa/Aoide");
        assert!(
            r.window_address.is_empty(),
            "windowAddress is filled later by the window sweep, never here"
        );
        assert_eq!(r.workspace, None);
        assert!(
            r.petname.is_some(),
            "a freshly enrolled app record must mint a petname"
        );
        assert_eq!(r.title, None, "title is apply_codex_titles's alone to fill");
        assert_eq!(r.conductable, None);
        assert_eq!(r.socket, None);
        assert_eq!(r.parent_session_id, None);
    }

    #[test]
    fn two_threads_of_one_app_are_two_records() {
        let (out, changed) = reconcile_codex_app_threads(
            vec![],
            &[
                thread("01a07d89-thread-one", "/home/khoa/Aoide", 2598256),
                thread(
                    "01a08a23-thread-two",
                    "/home/khoa/Documents/Codex/2026-09-10/wha",
                    2598256,
                ),
            ],
        );
        assert!(changed);
        assert_eq!(out.len(), 2);
        assert!(out.iter().any(|r| r.session_id == "01a07d89-thread-one"));
        assert!(out.iter().any(|r| r.session_id == "01a08a23-thread-two"));
        assert!(out.iter().all(|r| r.kind.as_deref() == Some("app")));
        // One shared app-server pid, two distinct records — never collapsed.
        assert_ne!(
            out[0].petname, out[1].petname,
            "two distinct threads must never share a minted petname"
        );
    }

    #[test]
    fn a_thread_whose_lock_is_gone_loses_its_record() {
        let (first, _) = reconcile_codex_app_threads(
            vec![],
            &[thread("01a07d89-gone", "/home/khoa/Aoide", 2598256)],
        );
        assert_eq!(first.len(), 1);
        let (second, changed) = reconcile_codex_app_threads(first, &[]);
        assert!(changed);
        assert!(
            second.is_empty(),
            "a thread with no live lock keeps no record"
        );
    }

    #[test]
    fn a_record_a_tracked_session_already_owns_is_never_overwritten() {
        // A real tracked session happens to sit on the same id a codex thread
        // reports (should not occur in practice, but the rule is absolute).
        let tracked = session("01a07d89-claimed", "/home/khoa/Aoide", "working", "t", None);
        let (out, changed) = reconcile_codex_app_threads(
            vec![tracked.clone()],
            &[thread("01a07d89-claimed", "/home/khoa/Aoide", 2598256)],
        );
        assert!(
            !changed,
            "a claimed id must never be touched by the app reconciler"
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].agent, tracked.agent);
        assert_eq!(out[0].kind, tracked.kind);
        assert_eq!(out[0].state, tracked.state);
        assert_eq!(out[0].pid, tracked.pid);
    }

    #[test]
    fn an_app_record_is_never_agent_kind_so_dedup_and_staleness_skip_it() {
        let (out, _) = reconcile_codex_app_threads(
            vec![],
            &[thread("01a07d89-live", "/home/khoa/Aoide", 2598256)],
        );
        let rec = &out[0];
        assert!(
            !crate::reap::is_agent_kind(rec),
            "kind:\"app\" must never read as an agent for dedup"
        );
        assert!(
            !crate::reap::is_session_dead(rec, None, None, |_| true, 0, |_| None),
            "a live holder pid must never let staleness condemn an app record"
        );
    }

    #[test]
    fn an_app_record_never_publishes_a_state_other_than_idle() {
        // Simulate a record whose state drifted away from "idle" by some
        // other path; the next reconcile must force it back.
        let mut drifted = session("01a07d89-drift", "/home/khoa/Aoide", "working", "t", None);
        drifted.agent = "codex".to_string();
        drifted.kind = Some("app".to_string());
        drifted.pid = Some(2598256);
        let (out, changed) = reconcile_codex_app_threads(
            vec![drifted],
            &[thread("01a07d89-drift", "/home/khoa/Aoide", 2598256)],
        );
        assert!(
            changed,
            "correcting a drifted state must report a change"
        );
        assert_eq!(
            out[0].state, "idle",
            "an app record must never publish a state other than idle"
        );
    }
}
