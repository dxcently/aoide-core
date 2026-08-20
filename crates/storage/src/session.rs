//! Pure UPSERT ops on the session/hook record vecs — no DAG/stage-lock
//! dependency (verified: neither function touches `graph/doc.rs`'s
//! `restage_graph`/`would_cycle` or `graph/common.rs`'s
//! `require_flag`/`stage_error`; both are pure `Vec<Record>` mutators the
//! handler wires I/O around).
//!
//! Moved from `graph/session_store.rs` (Phase 3a restructure,
//! docs/architecture/PACKAGE-LAYOUT.md); re-exported at the old path so every
//! existing `crate::graph::{upsert_session, upsert_hook}` (and the
//! `session_store.rs`-local) caller is untouched. The verb handlers
//! (`do_session_start/end/phase/phase_if`, …) stay in root — they move in
//! Phase 3b.

use crate::records::{HookRecord, SessionRecord};
use aoide_protocol::agents::CLAUDE_PROFILE;
use serde_json::Map;

/// UPSERT a session record by id (pure; the handler wires I/O around it).
///
/// A fresh id is inserted `state="idle"` (at rest until a prompt/tool or a
/// foreground command moves it to `working`), `startedAt=now`, `agent`
/// defaulting to `claude`. A re-start of an existing id updates only the fields
/// provided (a `None` leaves the stored value), leaves the live `state`
/// untouched (a resume must not reset a working session), and NEVER clobbers
/// `startedAt` — the record is bounded to one per id, never duplicated. Returns
/// `true` when a new record was inserted.
#[allow(clippy::too_many_arguments)]
pub fn upsert_session(
    sessions: &mut Vec<SessionRecord>,
    id: &str,
    agent: Option<&str>,
    cwd: Option<&str>,
    window: Option<&str>,
    parent: Option<&str>,
    conductable: Option<bool>,
    socket: Option<&str>,
    title: Option<&str>,
    pid: Option<u32>,
    now: &str,
) -> bool {
    let inserted = if let Some(s) = sessions.iter_mut().find(|s| s.session_id == id) {
        if let Some(a) = agent {
            s.agent = a.to_string();
        }
        if let Some(c) = cwd {
            s.cwd = c.to_string();
        }
        if let Some(w) = window {
            s.window_address = w.to_string();
        }
        if let Some(p) = parent {
            s.parent_session_id = Some(p.to_string());
        }
        if let Some(c) = conductable {
            s.conductable = Some(c);
        }
        if let Some(sock) = socket {
            s.socket = Some(sock.to_string());
        }
        if let Some(t) = title {
            s.title = Some(t.to_string());
        }
        if let Some(p) = pid {
            s.pid = Some(p);
        }
        // A re-start (hook SessionStart on resume/compact, or a re-run `graph
        // session start`) must NOT reset the live state — a working/awaiting
        // session stays as it is; only the provided fields update. `startedAt`
        // is likewise preserved.
        false
    } else {
        sessions.push(SessionRecord {
            session_id: id.to_string(),
            agent: agent.unwrap_or(CLAUDE_PROFILE.name).to_string(),
            window_address: window.unwrap_or_default().to_string(),
            cwd: cwd.unwrap_or_default().to_string(),
            // A freshly registered session is at rest until a prompt/tool (agent)
            // or a foreground command (shell) moves it to `working`.
            state: "idle".to_string(),
            started_at: now.to_string(),
            parent_session_id: parent.map(str::to_string),
            conductable,
            socket: socket.map(str::to_string),
            title: title.map(str::to_string),
            pid,
            // Workspace is stamped later by the window-event listener (it needs a
            // resolved window first); a fresh record starts without one.
            workspace: None,
            activity: None,
            kind: None,
            say: None,
            tool: None,
            model: None,
            context_tokens: None,
            context_ceiling: None,
            needs_sudo: None,
            // Stamped later by `set_session_log_path`, only for a headless
            // `aoide conduct` session; every other fresh record starts without one.
            log_path: None,
            // Compile-only for now: the petname mint wires into this INSERT
            // arm in P2 of the petnames plan, under the stage lock with the
            // live sessions vec already in hand. P1 only adds the field.
            petname: None,
            extra: Map::new(),
        });
        true
    };
    // Classify an unclassified record: a conducted "shell" vs an "agent"
    // (claude/other). Sub-agent nodes set kind="subagent" explicitly elsewhere;
    // a legacy record with no kind is backfilled here on its next touch.
    if let Some(s) = sessions.iter_mut().find(|s| s.session_id == id) {
        if s.kind.is_none() {
            s.kind = Some(if s.agent == "shell" { "shell" } else { "agent" }.to_string());
        }
    }
    inserted
}

/// UPSERT the single hook record for a session (pure; bounded one-per-id).
///
/// `merged_sessions` keys the live phase by (latest `updatedAt`), so a single
/// rolling record per session is all it needs — no unbounded append.
pub fn upsert_hook(hooks: &mut Vec<HookRecord>, id: &str, phase: &str, now: &str) {
    if let Some(h) = hooks.iter_mut().find(|h| h.session_id == id) {
        h.phase = phase.to_string();
        h.updated_at = now.to_string();
    } else {
        hooks.push(HookRecord {
            session_id: id.to_string(),
            phase: phase.to_string(),
            updated_at: now.to_string(),
            extra: Map::new(),
        });
    }
}
