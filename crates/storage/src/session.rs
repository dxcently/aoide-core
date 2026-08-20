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

use crate::petname;
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
        // Minted once, here, against the live in-hand vec (a done record's
        // name is free per `mint_for`'s liveness rule) — the UPDATE arm
        // above never touches `petname`: a re-start/resume must not rename
        // a session mid-flight, and a legacy `None` record is never
        // backfilled on later touches.
        let petname = petname::mint_for(sessions);
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
            petname: Some(petname),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upsert_session_insert_arm_mints_a_petname() {
        let mut sessions: Vec<SessionRecord> = Vec::new();
        assert!(upsert_session(
            &mut sessions, "s1", None, Some("/w"), None, None, None, None, None, None,
            "2026-01-01T00:00:00Z"
        ));
        assert!(sessions[0].petname.is_some(), "a fresh insert must mint a petname");
    }

    #[test]
    fn upsert_session_update_arm_never_touches_petname() {
        let mut sessions: Vec<SessionRecord> = Vec::new();
        upsert_session(
            &mut sessions, "s1", None, Some("/w"), None, None, None, None, None, None,
            "2026-01-01T00:00:00Z"
        );
        let minted = sessions[0].petname.clone();
        // Serialize before and after the re-start (update arm) with a
        // fully-populated set of fields, so any accidental re-mint or
        // clear shows up as a byte difference in the petname key alone.
        let before = serde_json::to_string(&sessions[0]).unwrap();
        assert!(!upsert_session(
            &mut sessions,
            "s1",
            Some("melete"),
            Some("/w2"),
            Some("0xabc"),
            Some("parent"),
            Some(true),
            Some("/run/user/1000/aoide/session-s1.sock"),
            Some("do the thing"),
            Some(123),
            "2026-02-02T00:00:00Z"
        ));
        assert_eq!(sessions[0].petname, minted, "the update arm re-minted or cleared petname");
        let after = serde_json::to_string(&sessions[0]).unwrap();
        let petname_key = format!("\"petname\":\"{}\"", minted.unwrap());
        assert!(before.contains(&petname_key), "before: {before}");
        assert!(after.contains(&petname_key), "the serialized petname changed across an update: {after}");
    }

    #[test]
    fn upsert_session_two_fresh_inserts_mint_different_petnames() {
        let mut sessions: Vec<SessionRecord> = Vec::new();
        upsert_session(
            &mut sessions, "s1", None, Some("/w"), None, None, None, None, None, None,
            "2026-01-01T00:00:00Z"
        );
        upsert_session(
            &mut sessions, "s2", None, Some("/w"), None, None, None, None, None, None,
            "2026-01-01T00:00:01Z"
        );
        assert_ne!(
            sessions[0].petname, sessions[1].petname,
            "two live records must never share a minted petname"
        );
    }

    #[test]
    fn upsert_session_update_arm_never_backfills_a_legacy_none_petname() {
        let mut sessions: Vec<SessionRecord> = vec![SessionRecord {
            session_id: "legacy".into(),
            agent: "claude".into(),
            state: "idle".into(),
            started_at: "2025-01-01T00:00:00Z".into(),
            petname: None,
            ..Default::default()
        }];
        assert!(!upsert_session(
            &mut sessions,
            "legacy",
            Some("melete"),
            Some("/w2"),
            None,
            None,
            None,
            None,
            None,
            None,
            "2026-02-02T00:00:00Z"
        ));
        assert_eq!(sessions[0].petname, None, "a legacy None petname must never be backfilled");
    }
}
