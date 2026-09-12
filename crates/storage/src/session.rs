//! Pure UPSERT ops on the session/hook record vecs — no DAG/stage-lock
//! dependency (verified: neither function touches `graph/doc.rs`'s
//! `restage_graph`/`would_cycle` or `graph/common.rs`'s
//! `require_flag`/`stage_error`; both are pure `Vec<Record>` mutators the
//! handler wires I/O around).
//!
//! Moved from `graph/session_store.rs` (Phase 3a restructure,
//! docs/architecture/PACKAGE-LAYOUT.md); re-exported at the old path so every
//! existing `crate::graph::{upsert_session, upsert_hook}` (and the
//! `session_store.rs`-local) caller is untouched. The command handlers
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
            enduring_agent_id: None,
            project: None,
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
            hook_ancestry: Vec::new(),
            headless: false,
            // Stamped moments later by `stamp_spawned`, only when this
            // registration carries `conduct --spawned` — i.e. only for a
            // record `aoide spawn` re-exec'd into being. A terminal the User
            // opened themselves never gains it.
            spawned: false,
            // No inheritance (task #20): a fresh registration always starts
            // un-exempt, spawned child or not — an agent that wants its own
            // worker shell shielded marks it after spawn.
            exempt: false,
            // Stamped later by `graph session hook` from the raw hook
            // payload's own `session_id` (P-D7); a fresh record starts
            // without one.
            harness_session_id: None,
            // A fresh registration is a first run, never a revival — the
            // resurrect path (P-D8) stamps this after the fact via
            // `stamp_resumed_from`, once the new record exists.
            resumed_from: None,
            // Stamped later by `stamp_origin` (P-P3), only for a session
            // aoide-server's A2A door spawned on behalf of a paired node; a
            // fresh registration otherwise starts without one.
            origin: None,
            // Stamped later by `stamp_seal` (LANE IDENTITY P-ID1), only once
            // a daemon has minted a sealed credential over this record's
            // pid; a fresh registration otherwise starts without one.
            seal: None,
            sealed_issued_at: None,
            // Stamped later by the PTY tick's `conduct_refresh_shell`
            // (P-C5), only for a conducted SHELL; a fresh registration has
            // not ticked yet.
            restore: None,
            // A fresh registration carries no native-capture provenance —
            // only Codex-app capture (`graph/codex_app.rs`) ever sets this.
            sources: None,
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

/// Bind an explicitly supplied enduring key, independent of knowledge services.
/// Restart UPSERT never changes it.
/// Returns false for the same binding; all refusals leave the records untouched.
pub fn bind_enduring_agent(
    sessions: &mut [SessionRecord],
    id: &str,
    key: &str,
) -> Result<bool, String> {
    if !crate::node_store::valid_node_name(key) {
        return Err("invalid-enduring-agent-id".into());
    }
    let session = sessions.iter_mut().find(|s| s.session_id == id)
        .ok_or_else(|| "unknown-session".to_string())?;
    match session.enduring_agent_id.as_deref() {
        Some(current) if current == key => Ok(false),
        Some(_) => Err("conflicting-binding".into()),
        None => {
            session.enduring_agent_id = Some(key.into());
            Ok(true)
        }
    }
}

#[cfg(test)]
mod context_binding_tests {
    use super::*;

    #[test]
    fn invalid_keys_are_rejected_before_binding_a_fresh_executor() {
        let mut sessions = vec![SessionRecord { session_id: "fresh".into(), ..Default::default() }];
        for key in ["", "UPPER", "two words", "../other", "-leading", "id_with_underscore"] {
            assert_eq!(bind_enduring_agent(&mut sessions, "fresh", key).unwrap_err(), "invalid-enduring-agent-id");
            assert!(sessions[0].enduring_agent_id.is_none());
        }
    }

    #[test]
    fn binding_survives_harness_restart_and_refusals_do_not_mutate() {
        let mut sessions = vec![SessionRecord { session_id: "executor-1".into(), ..Default::default() }];
        assert!(bind_enduring_agent(&mut sessions, "executor-1", "7e3f5976-98b2-44a4-827c-c687a0d9526e").unwrap());
        assert!(!bind_enduring_agent(&mut sessions, "executor-1", "7e3f5976-98b2-44a4-827c-c687a0d9526e").unwrap());
        let before = serde_json::to_value(&sessions).unwrap();
        for (id, key) in [("missing", "7e3f5976-98b2-44a4-827c-c687a0d9526e"), ("executor-1", "Bad Key"), ("executor-1", "opaque-2")] {
            assert!(bind_enduring_agent(&mut sessions, id, key).is_err());
            assert_eq!(serde_json::to_value(&sessions).unwrap(), before);
        }
        upsert_session(&mut sessions, "executor-1", Some("codex"), None, None, None, None, None, None, None, "later");
        assert_eq!(sessions[0].enduring_agent_id.as_deref(), Some("7e3f5976-98b2-44a4-827c-c687a0d9526e"));
        assert_eq!(sessions[0].agent, "codex");
        let legacy: SessionRecord = serde_json::from_str(r#"{"sessionId":"old"}"#).unwrap();
        assert!(legacy.enduring_agent_id.is_none());
        assert!(serde_json::to_value(legacy).unwrap().get("enduringAgentId").is_none());
    }
}
