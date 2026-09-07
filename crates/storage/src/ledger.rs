//! The durable session ledger: `state/session-ledger.jsonl`
//! (`docs/architecture/AOIDED.md`'s "L5 — harness summoning" section, P-D8).
//!
//! `sessions.json` (`records::SessionRecord`) is the LIVE roster — reaping
//! prunes it, so it has no memory past a session's own lifetime. This is the
//! memory that survives the prune: one line, appended once, at the exact
//! moment a session leaves the roster (a clean `graph session end` or a
//! `graph reap` sweep — `aoide-conduct`'s `graph::ledger_session_exit` is the
//! ONE call both routes share, never a second writer). `graph resurrect`
//! reads it back to find a project's resumable sessions — by default the
//! ones marked durable in [`crate::carry`], newest line per id.
//!
//! Append-only and UNCAPPED, unlike [`crate::fs`]'s stage files or
//! `aoide_protocol::feed::FeedWriter`'s truncate-at-cap feeds: this is
//! history, not live state or an ephemeral cue, so nothing here ever
//! truncates or rotates it — the same posture `aoide_protocol::audit`
//! already holds for the audit log, mirrored here for a second unbounded
//! JSON-lines log with its own record shape (never a lookup key for live
//! state; readers tolerate a partial trailing line same as any other
//! append-only log this codebase writes).

use crate::records::RestoreSnapshot;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;

/// One ledger line — the shape `docs/architecture/AOIDED.md`'s "L5" section
/// fixes verbatim. Every field always serializes (never `skip_serializing_if`):
/// unlike the live `SessionRecord`'s additive-optional discipline, a ledger
/// line is a closed historical record, so an absent fact reads as an
/// explicit `null` rather than a missing key — a `jq`/log reader always sees
/// the same shape on every line.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LedgerEntry {
    #[serde(default)]
    pub v: u32,
    #[serde(rename = "sessionId", default)]
    pub session_id: String,
    #[serde(default)]
    pub agent: String,
    #[serde(rename = "harnessSessionId", default)]
    pub harness_session_id: Option<String>,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub petname: Option<String>,
    #[serde(rename = "startedAt", default)]
    pub started_at: String,
    #[serde(rename = "endedAt", default)]
    pub ended_at: String,
    #[serde(rename = "resumedFrom", default)]
    pub resumed_from: Option<String>,
    /// Projected verbatim from `SessionRecord.origin` (P-P3,
    /// `docs/architecture/PAIRING.md` decision 7) — `"node:<name>"` for a
    /// session an identified, paired node's A2A spawn created; `None` for
    /// every locally-registered session and every entry predating this
    /// field. Always serializes (never `skip_serializing_if`), same
    /// closed-historical-record discipline every other field here holds.
    #[serde(rename = "origin", default)]
    pub origin: Option<String>,
    /// Projected verbatim from `SessionRecord.restore` (P-C5,
    /// durable-sessions plan) — a conducted terminal's continuously-captured
    /// cwd/idle/argv/typed at the exact instant it left the roster, `None`
    /// for every non-shell session and every entry predating this field.
    /// Always serializes (never `skip_serializing_if`), same
    /// closed-historical-record discipline every other field here holds —
    /// including `RestoreSnapshot`'s OWN fields when this is `Some`, so a
    /// populated `restore` reads the same complete shape here as it does on
    /// the live record.
    #[serde(default)]
    pub restore: Option<RestoreSnapshot>,
}

/// The ledger's path: `state/session-ledger.jsonl`, under
/// [`crate::fs::state_dir`] (real disk, not tmpfs) — sibling to
/// `state/usage.json`/`state/sessions/<id>.log`, never inside either stage
/// tree (`state/stage/` or `song/stage/`): this is durable history, not live
/// rehearsal/registry state a `rice mode`/stage-reseed ever resets, or a
/// broker roster a mutation ever rewrites wholesale.
pub fn session_ledger_path() -> PathBuf {
    crate::fs::state_dir().join("session-ledger.jsonl")
}

/// Append one line, best-effort — creates the parent dir and the file if
/// absent, never truncates. Mirrors `aoide_protocol::audit::append_audit`'s
/// exact mechanics (`OpenOptions::create(true).append(true)`) for a second,
/// differently-shaped unbounded JSON-lines log; every call site swallows the
/// `Err` and `eprintln!`s it, same discipline as every other best-effort
/// side channel in this codebase (a ledger-write failure must never fail the
/// roster-exit it is recording).
pub fn append_ledger_entry(entry: &LedgerEntry) -> std::io::Result<()> {
    let path = session_ledger_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut line = serde_json::to_string(entry)
        .unwrap_or_else(|e| format!("{{\"v\":0,\"error\":\"{e}\"}}"));
    line.push('\n');
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&path)?;
    f.write_all(line.as_bytes())
}

/// Read every well-formed line back, in on-disk (append) order — a malformed
/// or partial trailing line (a write racing a read, or a hand edit) is
/// skipped rather than failing the whole read, same tolerance every other
/// stage/ledger reader in this codebase extends a line it cannot parse.
/// `Ok(vec![])` for a missing file (nothing has ever left the roster yet) —
/// never an error.
pub fn read_ledger() -> std::io::Result<Vec<LedgerEntry>> {
    let path = session_ledger_path();
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    Ok(raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<LedgerEntry>(l).ok())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_state(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "aoide-storage-ledger-test-{tag}-{}-{}",
            std::process::id(),
            crate::time::now_iso_utc().replace([':', '-', '.'], "")
        ))
    }

    #[test]
    fn append_then_read_round_trips_every_field() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let state = unique_state("roundtrip");
        std::env::set_var("AOIDE_STATE_DIR", &state);

        let entry = LedgerEntry {
            v: 0,
            session_id: "s1".to_string(),
            agent: "claude".to_string(),
            harness_session_id: Some("h1".to_string()),
            cwd: "/home/khoa/Aoide".to_string(),
            title: Some("do the thing".to_string()),
            petname: Some("brave-otter".to_string()),
            started_at: "2026-08-24T00:00:00Z".to_string(),
            ended_at: "2026-08-24T01:00:00Z".to_string(),
            resumed_from: None,
            origin: Some("node:yomi-strix".to_string()),
            restore: Some(RestoreSnapshot {
                cwd: Some("/home/khoa/Aoide".to_string()),
                idle: true,
                argv: None,
                typed: Some("cargo test -p aoide-conduct".to_string()),
            }),
        };
        append_ledger_entry(&entry).unwrap();

        let back = read_ledger().unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].session_id, "s1");
        assert_eq!(back[0].harness_session_id.as_deref(), Some("h1"));
        assert_eq!(back[0].resumed_from, None);
        assert_eq!(back[0].origin.as_deref(), Some("node:yomi-strix"));
        assert_eq!(back[0].restore, entry.restore);

        std::env::remove_var("AOIDE_STATE_DIR");
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn restore_absent_serializes_as_explicit_null_never_omitted() {
        // Risk #7 (durable-sessions plan, P-C5): `restore` must serialize
        // unconditionally like every other `LedgerEntry` field — a
        // `skip_serializing_if` here would silently violate the closed-
        // historical-record discipline `CONTRACTS.md` fixes for this file.
        let entry = LedgerEntry {
            session_id: "s1".to_string(),
            ..Default::default()
        };
        let line = serde_json::to_string(&entry).unwrap();
        assert!(line.contains("\"restore\":null"), "serialised: {line}");
    }

    #[test]
    fn an_old_line_with_no_restore_key_parses_as_none() {
        // A ledger line written before this field existed has no `restore`
        // key at all — `#[serde(default)]` must still parse it, not fail
        // the whole line (which `read_ledger` would otherwise silently skip).
        let old_line = r#"{"v":0,"sessionId":"s0","agent":"claude","cwd":"/x","startedAt":"2026-01-01T00:00:00Z","endedAt":"2026-01-01T01:00:00Z"}"#;
        let entry: LedgerEntry = serde_json::from_str(old_line).unwrap();
        assert_eq!(entry.restore, None);
    }

    #[test]
    fn append_never_truncates_across_multiple_calls() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let state = unique_state("multi");
        std::env::set_var("AOIDE_STATE_DIR", &state);

        for i in 0..5 {
            let entry = LedgerEntry {
                session_id: format!("s{i}"),
                ..Default::default()
            };
            append_ledger_entry(&entry).unwrap();
        }
        let back = read_ledger().unwrap();
        assert_eq!(back.len(), 5, "every append must survive, none truncated");
        assert_eq!(back[0].session_id, "s0");
        assert_eq!(back[4].session_id, "s4");

        std::env::remove_var("AOIDE_STATE_DIR");
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn read_ledger_skips_a_malformed_line_rather_than_failing() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let state = unique_state("malformed");
        std::env::set_var("AOIDE_STATE_DIR", &state);

        let path = session_ledger_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "{\"sessionId\":\"good\"}\nnot json at all\n").unwrap();

        let back = read_ledger().unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].session_id, "good");

        std::env::remove_var("AOIDE_STATE_DIR");
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn missing_ledger_reads_as_empty_never_an_error() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let state = unique_state("missing");
        std::env::set_var("AOIDE_STATE_DIR", &state);

        assert_eq!(read_ledger().unwrap().len(), 0);

        std::env::remove_var("AOIDE_STATE_DIR");
    }
}
