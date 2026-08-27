//! The carry mark: `state/carry.json` (v0) — the set of session ids marked
//! durable, so a project's whole carried set can be resurrected together
//! (`graph session carry on|off`, a later phase; CONTRACTS.md's
//! `state/carry.json` section).
//!
//! Store only (P-C1 of the durable-sessions plan) — no command, no consumer
//! wired yet. Mirrors `peer_store.rs`'s shape and discipline exactly: a
//! `schemaVersion` container, tolerate-missing/corrupt-as-empty on read,
//! `fs::atomic_write` on write, pure list mutations for the CRUD so it's
//! unit-testable off disk.

use crate::fs::{atomic_write, state_dir};
use crate::time::now_iso_utc;
use serde::{Deserialize, Serialize};

/// `state/carry.json` schema version (CONTRACTS.md, v0).
pub const CARRY_VERSION: &str = "0";

/// One carried session id and when it was (most recently) marked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CarriedSession {
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "markedAt", default)]
    pub marked_at: String,
}

/// The `state/carry.json` container.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CarryRegistry {
    #[serde(rename = "schemaVersion", default)]
    pub schema_version: String,
    #[serde(default)]
    pub carried: Vec<CarriedSession>,
}

/// The carry file path: `state/carry.json` — the same gitignored
/// root-runtime `state/` dir `peers.json`/`usage.json` live in
/// (CONTRACTS.md), NOT `song/stage/`: a carry mark is durable operator
/// state, never staged rehearsal state.
pub fn carry_path() -> std::path::PathBuf {
    state_dir().join("carry.json")
}

/// Read the carried set, tolerating a missing/corrupt/wrong-shape file as
/// empty — never an error, the same discipline `peer_store::load_peers`
/// holds. A mark set on an id that never produced a ledger line is inert,
/// not an error condition, so an unreadable file is simply "nothing
/// carried."
pub fn load_carry() -> Vec<CarriedSession> {
    match std::fs::read_to_string(carry_path()) {
        Ok(raw) => serde_json::from_str::<CarryRegistry>(&raw)
            .map(|r| r.carried)
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Atomic-write the carried set (v0 shape) back to `state/carry.json`.
/// Plain [`atomic_write`], not `atomic_write_private` — `carry.json` holds
/// session ids, the same class of data `sessions.json`/`peers.json`
/// already keep at default mode; `atomic_write_private` is reserved for the
/// identity/secret lane (`identity.rs`).
pub fn save_carry(carried: &[CarriedSession]) -> Result<(), String> {
    let reg = CarryRegistry {
        schema_version: CARRY_VERSION.to_string(),
        carried: carried.to_vec(),
    };
    let body = serde_json::to_string_pretty(&reg)
        .map_err(|e| format!("serialize carry.json: {e}"))?
        + "\n";
    let path = carry_path();
    atomic_write(&path, &body).map_err(|e| format!("{}: {e}", path.display()))
}

/// Mark or unmark `id` as carried. `on: true` adds it, or — if already
/// present — refreshes its `markedAt` in place, since a re-mark is a live
/// timestamp, not a no-op write. `on: false` removes it if present.
///
/// Returns whether the carried/not-carried TRANSITION actually changed: an
/// already-carried id re-marked `on`, or an absent id marked `off`, both
/// return `false` even though the former still touched `markedAt`. Pure
/// list mutation, so the CRUD is unit-testable off disk; the caller (`graph
/// session carry`, a later phase) reports this bool as `changed`.
pub fn set_carried(carried: &mut Vec<CarriedSession>, id: &str, on: bool) -> bool {
    let pos = carried.iter().position(|c| c.session_id == id);
    match (pos, on) {
        (Some(i), true) => {
            carried[i].marked_at = now_iso_utc();
            false
        }
        (None, true) => {
            carried.push(CarriedSession {
                session_id: id.to_string(),
                marked_at: now_iso_utc(),
            });
            true
        }
        (Some(i), false) => {
            carried.remove(i);
            true
        }
        (None, false) => false,
    }
}

/// Is `id` currently in the carried set? Pure, unit-testable off disk.
pub fn is_carried(carried: &[CarriedSession], id: &str) -> bool {
    carried.iter().any(|c| c.session_id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_temp_state_dir<T>(name: &str, f: impl FnOnce() -> T) -> T {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-carry-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("AOIDE_STATE_DIR", &dir);

        let out = f();

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        out
    }

    fn fixture(id: &str) -> CarriedSession {
        CarriedSession { session_id: id.to_string(), marked_at: "2026-08-26T00:00:00Z".to_string() }
    }

    #[test]
    fn load_save_carry_round_trip_through_a_temp_state_dir() {
        with_temp_state_dir("roundtrip", || {
            // Missing file → empty (tolerate-missing).
            assert!(load_carry().is_empty());

            let carried = vec![fixture("s1"), fixture("s2")];
            save_carry(&carried).unwrap();
            assert_eq!(load_carry(), carried);

            // The on-disk shape carries the v0 schemaVersion.
            let raw = std::fs::read_to_string(carry_path()).unwrap();
            let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
            assert_eq!(v["schemaVersion"], "0");
            assert_eq!(v["carried"].as_array().unwrap().len(), 2);
        });
    }

    #[test]
    fn load_carry_tolerates_a_corrupt_file_as_empty() {
        with_temp_state_dir("corrupt", || {
            std::fs::create_dir_all(state_dir()).unwrap();
            std::fs::write(carry_path(), "{ not json at all").unwrap();
            assert!(load_carry().is_empty());

            // Valid JSON but the wrong shape (`carried` as an object) is
            // likewise tolerated as empty, not a panic or an error.
            std::fs::write(carry_path(), r#"{"schemaVersion":"0","carried":{}}"#).unwrap();
            assert!(load_carry().is_empty());
        });
    }

    #[test]
    fn set_carried_on_is_idempotent_and_reports_the_transition() {
        let mut carried = Vec::new();

        // First mark: absent → present, transition changed.
        assert!(set_carried(&mut carried, "s1", true));
        assert!(is_carried(&carried, "s1"));
        assert_eq!(carried.len(), 1);

        // Re-mark: already present, no transition — reports unchanged, and
        // does not duplicate the entry.
        assert!(!set_carried(&mut carried, "s1", true));
        assert_eq!(carried.len(), 1);
    }

    #[test]
    fn set_carried_off_is_idempotent_and_reports_the_transition() {
        let mut carried = vec![fixture("s1")];

        // First unmark: present → absent, transition changed.
        assert!(set_carried(&mut carried, "s1", false));
        assert!(!is_carried(&carried, "s1"));
        assert!(carried.is_empty());

        // Re-unmark: already absent, no transition — reports unchanged.
        assert!(!set_carried(&mut carried, "s1", false));
        assert!(carried.is_empty());

        // Unmarking an id that was never carried is likewise a no-op.
        let mut empty = Vec::new();
        assert!(!set_carried(&mut empty, "never-carried", false));
        assert!(empty.is_empty());
    }

    #[test]
    fn set_carried_refreshes_marked_at_on_a_remark() {
        let mut carried = vec![fixture("s1")]; // marked_at fixed at 2026-08-26T00:00:00Z
        let before = carried[0].marked_at.clone();

        let changed = set_carried(&mut carried, "s1", true);
        assert!(!changed, "re-marking an already-carried id is not a transition");
        assert_ne!(carried[0].marked_at, before, "markedAt must refresh on a re-mark");
    }
}
