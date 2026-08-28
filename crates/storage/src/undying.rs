//! The undying mark: `state/undying.json` (v0) — the set of session ids
//! marked durable, so a project's whole undying set can be resurrected
//! together (`session grant undying on|off`, CONTRACTS.md's
//! `state/undying.json` section).
//!
//! Prototyped under the name "carry" (task #96, `state/carry.json`); this is
//! the shipped rename (command-defrag lane U1, 2026-08-27) — same shape and
//! discipline as before, and the same discipline `peer_store.rs` set: a
//! `schemaVersion` container, tolerate-missing/corrupt-as-empty on read,
//! `fs::atomic_write` on write, pure list mutations for the CRUD so it's
//! unit-testable off disk. [`load_undying`] additionally folds in a one-shot
//! migration off the pre-rename `state/carry.json` — see
//! [`migrate_carry_to_undying`]'s own doc.

use crate::fs::{atomic_write, state_dir};
use crate::time::now_iso_utc;
use serde::{Deserialize, Serialize};

/// `state/undying.json` schema version (CONTRACTS.md, v0).
pub const UNDYING_VERSION: &str = "0";

/// One undying session id and when it was (most recently) marked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UndyingSession {
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "markedAt", default)]
    pub marked_at: String,
}

/// The `state/undying.json` container.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UndyingRegistry {
    #[serde(rename = "schemaVersion", default)]
    pub schema_version: String,
    // `alias = "carried"`: a file the migration below just renamed (but has
    // not yet been re-saved through `save_undying`) still holds its
    // PRE-RENAME content, keyed `"carried"` — the migration moves the FILE,
    // never rewrites its bytes, so this read side must still understand the
    // old key until the next `save_undying` normalizes it to `"undying"`.
    #[serde(default, alias = "carried")]
    pub undying: Vec<UndyingSession>,
}

/// The undying file path: `state/undying.json` — the same gitignored
/// root-runtime `state/` dir `peers.json`/`usage.json` live in
/// (CONTRACTS.md), NOT inside either stage tree (`state/stage/` or
/// `song/stage/`): an undying mark is durable operator state, never staged
/// rehearsal/registry state.
pub fn undying_path() -> std::path::PathBuf {
    state_dir().join("undying.json")
}

/// One-shot-in-effect migration of the pre-rename `state/carry.json` onto
/// `state/undying.json` (command-defrag lane U1, 2026-08-27) — the mark
/// prototyped under the name "carry" (task #96) ships as "undying". Same
/// atomic discipline `aoide-storage::fs::migrate_conducting_stage`
/// established for the S1 stage-tree split: a plain `rename` (both paths
/// live under the same [`state_dir`], so this is always same-filesystem —
/// no cross-filesystem copy fallback is needed the way the multi-directory
/// S1 migration required one), never clobbers an existing `undying.json` (a
/// fresher file, or a process that already migrated), and narrates rather
/// than panics on a failed rename.
///
/// Unlike S1's migration, this one carries no process-wide `Once` guard — a
/// single small file, checked with one cheap `exists()` stat immediately
/// before every [`load_undying`] call, is idempotent by construction: once
/// the rename lands, `carry.json` is gone, so every later check is a single
/// stat that finds nothing to do. A host that never had a `carry.json` (a
/// fresh install, or one that already migrated) pays that one stat and
/// nothing else — and every existing caller of `load_undying`/`save_undying`
/// gets the migration for free, with no new call site to remember.
fn migrate_carry_to_undying() {
    let old_path = state_dir().join("carry.json");
    let new_path = undying_path();
    if new_path.exists() || !old_path.exists() {
        return;
    }
    if let Some(parent) = new_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!(
                "aoide: cannot create {} ({e}) — undying marks remain at {}",
                parent.display(),
                old_path.display()
            );
            return;
        }
    }
    if let Err(e) = std::fs::rename(&old_path, &new_path) {
        eprintln!(
            "aoide: could not migrate {} to {} ({e}) — undying marks stay at the old path",
            old_path.display(),
            new_path.display()
        );
    }
}

/// Read the undying set, tolerating a missing/corrupt/wrong-shape file as
/// empty — never an error, the same discipline `peer_store::load_peers`
/// holds. A mark set on an id that never produced a ledger line is inert,
/// not an error condition, so an unreadable file is simply "nothing
/// undying." Migrates a legacy `carry.json` in first, if one is found (see
/// [`migrate_carry_to_undying`]).
pub fn load_undying() -> Vec<UndyingSession> {
    migrate_carry_to_undying();
    match std::fs::read_to_string(undying_path()) {
        Ok(raw) => serde_json::from_str::<UndyingRegistry>(&raw)
            .map(|r| r.undying)
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Atomic-write the undying set (v0 shape) back to `state/undying.json`.
/// Plain [`atomic_write`], not `atomic_write_private` — `undying.json` holds
/// session ids, the same class of data `sessions.json`/`peers.json`
/// already keep at default mode; `atomic_write_private` is reserved for the
/// identity/secret lane (`identity.rs`).
pub fn save_undying(undying: &[UndyingSession]) -> Result<(), String> {
    let reg = UndyingRegistry {
        schema_version: UNDYING_VERSION.to_string(),
        undying: undying.to_vec(),
    };
    let body = serde_json::to_string_pretty(&reg)
        .map_err(|e| format!("serialize undying.json: {e}"))?
        + "\n";
    let path = undying_path();
    atomic_write(&path, &body).map_err(|e| format!("{}: {e}", path.display()))
}

/// Mark or unmark `id` as undying. `on: true` adds it, or — if already
/// present — refreshes its `markedAt` in place, since a re-mark is a live
/// timestamp, not a no-op write. `on: false` removes it if present.
///
/// Returns whether the undying/not-undying TRANSITION actually changed: an
/// already-undying id re-marked `on`, or an absent id marked `off`, both
/// return `false` even though the former still touched `markedAt`. Pure
/// list mutation, so the CRUD is unit-testable off disk; the caller
/// (`session grant undying`) reports this bool as `changed`.
pub fn set_undying(undying: &mut Vec<UndyingSession>, id: &str, on: bool) -> bool {
    let pos = undying.iter().position(|c| c.session_id == id);
    match (pos, on) {
        (Some(i), true) => {
            undying[i].marked_at = now_iso_utc();
            false
        }
        (None, true) => {
            undying.push(UndyingSession {
                session_id: id.to_string(),
                marked_at: now_iso_utc(),
            });
            true
        }
        (Some(i), false) => {
            undying.remove(i);
            true
        }
        (None, false) => false,
    }
}

/// Is `id` currently in the undying set? Pure, unit-testable off disk.
pub fn is_undying(undying: &[UndyingSession], id: &str) -> bool {
    undying.iter().any(|c| c.session_id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_temp_state_dir<T>(name: &str, f: impl FnOnce() -> T) -> T {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-undying-{name}-{}", std::process::id()));
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

    fn fixture(id: &str) -> UndyingSession {
        UndyingSession { session_id: id.to_string(), marked_at: "2026-08-26T00:00:00Z".to_string() }
    }

    #[test]
    fn load_save_undying_round_trip_through_a_temp_state_dir() {
        with_temp_state_dir("roundtrip", || {
            // Missing file → empty (tolerate-missing).
            assert!(load_undying().is_empty());

            let undying = vec![fixture("s1"), fixture("s2")];
            save_undying(&undying).unwrap();
            assert_eq!(load_undying(), undying);

            // The on-disk shape carries the v0 schemaVersion.
            let raw = std::fs::read_to_string(undying_path()).unwrap();
            let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
            assert_eq!(v["schemaVersion"], "0");
            assert_eq!(v["undying"].as_array().unwrap().len(), 2);
        });
    }

    #[test]
    fn load_undying_tolerates_a_corrupt_file_as_empty() {
        with_temp_state_dir("corrupt", || {
            std::fs::create_dir_all(state_dir()).unwrap();
            std::fs::write(undying_path(), "{ not json at all").unwrap();
            assert!(load_undying().is_empty());

            // Valid JSON but the wrong shape (`undying` as an object) is
            // likewise tolerated as empty, not a panic or an error.
            std::fs::write(undying_path(), r#"{"schemaVersion":"0","undying":{}}"#).unwrap();
            assert!(load_undying().is_empty());
        });
    }

    #[test]
    fn set_undying_on_is_idempotent_and_reports_the_transition() {
        let mut undying = Vec::new();

        // First mark: absent → present, transition changed.
        assert!(set_undying(&mut undying, "s1", true));
        assert!(is_undying(&undying, "s1"));
        assert_eq!(undying.len(), 1);

        // Re-mark: already present, no transition — reports unchanged, and
        // does not duplicate the entry.
        assert!(!set_undying(&mut undying, "s1", true));
        assert_eq!(undying.len(), 1);
    }

    #[test]
    fn set_undying_off_is_idempotent_and_reports_the_transition() {
        let mut undying = vec![fixture("s1")];

        // First unmark: present → absent, transition changed.
        assert!(set_undying(&mut undying, "s1", false));
        assert!(!is_undying(&undying, "s1"));
        assert!(undying.is_empty());

        // Re-unmark: already absent, no transition — reports unchanged.
        assert!(!set_undying(&mut undying, "s1", false));
        assert!(undying.is_empty());

        // Unmarking an id that was never undying is likewise a no-op.
        let mut empty = Vec::new();
        assert!(!set_undying(&mut empty, "never-undying", false));
        assert!(empty.is_empty());
    }

    #[test]
    fn set_undying_refreshes_marked_at_on_a_remark() {
        let mut undying = vec![fixture("s1")]; // marked_at fixed at 2026-08-26T00:00:00Z
        let before = undying[0].marked_at.clone();

        let changed = set_undying(&mut undying, "s1", true);
        assert!(!changed, "re-marking an already-undying id is not a transition");
        assert_ne!(undying[0].marked_at, before, "markedAt must refresh on a re-mark");
    }

    // ── carry.json → undying.json migration (command-defrag lane U1) ──────

    #[test]
    fn migrate_carry_to_undying_renames_the_old_file_once() {
        with_temp_state_dir("migrate-basic", || {
            std::fs::create_dir_all(state_dir()).unwrap();
            std::fs::write(
                state_dir().join("carry.json"),
                r#"{"schemaVersion":"0","carried":[{"sessionId":"live-1234","markedAt":"2026-08-26T00:00:00Z"}]}"#,
            )
            .unwrap();

            migrate_carry_to_undying();

            assert!(!state_dir().join("carry.json").exists(), "the legacy file must have moved");
            let raw = std::fs::read_to_string(undying_path()).unwrap();
            assert!(raw.contains("live-1234"), "content must move verbatim, got {raw}");

            // A second call is a pure no-op: nothing left at the old path.
            migrate_carry_to_undying();
            assert!(!state_dir().join("carry.json").exists());
        });
    }

    #[test]
    fn migrate_carry_to_undying_never_clobbers_an_existing_new_file() {
        with_temp_state_dir("migrate-no-clobber", || {
            std::fs::create_dir_all(state_dir()).unwrap();
            // A STALE legacy file alongside an already-populated undying.json
            // (a process that already migrated) — the new file must win, and
            // the stale legacy file is left in place rather than destroyed.
            std::fs::write(state_dir().join("carry.json"), "stale-legacy").unwrap();
            std::fs::write(undying_path(), "fresh-undying").unwrap();

            migrate_carry_to_undying();

            assert_eq!(std::fs::read_to_string(undying_path()).unwrap(), "fresh-undying");
            assert_eq!(std::fs::read_to_string(state_dir().join("carry.json")).unwrap(), "stale-legacy");
        });
    }

    #[test]
    fn migrate_carry_to_undying_is_a_no_op_when_neither_file_exists() {
        with_temp_state_dir("migrate-neither", || {
            migrate_carry_to_undying(); // must not panic or create anything
            assert!(!undying_path().exists());
            assert!(!state_dir().join("carry.json").exists());
        });
    }

    #[test]
    fn load_undying_migrates_a_legacy_carry_json_transparently() {
        with_temp_state_dir("migrate-via-load", || {
            std::fs::create_dir_all(state_dir()).unwrap();
            std::fs::write(
                state_dir().join("carry.json"),
                r#"{"schemaVersion":"0","carried":[{"sessionId":"legacy-id","markedAt":"2026-08-26T00:00:00Z"}]}"#,
            )
            .unwrap();

            let loaded = load_undying();
            assert!(is_undying(&loaded, "legacy-id"), "loaded: {loaded:?}");
            assert!(!state_dir().join("carry.json").exists(), "the legacy file must have moved");
            assert!(undying_path().exists());
        });
    }
}
