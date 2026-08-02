//! `stage/design.json` — the active "design mode" marker: the fact that a
//! particular song is being actively iterated on right now (concepts/
//! Self-Ricing's design-mode extension).
//!
//! Phase A only defines the shape + `load`/`save` pair and ships a read-only
//! `aoide rice design status`. Nothing writes this file yet — `rice design
//! enter`/`exit` (which would call [`save_design_marker`]) are later-phase
//! work; `status` today reports whatever a marker was dropped here some other
//! way (or `None`, honestly, when nothing has).

use crate::fs::{atomic_write, stage_dir};
use serde::{Deserialize, Serialize};

/// The active design-mode marker. `carried_slots` is always empty in Phase A
/// — no widget-carry logic exists yet; a later phase populates it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct DesignMarker {
    #[serde(default)]
    pub song: String,
    /// ISO-8601 UTC (`aoide_storage::time::now_iso_utc`) — when design mode
    /// was entered for `song`.
    #[serde(rename = "enteredAt", default)]
    pub entered_at: String,
    /// Who/what entered design mode (a session id, a username — caller's
    /// choice); absent when unknown, mirroring the `SessionRecord`/`A2aAgent`
    /// Option convention (omitted on the wire, not written as `null`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    /// Absolute path to `song/songbook/<song>/design/intent.md`.
    #[serde(default)]
    pub intent: String,
    /// Whether `intent` actually exists on disk at write time — `status`
    /// surfaces this so a reader never has to `stat` the path itself.
    #[serde(rename = "intentPresent", default)]
    pub intent_present: bool,
    #[serde(default)]
    pub sources: Vec<String>,
    /// Widget slots carried live into design mode — always `[]` in Phase A
    /// (no widget-carry logic yet; a later phase populates this).
    #[serde(rename = "carriedSlots", default)]
    pub carried_slots: Vec<String>,
}

/// The marker path: `stage/design.json`.
pub fn design_marker_path() -> std::path::PathBuf {
    stage_dir().join("design.json")
}

/// Load the marker, tolerating a missing/corrupt file as `None`
/// (CONTRACTS.md §4 additive discipline — an absent file simply means "no
/// design session active", never an error).
pub fn load_design_marker() -> Option<DesignMarker> {
    let raw = std::fs::read_to_string(design_marker_path()).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Atomic-write the marker to `stage/design.json`.
pub fn save_design_marker(marker: &DesignMarker) -> Result<(), String> {
    let body = serde_json::to_string_pretty(marker)
        .map_err(|e| format!("serialize design.json: {e}"))?
        + "\n";
    let path = design_marker_path();
    atomic_write(&path, &body).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// Mirrors the `SessionRecord`/`A2aAgent` round-trip pattern: the JSON
    /// shape is camelCase on the wire, and an absent `by`/legacy-missing
    /// `carriedSlots` parses to a sensible default rather than an error.
    #[test]
    fn design_marker_round_trips_camel_case_and_tolerates_absent_optionals() {
        let marker = DesignMarker {
            song: "moonlight".to_string(),
            entered_at: "2026-08-02T00:00:00Z".to_string(),
            by: Some("khoa".to_string()),
            intent: "/home/khoa/Aoide/song/songbook/moonlight/design/intent.md".to_string(),
            intent_present: true,
            sources: vec!["stage/drachma.json".to_string()],
            carried_slots: vec![],
        };
        let json = serde_json::to_string(&marker).unwrap();
        assert!(json.contains("\"enteredAt\":"), "camelCase key: {json}");
        assert!(json.contains("\"intentPresent\":true"), "camelCase key: {json}");
        assert!(json.contains("\"carriedSlots\":[]"), "camelCase key: {json}");
        let back: DesignMarker = serde_json::from_str(&json).unwrap();
        assert_eq!(back, marker);

        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["by"], "khoa");

        // A record with no `by` omits the key entirely (no null noise) —
        // same Option convention as `SessionRecord::parent_session_id`.
        let mut no_by = marker.clone();
        no_by.by = None;
        let no_by_json = serde_json::to_string(&no_by).unwrap();
        assert!(!no_by_json.contains("\"by\""), "serialised: {no_by_json}");

        // A legacy/partial record missing `by` and `carriedSlots` entirely
        // still parses: `by` stays `None`, `carriedSlots` defaults to `[]`.
        let legacy: DesignMarker = serde_json::from_str(
            r#"{ "song": "dusk", "enteredAt": "t", "intent": "i", "intentPresent": false, "sources": [] }"#,
        )
        .unwrap();
        assert_eq!(legacy.by, None);
        assert!(legacy.carried_slots.is_empty());
    }

    #[test]
    fn load_save_design_marker_round_trip_through_a_temp_stage_dir() {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-design-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("AOIDE_STAGE_DIR", &dir);

        // Missing file → None (tolerate-missing, never an error).
        assert!(load_design_marker().is_none());

        let marker = DesignMarker {
            song: "moonlight".to_string(),
            entered_at: "2026-08-02T00:00:00Z".to_string(),
            by: None,
            intent: "/x/intent.md".to_string(),
            intent_present: false,
            sources: vec![],
            carried_slots: vec![],
        };
        save_design_marker(&marker).unwrap();
        let back = load_design_marker().unwrap();
        assert_eq!(back, marker);

        let raw = std::fs::read_to_string(design_marker_path()).unwrap();
        let v: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["song"], "moonlight");
        assert!(v.get("by").is_none(), "by omitted when None");

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }
}
