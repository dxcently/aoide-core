//! `stage/mode.json` — whether the rice system is in STAGING mode (hot-load
//! unlocked: `rice stage`/`cover set` write live), DECLARATIVE mode (nix/
//! home-manager is the only writer; staging writers refuse), or DRAFT mode
//! (`stage/livery.json` is a symlink routed into a saved
//! `songbook/<song>/drafts/<name>/livery.json` — every writer that ever
//! touches the stage lands directly in the draft file, transparently, via
//! [`crate::fs::atomic_write`]'s symlink-resolving rename) — Self-Ricing's
//! mode-toggle extension (khoa, 2026-08-14; draft mode, khoa, 2026-08-14).
//!
//! Absent file = `declarative` (the safe default: nothing has ever unlocked
//! staging writes, so nothing should silently be mutable — the same "an
//! absent stage file means the safe default, never an error" discipline
//! this module's own [`load_mode_marker`] follows).
//!
//! `Draft` is a distinct THIRD mode, not a flag riding on top of `Staging` —
//! routing, not guessing: entering it (`rice mode draft <name>`,
//! `crates/song/src/commands/mode.rs`) is the only way to reach a saved
//! draft at all. `rice stage`/`rice mode stage` never auto-prefer or
//! auto-detect a draft; they always mean plain declared content, and are
//! simply unaware that the file they write might currently be routed
//! elsewhere (that unawareness, plus `atomic_write`'s symlink transparency,
//! is the entire mechanism).

use crate::fs::{atomic_write, stage_dir};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiceMode {
    Staging,
    Declarative,
    Draft,
}

impl Default for RiceMode {
    fn default() -> Self {
        RiceMode::Declarative
    }
}

/// The active mode marker. `song` names what a `staging`- or `draft`-mode
/// session is pointed at (absent in the common
/// `declarative`-with-no-marker-file case). `draft` is `Some(name)`
/// **if and only if** `mode == Draft` — every other mode always carries
/// `draft: None`; nothing in the codebase ever sets one without the other.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ModeMarker {
    #[serde(default)]
    pub mode: RiceMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub song: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft: Option<String>,
    /// ISO-8601 UTC (`aoide_storage::time::now_iso_utc`) — when this mode was
    /// entered. Empty string on the zero-value `Default` (no marker ever
    /// written), never fabricated.
    #[serde(default)]
    pub since: String,
}

/// The marker path: `stage/mode.json`.
pub fn mode_marker_path() -> std::path::PathBuf {
    stage_dir().join("mode.json")
}

/// The system's CURRENT effective mode. An absent or corrupt marker resolves
/// to the zero-value `declarative` default — never an error (CONTRACTS.md §4
/// additive discipline).
pub fn load_mode_marker() -> ModeMarker {
    std::fs::read_to_string(mode_marker_path())
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

/// Atomic-write the marker to `stage/mode.json`.
pub fn save_mode_marker(marker: &ModeMarker) -> Result<(), String> {
    let body = serde_json::to_string_pretty(marker)
        .map_err(|e| format!("serialize mode.json: {e}"))?
        + "\n";
    let path = mode_marker_path();
    atomic_write(&path, &body).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn default_marker_is_declarative_with_no_song_or_draft() {
        let m = ModeMarker::default();
        assert_eq!(m.mode, RiceMode::Declarative);
        assert_eq!(m.song, None);
        assert_eq!(m.draft, None);
        assert_eq!(m.since, "");
    }

    #[test]
    fn missing_marker_file_loads_as_the_declarative_default() {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-mode-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("AOIDE_STAGE_DIR", &dir);

        let m = load_mode_marker();
        assert_eq!(m, ModeMarker::default());
        assert!(!mode_marker_path().exists());

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    #[test]
    fn save_load_round_trips_through_a_temp_stage_dir() {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-mode-rt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("AOIDE_STAGE_DIR", &dir);

        let marker = ModeMarker {
            mode: RiceMode::Staging,
            song: Some("moonlight".to_string()),
            draft: None,
            since: "2026-08-14T00:00:00Z".to_string(),
        };
        save_mode_marker(&marker).unwrap();
        let back = load_mode_marker();
        assert_eq!(back, marker);

        let raw = std::fs::read_to_string(mode_marker_path()).unwrap();
        let v: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["mode"], "staging");
        assert_eq!(v["song"], "moonlight");
        assert!(v.get("draft").is_none(), "draft omitted when None");

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    #[test]
    fn draft_mode_round_trips_with_a_draft_name_and_serializes_lowercase() {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-mode-draft-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("AOIDE_STAGE_DIR", &dir);

        let marker = ModeMarker {
            mode: RiceMode::Draft,
            song: Some("sonata".to_string()),
            draft: Some("neon-night".to_string()),
            since: "2026-08-14T00:00:00Z".to_string(),
        };
        save_mode_marker(&marker).unwrap();
        let back = load_mode_marker();
        assert_eq!(back, marker);

        let raw = std::fs::read_to_string(mode_marker_path()).unwrap();
        let v: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["mode"], "draft");
        assert_eq!(v["draft"], "neon-night");

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    #[test]
    fn corrupt_marker_file_loads_as_the_declarative_default() {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-mode-corrupt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &dir);

        std::fs::write(mode_marker_path(), "not json").unwrap();
        let m = load_mode_marker();
        assert_eq!(m, ModeMarker::default());

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }
}
