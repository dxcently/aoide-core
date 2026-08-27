//! Stage-file I/O (missing file → empty registry; writes atomic) and the
//! four CONDUCTING stage-file paths.
//!
//! Moved from `graph/model.rs` (Phase 3a restructure,
//! docs/architecture/PACKAGE-LAYOUT.md); re-exported at the old path so every
//! existing `crate::graph::{load_stage, write_stage, sessions_path, …}`
//! caller is untouched.
//!
//! `projects_path`/`graph_path` were `pub(in crate::graph)` in root — now
//! crossing a crate boundary they must be `pub` here; the root shim narrows
//! their re-export back to `pub(in crate::graph)` so the original visibility
//! contract at the root crate boundary is unchanged.
//!
//! **`state/stage/`, not `song/stage/` (command-defrag lane S1,
//! 2026-08-27).** These four files are core orchestration state — CONTRACTS.md
//! §4 — so they resolve through [`crate::fs::conducting_stage_dir`], not
//! [`crate::fs::stage_dir`] (which still means the rice/paint stage tree).
//! `pending.json`/`herald.json`, the other two files in the same broker-owned
//! roster, live in `aoide-conduct` instead (`graph::pending_path`,
//! `herald::herald_path`) and made the identical switch.

use crate::fs::{atomic_write, conducting_stage_dir};
use serde::Serialize;

pub fn projects_path() -> std::path::PathBuf {
    conducting_stage_dir().join("projects.json")
}
pub fn sessions_path() -> std::path::PathBuf {
    conducting_stage_dir().join("sessions.json")
}
pub fn hooks_path() -> std::path::PathBuf {
    conducting_stage_dir().join("hooks.json")
}
pub fn graph_path() -> std::path::PathBuf {
    conducting_stage_dir().join("graph.json")
}

/// Load one stage file; a missing file is an empty registry (tolerated), a
/// corrupt one is a structured error string.
pub fn load_stage<T: serde::de::DeserializeOwned + Default>(
    path: &std::path::Path,
) -> Result<T, String> {
    match std::fs::read_to_string(path) {
        Ok(s) => serde_json::from_str(&s)
            .map_err(|e| format!("{}: unreadable stage file: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Atomic write of one stage file (write-temp-then-rename, CONTRACTS.md §4).
pub fn write_stage<T: Serialize>(path: &std::path::Path, value: &T) -> Result<(), String> {
    let body = serde_json::to_string_pretty(value)
        .map_err(|e| format!("{}: serialize: {e}", path.display()))?;
    atomic_write(path, &body).map_err(|e| format!("{}: {e}", path.display()))
}
