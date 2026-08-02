//! aoide-storage — Aoide's durable session data (Phase 3a restructure,
//! docs/architecture/PACKAGE-LAYOUT.md): the stage-file record shapes
//! (`records`), atomic stage I/O (`fs`, `stage`), time formatting (`time`),
//! the pure session/hook upsert ops (`session`), the client-side A2A agent
//! roster (`a2a_store`), and the active design-mode marker (`design`).
//!
//! Extracted from root `src/` (`shellbridge.rs`, `graph/model.rs`,
//! `graph/session_store.rs`, `conductor/theme.rs`, `a2a.rs`) following the
//! same shim discipline `aoide-protocol` (Phase 2) established: every moved
//! symbol is re-exported at its old root path via `pub use`, so no existing
//! call site changes.

pub mod a2a_store;
pub mod design;
pub mod fs;
pub mod records;
pub mod session;
pub mod stage;
pub mod time;

/// A crate-wide lock serialising every test that mutates process-global env
/// (`AOIDE_STAGE_DIR`, `AOIDE_STATE_DIR`, …) — mirrors `aoide::env_lock()`
/// (root `src/lib.rs`), needed here because the moved fs/a2a_store tests
/// touch the same process-global env vars and must serialise against each
/// other under the multithreaded test harness.
#[cfg(test)]
pub(crate) fn env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    &LOCK
}
