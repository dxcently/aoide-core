//! aoide-storage — Aoide's durable session data (Phase 3a restructure,
//! docs/architecture/PACKAGE-LAYOUT.md): the stage-file record shapes
//! (`records`), atomic stage I/O (`fs`, `stage`), time formatting (`time`),
//! the pure session/hook upsert ops (`session`), the client-side A2A agent
//! roster (`a2a_store`), the staging/declarative mode marker (`mode`), and
//! the peer-federation registry + pull cache (`peer_store`, CONTRACTS.md §7).
//!
//! Extracted from root `src/` (`shellbridge.rs`, `graph/model.rs`,
//! `graph/session_store.rs`, `conductor/theme.rs`, `a2a.rs`) following the
//! same shim discipline `aoide-protocol` (Phase 2) established: every moved
//! symbol is re-exported at its old root path via `pub use`, so no existing
//! call site changes.
//!
//! `takes` (Self-Ricing Phase A) is a new addition, not a moved one: the
//! per-draft take store backing `rice back`/`rice take` — see its module
//! doc for the tree-of-takes model.

pub mod a2a_store;
pub mod commands;
pub mod edits;
pub mod fs;
pub mod git;
pub mod mode;
pub mod peer_store;
pub mod records;
pub mod session;
pub mod stage;
pub mod takes;
pub mod time;

/// A crate-wide lock serialising every test that mutates process-global env
/// (`AOIDE_STAGE_DIR`, `AOIDE_STATE_DIR`, …). Delegates to
/// `aoide-test-support`'s single mutex (Phase 9 restructure): the `commands`
/// tests moved INTO this crate's test binary hold that lock, so every
/// env-touching test in the binary must share it or they race.
#[cfg(test)]
pub(crate) fn env_lock() -> &'static std::sync::Mutex<()> {
    aoide_test_support::env_lock()
}
