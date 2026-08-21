//! aoide-conduct — Aoide's session core: the PTY multiplexer (`aoide
//! conduct`), the session DAG (`aoide graph`), Claude-Code hook plumbing, and
//! liveness reaping (Phase 3b restructure,
//! docs/architecture/PACKAGE-LAYOUT.md).
//!
//! Extracted from root `src/graph.rs` + `src/graph/*.rs` + `src/reap.rs` +
//! the socket-loop half of `src/shellbridge.rs`, following the same shim
//! discipline `aoide-protocol` (Phase 2) and `aoide-storage` (Phase 3a)
//! established: every moved symbol is re-exported at its old root path via
//! `pub use`, so no existing call site changes. Sits ABOVE `aoide-storage`
//! (the durable session-record substrate) and `aoide-protocol` (the
//! Invocation/Outcome/audit contract every door shares).

pub mod commands;
pub mod graph;
pub mod herald;
pub mod reap;
pub mod shellbridge;

/// A crate-wide lock serialising every test that mutates process-global env
/// (`AOIDE_STAGE_DIR`, `XDG_RUNTIME_DIR`, `AOIDE_AUDIT_LOG`,
/// `HYPRLAND_INSTANCE_SIGNATURE`, …) — mirrors `aoide::env_lock()` (root
/// `src/lib.rs`) and `aoide_storage::env_lock()` (Phase 3a). Needed here
/// because the moved `graph`/`reap`/`shellbridge` tests touch the same
/// process-global env vars and must serialise against each other under the
/// multithreaded test harness.
#[cfg(test)]
pub(crate) fn env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    &LOCK
}
