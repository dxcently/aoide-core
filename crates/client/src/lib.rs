//! aoide-client — Aoide's outbound A2A door (Phase 4b restructure,
//! docs/architecture/PACKAGE-LAYOUT.md): the client-side wire builders/parsers
//! (`wire`) and the melete neutral-event adapter (`adapter`).
//!
//! Extracted from root `src/a2a.rs` (its CLIENT-side region only — the
//! server-side JSON-RPC/HTTP door stays in root, Phase 4c's job) and root
//! `src/adapter.rs` wholesale, following the same shim discipline
//! `aoide-protocol` (Phase 2), `aoide-storage` (Phase 3a), and `aoide-conduct`
//! (Phase 3b) established: every moved symbol is re-exported at its old root
//! path via `pub use`, so no existing call site changes.
//!
//! `daemon` (P-D6, `docs/architecture/AOIDED.md`'s "L4 — graph residency")
//! is this crate's second outbound door, beside the A2A one: `daemon::
//! daemon_dispatch` is the connect-or-`None` client every session-write
//! handler in `aoide-conduct` tries first, over the resident `aoided`'s
//! own control socket.

pub mod adapter;
pub mod commands;
pub mod daemon;
pub mod peer;
pub mod wire;

/// A crate-wide lock serialising every test that mutates process-global env
/// (`AOIDE_DAEMON_SOCKET` today). Delegates to `aoide-test-support`'s single
/// mutex, the same pattern `aoide-storage`/`aoide-conduct` already hold
/// (`pkgs/aoide/crates/AGENTS.md`'s "per-crate tests only").
#[cfg(test)]
pub(crate) fn env_lock() -> &'static std::sync::Mutex<()> {
    aoide_test_support::env_lock()
}
