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
//!
//! `discover` (P-P6, `docs/architecture/PAIRING.md`'s "Discovery
//! (advertise-but-locked)" section) is the discovery beacon's LISTEN half —
//! `peer discover`/`peer invite`'s shared multicast sweep, dedupe-by-
//! fingerprint fold, and (for `peer invite`) the pure heard-set resolution
//! its ambiguous/absent-name refusal is built on. The SEND half
//! (`a2a serve`'s own advertise thread) lives in `aoide-server::discovery`
//! instead — this crate is outbound-only, and joining a multicast group to
//! LISTEN is the client-side action here, mirroring every other `peer *`
//! command's shape.
//!
//! `tunnel` (P-S3, ssh-transport lane) is the ONE place `ssh` is ever
//! spawned: `open_or_reuse`/`close`/`close_all_for_session` open, probe,
//! reuse, and tear down the loopback forward a cross-box peer action dials
//! through when a `--via`/`Peer.via` transport marker is present.
//! `aoide_storage::tunnel` (P-S2) owns the record's shape and every pure
//! helper around it; this module owns the child process.

pub mod adapter;
pub mod commands;
pub mod daemon;
pub mod discover;
pub mod peer;
pub mod tunnel;
pub mod wire;

/// A crate-wide lock serialising every test that mutates process-global env
/// (`AOIDE_DAEMON_SOCKET` today). Delegates to `aoide-test-support`'s single
/// mutex, the same pattern `aoide-storage`/`aoide-conduct` already hold
/// (`pkgs/aoide/crates/AGENTS.md`'s "per-crate tests only").
#[cfg(test)]
pub(crate) fn env_lock() -> &'static std::sync::Mutex<()> {
    aoide_test_support::env_lock()
}
