//! Liveness reaping: mark KILLED sessions done so they cannot haunt forever.
//!
//! Moved to `aoide-conduct` (Phase 3b restructure,
//! docs/architecture/PACKAGE-LAYOUT.md); this module is a pure re-export shim
//! reproducing the exact old `reap.rs` surface at the exact old paths, so
//! every existing `crate::reap::*` caller (`commands/graph.rs`) is untouched.

pub use aoide_conduct::reap::{reap, is_session_dead, REAP_IDLE_STALE_SECS};
