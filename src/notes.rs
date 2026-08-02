//! Locating the `drachma` binary (the note engine, pkgs/drachma).
//!
//! Moved to `aoide-song` (Phase 5a restructure,
//! docs/architecture/PACKAGE-LAYOUT.md); this module is a pure re-export shim
//! reproducing the exact old `notes.rs` surface at the exact old paths, so
//! every existing `crate::notes::*` / `notes::*` caller (`commands/rice.rs`)
//! is untouched.

pub use aoide_song::notes::{locate, run_lint, LintRun};
