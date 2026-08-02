//! Hyprland live-apply helpers — the compositor half of `rice preview`.
//!
//! Moved to `aoide-song` (Phase 5a restructure,
//! docs/architecture/PACKAGE-LAYOUT.md) as `aoide_song::live`; this module is
//! a pure re-export shim reproducing the exact old `hypr.rs` surface at the
//! exact old paths, so every existing `crate::hypr::*` caller
//! (`commands/rice.rs`) is untouched.

pub use aoide_song::live::{apply_live, batch_command, geometry_keywords};
