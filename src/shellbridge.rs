//! shellbridge — the session/hook state bridge (concepts/shellbridge).
//!
//! Registers agent sessions + window addresses and records Claude Code hook
//! phases, publishing them to `song/stage/` for Quickshell to read. Writes are
//! atomic (write-temp-then-rename) so a hot-reload never sees a torn file
//! (CONTRACTS.md §4 discipline).

/// The stage-file FS substrate (where the stage tree lives, atomic
/// write/lock primitives) — moved to `aoide-storage` (Phase 3a restructure,
/// docs/architecture/PACKAGE-LAYOUT.md); re-exported here so every existing
/// `crate::shellbridge::{stage_dir, atomic_write, …}` caller is untouched.
pub use aoide_storage::fs::{
    atomic_write, seed_if_absent, song_dir, songbook_dir, songbook_notes, stage_dir, state_dir,
    with_stage_lock,
};

/// The socket-loop half (`socket_path`, `BridgeCommand`, `parse_command`,
/// `run` — the accept loop that seeds the stage files and serves widget-click
/// focus commands) — moved to `aoide-conduct` (Phase 3b restructure,
/// docs/architecture/PACKAGE-LAYOUT.md); re-exported here so every existing
/// `crate::shellbridge::{run, socket_path, …}` caller is untouched.
pub use aoide_conduct::shellbridge::{socket_path, run, BridgeCommand, parse_command};
