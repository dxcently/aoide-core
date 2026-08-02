//! `aoide graph` — the project/session DAG viewer + manager
//! (concepts/Terminal-Commander).
//!
//! Moved to `aoide-conduct` (Phase 3b restructure,
//! docs/architecture/PACKAGE-LAYOUT.md): the PTY multiplexer (`aoide
//! conduct`), the session DAG (`aoide graph`), Claude-Code hook plumbing, and
//! everything under the old `src/graph/*.rs` submodules now live in
//! `aoide_conduct::graph`. This module is a pure re-export shim reproducing
//! the exact old `graph.rs` surface at the exact old paths, so every existing
//! `crate::graph::*` caller (a2a.rs, conductor/*, commands/*) is untouched.

pub use aoide_conduct::graph::session_conduct;
pub use aoide_conduct::graph::{build_graph, render};
pub use aoide_conduct::graph::{
    anchor_for, canonical_state, merged_sessions, HookRecord, HooksFile, Project, ProjectsFile,
    SessionRecord, SessionsFile,
};
pub use aoide_conduct::graph::{session_hook, session_send};
pub use aoide_conduct::graph::{session_end, session_phase, session_start, session_wrap};
pub use aoide_conduct::graph::{emit, link, project_add, project_list, project_remove, prune, view};
pub use aoide_conduct::graph::{
    focus, focus_session, focus_window, run_hypr_window_listener, FocusError,
};

// Storage/time passthrough `commands/usage.rs` reaches at
// `crate::graph::now_iso_utc` — unchanged path, now sourced through
// `aoide-conduct`. `conduct_socket_path`/`load_stage`/`sessions_path`/
// `write_stage` were re-exported here too (for `a2a.rs`'s server-region
// code and tests), but that region moved wholesale to `aoide-server` (Phase
// 4c restructure, docs/architecture/PACKAGE-LAYOUT.md), which reaches
// `aoide_conduct::graph::{conduct_socket_path, load_stage, sessions_path,
// write_stage}` directly — nothing left in THIS crate uses them, so they're
// dropped from this shim rather than kept dead.
pub(crate) use aoide_conduct::graph::now_iso_utc;
