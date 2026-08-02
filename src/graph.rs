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
// `a2a.rs`'s spawn path (Phase B2) computes a just-spawned conducted session's
// deterministic control-socket path itself, to retry-connect and inject the
// first turn before `sessions.json` necessarily reflects the new record yet —
// the same path `graph send`/`conduct` derive internally.
pub(crate) use aoide_conduct::graph::conduct_socket_path;
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

// Storage/time passthroughs `a2a.rs` / `commands/{a2a,usage}.rs` reach at
// `crate::graph::{load_stage, now_iso_utc, sessions_path, write_stage}` —
// unchanged paths, now sourced through `aoide-conduct`.
pub(crate) use aoide_conduct::graph::{load_stage, now_iso_utc, sessions_path};
// `write_stage` is reached only from `a2a.rs`'s `#[cfg(test)]` fixtures
// (its non-test code only ever reads via `load_stage`) — cfg-gated the same
// way, or a release build would flag it unused (the class of warning Phase
// 3a's review caught).
#[cfg(test)]
pub(crate) use aoide_conduct::graph::write_stage;
