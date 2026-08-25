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
// `graph resurrect` (P-D8, `docs/architecture/AOIDED.md`'s "L5") — see this
// crate's own `AGENTS.md`/README for the golden-count bump this landed with.
pub use aoide_conduct::graph::session_resurrect;
pub use aoide_conduct::graph::{
    focus, focus_session, focus_window, run_hypr_window_listener, FocusError,
};

// The `now_iso_utc` passthrough this shim used to carry for
// `commands/usage.rs` is gone (Phase 9 restructure): `usage` moved to
// `aoide-storage`, which owns `time::now_iso_utc` natively — nothing left in
// THIS crate uses it, so it's dropped rather than kept dead (the same
// discipline the `conduct_socket_path`/`load_stage`/`sessions_path`/
// `write_stage` drop below established in Phase 4c).
