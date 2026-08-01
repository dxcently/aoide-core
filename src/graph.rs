//! `aoide graph` — the project/session DAG viewer + manager
//! (concepts/Terminal-Commander).
//!
//! Projects are anchor nodes; agent terminal sessions hang under them
//! (anchored by cwd, longest path prefix wins) and under each other via
//! spawned-by edges (`parentSessionId` on the session record). One
//! computation feeds three outputs: the Unicode tree render, the `--json`
//! graph document, and the `song/stage/graph.json` stage file Quickshell
//! hot-reloads (CONTRACTS.md §4). Every stage write goes through
//! shellbridge's atomic writer — never a bare `fs::write`.

mod common;
mod conduct;
mod doc;
mod model;
mod send;
mod session_store;
#[cfg(test)]
pub(crate) mod testutil;
mod verbs;
mod window;

// Public API: dispatch.rs, conductor/*, and shellbridge.rs all reach these at
// `crate::graph::*`, unchanged by the submodule split below.
pub use self::conduct::session_conduct;
pub use self::doc::{build_graph, render};
pub use self::model::{
    anchor_for, canonical_state, merged_sessions, HookRecord, HooksFile, Project, ProjectsFile,
    SessionRecord, SessionsFile,
};
pub use self::send::{session_hook, session_send};
pub use self::session_store::{session_end, session_phase, session_start, session_wrap};
pub use self::verbs::{emit, link, project_add, project_list, project_remove, prune, view};
pub use self::window::{focus, focus_session, focus_window, run_hypr_window_listener, FocusError};

// Crate-internal: reap.rs's own `use crate::graph::{...}` list (reap.rs was
// extracted from this module before this refactor and still leans on these
// stage helpers).
pub(crate) use self::common::stage_error;
pub(crate) use self::doc::{prune_done, restage_graph};
pub(crate) use self::model::{
    hooks_path, load_stage, sessions_path, write_stage, STAGE_GRAPH_VERSION,
};
pub(crate) use self::session_store::{now_iso_utc, transcript_path_for, upsert_hook};
pub(crate) use self::window::{hyprctl_clients, normalize_addr};

