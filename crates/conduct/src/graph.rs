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
//!
//! Moved here from root `src/graph.rs` + `src/graph/*.rs` (Phase 3b
//! restructure, docs/architecture/PACKAGE-LAYOUT.md); the root module is now
//! a pure re-export shim onto this crate.

mod common;
mod conduct;
mod doc;
mod model;
mod permit;
mod send;
mod session_store;
#[cfg(test)]
pub(crate) mod testutil;
mod verbs;
mod window;

// Public API: reached at `crate::graph::*` from WITHIN this crate (used by
// this crate's own `reap.rs`/`shellbridge.rs`) — the exact list root's old
// `graph.rs` exposed pre-Phase-3b — AND now ALSO the crate-external surface
// root's shim (`pkgs/aoide/src/graph.rs`) re-exports onward at the SAME old
// paths, so every existing `crate::graph::*` caller in root (a2a.rs,
// conductor/*, commands/*) is untouched. `pub` (not `pub(crate)`) throughout
// this block because it now crosses the aoide-conduct → aoide crate
// boundary; root's own shim re-narrows visibility to match what `graph.rs`
// exposed at root before this split (see that file's comments).
pub use self::conduct::session_conduct;
// `a2a.rs`'s spawn path (Phase B2) computes a just-spawned conducted session's
// deterministic control-socket path itself, to retry-connect and inject the
// first turn before `sessions.json` necessarily reflects the new record yet —
// the same path `graph send`/`conduct` derive internally.
pub use self::conduct::conduct_socket_path;
pub use self::doc::{build_graph, render, resolve_graph_document};
pub use self::model::{
    anchor_for, canonical_state, merged_sessions, HookRecord, HooksFile, Project, ProjectsFile,
    SessionRecord, SessionsFile,
};
pub use self::permit::session_permit;
pub use self::send::{session_hook, session_send};
pub use self::session_store::{session_end, session_phase, session_start, session_wrap};
pub use self::verbs::{emit, link, project_add, project_list, project_remove, prune, view};
pub use self::window::{focus, focus_session, focus_window, run_hypr_window_listener, FocusError};

// Storage/time passthroughs root's `a2a.rs` / `commands/{a2a,usage}.rs` still
// reach at `crate::graph::{load_stage, now_iso_utc, sessions_path,
// write_stage}` — `pub` here (crossing the crate boundary); root's shim
// re-narrows them back to `pub(crate)` to match the original root-facing
// visibility exactly.
pub use self::model::{load_stage, sessions_path, write_stage};
pub use self::session_store::now_iso_utc;

// Crate-internal only: this crate's OWN `reap.rs` leans on these stage
// helpers (mirrors the pre-3b `graph.rs`'s "Crate-internal: reap.rs's own
// `use crate::graph::{...}`" section) — never reached from root, so they stay
// `pub(crate)`.
pub(crate) use self::common::stage_error;
pub(crate) use self::doc::{drop_sessions, prune_done, restage_graph};
pub(crate) use self::model::{hooks_path, STAGE_GRAPH_VERSION};
pub(crate) use self::session_store::{
    refresh_subagent_says, refresh_transcript_fields, upsert_hook,
};
pub(crate) use self::window::{hyprctl_clients, normalize_addr};
