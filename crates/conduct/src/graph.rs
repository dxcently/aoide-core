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
mod pending;
mod permit;
mod resurrect;
mod send;
mod session_store;
mod spawn;
#[cfg(test)]
pub(crate) mod testutil;
mod manage;
mod who;
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
pub use self::pending::{pending_approve, pending_deny, pending_list};
pub use self::permit::{answer_summons, session_permit, summons_card_id};
pub use self::send::{pending_path, session_hook, session_send};
pub use self::session_store::{session_end, session_phase, session_start, session_wrap};
// `graph spawn` (P2 of the conducted-agents plan): the detached sibling of
// `conduct`/`wrap` that re-execs `conduct --headless` and returns without
// waiting on the agent's own lifetime — see `graph/spawn.rs`'s module doc.
pub use self::spawn::session_spawn;
// `graph resurrect` (P-D8, `docs/architecture/AOIDED.md`'s "L5"): revives a
// project's most recently-ended resumable session off the durable ledger,
// via the windowed spawn path — see `graph/resurrect.rs`'s module doc. Also
// the daemon's own boot-time auto-resume trigger (`aoide-server`'s
// `daemon.rs`), called in-process the same way `run_internal_reap` calls
// `crate::reap::reap_and_announce`.
pub use self::resurrect::session_resurrect;
pub use self::manage::{emit, link, project_add, project_list, project_remove, prune, view};
// `aoide who` (messaging/presence plan, P-C2): live presence over this
// box's own sessions plus every registered peer — see `graph/who.rs`'s
// module doc for the probe/filter design. `glyph` (the node-presence
// online/unreachable/never-pulled map) rides alongside it — P-C4's
// conductor ROSTER panel is its second consumer (`who.rs`'s doc comment
// on `glyph`), reused rather than redrawn.
pub use self::who::{glyph, who};
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
pub(crate) use self::doc::{drop_sessions, ledger_session_exit, prune_done, restage_graph};
pub(crate) use self::model::{hooks_path, STAGE_GRAPH_VERSION};
pub(crate) use self::session_store::{
    lineage_of, refresh_subagent_says, refresh_transcript_fields, upsert_hook,
};
pub(crate) use self::window::hyprctl_clients;
/// Widened from `pub(crate)` to `pub` at P-A1 of the binary-split
/// workstream: `aoide-screen` (moved out of this crate) needs the same
/// `0x`/case-tolerant window-address comparison its own session-targeted
/// commands (`screen shot --session`, `screen point --from-shot`, …) already
/// relied on when they lived here.
pub use self::window::normalize_addr;
