//! `aoide graph` — the project/session DAG viewer + manager
//! (concepts/Terminal-Commander).
//!
//! Projects are anchor nodes; agent terminal sessions hang under them
//! (anchored by cwd, longest path prefix wins) and under each other via
//! spawned-by edges (`parentSessionId` on the session record). One
//! computation feeds three outputs: the Unicode tree render, the `--json`
//! graph document, and the `state/stage/graph.json` stage file Quickshell
//! hot-reloads (CONTRACTS.md §4). Every stage write goes through
//! shellbridge's atomic writer — never a bare `fs::write`.
//!
//! Moved here from root `src/graph.rs` + `src/graph/*.rs` (Phase 3b
//! restructure, docs/architecture/PACKAGE-LAYOUT.md); the root module is now
//! a pure re-export shim onto this crate.

mod actions;
pub use actions::{session_kill, session_project};
// The P-CX desktop Codex/ChatGPT association design
// (`docs/architecture/CODEX-INTEGRATION.md`): the pure reconciler plus its
// discovery seam. `sync_codex_app_threads` (re-exported below) is called
// from the reaper tick (`reap.rs`) and, for promptness, the Hyprland window
// listener (`window.rs`); `codex_home` is re-exported separately for
// `reap.rs`'s own title refresh. Only `reconcile_codex_app_threads` itself
// stays reachable from its own tests alone.
mod codex_app;
// S1 of P-CX-5 (native Codex capture, the codex-integration follow-on): the
// PURE fold from a rollout's own JSONL lines into a `CodexCapture` — no I/O,
// no stage, no call site yet (the bounded reader and the upsert are a later
// slice). Reachable only from its own tests until then.
mod codex_capture;
mod common;
mod conduct;
mod doc;
mod doorbell;
// The P-EIDOLON adapter lane, slice E1b (readiness E2 folded in): the pure
// presence reconciler plus its read-only discovery seam over
// `$XDG_RUNTIME_DIR/eidolon`, mirroring `codex_app`'s split rule for rule.
// `sync_eidolon_sessions` (re-exported below) is called from the reaper tick
// (`reap.rs`) beside `sync_codex_app_threads`.
mod eidolon;
// LANE IDENTITY P-ID3: `pub(crate)`, not private — `shellbridge.rs` (a
// SIBLING of this module, not a descendant) reuses `peer_cred`/`PeerCred`
// for its own cross-uid accept floor rather than hand-rolling a second
// `SO_PEERCRED` read in this same crate. Still not `pub` at the top block
// below: this stays an internal kernel-truth primitive, never crossing the
// `aoide-conduct` -> `aoide` crate boundary root's shim re-exports onward.
pub(crate) mod identity;
mod model;
mod node_list;
mod pending;
mod permit;
mod resurrect;
mod send;
mod session_store;
mod spawn;
#[cfg(test)]
pub(crate) mod testutil;
mod grant;
mod manage;
mod undying;
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
// `aoide-server`'s stdio MCP server (P-M5c-2, `docs/architecture/
// CLAUDE-CHANNEL-PROOF.md`) resolves the SAME session id's channel socket —
// the socket the doorbell will eventually write a nudge line onto — the
// same way `conduct_socket_path` already crosses this boundary above.
pub use self::conduct::channel_socket_path;
pub use self::doc::{build_graph, render, resolve_graph_document};
// `mail ring` (P-M5a-2, MAIL.md "Delivery and the doorbell"): the ring
// itself, callable in-process by any door that has this crate (the daemon
// on a Stop hook, the CLI on `mail ring`, `aoide-server`'s deposit arm).
pub use self::doorbell::{mail_ring, ring, RingReport};
pub use self::model::{
    anchor_for, project_for, canonical_state, merged_sessions, HookRecord, HooksFile, Project, ProjectsFile,
    SessionRecord, SessionsFile,
};
pub use self::pending::{pending_approve, pending_deny, pending_list};
pub use self::permit::{answer_summons, session_permit, summons_card_id};
pub use self::send::{pending_path, session_hook, session_send};
pub use self::session_store::{session_bind, session_end, session_phase, session_start};
// LANE IDENTITY P-ID0 (G16/G5): `aoide-server`'s `a2a::do_spawn` is the
// authenticated-node-origin writer — it stamps `node:<name>` directly on
// the record it just spawned, rather than threading the value through the
// child's own (forgeable) env. `stamp_origin`'s own doc comment names both
// legitimate callers.
pub use self::session_store::stamp_origin;
// LANE IDENTITY P-ID1: `aoide-server`'s daemon `dispatch` handler is the one
// legitimate caller — it stamps a just-minted sealed credential directly
// onto the record it just registered a pid for, the same "stamp from the
// authority that just authenticated the fact" shape `stamp_origin` set the
// precedent for.
pub use self::session_store::stamp_seal;
// `graph spawn` (P2 of the conducted-agents plan): the detached sibling of
// `conduct` that re-execs `conduct --headless` and returns without
// waiting on the agent's own lifetime — see `graph/spawn.rs`'s module doc.
pub use self::spawn::session_spawn;
// `graph resurrect` (P-D8, `docs/architecture/AOIDED.md`'s "L5"): revives a
// project's undying set (or `--all`/`--id`) off the durable ledger, via the
// windowed spawn path, resolving each candidate through a harness or a
// terminal arm and delivering its restore snapshot — see
// `graph/resurrect.rs`'s module doc. Also the daemon's own boot-time
// auto-resume trigger (`aoide-server`'s `daemon.rs`), called in-process the
// same way `run_internal_reap` calls `crate::reap::reap_and_announce`.
pub use self::resurrect::session_resurrect;
// `session grant` (session-surface redesign, command-defrag lane X,
// 2026-08-28): the GRANT family — `undying` (U1/U3's mark, relocated
// verbatim) and `exempt` (task #20's reaper shield); the standalone
// `session undying` command this absorbs is retired — see
// `graph/grant.rs`'s module doc.
pub use self::grant::session_grant;
pub use self::manage::{
    link, project_add, project_edit, project_list, project_remove, prune,
    register_bootstrap_project, view,
};
// Bare `session` (session-surface redesign, command-defrag lane X): the
// ROSTER — grouped by PROJECT bare, by HOST under `--hosts` (byte-identical
// to the retired standalone `aoide who` command's own rendering) — see
// `graph/who.rs`'s module doc for the probe/filter/attribution design.
// `glyph` (the node-presence online/unreachable/never-pulled map) rides
// alongside it — P-C4's conductor ROSTER panel is its second consumer
// (`who.rs`'s doc comment on `glyph`), reused rather than redrawn.
pub use self::who::{glyph, session_roster};
// `aoide node list` (task #120 P2): the one-glance mesh roster — this host,
// every registered node, every advertising instance heard in one bounded
// sweep, each with its running sessions. Lives beside the roster core
// because it IS `who.rs`'s probe/classification core under a wider fold
// (`node_list.rs`'s module doc) — `node status` (aoide-client) keeps the
// deep per-node view.
pub use self::node_list::node_list;
pub use self::window::{focus_session, focus_window, run_hypr_window_listener, FocusError};

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
pub(crate) use self::doc::{drop_sessions, ledger_session_exit, prune_done};
pub use self::doc::restage_graph;
pub(crate) use self::model::{hooks_path, STAGE_GRAPH_VERSION};
pub(crate) use self::session_store::{
    lineage_of, refresh_subagent_says, refresh_transcript_fields, upsert_hook,
};
pub(crate) use self::window::hyprctl_clients;
pub(crate) use self::codex_app::codex_home;
pub(crate) use self::codex_app::sync_codex_app_threads;
pub(crate) use self::eidolon::sync_eidolon_sessions;
/// Widened from `pub(crate)` to `pub` at P-A1 of the binary-split
/// workstream: `aoide-screen` (moved out of this crate) needs the same
/// `0x`/case-tolerant window-address comparison its own session-targeted
/// commands (`screen shot --session`, `screen point --from-shot`, …) already
/// relied on when they lived here.
pub use self::window::normalize_addr;

/// LANE IDENTITY P-ID1: `aoide-server`'s daemon needs this SAME careful
/// `/proc/<pid>/stat` parse (window.rs's own doc) to mint a sealed
/// credential's `pidStarttime` field — re-exported here rather than a
/// second implementation one crate up.
pub use self::window::pid_starttime;
