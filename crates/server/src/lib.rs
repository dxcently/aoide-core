//! aoide-server — Aoide's door serve-loops: the A2A JSON-RPC/HTTP server, the
//! MCP stdio server, and the `aoided` policy skeleton (Phase 4c restructure,
//! docs/architecture/PACKAGE-LAYOUT.md).
//!
//! Extracted from root `src/a2a.rs` (the SERVER half — the client half,
//! outbound registration/driving of external agents, stays in root as a
//! Phase 4a/4b shim), `src/mcp.rs` (wholesale), and `src/daemon.rs`'s `run`
//! (the policy-type re-exports stay in root; they already live in
//! `aoide-protocol` since Phase 4a).
//!
//! **The one non-mechanical seam this phase threads through:** both serve
//! loops used to reach the crate-global, fully-assembled command registry
//! (`dispatch::registry()`) and dispatcher (`dispatch::dispatch()`) directly.
//! That registry pulls in every command family (`commands::all()`) and does
//! not move to any crate until Phase 6 (`cli`) — a `server` crate reaching for
//! it would be `server → root`, exactly the dependency direction this split
//! exists to forbid. So [`mcp::serve_stdio`] and [`a2a::serve`] (and every
//! function under them that used to consult the registry) take it as a
//! parameter instead; root `lib.rs`'s two launch sites now pass
//! `dispatch::registry()` and `dispatch::dispatch` in.
//!
//! Sits ABOVE `aoide-conduct` (the session core `do_inject`/`do_spawn`/
//! `tasks/get` read/write through) and `aoide-storage`, and depends on
//! `aoide-protocol` for the `Registry`/`Invocation`/`Outcome`/audit/`Door`
//! contract every door shares. Does NOT depend on `aoide-client` in
//! production (only as a dev-dependency for one round-trip test — see
//! `Cargo.toml`) — the outbound A2A client stays entirely in root/`aoide-client`.

pub mod a2a;
pub mod commands;
pub mod daemon;
pub mod events;
pub mod mcp;
pub mod producers;

/// A crate-wide lock serialising every test that mutates process-global env
/// (`AOIDE_STAGE_DIR`, …) — mirrors `aoide::env_lock()` (root `src/lib.rs`),
/// `aoide_storage::env_lock()`, and `aoide_conduct::env_lock()`. Each crate's
/// tests run in their own process (`cargo test -p <crate>`), so a single
/// crate-local lock is enough; it doesn't need to coordinate across crates.
#[cfg(test)]
pub(crate) fn env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    &LOCK
}
