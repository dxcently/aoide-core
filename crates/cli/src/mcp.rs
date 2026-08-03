//! Minimal MCP stdio server (concepts/Agent-Interface, Tier 2).
//!
//! Moved to `aoide-server` (Phase 4c restructure,
//! docs/architecture/PACKAGE-LAYOUT.md); this module re-exports it so every
//! existing `crate::mcp::*` caller is untouched.
//!
//! **One signature change, unlike every prior phase's zero-call-site-churn:**
//! `serve_stdio` now takes the command registry + a dispatch fn pointer as
//! parameters (the DI seam `aoide-server`'s module doc comment explains — a
//! `server` crate cannot reach the crate-global, fully-assembled
//! `dispatch::registry()`/`dispatch::dispatch()` without becoming
//! `server → root`, since that registry doesn't move until Phase 6 `cli`).
//! Its ONE caller (`lib.rs::run_cli`'s `mcp serve --stdio` launch site) was
//! updated to pass `dispatch::registry()` and `dispatch::dispatch` in.

pub use aoide_server::mcp::{serve_stdio, DispatchFn};
