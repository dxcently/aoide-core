//! The conduct domain's CLI commands: the `graph *`/`conduct` registrations,
//! the `hooks install` hook-installer command, and `who` (live presence,
//! messaging/presence plan P-C2, appended newest).
//!
//! Moved from the root package's `src/commands/{graph,hooks}.rs` (Phase 9
//! restructure, docs/architecture/PACKAGE-LAYOUT.md): a domain's CLI commands
//! live with the domain. The root package's `commands::all()` calls each
//! `register()` at the exact historical position so `schema --json` order
//! never shifts.

pub mod graph;
pub mod herald;
pub mod hooks;
pub mod shellbridge;
pub mod who;
