//! The conduct domain's CLI verbs: the `graph *`/`conduct` registrations and
//! the `hooks install` hook-installer verb.
//!
//! Moved from the root package's `src/commands/{graph,hooks}.rs` (Phase 9
//! restructure, docs/architecture/PACKAGE-LAYOUT.md): a domain's CLI verbs
//! live with the domain. The root package's `commands::all()` calls each
//! `register()` at the exact historical position so `schema --json` order
//! never shifts.

pub mod graph;
pub mod hooks;
pub mod screen;
