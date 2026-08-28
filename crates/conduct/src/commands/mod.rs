//! The conduct domain's CLI commands: the `graph *`/`conduct` registrations
//! (which include `session`, the ROSTER — grouped by project bare, by host
//! under `--hosts`, folding away the retired standalone `who` command — and
//! `session grant`, the grant family), the `hooks install` hook-installer
//! command, and `peer list` (the one-glance mesh roster over the roster's
//! own probe core plus one discovery sweep, task #120 P2, appended newest).
//!
//! Moved from the root package's `src/commands/{graph,hooks}.rs` (Phase 9
//! restructure, docs/architecture/PACKAGE-LAYOUT.md): a domain's CLI commands
//! live with the domain. The root package's `commands::all()` calls each
//! `register()` at the exact historical position so `schema --json` order
//! never shifts.

pub mod graph;
pub mod herald;
pub mod hooks;
pub mod peer_list;
pub mod shellbridge;
