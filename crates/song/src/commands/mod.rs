//! The `rice`/`cover` command groups — the song domain's CLI verbs.
//!
//! Moved from the root package's `src/commands/{rice,cover,design}.rs`
//! (Phase 9 restructure, docs/architecture/PACKAGE-LAYOUT.md): a domain's
//! CLI verbs live with the domain. The root package's `commands::all()`
//! calls each `register()` at the exact historical position so
//! `schema --json` order never shifts (rice → design → mode → cover, keeping
//! the whole `rice` family contiguous).

pub mod cover;
pub mod design;
pub mod livery;
pub mod mode;
pub mod rice;
