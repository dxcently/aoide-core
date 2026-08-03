//! Structured output envelopes and exit codes.
//!
//! Every command returns an [`Outcome`]; the dispatcher renders it as either
//! JSON (`--json`) or a human line, and maps its status to a process exit code.
//! This is the "every command emits `--json`, structured errors, meaningful
//! exit codes, reports exactly what changed" contract (CONTRACTS.md §3).
//!
//! Moved to `aoide-protocol` (Phase 2 restructure, docs/architecture/PACKAGE-LAYOUT.md);
//! this module re-exports it so every existing `crate::output::*` caller is untouched.

pub use aoide_protocol::output::*;
