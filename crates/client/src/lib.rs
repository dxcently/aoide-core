//! aoide-client — Aoide's outbound A2A door (Phase 4b restructure,
//! docs/architecture/PACKAGE-LAYOUT.md): the client-side wire builders/parsers
//! (`wire`) and the melete neutral-event adapter (`adapter`).
//!
//! Extracted from root `src/a2a.rs` (its CLIENT-side region only — the
//! server-side JSON-RPC/HTTP door stays in root, Phase 4c's job) and root
//! `src/adapter.rs` wholesale, following the same shim discipline
//! `aoide-protocol` (Phase 2), `aoide-storage` (Phase 3a), and `aoide-conduct`
//! (Phase 3b) established: every moved symbol is re-exported at its old root
//! path via `pub use`, so no existing call site changes.

pub mod adapter;
pub mod commands;
pub mod wire;
