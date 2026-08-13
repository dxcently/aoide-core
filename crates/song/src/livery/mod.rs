//! `livery` — the native note engine, ported into song from the standalone
//! Node engine (see docs/architecture/LIVERY-MERGE.md).
//!
//! The engine is a pure-Rust port of the standalone Node note engine's
//! `{schema,resolve,emitters,cli}.js`, folded into song's charter ("the
//! ricing / design engine"):
//!
//! ```text
//!   schema.rs   validate the raw container against the closed v0 schema
//!       │       (byte-exact Node error strings)
//!       ▼
//!   resolve.rs  native {group.key} deref (cycle-guarded) + component
//!       │       null/empty→palette fallback → flat Resolved set
//!       ▼
//!   emit/       one Emitter trait, one registry: stage · hyprctl · osc
//!               (+ file, the arbitrary-config-template generalization proof)
//! ```
//!
//! Pure computation only: the effectful half (running `hyprctl --batch`,
//! atomically writing the stage file) lives outside — `live::apply_live` and
//! `shellbridge::atomic_write` — so the engine is golden-testable and the
//! host-apply seam stays exactly where song already draws it.

pub mod emit;
pub mod resolve;
pub mod schema;

pub(crate) mod json;

pub use resolve::{Resolved, resolve, strip_hash, with_hash};
pub use schema::SCHEMA_VERSION;

/// Validate a raw note container against the v0 schema (the `livery lint`
/// contract: `{ ok, errors }`).
pub fn lint(container: &serde_json::Value) -> schema::Validation {
    schema::validate(container)
}
