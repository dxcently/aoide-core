//! Adapters — thin per-agent consumers of the aoided neutral event stream.
//!
//! Moved to `aoide-client` (Phase 4b restructure,
//! docs/architecture/PACKAGE-LAYOUT.md); re-exported here so every existing
//! `crate::adapter::{run_melete, subscription_from_env, safe_notification}`
//! caller is untouched. See `aoide_client::adapter` for the real
//! implementation and its doc comments (subscription default-deny model,
//! the metadata-only notification security boundary).

pub use aoide_client::adapter::{run_melete, safe_notification, subscription_from_env};
