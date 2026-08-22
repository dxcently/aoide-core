//! `aoide-vault`: Aoide's secrets broker (Workstream VAULT). P-V1 landed
//! the pure logic — hand-rolled RFC 2104/3174/6238 TOTP, RFC 4648 base32,
//! `otpauth://` URI construction, the single-use replay ledger, and
//! policy-store types. **P-V2 (this commit) adds the broker daemon, the
//! unix-socket wire, and the client + admin CLI verbs**: `aoide vault
//! serve`/`exec`/`add`/`rm`/`grant`/`revoke`, now registered into
//! `aoide-cli`'s `Registry` via [`commands::register`] — `aoide-cli` has
//! depended on this crate since this commit (the workspace `Cargo.toml`
//! comment that used to say otherwise is updated in the same commit).
//!
//! **STANDING GRANTS ONLY this phase.** TOTP verification stays unwired
//! until `vault enroll` lands (P-V3/P-V4) — there is no enrolled secret to
//! verify a code against yet. A policy with `requireTotp: true` is simply
//! UNRESOLVABLE for now: `broker`'s resolve gate rejects it outright with
//! a clear message, never silently falling back to a standing grant.
//!
//! See `README.md` for the wire shape and the release-to-client flow, and
//! `AGENTS.md` for the invariants a change here must hold — most
//! importantly: a secret's VALUE never appears on a `Serialize`/
//! `Deserialize` type anywhere in this crate ([`policy::Policy`] is still
//! the only derived-`Serialize` type that touches the wire; the resolve
//! reply is hand-built `serde_json::Value`, never a struct).

pub mod backend;
pub mod base32;
pub mod broker;
pub mod client;
pub mod commands;
pub mod hmac;
pub mod home;
pub mod policy;
pub mod replay;
pub mod sha1;
pub mod socket;
pub mod store;
pub mod totp;
pub mod uri;

/// A crate-wide lock serialising every test that mutates process-global
/// env (`AOIDE_VAULT_HOME`, `AOIDE_VAULT_SOCKET`, `AOIDE_AUDIT_LOG`) —
/// same pattern as `aoide_conduct`/`aoide_storage`/`aoide_server`'s own
/// `env_lock()` (`pkgs/aoide/crates/AGENTS.md`'s per-crate-tests rule).
/// Not delegated to `aoide-test-support`: this crate has no dev-dependency
/// on it, and a two-line local mutex is cheaper than adding one.
#[cfg(test)]
pub(crate) fn env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    &LOCK
}
