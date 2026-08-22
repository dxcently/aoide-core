//! `aoide-vault`: Aoide's secrets broker (Workstream VAULT). P-V1 landed
//! the pure logic — hand-rolled RFC 2104/3174/6238 TOTP, RFC 4648 base32,
//! `otpauth://` URI construction, the single-use replay ledger, and
//! policy-store types. P-V2 added the broker daemon, the unix-socket wire,
//! and the client + admin CLI verbs: `aoide vault serve`/`exec`/`add`/`rm`/
//! `grant`/`revoke`, registered into `aoide-cli`'s `Registry` via
//! [`commands::register`] — `aoide-cli` has depended on this crate since
//! P-V2.
//!
//! **P-V3 (this commit) lands `vault enroll` and wires `requireTotp` live**:
//! [`enroll::run`] generates a fresh secret, persists it via
//! [`store::save_totp_secret`], and prints its `otpauth://` URI + base32
//! form (plus a QR code when `qrencode` is on `PATH`) — see `enroll`'s
//! module doc for why the printing happens there rather than in
//! `commands::handle_vault_enroll`'s `Outcome`. `broker::resolve_gate` now
//! verifies a `requireTotp` policy's code against the host's enrolled
//! secret (`totp::verify`, `±1` window) and consumes the matched timestep
//! in a [`replay::ReplayLedger`] persisted via [`store::load_replay_ledger`]/
//! [`store::save_replay_ledger`] — a policy with `requireTotp: true` is
//! UNRESOLVABLE only when NO enrollment exists on this host yet; once
//! enrolled, a missing/wrong/replayed code is a denial, never a silent
//! standing-grant fallback. `backend`'s `pass`/`gopass`/`bw`/`sops` DOC
//! PRESETS live in `README.md`'s "Backend presets" section (P-V3), not in
//! this module — `backend` itself is unchanged.
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
pub mod enroll;
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
