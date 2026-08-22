//! `aoide-secrets`: Aoide's secrets broker (Workstream SECRETS). P-V1 landed
//! the pure logic — hand-rolled RFC 2104/3174/6238 TOTP, RFC 4648 base32,
//! `otpauth://` URI construction, the single-use replay ledger, and
//! policy-store types. P-V2 added the broker daemon, the unix-socket wire,
//! and the client + admin CLI verbs: `aoide secrets serve`/`exec`/`add`/`rm`/
//! `grant`/`revoke`, registered into `aoide-cli`'s `Registry` via
//! [`commands::register`] — `aoide-cli` has depended on this crate since
//! P-V2.
//!
//! **P-V3 (this commit) lands `secrets enroll` and wires `requireTotp` live**:
//! [`enroll::run`] generates a fresh secret, persists it via
//! [`store::save_totp_secret`], and prints its `otpauth://` URI + base32
//! form (plus a QR code when `qrencode` is on `PATH`) — see `enroll`'s
//! module doc for why the printing happens there rather than in
//! `commands::handle_secrets_enroll`'s `Outcome`. `broker::resolve_gate` now
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
//! **P-V4c (this commit) is the backend build-out**: a built-in `file`
//! backend (plain `0600` files under the secrets home, [`backend::
//! seed_default_backends`] seeds it into a fresh `backends.json`) and a
//! `{home}` template placeholder that makes it possible
//! ([`backend::expand_template`]), an optional per-backend `set` template
//! ([`backend::store_value`]), and the write half: a new `secrets put
//! <name>` verb ([`commands::handle_secrets_put`], [`client::put`]/
//! [`client::run_put`], [`broker::handle_put`]/[`broker::put_gate`]/
//! [`broker::audit_put`]) that reads a value from stdin and stores it
//! through the named secret's backend — never gated by `requireTotp`, no
//! `consumer` field on the wire (`put` is CLI-only/admin-side, never
//! agent-facing; `broker`'s module doc has the full reasoning). The
//! socket wire (`resolve` + `put`) is now ALSO documented in
//! `CONTRACTS.md`'s "Secrets wire" subsection as a first-class,
//! directly-speakable API for non-agent consumers.
//!
//! **P-V4e (this commit) closes two live UX gaps**: [`commands::
//! handle_secrets_set_totp`] (`secrets set-totp <name> on|off`) flips an
//! existing policy's `requireTotp` bit directly, replacing a hand-edited
//! `jq` one-liner against `policy.json`; [`enroll::show`] (`secrets enroll
//! --show`) reprints an EXISTING enrollment's URI/base32/QR without
//! rotating anything, mutually exclusive with `--force`; and
//! [`client::run_put`] now prompts on stderr with echo disabled when
//! stdin is a terminal (a piped/redirected stdin is unchanged).
//!
//! **P-67 (this commit) makes `secrets put` warn and confirm before an
//! overwrite.** The wire's `put` op gains an optional `overwrite` bool
//! (absent means `false`); [`broker::put_gate`] probes existence via
//! [`backend::has_value`] and refuses with a distinct `{"exists":true}`
//! reply rather than silently clobbering a secret that already has a
//! stored value — the existence check is BROKER-SIDE ONLY, since the
//! client must never fetch a value to find out, and a client-side file
//! peek would break the uid boundary outright. [`commands::
//! handle_secrets_put`] gained a `--force` flag; [`client::run_put`] sends
//! it as `overwrite` on the first attempt, and on an `exists` refusal
//! ([`client::PutError::Exists`]) prompts `y/N` on a tty (retrying with
//! the SAME in-memory value + `overwrite:true` on yes) or refuses outright
//! and teaches `--force` on a non-tty stdin ([`client::
//! non_tty_exists_message`]). A put with no stored value yet is unaffected
//! — no prompt, no warning, same as before this feature.
//!
//! See `README.md` for the wire shape and the release-to-client flow, and
//! `AGENTS.md` for the invariants a change here must hold — most
//! importantly: a secret's VALUE never appears on a `Serialize`/
//! `Deserialize` type anywhere in this crate ([`policy::Policy`] is still
//! the only derived-`Serialize` type that touches the wire; both the
//! resolve reply and the put reply are hand-built `serde_json::Value`,
//! never a struct); NO CACHE EVER; and ONE VALUE PER SECRET.

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
/// env (`AOIDE_SECRETS_HOME`, `AOIDE_SECRETS_SOCKET`, `AOIDE_AUDIT_LOG`) —
/// same pattern as `aoide_conduct`/`aoide_storage`/`aoide_server`'s own
/// `env_lock()` (`pkgs/aoide/crates/AGENTS.md`'s per-crate-tests rule).
/// Not delegated to `aoide-test-support`: this crate has no dev-dependency
/// on it, and a two-line local mutex is cheaper than adding one.
#[cfg(test)]
pub(crate) fn env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    &LOCK
}
