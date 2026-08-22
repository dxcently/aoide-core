//! `aoide-vault`: pure logic for Aoide's secrets broker (Workstream
//! VAULT, P-V1). TOTP (hand-rolled RFC 2104/3174/6238), RFC 4648 base32,
//! `otpauth://` URI construction, the single-use replay ledger, and
//! policy-store types.
//!
//! **This crate has NO daemon, NO unix socket, NO CLI verbs, and
//! registers nothing.** It is a workspace member with zero consumers —
//! `aoide-cli` does not depend on it (see the workspace `Cargo.toml`
//! comment on the `aoide-vault` entry) until P-V2 wires the broker/
//! client around this logic. See `README.md` for the broker charter this
//! crate is the first slice of, and `AGENTS.md` for the invariants a
//! later phase must hold — most importantly: a secret's VALUE may never
//! appear on a `Serialize` type, written down now even though
//! [`policy::Policy`] is the only such type that exists yet.

pub mod base32;
pub mod hmac;
pub mod policy;
pub mod replay;
pub mod sha1;
pub mod totp;
pub mod uri;
