//! aoide-storage — Aoide's durable session data (Phase 3a restructure,
//! docs/architecture/PACKAGE-LAYOUT.md): the stage-file record shapes
//! (`records`), atomic stage I/O (`fs`, `stage`), time formatting (`time`),
//! the pure session/hook upsert ops (`session`), the client-side A2A agent
//! roster (`a2a_store`), the staging/declarative mode marker (`mode`), and
//! the peer-federation registry + pull cache (`peer_store`, CONTRACTS.md §7).
//!
//! Extracted from root `src/` (`shellbridge.rs`, `graph/model.rs`,
//! `graph/session_store.rs`, `conductor/theme.rs`, `a2a.rs`) following the
//! same shim discipline `aoide-protocol` (Phase 2) established: every moved
//! symbol is re-exported at its old root path via `pub use`, so no existing
//! call site changes.
//!
//! `takes` (Self-Ricing Phase A) is a new addition, not a moved one: the
//! per-draft take store backing `rice back`/`rice take` — see its module
//! doc for the tree-of-takes model.
//!
//! `petname` and `display` (petnames plan, P1) are likewise new: the
//! `adjective-noun` wordlist + mint, and the render-time-only
//! `<host>/<role>/<petname> (…<tail4>)` grammar — both pure, both agnostic
//! of any call site (nothing outside this crate wires them yet).
//!
//! `addr` (messaging/presence plan, P-C1) is a pure resolver that inverts
//! `display::session_label` — a human types what the label showed,
//! `addr::resolve` works back to a session id or a deferred remote query.
//! Zero I/O, agnostic of any call site, same as `petname`/`display` — C2
//! (`aoide who`) and C3 (`graph send --to`) are its callers.
//! `addr::resolve_with_hub` (P-D5) composes it with the hub preference
//! (`peer_store::Peer.hub`): a hub-designated peer as one last,
//! least-specific candidate only when `resolve` finds nothing at all.
//!
//! `inbox` (messaging plan, P-C6) is the newest: the durable per-host
//! message store (`state/inbox.json`) both delivery seams file into — see
//! its own module doc for the one-writer-covers-both-seams reasoning.
//!
//! `identity` (pairing workstream, P-P1, `docs/architecture/PAIRING.md`) is
//! this instance's lazily-minted ed25519 keypair (`state/identity/`) — the
//! substrate the pairing ceremony (P-P2), per-peer `allows` (P-P3), and
//! signed wire requests (P-P4) all build on. Its own module doc states the
//! private-key-never-serializes discipline and the mechanical test that
//! holds it.
//!
//! `pairing` (P-P2) is the newest: the ceremony's own park-and-approve
//! state (`state/peer-pairing-inbound.json`/`-outbound.json`, one file per
//! direction) and the SAS transcript-hash derivation both sides compute
//! independently. `peer_store::Peer` gained `pubkey`/`verified` in the same
//! phase — additive fields `peer_store::upsert_paired_peer` is the one
//! write site for.
//!
//! `wire_auth` (P-P4) is the newest: the canonical string every signed A2A
//! POST binds itself to (method, path, timestamp, nonce, body digest) and
//! the sign/verify wrappers around `identity::Keypair` that keep every
//! `ed25519_dalek` type contained to THIS crate — `aoide-client` (the
//! signer) and `aoide-server` (the verifier) each call through it rather
//! than depending on the crypto crate directly. `peer_store::PeerRung`
//! gained a `Signature` variant in the same phase — the new strongest rung,
//! yielded only by the server's own request-verification flow (never by
//! `peer_store::resolve_peer`, which has no access to the raw HTTP request
//! a signature needs).
//!
//! `beacon` (P-P6, `docs/architecture/PAIRING.md`'s "Discovery
//! (advertise-but-locked)" section) is the newest: the one-JSON-line
//! `{v, name, fpr, url}` wire format an `a2a serve` process may emit on a
//! fixed UDP multicast group+port, and the validation `aoide peer
//! discover`/`peer invite` apply to every line heard before trusting it.
//! Pure wire format and validators only — no socket I/O lives here (that's
//! `aoide-server::discovery`'s send side and `aoide-client::discover`'s
//! listen side), and no write path into `peer_store` either: discovery
//! grants nothing, by design.
//!
//! `carry` (durable-sessions plan, P-C1) holds `state/carry.json`, the set
//! of session ids marked durable so a project's whole carried set can be
//! resurrected together. Store only for now — mirrors `a2a_store`'s
//! shape and discipline exactly (tolerate-missing/corrupt-as-empty,
//! `fs::atomic_write`, pure list mutations); no command or consumer is
//! wired to it yet.

pub mod a2a_store;
pub mod addr;
pub mod beacon;
pub mod carry;
pub mod commands;
pub mod display;
pub mod edits;
pub mod fs;
pub mod git;
pub mod identity;
pub mod inbox;
pub mod ledger;
pub mod mode;
pub mod pairing;
pub mod peer_store;
pub mod petname;
pub mod records;
pub mod session;
pub mod stage;
pub mod takes;
pub mod time;
pub mod wire_auth;

/// A crate-wide lock serialising every test that mutates process-global env
/// (`AOIDE_STAGE_DIR`, `AOIDE_STATE_DIR`, …). Delegates to
/// `aoide-test-support`'s single mutex (Phase 9 restructure): the `commands`
/// tests moved INTO this crate's test binary hold that lock, so every
/// env-touching test in the binary must share it or they race.
#[cfg(test)]
pub(crate) fn env_lock() -> &'static std::sync::Mutex<()> {
    aoide_test_support::env_lock()
}
