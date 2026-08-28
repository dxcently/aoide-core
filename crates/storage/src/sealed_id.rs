//! The sealed session credential (LANE IDENTITY P-ID1, `docs/architecture/
//! CONTRACTS.md`'s identity section; plan file "LANE IDENTITY (#63)"'s
//! thesis: same-uid secrecy is impossible in this threat model, so a
//! session's identity has to be a fact the daemon ATTESTS about a kernel-
//! authenticated pid, never a string a session holds and presents).
//!
//! **What this phase proves, and what it explicitly does not.** P-ID1 mints
//! the seal, stores it, and proves it round-trips (mint → verify true,
//! tamper any field → verify false, wrong key → verify false). It does
//! **NOT** wire a peercred-verified connecting pid (that socket change is
//! P-ID2) and **NO GATE consumes this field yet** — `seal` on a session
//! record is inert data today, exactly as inert as `origin` was before
//! P-ID0. Treat every value produced here as scaffolding proving the
//! MACHINERY, not a security boundary in force.
//!
//! **The signing key is NOT [`crate::identity::Keypair::load_or_mint`]'s
//! on-disk peer-wire key.** Under OQ1-A (the User-answered threat-model
//! question, plan file) the seal's secrecy rests on PROCESS LIVENESS, not
//! file permissions: the daemon mints [`crate::identity::mint_ephemeral`]
//! once at startup and holds it only in memory, never on disk. A same-uid
//! attacker can read any `0600` file under the operator's own uid —
//! including `identity.rs`'s own on-disk key — but cannot read another live
//! process's heap without `ptrace`, which Yama `ptrace_scope>=1` blocks by
//! default on the target host. If Yama is off, this degrades to a
//! liveness-only guarantee (a live daemon process, not a same-uid-secret
//! key) — an honesty note carried into CONTRACTS, not hidden here. The
//! on-disk `identity.rs` key keeps its unrelated peer-wire (`wire_auth.rs`)
//! role untouched; nothing in this module reads or writes it.
//!
//! **The canonical signing string** ([`canonical_seal_string`]) follows
//! `wire_auth::canonical_string`'s own field-hashing shape exactly (this
//! crate's established convention, restated rather than imported since the
//! field SET differs): every field trimmed and lowercased, a `\x00`
//! separator after EVERY field including the last — the same "field
//! concatenation ambiguity" close `pairing.rs::transcript_digest`'s own doc
//! names (`"12" + "3"` and `"1" + "23"` must never hash equal). Five fields,
//! in this fixed order: `session_id`, `pid` (decimal), `pid_starttime`
//! (decimal), `origin_class`, `issued_at` (decimal, unix seconds). Pinned by
//! `tests::canonical_seal_string_stability_vectors_never_drift` — a future
//! change to the field order, separator, or case-folding breaks that test,
//! not just "looks different"; CONTRACTS.md's own copy of this shape must
//! move in the same commit as any change here.
//!
//! **Signing itself is a thin wrapper over `wire_auth::sign_hex`/
//! `verify_signature_hex`** — this module never touches an `ed25519_dalek`
//! type directly, keeping that dependency contained to this crate exactly
//! as `identity.rs`'s own module doc already advertises for the peer wire.

use crate::identity::Keypair;
use crate::wire_auth::{sign_hex, verify_signature_hex};

/// A daemon-attested fact about a session: WHICH pid the daemon registered
/// it against, that pid's `/proc` start time (so a pid-reuse cannot be
/// mistaken for the same process — P-ID2's verify-on-accept re-checks both
/// together), and the origin class it was born under. Never held or
/// presented BY the session itself (module doc) — the daemon looks the seal
/// up by the connecting pid; the session does not carry a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedIdentity {
    pub session_id: String,
    pub pid: i32,
    pub pid_starttime: u64,
    pub origin_class: String,
    pub issued_at: i64,
}

/// Build the canonical string [`mint_seal`]/[`verify_seal`] sign/verify
/// (module doc): `session_id`, `pid`, `pid_starttime`, `origin_class`,
/// `issued_at` — each field trimmed+lowercased, NUL-separated after every
/// field including the last. Pure; both the minting and verifying side call
/// this with values they each hold independently (the daemon at mint time,
/// a verifier reconstructing the SAME struct from the stored record at
/// check time — P-ID2), never a wire-carried canonical string.
pub fn canonical_seal_string(id: &SealedIdentity) -> String {
    let pid_field = id.pid.to_string();
    let starttime_field = id.pid_starttime.to_string();
    let issued_field = id.issued_at.to_string();
    let mut s = String::new();
    for field in [
        id.session_id.as_str(),
        pid_field.as_str(),
        starttime_field.as_str(),
        id.origin_class.as_str(),
        issued_field.as_str(),
    ] {
        s.push_str(&field.trim().to_ascii_lowercase());
        s.push('\u{0}');
    }
    s
}

/// Sign `id` with the daemon's own in-memory seal key, returning the seal as
/// a hex string — the value [`crate::records::SessionRecord::seal`] stores.
/// A thin wrapper over [`sign_hex`] (module doc); `keypair` is expected to be
/// [`crate::identity::mint_ephemeral`]'s ONE per-process instance under
/// OQ1-A, never `load_or_mint`'s on-disk key.
pub fn mint_seal(keypair: &Keypair, id: &SealedIdentity) -> String {
    sign_hex(keypair, canonical_seal_string(id).as_bytes())
}

/// Verify a hex-encoded seal over `id` against the daemon's own public key
/// (hex). A thin wrapper over [`verify_signature_hex`] (module doc) — a
/// malformed `pubkey_hex`/`seal_hex` is a clean `false`, never a panic, same
/// as its underlying wrapper's own contract. Verification needs ONLY the
/// public key: the seal is a signature, never secret material itself
/// (module doc's "what this phase proves").
pub fn verify_seal(pubkey_hex: &str, id: &SealedIdentity, seal_hex: &str) -> bool {
    verify_signature_hex(pubkey_hex, canonical_seal_string(id).as_bytes(), seal_hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity;

    fn sample() -> SealedIdentity {
        SealedIdentity {
            session_id: "session-abc123".to_string(),
            pid: 4242,
            pid_starttime: 987654321,
            origin_class: "local".to_string(),
            issued_at: 1_700_000_000,
        }
    }

    // ── canonical_seal_string ────────────────────────────────────────────

    /// Pinned stability vector (module doc): computed independently
    /// (manual byte transcript, same discipline `wire_auth`'s own
    /// `canonical_string_stability_vectors_never_drift` uses) so this test
    /// actually pins the algorithm, not just self-agreement.
    #[test]
    fn canonical_seal_string_stability_vectors_never_drift() {
        let id = sample();
        assert_eq!(
            canonical_seal_string(&id),
            "session-abc123\u{0}4242\u{0}987654321\u{0}local\u{0}1700000000\u{0}"
        );
    }

    #[test]
    fn canonical_seal_string_is_case_and_whitespace_insensitive_but_content_sensitive() {
        let mut a = sample();
        a.origin_class = "  PEER:BOX-B  ".to_string();
        let mut b = sample();
        b.origin_class = "peer:box-b".to_string();
        assert_eq!(
            canonical_seal_string(&a),
            canonical_seal_string(&b),
            "surrounding whitespace/case on a string field must not change the canonical string"
        );

        let mut different = sample();
        different.session_id = "session-xyz789".to_string();
        assert_ne!(
            canonical_seal_string(&sample()),
            canonical_seal_string(&different),
            "a different session_id must change the canonical string"
        );
    }

    // ── mint_seal / verify_seal round trip ───────────────────────────────

    #[test]
    fn mint_and_verify_round_trip_a_real_ephemeral_keypair() {
        let kp = identity::mint_ephemeral().unwrap();
        let pubkey_hex = kp.info().pubkey_hex;
        let id = sample();

        let seal_hex = mint_seal(&kp, &id);
        assert!(verify_seal(&pubkey_hex, &id, &seal_hex), "a genuine seal must verify");
    }

    #[test]
    fn verify_seal_rejects_a_tampered_pid() {
        let kp = identity::mint_ephemeral().unwrap();
        let pubkey_hex = kp.info().pubkey_hex;
        let id = sample();
        let seal_hex = mint_seal(&kp, &id);

        let mut tampered = id.clone();
        tampered.pid += 1;
        assert!(
            !verify_seal(&pubkey_hex, &tampered, &seal_hex),
            "a seal must not verify against a DIFFERENT pid than it was minted over"
        );
    }

    #[test]
    fn verify_seal_rejects_a_tampered_origin_class() {
        let kp = identity::mint_ephemeral().unwrap();
        let pubkey_hex = kp.info().pubkey_hex;
        let id = sample();
        let seal_hex = mint_seal(&kp, &id);

        let mut tampered = id.clone();
        tampered.origin_class = "peer:forged".to_string();
        assert!(
            !verify_seal(&pubkey_hex, &tampered, &seal_hex),
            "a seal must not verify against a tampered origin_class"
        );
    }

    #[test]
    fn verify_seal_rejects_a_tampered_session_id() {
        let kp = identity::mint_ephemeral().unwrap();
        let pubkey_hex = kp.info().pubkey_hex;
        let id = sample();
        let seal_hex = mint_seal(&kp, &id);

        let mut tampered = id.clone();
        tampered.session_id = "session-forged".to_string();
        assert!(
            !verify_seal(&pubkey_hex, &tampered, &seal_hex),
            "a seal must not verify against a tampered session_id"
        );
    }

    #[test]
    fn verify_seal_rejects_a_tampered_starttime() {
        let kp = identity::mint_ephemeral().unwrap();
        let pubkey_hex = kp.info().pubkey_hex;
        let id = sample();
        let seal_hex = mint_seal(&kp, &id);

        let mut tampered = id.clone();
        tampered.pid_starttime += 1;
        assert!(
            !verify_seal(&pubkey_hex, &tampered, &seal_hex),
            "a seal must not verify against a tampered pid_starttime — this is exactly the \
             pid-reuse defense P-ID2's verify-on-accept relies on"
        );
    }

    #[test]
    fn verify_seal_rejects_a_different_keypair() {
        let kp = identity::mint_ephemeral().unwrap();
        let other = identity::mint_ephemeral().unwrap();
        let id = sample();
        let seal_hex = mint_seal(&kp, &id);

        assert!(
            !verify_seal(&other.info().pubkey_hex, &id, &seal_hex),
            "a seal minted under one daemon's key must not verify under a DIFFERENT key — \
             the exact property a same-uid attacker without the live daemon's memory cannot forge"
        );
    }

    #[test]
    fn verify_seal_refuses_malformed_hex_cleanly() {
        let id = sample();
        assert!(!verify_seal("not-hex!", &id, "also-not-hex"));
        assert!(!verify_seal("", &id, ""));
    }
}
