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
//! **The canonical signing string** ([`canonical_seal_string`]) reuses
//! `wire_auth::canonical_string`'s `\x00`-after-every-field separator (the
//! same "field concatenation ambiguity" close `pairing.rs::
//! transcript_digest`'s own doc names — `"12" + "3"` and `"1" + "23"` must
//! never hash equal) but **deliberately does NOT lower-case or trim
//! `session_id`/`origin_class` the way `wire_auth::canonical_string`
//! folds its own string fields.** Those two are EXACT-MATCH IDENTITY
//! fields, not HTTP-normalize fields: `session_id` is the session store's
//! own primary key (`session_store.rs` compares it with plain `==`
//! everywhere — case-folding it here would let a seal minted for
//! `"AgentA"` verify against a session record actually named `"agenta"`
//! the moment `pid`/`pid_starttime`/`origin_class` happened to line up,
//! defeating the exact identity binding a credential exists to provide).
//! `origin_class` gets the same treatment for the same reason — it is
//! about to become the P-ID4 origin-gate's own lookup key, and folding
//! `"peer:Box-B"` and `"peer:box-b"` together would be exactly the wrong
//! kind of leniency for a security-relevant enum-shaped string. Neither
//! field is trimmed either: nothing in this codebase's session-id
//! generation (`conduct-<pid>-<ts>`, an operator's own `--id`, or a
//! harness's raw hook `session_id`) legitimately produces leading/trailing
//! whitespace, so trimming would only ever silently accept a value that is
//! NOT the exact identity string on record. `pid`/`pid_starttime`/
//! `issued_at` render as their plain canonical decimal digit strings
//! (`i32`/`u64`/`i64::to_string()`), which are inherently free of case or
//! whitespace variance — nothing to fold there either. Five fields, in
//! this fixed order: `session_id` (exact), `pid` (decimal), `pid_starttime`
//! (decimal), `origin_class` (exact), `issued_at` (decimal, unix seconds).
//! Pinned by `tests::canonical_seal_string_stability_vectors_never_drift`
//! and `tests::canonical_seal_string_is_case_sensitive_for_identity_fields`
//! — a future change to the field order, separator, or (re-)introduced
//! case/whitespace folding breaks those tests, not just "looks different";
//! CONTRACTS.md's own copy of this shape must move in the same commit as
//! any change here.
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
/// `issued_at`, NUL-separated after every field including the last.
/// `session_id`/`origin_class` ride VERBATIM — no trim, no case-folding
/// (module doc: they are exact-match identity fields, not HTTP-normalize
/// fields); `pid`/`pid_starttime`/`issued_at` are their plain decimal
/// `to_string()`, already free of case/whitespace variance. Pure; both the
/// minting and verifying side call this with values they each hold
/// independently (the daemon at mint time, a verifier reconstructing the
/// SAME struct from the stored record at check time — P-ID2), never a
/// wire-carried canonical string.
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
        s.push_str(field);
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

    /// Pinned stability vector (module doc): a MIXED-CASE `session_id`/
    /// `origin_class` on purpose — computed independently (manual byte
    /// transcript, same discipline `wire_auth`'s own
    /// `canonical_string_stability_vectors_never_drift` uses), this pins
    /// BOTH the field order/separator AND that neither identity field is
    /// case-folded or trimmed (the fix this test replaces used a
    /// suspiciously-already-lowercase sample, which would have silently
    /// passed even with the old lower-casing behavior still in place).
    #[test]
    fn canonical_seal_string_stability_vectors_never_drift() {
        let id = SealedIdentity {
            session_id: "Session-AbC123".to_string(),
            pid: 4242,
            pid_starttime: 987654321,
            origin_class: "Peer:Box-B".to_string(),
            issued_at: 1_700_000_000,
        };
        assert_eq!(
            canonical_seal_string(&id),
            "Session-AbC123\u{0}4242\u{0}987654321\u{0}Peer:Box-B\u{0}1700000000\u{0}"
        );
    }

    /// The property FIX 1 exists for: `session_id`/`origin_class` are
    /// EXACT-match identity fields (module doc) — case must be load-bearing,
    /// never folded. A canonical string that folded case would let a seal
    /// minted for `"AgentA"` verify against a differently-cased session
    /// record; this both proves the CANONICAL STRING differs (the direct
    /// property) and, one level up, that `verify_seal` actually refuses the
    /// cross-case match (the property that matters to a caller).
    #[test]
    fn canonical_seal_string_is_case_sensitive_for_identity_fields() {
        let mut lower = sample();
        lower.session_id = "agenta".to_string();
        let mut upper = sample();
        upper.session_id = "AgentA".to_string();
        assert_ne!(
            canonical_seal_string(&lower),
            canonical_seal_string(&upper),
            "session_id differing only in case must produce a DIFFERENT canonical string"
        );

        let mut origin_lower = sample();
        origin_lower.origin_class = "peer:box-b".to_string();
        let mut origin_upper = sample();
        origin_upper.origin_class = "Peer:Box-B".to_string();
        assert_ne!(
            canonical_seal_string(&origin_lower),
            canonical_seal_string(&origin_upper),
            "origin_class differing only in case must produce a DIFFERENT canonical string"
        );

        // Whitespace is likewise significant now — no field is trimmed.
        let mut padded = sample();
        padded.session_id = " session-abc123".to_string();
        assert_ne!(
            canonical_seal_string(&sample()),
            canonical_seal_string(&padded),
            "surrounding whitespace on session_id must not be silently trimmed away"
        );

        let mut different = sample();
        different.session_id = "session-xyz789".to_string();
        assert_ne!(
            canonical_seal_string(&sample()),
            canonical_seal_string(&different),
            "a different session_id must change the canonical string"
        );
    }

    /// One level up from the canonical-string proof above: a seal minted
    /// for one session_id must not verify against a record whose id
    /// differs ONLY in case — the exact cross-identity forgery FIX 1
    /// closes. Before the fix, `"AgentA"` and `"agenta"` folded to the same
    /// signing string, so a seal minted for one verified against the
    /// other whenever pid/pid_starttime/origin_class happened to match.
    #[test]
    fn verify_seal_rejects_a_session_id_differing_only_in_case() {
        let kp = identity::mint_ephemeral().unwrap();
        let pubkey_hex = kp.info().pubkey_hex;

        let mut lower = sample();
        lower.session_id = "agenta".to_string();
        let seal_hex = mint_seal(&kp, &lower);

        let mut upper = lower.clone();
        upper.session_id = "AgentA".to_string();
        assert!(
            !verify_seal(&pubkey_hex, &upper, &seal_hex),
            "a seal minted for `agenta` must NOT verify against `AgentA` — case is part of \
             the identity, not a normalize-away detail"
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
