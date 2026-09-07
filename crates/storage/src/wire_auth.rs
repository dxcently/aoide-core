//! Per-request signed wire authentication for paired nodes (P-P4,
//! `docs/architecture/PAIRING.md`'s "Wire authentication (paired nodes)"
//! section): the canonical string every signed A2A POST binds itself to,
//! the header names carrying it, and the sign/verify wrappers around
//! [`crate::identity::Keypair`] that keep every `ed25519_dalek` type
//! contained to this crate — neither `aoide-client` (the signer) nor
//! `aoide-server` (the verifier) needs that dependency directly, mirroring
//! `identity.rs`'s own "this crate is the sanctioned dependent" charter
//! note.
//!
//! **What gets signed, and why it's a STRING, not a re-hash of one.** The
//! brief's wire shape names five inputs: the HTTP method, the request path,
//! a timestamp, a nonce, and the request body — bound together as ONE
//! canonical string ([`canonical_string`]), which `ed25519_dalek::Signer`
//! then signs directly (EdDSA hashes its own message internally via
//! SHA-512; wrapping the canonical string in a SECOND SHA-256 first, the
//! way [`crate::pairing::transcript_digest`] does for the SAS/commitment,
//! would add nothing — those two exist to REDUCE a transcript to a short
//! code or a collision-resistant commitment, not to feed a signer, and
//! P-P4's own test vectors need to pin exact STRING bytes, not a further
//! hash of them). Only the BODY gets a `sha2` digest of its own inside the
//! canonical string (`sha2` per PAIRING.md decision 1's dependency
//! grounding, reused rather than re-justified) — a multi-KB JSON-RPC body
//! has no business riding inside the signed string verbatim, so its digest
//! stands in for it, the same "sign a digest of the large thing" pattern
//! every wire-signing scheme uses.
//!
//! **Field-hashing style matches P-P2's `derive_sas`/`derive_commit`
//! exactly, on purpose** (the brief: "Follow P-P2's canonical-form style
//! ... unless you state a reason not to" — no reason found): each of the
//! five fields (method, path, timestamp, nonce, body-digest-hex) is
//! trimmed and lowercased before joining, with a `\x00` separator after
//! EVERY field including the last, closing the same "field concatenation
//! ambiguity" [`crate::pairing::transcript_digest`]'s own doc names. Both
//! ends of the wire build this string from values they hold independently
//! (the client from what it's about to send, the server from what it just
//! parsed off the raw request) — never trusting a wire-carried canonical
//! string the way `derive_sas` never trusts a wire-carried SAS.
//!
//! **Headers.** Four new ones, all present together or not at all — a
//! request carrying SOME but not all four is treated as a malformed signed
//! request (refused), never silently downgraded to the unsigned path (see
//! `aoide-server::a2a::verify_signed_request`'s own doc comment for the
//! fail-closed handling this module's constants feed).
//!
//! **Replay guard split**: [`signature_skew_secs`] (the ±120s-default
//! timestamp window, `AOIDE_SIGNATURE_SKEW_SECS` override) is a pure env
//! read and lives here, next to the canonical string it bounds. The
//! **nonce cache** does NOT live here — it's ephemeral, in-memory,
//! per-`a2a serve`-PROCESS runtime state with no durable file behind it at
//! all, unlike everything else this crate persists
//! (`state/node-pairing-*.json`, `state/nodes.json`, …); it lives in
//! `aoide-server::a2a` instead, next to the verification flow that's its
//! only consumer — see that module's own doc comment for the process-
//! locality note.

use crate::identity::Keypair;
use ed25519_dalek::Signature;
use sha2::{Digest, Sha256};

/// The signer's claimed self name — the same
/// [`crate::node_store::valid_node_name`] vocabulary as every other
/// node-name field on this wire. Attribution only (#63 P-ID5): the verifier
/// resolves the caller by the stored pubkey that verifies the signature,
/// never by this value, which is checked for wire-format validity, audited
/// (drift included), and consulted solely as the exact-name tiebreak among
/// verified records sharing the verifying pubkey.
pub const HEADER_NODE: &str = "X-Aoide-Node";
/// ISO-8601 UTC, [`crate::time::parse_iso_utc`]-shaped — the moment the
/// SIGNER minted this request, checked against the verifier's own "now"
/// within [`signature_skew_secs`].
pub const HEADER_TIMESTAMP: &str = "X-Aoide-Timestamp";
/// A fresh random value per request (hex; the signer mints it the same way
/// [`crate::pairing::random_hex`] does) — the replay guard's other half:
/// unique across every request a signer legitimately makes within one skew
/// window, so a captured-and-replayed request inside that window is caught
/// by nonce reuse, not by the timestamp alone.
pub const HEADER_NONCE: &str = "X-Aoide-Nonce";
/// The ed25519 signature over [`canonical_string`], hex-encoded, no
/// separator — 128 hex chars (64 raw bytes).
pub const HEADER_SIGNATURE: &str = "X-Aoide-Signature";

/// Env override for the replay-guard's timestamp window, in seconds
/// (PAIRING.md: "±120s default, env knob"). Same tolerant-fallback shape
/// [`crate::pairing::pairing_timeout_secs`] already established for its own
/// analogous knob: a blank/unparsable/non-positive value falls back to
/// [`DEFAULT_SIGNATURE_SKEW_SECS`] rather than producing a zero or negative
/// window.
pub const SIGNATURE_SKEW_ENV: &str = "AOIDE_SIGNATURE_SKEW_SECS";

/// The default replay-guard window: 120 seconds either side of "now"
/// (PAIRING.md's own default).
pub const DEFAULT_SIGNATURE_SKEW_SECS: i64 = 120;

/// Resolve the signature replay-guard window in seconds:
/// [`SIGNATURE_SKEW_ENV`] when set to a valid positive integer, else
/// [`DEFAULT_SIGNATURE_SKEW_SECS`].
pub fn signature_skew_secs() -> i64 {
    if let Ok(v) = std::env::var(SIGNATURE_SKEW_ENV) {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            if let Ok(secs) = trimmed.parse::<i64>() {
                if secs > 0 {
                    return secs;
                }
            }
        }
    }
    DEFAULT_SIGNATURE_SKEW_SECS
}

/// Hex-encode raw bytes, lowercase, no separator. A small local copy rather
/// than reaching into `identity.rs`'s own private `hex_encode` (that one
/// stays `fn`-private to its file, same as `pairing.rs`'s own local hex
/// join in [`crate::pairing::derive_commit`]) — this crate's established
/// convention is a tiny per-module copy over a shared `pub` utility with
/// exactly one real caller pattern per module.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode a hex string to raw bytes — `None` on an odd length or any
/// non-hex-digit character, never a panic (every caller here feeds it
/// untrusted wire input: a header value or a node's stored `pubkeyHex`).
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() || s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

/// Build the canonical string P-P4 signs (module doc): `method`, `path`,
/// `timestamp`, `nonce`, and `body`'s SHA-256 digest (hex) — each field
/// trimmed+lowercased, NUL-separated after every field including the last.
/// Pure; both the signer and the verifier call this with values they each
/// hold independently, never a wire-carried canonical string.
///
/// Pinned by `tests::canonical_string_stability_vectors_never_drift` — a
/// future change to the field order, the separator, the case-folding, or
/// the digest algorithm breaks that test, not just "looks different";
/// CONTRACTS.md §6's own copy of this shape must move in the same commit
/// as any change here.
pub fn canonical_string(method: &str, path: &str, timestamp: &str, nonce: &str, body: &[u8]) -> String {
    let digest_hex = hex_encode(&Sha256::digest(body));
    let mut s = String::new();
    for field in [method, path, timestamp, nonce, digest_hex.as_str()] {
        s.push_str(&field.trim().to_ascii_lowercase());
        s.push('\u{0}');
    }
    s
}

/// Sign `msg` with `keypair` (this instance's own P-P1 identity), returning
/// the [`HEADER_SIGNATURE`] header VALUE directly (hex, no separator) — the
/// one function `aoide-client`'s wire builder calls, so it never touches an
/// `ed25519_dalek::Signature` itself.
pub fn sign_hex(keypair: &Keypair, msg: &[u8]) -> String {
    hex_encode(&keypair.sign(msg).to_bytes())
}

/// Verify a hex-encoded signature over `msg` against a hex-encoded public
/// key — the one function `aoide-server`'s verification flow calls, so it
/// never touches an `ed25519_dalek::Signature`/`VerifyingKey` itself. A
/// malformed `pubkey_hex`/`signature_hex` (wrong length, non-hex chars) is a
/// clean `false`, same as [`Keypair::verify`]'s own malformed-pubkey
/// handling — never a panic on untrusted wire input.
pub fn verify_signature_hex(pubkey_hex: &str, msg: &[u8], signature_hex: &str) -> bool {
    let Some(pubkey_bytes) = hex_decode(pubkey_hex) else {
        return false;
    };
    let Ok(pubkey_arr): Result<[u8; 32], _> = pubkey_bytes.try_into() else {
        return false;
    };
    let Some(sig_bytes) = hex_decode(signature_hex) else {
        return false;
    };
    let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.try_into() else {
        return false;
    };
    Keypair::verify(&pubkey_arr, msg, &Signature::from_bytes(&sig_arr))
}

/// Is `ts_epoch` within `window_secs` of `now_epoch`, either direction?
/// Pure — `verify_signed_request` (`aoide-server::a2a`) is the one
/// production caller, feeding it [`signature_skew_secs`]'s value.
pub fn within_skew(now_epoch: i64, ts_epoch: i64, window_secs: i64) -> bool {
    (now_epoch - ts_epoch).abs() <= window_secs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity;

    // ── canonical_string ─────────────────────────────────────────────────

    /// Pinned stability vector (module doc): computed independently
    /// (sha256sum over the exact byte transcript, same discipline
    /// `pairing.rs`'s own `derive_sas_stability_vectors_never_drift` uses)
    /// so this test actually pins the algorithm, not just self-agreement.
    #[test]
    fn canonical_string_stability_vectors_never_drift() {
        let s = canonical_string("POST", "/", "2026-08-25T00:00:00Z", "abcd1234", b"{}");
        // body digest: sha256("{}") = 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
        assert_eq!(
            s,
            "post\u{0}/\u{0}2026-08-25t00:00:00z\u{0}abcd1234\u{0}44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a\u{0}"
        );
    }

    #[test]
    fn canonical_string_is_case_and_whitespace_insensitive_but_content_sensitive() {
        let lower = canonical_string("post", "/x", "ts", "nonce", b"body");
        let upper = canonical_string("POST", "/X", "TS", "NONCE", b"body");
        let padded = canonical_string("  post  ", "/x", "ts", "nonce", b"body");
        assert_eq!(lower, upper, "method/path/timestamp/nonce case must not change the canonical string");
        assert_eq!(lower, padded, "surrounding whitespace must not change the canonical string");

        let different_body = canonical_string("post", "/x", "ts", "nonce", b"different");
        assert_ne!(lower, different_body, "a different body must change the canonical string (via its digest)");

        let different_path = canonical_string("post", "/y", "ts", "nonce", b"body");
        assert_ne!(lower, different_path, "a different path must change the canonical string");
    }

    // ── sign_hex / verify_signature_hex round trip ─────────────────────────

    #[test]
    fn sign_and_verify_round_trip_a_real_keypair() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _s = aoide_test_support::EnvSaver::capture(&["AOIDE_STATE_DIR"]);
        let root = aoide_test_support::unique_tmp("wire-auth-sign-verify");
        std::env::set_var("AOIDE_STATE_DIR", &root);

        let (kp, _) = identity::load_or_mint().unwrap();
        let pubkey_hex = kp.info().pubkey_hex;
        let canonical = canonical_string("POST", "/", "2026-08-25T00:00:00Z", "n1", b"{\"a\":1}");
        let sig_hex = sign_hex(&kp, canonical.as_bytes());

        assert!(verify_signature_hex(&pubkey_hex, canonical.as_bytes(), &sig_hex), "a genuine signature must verify");
        assert!(
            !verify_signature_hex(&pubkey_hex, b"tampered body", &sig_hex),
            "a signature over a DIFFERENT message must not verify"
        );

        let other_canonical = canonical_string("POST", "/other-path", "2026-08-25T00:00:00Z", "n1", b"{\"a\":1}");
        assert!(
            !verify_signature_hex(&pubkey_hex, other_canonical.as_bytes(), &sig_hex),
            "a tampered PATH changes the canonical string, so the same signature must not verify against it"
        );

        let wrong_pubkey = "a".repeat(64);
        assert!(
            !verify_signature_hex(&wrong_pubkey, canonical.as_bytes(), &sig_hex),
            "a wrong public key must not verify a genuine signature"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn verify_signature_hex_refuses_malformed_hex_cleanly() {
        assert!(!verify_signature_hex("not-hex!", b"msg", "also-not-hex"));
        assert!(!verify_signature_hex("aa", b"msg", "bb"), "well-formed but wrong-length hex must not panic or verify");
        assert!(!verify_signature_hex("", b"msg", ""));
    }

    // ── signature_skew_secs ─────────────────────────────────────────────

    #[test]
    fn signature_skew_secs_defaults_to_120_and_honors_a_valid_override() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var(SIGNATURE_SKEW_ENV).ok();
        std::env::remove_var(SIGNATURE_SKEW_ENV);
        assert_eq!(signature_skew_secs(), 120);

        std::env::set_var(SIGNATURE_SKEW_ENV, "30");
        assert_eq!(signature_skew_secs(), 30);

        std::env::set_var(SIGNATURE_SKEW_ENV, "0");
        assert_eq!(signature_skew_secs(), 120, "zero falls back to the default, never a zero window");

        std::env::set_var(SIGNATURE_SKEW_ENV, "not-a-number");
        assert_eq!(signature_skew_secs(), 120, "unparsable falls back to the default");

        match saved {
            Some(v) => std::env::set_var(SIGNATURE_SKEW_ENV, v),
            None => std::env::remove_var(SIGNATURE_SKEW_ENV),
        }
    }

    // ── within_skew ───────────────────────────────────────────────────────

    #[test]
    fn within_skew_covers_both_directions_and_the_boundary() {
        assert!(within_skew(1000, 1000, 120), "exact match");
        assert!(within_skew(1000, 880, 120), "120s in the past — at the boundary, still inside");
        assert!(within_skew(1000, 1120, 120), "120s in the future — at the boundary, still inside");
        assert!(!within_skew(1000, 879, 120), "121s in the past — outside");
        assert!(!within_skew(1000, 1121, 120), "121s in the future — outside");
    }
}
