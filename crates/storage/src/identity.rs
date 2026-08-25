//! Instance identity (`docs/architecture/PAIRING.md`'s "Identity" section,
//! P-P1 of the pairing workstream): a real ed25519 keypair identifying THIS
//! Aoide instance. Landed here: the dependency + mint/load/store + the
//! `aoide identity` show verb. The pairing ceremony itself (`peer pair`,
//! P-P2), the `allows`/spawn-gate wiring (P-P3), and signed wire requests
//! (P-P4) are later phases — this module exists so they have an identity to
//! build on, nothing more.
//!
//! **Home in `aoide-storage`, not a new crate.** This crate's own charter
//! (`README.md`: "durable session data + memory persistence... file-first
//! by decision") already covers a single lazily-minted, atomically-written,
//! privately-permissioned file under `fs::state_dir()` — the identity
//! keypair is exactly that shape, one file more like `state/usage.json` or
//! the secrets-adjacent `totp.secret` precedent (a different crate, same
//! discipline) than a reason to stand up a whole new crate for one keypair.
//! Nothing here depends on `conduct`/`server`/`client`, so no cross-crate
//! edge is created by landing it in the crate that is already the
//! second-lowest in the DAG.
//!
//! **The private key never enters a `Serialize`/`Deserialize` type, full
//! stop** (`PAIRING.md`'s kill-list: "The identity private key never
//! crosses any socket, any Outcome, any log"). [`Keypair`] holds nothing
//! but the raw `ed25519_dalek::SigningKey` and a plain `String` timestamp —
//! no derive on it at all. The only serializable type this module defines
//! is [`IdentityInfo`], built by [`Keypair::info`], which carries public
//! material only (hex pubkey, a short fingerprint, the mint time). The
//! `no_private_material_in_any_serialize_type` test below is a MECHANICAL
//! gate for this, not prose-only discipline the way the secrets crate's
//! sibling invariant is: it reads this file's own source text and fails the
//! build if any `#[derive(...Serialize...)]` struct in it ever grows a
//! field that looks like it holds key material.
//!
//! **Storage** (`fs::state_dir()/identity/`, locked down at both levels —
//! [`fs::secure_private_dir`] on the directory, [`fs::atomic_write_private`]
//! on the sensitive file — added to `fs.rs` by this phase as the named
//! helpers the design doc anticipated but this crate didn't have yet):
//! - `identity/` itself is created via [`fs::secure_private_dir`] (`0700`,
//!   owner rwx only) BEFORE anything is written into it — a locked-down
//!   file inside a world-listable directory still leaks the directory's
//!   own entry names, so the dir gets the same treatment the file does.
//! - `ed25519.key` — the raw 32-byte private seed, `0600`, written via
//!   [`fs::atomic_write_private`], which creates its temp file ALREADY at
//!   `0600` (via `OpenOptions::mode`, not a `chmod` after the fact) so
//!   there is no window at any wider mode between the write landing and
//!   the permission lock — see that function's own doc for the exact
//!   defect an earlier revision of this phase shipped and how the fix
//!   closes it. Written ONCE at mint and never rewritten afterward;
//!   `SigningKey::from_bytes` reconstructs the full keypair from it on
//!   every later load — nothing else needs to persist, since the public
//!   key and every signature derive from this one seed deterministically.
//! - `created_at` — a plain ISO-8601 UTC string ([`crate::time::now_iso_utc`]),
//!   written once alongside the key, `0644` (not sensitive — a mint
//!   timestamp leaks nothing; the directory's own `0700` already keeps it
//!   from being LISTED by anyone else regardless). Kept as its own tiny
//!   file rather than folded into a JSON metadata file next to the key so
//!   there is exactly ONE file this module ever re-derives the public key
//!   from (the key itself) — no second copy of the pubkey to keep in sync
//!   or trust.
//!
//! **Keygen** seeds a 32-byte array via `getrandom::fill` and builds the
//! key with `SigningKey::from_bytes` — see the workspace `Cargo.toml`'s own
//! comment on the `ed25519-dalek`/`getrandom` entries for why this route
//! was chosen over enabling `ed25519-dalek`'s `rand_core` feature (rand_core
//! 0.10 dropped `OsRng`; this way needs no `rand_core` dependency at all).

use crate::fs;
use crate::time::now_iso_utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Serialize;
use std::io;
use std::path::PathBuf;

/// This instance's identity directory: `<state_dir>/identity/`.
pub fn identity_dir() -> PathBuf {
    fs::state_dir().join("identity")
}

fn key_path() -> PathBuf {
    identity_dir().join("ed25519.key")
}

fn created_at_path() -> PathBuf {
    identity_dir().join("created_at")
}

/// This instance's loaded keypair. Deliberately holds NOTHING but the raw
/// `SigningKey` and the mint timestamp — no `derive(Serialize)`, no
/// `Debug`/`Clone` either (a `Clone`d private key is still a private key
/// sitting in a second place; every caller that needs to sign holds the one
/// `Keypair` [`load_or_mint`] returns rather than copying it around).
pub struct Keypair {
    signing_key: SigningKey,
    created_at: String,
}

/// Public-facing identity info — safe to serialize, print, log, or send
/// over the wire (`aoide identity`'s `--json` shape, and later phases'
/// pairing-request payloads). Never carries a private byte.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct IdentityInfo {
    #[serde(rename = "pubkeyHex")]
    pub pubkey_hex: String,
    pub fingerprint: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

impl Keypair {
    /// This keypair's public info (hex pubkey, fingerprint, mint time) —
    /// safe to serialize/print/send anywhere; derives nothing but the
    /// PUBLIC key from `signing_key`.
    pub fn info(&self) -> IdentityInfo {
        let vk = self.signing_key.verifying_key();
        IdentityInfo {
            pubkey_hex: hex_encode(vk.as_bytes()),
            fingerprint: fingerprint(vk.as_bytes()),
            created_at: self.created_at.clone(),
        }
    }

    /// Sign `msg` with this instance's private key (P-P4's wire-auth seam
    /// builds on this; exercised directly by this phase's own smoke test
    /// only — nothing calls it live yet).
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing_key.sign(msg)
    }

    /// Verify `sig` over `msg` against a raw 32-byte public key. A
    /// malformed `pubkey` (not a valid curve point) is a clean `false`,
    /// never a panic.
    pub fn verify(pubkey: &[u8; 32], msg: &[u8], sig: &Signature) -> bool {
        match VerifyingKey::from_bytes(pubkey) {
            Ok(vk) => vk.verify(msg, sig).is_ok(),
            Err(_) => false,
        }
    }
}

/// Hex-encode raw bytes, lowercase, no separator — [`IdentityInfo`]'s
/// `pubkeyHex` form.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A short, display-friendly fingerprint: the public key's first 8 bytes,
/// hex, colon-separated (`aa:bb:cc:dd:ee:ff:00:11`) — long enough to tell
/// instances apart at a glance, short enough to read aloud. Distinct from
/// P-P2's SAS (short authentication string): that one is a pairing-time
/// comparison code derived from BOTH sides' keys plus nonces; this is a
/// standing, one-sided display label `aoide identity` always shows.
fn fingerprint(pubkey: &[u8]) -> String {
    pubkey
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Load this instance's keypair, minting one lazily on first need. Returns
/// `(keypair, minted)` — `minted` is `true` only the FIRST time this ever
/// runs against a given state dir (the `aoide identity` handler's `changed`
/// signal); every later call is an idempotent read (house rule 2).
///
/// A key file present but the wrong length, or a corrupt/missing
/// `created_at` sidecar, are handled honestly rather than treated as fatal:
/// a bad-length key file is refused (never silently re-minted over — that
/// would invalidate every peer that already trusted the old pubkey without
/// telling anyone); a missing/corrupt `created_at` next to a GOOD key
/// degrades to reporting the load moment as the timestamp, since there is
/// no way to recover the true mint time and fabricating one would be
/// worse than admitting we don't know it.
pub fn load_or_mint() -> io::Result<(Keypair, bool)> {
    let kp = key_path();
    match std::fs::read(&kp) {
        Ok(bytes) => {
            let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{}: expected a 32-byte ed25519 seed, found {} bytes — refusing to mint over an existing identity file",
                        kp.display(),
                        bytes.len()
                    ),
                )
            })?;
            let signing_key = SigningKey::from_bytes(&seed);
            let created_at = std::fs::read_to_string(created_at_path())
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(now_iso_utc);
            Ok((
                Keypair {
                    signing_key,
                    created_at,
                },
                false,
            ))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => mint(),
        Err(e) => Err(e),
    }
}

/// Mint a fresh keypair and write both identity files. Private, called only
/// from [`load_or_mint`]'s not-found branch — every other caller goes
/// through the idempotent `load_or_mint`.
fn mint() -> io::Result<(Keypair, bool)> {
    // Locks the directory itself down to 0700 — `atomic_write_private`
    // below only ever secures the FILE it writes; nothing else in this
    // crate secured `identity/` as a directory, so on a state dir whose
    // default mode is whatever `create_dir_all` leaves it at (0755 under
    // this box's normal umask), the directory's entries would stay
    // world-listable even with `ed25519.key` itself locked to 0600
    // (review rider — RIDER 1).
    fs::secure_private_dir(&identity_dir())?;

    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("system RNG unavailable: {e}")))?;
    let signing_key = SigningKey::from_bytes(&seed);

    fs::atomic_write_private(&key_path(), &seed)?;
    let created_at = now_iso_utc();
    fs::atomic_write(&created_at_path(), &created_at)?;

    Ok((
        Keypair {
            signing_key,
            created_at,
        },
        true,
    ))
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn env(dir: &std::path::Path) {
        std::env::set_var("AOIDE_STATE_DIR", dir);
    }

    #[test]
    fn mint_once_is_idempotent_and_the_second_call_reports_no_mint() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = aoide_test_support::EnvSaver::capture(&["AOIDE_STATE_DIR"]);
        let root = aoide_test_support::unique_tmp("identity-mint-once");
        env(&root);

        let (first, minted_first) = load_or_mint().unwrap();
        assert!(minted_first, "the first call on a fresh state dir mints");
        let (second, minted_second) = load_or_mint().unwrap();
        assert!(!minted_second, "the second call is an idempotent read, not a re-mint");

        assert_eq!(
            first.info().pubkey_hex,
            second.info().pubkey_hex,
            "both loads must resolve to the SAME key"
        );
        assert_eq!(first.info().fingerprint, second.info().fingerprint);
        assert_eq!(
            first.info().created_at,
            second.info().created_at,
            "created_at must not change on a re-load"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_private_key_file_is_locked_to_0600() {
        use std::os::unix::fs::PermissionsExt;
        let _g = crate::env_lock().lock().unwrap();
        let _s = aoide_test_support::EnvSaver::capture(&["AOIDE_STATE_DIR"]);
        let root = aoide_test_support::unique_tmp("identity-0600");
        env(&root);

        let (_kp, minted) = load_or_mint().unwrap();
        assert!(minted);

        let mode = std::fs::metadata(key_path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "ed25519.key must be 0600, got {mode:o}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_identity_directory_itself_is_locked_to_0700() {
        // RIDER 1 (review): the file lock alone isn't enough — the
        // directory it lives in must be locked down too, or its entries
        // stay world-listable under `create_dir_all`'s umask-derived
        // default.
        use std::os::unix::fs::PermissionsExt;
        let _g = crate::env_lock().lock().unwrap();
        let _s = aoide_test_support::EnvSaver::capture(&["AOIDE_STATE_DIR"]);
        let root = aoide_test_support::unique_tmp("identity-dir-0700");
        env(&root);

        let (_kp, minted) = load_or_mint().unwrap();
        assert!(minted);

        let mode = std::fs::metadata(identity_dir()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "identity/ must be 0700, got {mode:o}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pubkey_round_trips_load_to_load_with_the_same_fingerprint() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = aoide_test_support::EnvSaver::capture(&["AOIDE_STATE_DIR"]);
        let root = aoide_test_support::unique_tmp("identity-roundtrip");
        env(&root);

        let (minted, _) = load_or_mint().unwrap();
        let minted_info = minted.info();
        drop(minted);

        // A brand-new load (a fresh process would do exactly this) must
        // reconstruct the identical public identity from the on-disk seed.
        let (loaded, minted_again) = load_or_mint().unwrap();
        assert!(!minted_again);
        assert_eq!(loaded.info(), minted_info);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn sign_and_verify_round_trip_against_the_dependency() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = aoide_test_support::EnvSaver::capture(&["AOIDE_STATE_DIR"]);
        let root = aoide_test_support::unique_tmp("identity-sign-verify");
        env(&root);

        let (kp, _) = load_or_mint().unwrap();
        let msg = b"aoide pairing smoke test";
        let sig = kp.sign(msg);

        let pubkey: [u8; 32] = {
            let mut b = [0u8; 32];
            let hex = kp.info().pubkey_hex;
            for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
                b[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
            }
            b
        };
        assert!(Keypair::verify(&pubkey, msg, &sig), "a genuine signature must verify");
        assert!(
            !Keypair::verify(&pubkey, b"a different message", &sig),
            "a signature over a different message must NOT verify"
        );

        let mut tampered_pubkey = pubkey;
        tampered_pubkey[0] ^= 0xff;
        assert!(
            !Keypair::verify(&tampered_pubkey, msg, &sig),
            "a wrong public key must NOT verify a genuine signature"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_legacy_state_dir_with_no_key_file_mints_cleanly() {
        // The "legacy state dir without a key = clean lazy mint" case named
        // in the brief: a state dir that already has OTHER files (the way
        // every real ~/Aoide/state predates this phase) but no `identity/`
        // subtree at all must mint on first touch, not error.
        let _g = crate::env_lock().lock().unwrap();
        let _s = aoide_test_support::EnvSaver::capture(&["AOIDE_STATE_DIR"]);
        let root = aoide_test_support::unique_tmp("identity-legacy-dir");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("usage.json"), r#"{"schemaVersion":"0"}"#).unwrap();
        env(&root);

        let (_kp, minted) = load_or_mint().unwrap();
        assert!(minted, "an absent identity/ subtree mints, it does not error");
        assert!(key_path().exists());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_key_file_of_the_wrong_length_is_refused_not_silently_reminted() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = aoide_test_support::EnvSaver::capture(&["AOIDE_STATE_DIR"]);
        let root = aoide_test_support::unique_tmp("identity-bad-length");
        env(&root);
        std::fs::create_dir_all(identity_dir()).unwrap();
        std::fs::write(key_path(), b"too short").unwrap();

        // `Keypair` deliberately carries no `Debug` impl (it would risk
        // printing key-shaped bytes) — match the Result directly rather
        // than `.unwrap_err()`, which needs the Ok side to be `Debug` too.
        match load_or_mint() {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
            Ok(_) => panic!("a wrong-length key file must be refused, not silently accepted"),
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_missing_created_at_sidecar_next_to_a_good_key_degrades_to_load_time() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = aoide_test_support::EnvSaver::capture(&["AOIDE_STATE_DIR"]);
        let root = aoide_test_support::unique_tmp("identity-no-sidecar");
        env(&root);

        let (_kp, _) = load_or_mint().unwrap();
        std::fs::remove_file(created_at_path()).unwrap();

        let (loaded, minted) = load_or_mint().unwrap();
        assert!(!minted, "a present key file never re-mints, sidecar or not");
        assert!(!loaded.info().created_at.is_empty(), "created_at degrades to SOME timestamp, never empty");

        let _ = std::fs::remove_dir_all(&root);
    }

    // ── The mechanical private-material gate ────────────────────────────

    /// `true` when `field_name` (lowercased already) is explicitly
    /// permitted despite mentioning `key`/`seed` — the PUBLIC half of a
    /// keypair is exactly what [`IdentityInfo`] is FOR, so `pubkey_hex`/
    /// `pubkeyHex`/`public_key`/`publicKey`-shaped names must not trip the
    /// gate below. Anything not on this allowlist that mentions `key` or
    /// `seed` is refused — a closed allowlist, not a growing denylist of
    /// specific bad names (RIDER 2 review fix: the old denylist named
    /// `signing_key`/`private_key`/`secret_key`/`seed` explicitly and would
    /// have missed a struct with a field simply named `key`).
    fn field_name_is_allowed_to_mention_key_or_seed(lower_field_name: &str) -> bool {
        lower_field_name.contains("pubkey") || lower_field_name.contains("public_key")
    }

    /// Extract a struct field's name from one line of its body, or `None`
    /// when the line isn't a simple `[pub] name: Type,`-shaped field
    /// declaration (an attribute line, a blank line, the `struct Foo {`
    /// opener, the closing `}`, etc. all correctly yield `None`).
    fn field_name_on_line(line: &str) -> Option<&str> {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') || l.starts_with("//") || l.contains("struct ") || l == "{" || l == "}" {
            return None;
        }
        let stripped = l.strip_prefix("pub ").unwrap_or(l);
        let colon = stripped.find(':')?;
        let name = stripped[..colon].trim();
        if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return None; // not a plain identifier — nothing to false-positive on
        }
        Some(name)
    }

    /// Reads THIS FILE'S OWN source and fails if any `#[derive(...)]`
    /// attribute that mentions `Serialize`/`Deserialize` decorates a struct
    /// with a FIELD NAME containing `key` or `seed` (case-insensitive)
    /// that isn't on the public-key allowlist above. This is the module
    /// doc's "MECHANICAL gate": today [`IdentityInfo`] is the only such
    /// struct, and it must stay that way — a future field named
    /// `signing_key`/`private_key`/`secret_key`/`seed`, OR simply `key`,
    /// added to it (or to a future `derive(Serialize)` struct added
    /// anywhere in this file) trips this test rather than silently
    /// shipping. Checking FIELD NAMES rather than scanning the whole
    /// struct body as one blob (the gate's original shape) is what catches
    /// a bare `key` field — a whole-body substring scan for `"key"` would
    /// also match `pubkey_hex`'s legitimate mention and every doc comment
    /// reproduced inside the block, so it isn't a workable denylist shape
    /// once `key` alone must be caught.
    #[test]
    fn no_private_material_in_any_serialize_type() {
        let src = include_str!("identity.rs");

        // Real code lines only — a doc comment (`//!`/`///`) or a plain `//`
        // comment mentioning "derive(Serialize)" in PROSE (this very test's
        // own doc, several paragraphs above) must never trip the scanner.
        // Rust has no block comments in this file, so stripping any line
        // whose trimmed start is `//` is exact, not a heuristic.
        let lines: Vec<&str> = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect();

        let mut i = 0;
        while i < lines.len() {
            let line = lines[i].trim_start();
            let is_derive_attr = line.starts_with("#[derive(")
                && (line.contains("Serialize") || line.contains("Deserialize"));
            if is_derive_attr {
                // Walk forward to the struct's opening `{` and collect its
                // body up to the matching `}` (flat — no nested braces
                // appear inside any field list in this file today).
                let mut j = i + 1;
                let mut body_lines = Vec::new();
                let mut opened = false;
                while j < lines.len() {
                    let l = lines[j];
                    if l.contains('{') {
                        opened = true;
                    }
                    if opened {
                        body_lines.push(l);
                    }
                    if opened && l.contains('}') {
                        break;
                    }
                    j += 1;
                }
                for body_line in &body_lines {
                    let Some(field_name) = field_name_on_line(body_line) else {
                        continue;
                    };
                    let lower = field_name.to_lowercase();
                    let mentions_key_or_seed = lower.contains("key") || lower.contains("seed");
                    if mentions_key_or_seed && !field_name_is_allowed_to_mention_key_or_seed(&lower) {
                        panic!(
                            "a #[derive(Serialize/Deserialize)] struct in identity.rs has a field named `{field_name}` — private key material must never enter a Serialize/Deserialize type (PAIRING.md's kill-list), and this field name isn't on the pubkey/public_key allowlist. Offending block:\n{}",
                            body_lines.join("\n")
                        );
                    }
                }
                i = j;
            }
            i += 1;
        }
    }

    #[test]
    fn the_gate_allows_pubkey_shaped_names_but_refuses_a_bare_key_field() {
        // Proves the allowlist/denylist boundary directly, independent of
        // this file's real structs — a plain `key`-named field (the exact
        // shape RIDER 2 flagged as missed by the old whole-body scan) must
        // be refused, while `pubkey_hex`/`public_key` must not be.
        assert!(!field_name_is_allowed_to_mention_key_or_seed("key"));
        assert!(!field_name_is_allowed_to_mention_key_or_seed("signing_key"));
        assert!(!field_name_is_allowed_to_mention_key_or_seed("seed"));
        assert!(field_name_is_allowed_to_mention_key_or_seed("pubkey_hex"));
        assert!(field_name_is_allowed_to_mention_key_or_seed("public_key"));

        assert_eq!(field_name_on_line("pub pubkey_hex: String,"), Some("pubkey_hex"));
        assert_eq!(field_name_on_line("    key: [u8; 32],"), Some("key"));
        assert_eq!(field_name_on_line("#[serde(rename = \"pubkeyHex\")]"), None);
        assert_eq!(field_name_on_line("pub struct IdentityInfo {"), None);
        assert_eq!(field_name_on_line("}"), None);
    }
}
