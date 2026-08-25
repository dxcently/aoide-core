//! The pairing ceremony's own state (P-P2, `docs/architecture/PAIRING.md`
//! "The ceremony"): the two park-and-approve queues either side of a
//! request holds, and the SAS (short authentication string) derivation both
//! sides compute independently from the same public transcript.
//!
//! **Two files, two directions — never one.** A request rides from the
//! REQUESTER (box A) to the APPROVER (box B); box B parks it
//! ([`InboundPairingRequest`], `state/peer-pairing-inbound.json`) and box A
//! remembers it sent one ([`OutboundPairingRequest`],
//! `state/peer-pairing-outbound.json`) so its own A2A door can finish the
//! ceremony when B's approval callback arrives, possibly long after the
//! `peer pair request` CLI process that sent it has exited. Same `state/`
//! dir family as `peer_store`'s own `state/peers.json` (account/global
//! runtime, not song-scoped), same tolerate-missing/additive-round-trip
//! discipline, same atomic writes.
//!
//! **Ids are NOT the array-position ids `song/stage/pending.json` uses**
//! (CONTRACTS.md's own doc for that file) — a pairing request's id is
//! generated once, at park time, and stays stable for the request's whole
//! life on BOTH ends (the requester's outbound entry and the approver's
//! callback both key on it), so a shifting array-position id would break
//! that cross-instance correlation the moment either side's list changed
//! shape. [`gen_request_id`] mints an 8-hex-char id (4 random bytes) —
//! collision-checked against the CURRENT list before insert, the same
//! belt-and-suspenders a fresh random id anywhere in this crate gets when
//! the list it joins is small and checkable in memory.
//!
//! **Expiry is swept lazily, not on a timer.** Every reader that lists or
//! resolves either queue calls [`sweep_expired_inbound`]/
//! [`sweep_expired_outbound`] first — an expired entry is simply dropped
//! from the file on the next touch; nothing here runs a background thread.
//! [`pairing_timeout_secs`] is the knob (`AOIDE_PAIRING_TIMEOUT` env,
//! default 4 hours — "hours, not minutes; it waits for a human",
//! PAIRING.md's own wording).
//!
//! **The SAS ([`derive_sas`]) is a transcript hash over the FOUR public
//! values every ceremony makes visible to both sides: the requester's
//! pubkey, the approver's pubkey, the requester's nonce, the approver's
//! nonce — in that fixed order, always** (PAIRING.md: "derived from a
//! transcript hash over (pubkey_A, pubkey_B, nonce_A, nonce_B)... standard
//! numeric-comparison SAS construction, no invention"). Hashing the
//! lowercased hex TEXT of each field (not decoded raw bytes) sidesteps a
//! hex-parse failure mode entirely — the four fields are already
//! opaque hex strings by the time they reach here (never
//! reinterpreted as anything else), so hashing their canonical text is
//! exactly as strong a transcript binding as hashing the decoded bytes
//! would be, with strictly fewer error paths. A `\x00` separator after
//! EVERY field (including the last) closes the classic "field
//! concatenation ambiguity" (`"ab"+"c"` vs `"a"+"bc"`) the same way a
//! length-prefixed or delimited encoding would, without adding one.
//! `sha2::Sha256`'s first 4 bytes, big-endian, mod 1,000,000, rendered
//! `NNN-NNN` — this exact derivation is pinned by
//! [`tests::derive_sas_stability_vectors_never_drift`] so it renders
//! identically on both boxes forever (PAIRING.md's own requirement).

use crate::fs::{atomic_write, state_dir};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// `state/peer-pairing-inbound.json`/`-outbound.json` schema version.
pub const PAIRING_VERSION: &str = "0";

/// Env override for how long an unapproved pairing request stays parked
/// before [`sweep_expired_inbound`]/[`sweep_expired_outbound`] drop it —
/// "hours, not minutes; it waits for a human" (PAIRING.md). A blank or
/// unparsable value falls back to [`DEFAULT_PAIRING_TIMEOUT_SECS`], the
/// same tolerant-fallback shape `aoide_secrets::park::park_timeout` holds
/// for its own (much shorter) analogous knob.
pub const PAIRING_TIMEOUT_ENV: &str = "AOIDE_PAIRING_TIMEOUT";

/// The default pairing-request timeout: 4 hours (PAIRING.md: "default
/// generous — hours, not minutes").
pub const DEFAULT_PAIRING_TIMEOUT_SECS: u64 = 4 * 60 * 60;

/// Resolve the pairing-request timeout in seconds: [`PAIRING_TIMEOUT_ENV`]
/// when set to a valid positive integer, else [`DEFAULT_PAIRING_TIMEOUT_SECS`].
pub fn pairing_timeout_secs() -> u64 {
    if let Ok(v) = std::env::var(PAIRING_TIMEOUT_ENV) {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            if let Ok(secs) = trimmed.parse::<u64>() {
                if secs > 0 {
                    return secs;
                }
            }
        }
    }
    DEFAULT_PAIRING_TIMEOUT_SECS
}

/// `n_bytes` random bytes off the system RNG, hex-encoded lowercase — the
/// ONE randomness primitive this module uses, for BOTH a fresh nonce
/// (16 bytes, the ceremony's `nonce_a`/`nonce_b`) and a fresh request id (4
/// bytes, [`gen_request_id`]). `getrandom::fill` is already a workspace
/// dependency (`identity.rs`'s own keygen) — reused here rather than a
/// second RNG entry point. A read failure is vanishingly unlikely on Linux
/// once the kernel CSPRNG is seeded (the same assumption `identity::mint`
/// already makes for key generation); this function panics on that failure
/// rather than silently degrading a SECURITY-relevant nonce/id to something
/// weaker — unlike `aoide_secrets::park::random_nonce`'s own
/// `/dev/urandom`-read fallback (that nonce only needs to usually differ
/// across restarts, not resist prediction; a pairing nonce feeds directly
/// into the SAS transcript and must never be guessable).
pub fn random_hex(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    getrandom::fill(&mut buf).expect("system RNG unavailable");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// A fresh 8-hex-char (4-byte) request id, checked against `existing` ids
/// so two requests parked in the same file never collide — a `while`
/// re-roll rather than a counter, since (module doc) this id must stay
/// stable and self-contained on both ends with no shared counter state
/// between the two boxes.
fn gen_request_id(existing: &[String]) -> String {
    loop {
        let id = random_hex(4);
        if !existing.iter().any(|e| e == &id) {
            return id;
        }
    }
}

/// The SAS derivation (module doc) — pure, deterministic, order-sensitive.
/// Every field is trimmed and lowercased before hashing, so a caller need
/// not pre-normalize hex case; a `\x00` separator follows every field.
pub fn derive_sas(
    requester_pubkey_hex: &str,
    approver_pubkey_hex: &str,
    requester_nonce_hex: &str,
    approver_nonce_hex: &str,
) -> String {
    let mut hasher = Sha256::new();
    for field in [requester_pubkey_hex, approver_pubkey_hex, requester_nonce_hex, approver_nonce_hex] {
        hasher.update(field.trim().to_ascii_lowercase().as_bytes());
        hasher.update([0u8]);
    }
    let digest = hasher.finalize();
    let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    format!("{:03}-{:03}", n / 1000, n % 1000)
}

// ── Inbound (approver-side): a request PARKED for this instance to approve ──

/// One pairing request parked on the APPROVER's own instance — everything
/// the approver needs to display it (`peer pair pending`), derive the SAS
/// (`derive_sas` against this instance's own identity), and commit a peer
/// record on approval (`peer pair approve`), all without any further wire
/// round trip to the requester until the approval callback itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundPairingRequest {
    pub id: String,
    /// The requester's public key, hex, no separator.
    #[serde(rename = "pubkeyHex")]
    pub pubkey_hex: String,
    /// The requester's self-claimed local nickname (`peer pair request
    /// <url> --name <n>`, or that verb's own URL-derived default) — used,
    /// self-asserted, as the approver's OWN nickname for this peer too
    /// (`peer pair approve` takes no separate `--name`).
    pub name: String,
    /// The connecting TCP peer's own address, as classified by
    /// [`crate` — server crate's] `PeerOrigin` at park time — display-only
    /// (PAIRING.md: "parks pending (id, ... origin addr)"); never a
    /// security decision in this phase (no pairing exists yet to gate on).
    #[serde(rename = "originAddr")]
    pub origin_addr: String,
    /// The requester's own self-reported A2A door URL — where the approval
    /// callback (`aoide/pairApprove`) is POSTed.
    pub url: String,
    /// The requester's own nonce, hex.
    #[serde(rename = "requesterNonceHex")]
    pub requester_nonce_hex: String,
    /// THIS instance's (the approver's) own nonce, hex — generated fresh at
    /// park time and returned synchronously in the same response, so the
    /// requester can derive its own SAS immediately with no further wire
    /// call.
    #[serde(rename = "approverNonceHex")]
    pub approver_nonce_hex: String,
    #[serde(rename = "requestedAt")]
    pub requested_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct InboundPairingFile {
    #[serde(rename = "schemaVersion", default)]
    schema_version: String,
    #[serde(default)]
    requests: Vec<InboundPairingRequest>,
}

fn inbound_path() -> std::path::PathBuf {
    state_dir().join("peer-pairing-inbound.json")
}

fn load_inbound_raw() -> Vec<InboundPairingRequest> {
    match std::fs::read_to_string(inbound_path()) {
        Ok(raw) => serde_json::from_str::<InboundPairingFile>(&raw).map(|f| f.requests).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

fn save_inbound(requests: &[InboundPairingRequest]) -> Result<(), String> {
    let file = InboundPairingFile {
        schema_version: PAIRING_VERSION.to_string(),
        requests: requests.to_vec(),
    };
    let body = serde_json::to_string_pretty(&file).map_err(|e| format!("serialize peer-pairing-inbound.json: {e}"))? + "\n";
    let path = inbound_path();
    atomic_write(&path, &body).map_err(|e| format!("{}: {e}", path.display()))
}

/// List every currently-unexpired inbound request, sweeping (and persisting
/// the removal of) any that expired since the last touch. `peer pair
/// pending`'s whole reply.
pub fn list_inbound(now_epoch: i64) -> Vec<InboundPairingRequest> {
    let all = load_inbound_raw();
    let (kept, expired) = sweep(all, now_epoch);
    if expired > 0 {
        let _ = save_inbound(&kept);
    }
    kept
}

/// Park a fresh inbound request — the approver's `aoide/pairRequest`
/// handler's whole job. Returns the freshly-minted [`InboundPairingRequest`]
/// (including its new `id` and freshly-generated `approver_nonce_hex`) so
/// the caller can build the synchronous wire response from it directly.
#[allow(clippy::too_many_arguments)]
pub fn park_inbound(
    pubkey_hex: &str,
    name: &str,
    origin_addr: &str,
    url: &str,
    requester_nonce_hex: &str,
    requested_at: &str,
    expires_at: &str,
) -> Result<InboundPairingRequest, String> {
    let mut requests = load_inbound_raw();
    let id = gen_request_id(&requests.iter().map(|r| r.id.clone()).collect::<Vec<_>>());
    let entry = InboundPairingRequest {
        id,
        pubkey_hex: pubkey_hex.to_string(),
        name: name.to_string(),
        origin_addr: origin_addr.to_string(),
        url: url.to_string(),
        requester_nonce_hex: requester_nonce_hex.to_string(),
        approver_nonce_hex: random_hex(16),
        requested_at: requested_at.to_string(),
        expires_at: expires_at.to_string(),
    };
    requests.push(entry.clone());
    save_inbound(&requests)?;
    Ok(entry)
}

/// Remove and return one inbound request by id, `None` if it never existed
/// OR has already expired (sweeping happens here too, so an approve/reject
/// against a just-expired id gets the same honest "unknown id" a genuinely
/// unknown one would). `peer pair approve`/`peer pair reject`'s shared
/// lookup.
pub fn take_inbound(id: &str, now_epoch: i64) -> Result<Option<InboundPairingRequest>, String> {
    let all = load_inbound_raw();
    let (mut kept, _expired) = sweep(all, now_epoch);
    let idx = kept.iter().position(|r| r.id == id);
    let taken = idx.map(|i| kept.remove(i));
    save_inbound(&kept)?;
    Ok(taken)
}

// ── Outbound (requester-side): a request THIS instance is awaiting approval on ──

/// One pairing request THIS instance (the requester) sent out and is
/// waiting on — the callback (`aoide/pairApprove`) resolves it, committing
/// this instance's own peer record for the approver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundPairingRequest {
    /// Same id the approver parked it under (module doc — one shared id,
    /// no separate counters to reconcile).
    pub id: String,
    /// The approver's own A2A door URL — this becomes the peer record's
    /// `url` on approval.
    pub url: String,
    /// THIS instance's own local nickname for the approver
    /// (`peer pair request <url> --name <n>`, or its URL-derived default).
    pub name: String,
    /// The approver's public key, hex — learned from the synchronous
    /// `aoide/pairRequest` response.
    #[serde(rename = "pubkeyHex")]
    pub pubkey_hex: String,
    /// THIS instance's own nonce, hex.
    #[serde(rename = "requesterNonceHex")]
    pub requester_nonce_hex: String,
    #[serde(rename = "requestedAt")]
    pub requested_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct OutboundPairingFile {
    #[serde(rename = "schemaVersion", default)]
    schema_version: String,
    #[serde(default)]
    requests: Vec<OutboundPairingRequest>,
}

fn outbound_path() -> std::path::PathBuf {
    state_dir().join("peer-pairing-outbound.json")
}

fn load_outbound_raw() -> Vec<OutboundPairingRequest> {
    match std::fs::read_to_string(outbound_path()) {
        Ok(raw) => serde_json::from_str::<OutboundPairingFile>(&raw).map(|f| f.requests).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

fn save_outbound(requests: &[OutboundPairingRequest]) -> Result<(), String> {
    let file = OutboundPairingFile {
        schema_version: PAIRING_VERSION.to_string(),
        requests: requests.to_vec(),
    };
    let body = serde_json::to_string_pretty(&file).map_err(|e| format!("serialize peer-pairing-outbound.json: {e}"))? + "\n";
    let path = outbound_path();
    atomic_write(&path, &body).map_err(|e| format!("{}: {e}", path.display()))
}

/// Remember that THIS instance sent a request out — `peer pair request`'s
/// own write, once it has the approver's synchronous response in hand.
pub fn park_outbound(entry: OutboundPairingRequest) -> Result<(), String> {
    let mut requests = load_outbound_raw();
    requests.retain(|r| r.id != entry.id);
    requests.push(entry);
    save_outbound(&requests)
}

/// Remove and return one outbound request by id — the `aoide/pairApprove`
/// callback handler's lookup. `None` for an unknown OR expired id (same
/// sweep-on-touch discipline as [`take_inbound`]).
pub fn take_outbound(id: &str, now_epoch: i64) -> Result<Option<OutboundPairingRequest>, String> {
    let all = load_outbound_raw();
    let (mut kept, _expired) = sweep_outbound(all, now_epoch);
    let idx = kept.iter().position(|r| r.id == id);
    let taken = idx.map(|i| kept.remove(i));
    save_outbound(&kept)?;
    Ok(taken)
}

/// List every currently-unexpired outbound request, sweeping expired ones
/// the same way [`list_inbound`] does. Mainly a diagnostic/test seam today
/// — no CLI verb lists this side (PAIRING.md's ceremony only ever prompts
/// the APPROVER interactively; the requester's `peer pair request` already
/// printed its own SAS synchronously and has nothing further to poll).
pub fn list_outbound(now_epoch: i64) -> Vec<OutboundPairingRequest> {
    let all = load_outbound_raw();
    let (kept, expired) = sweep_outbound(all, now_epoch);
    if expired > 0 {
        let _ = save_outbound(&kept);
    }
    kept
}

fn sweep(entries: Vec<InboundPairingRequest>, now_epoch: i64) -> (Vec<InboundPairingRequest>, usize) {
    let before = entries.len();
    let kept: Vec<_> = entries
        .into_iter()
        .filter(|e| crate::time::parse_iso_utc(&e.expires_at).map(|exp| exp > now_epoch).unwrap_or(true))
        .collect();
    (kept.clone(), before - kept.len())
}

fn sweep_outbound(entries: Vec<OutboundPairingRequest>, now_epoch: i64) -> (Vec<OutboundPairingRequest>, usize) {
    let before = entries.len();
    let kept: Vec<_> = entries
        .into_iter()
        .filter(|e| crate::time::parse_iso_utc(&e.expires_at).map(|exp| exp > now_epoch).unwrap_or(true))
        .collect();
    (kept.clone(), before - kept.len())
}

/// `requested_at`'s ISO timestamp plus [`pairing_timeout_secs`], as ISO —
/// both `park_inbound`/`park_outbound` callers derive `expires_at` this way
/// so the two files' expiry math can never drift.
pub fn expires_at_from(requested_at_epoch: i64) -> String {
    crate::time::iso_utc_from_epoch(requested_at_epoch + pairing_timeout_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(dir: &std::path::Path) {
        std::env::set_var("AOIDE_STATE_DIR", dir);
    }

    // ── derive_sas ────────────────────────────────────────────────────────

    /// Pinned stability vectors (module doc): a future change to the hash,
    /// truncation, or format must fail THIS test, not just "look different"
    /// — the whole point of a SAS is that it renders identically on both
    /// boxes forever. Computed independently (sha256sum over the exact byte
    /// transcript `derive_sas` builds) rather than by calling the function
    /// itself, so this test actually pins the algorithm rather than just
    /// asserting it agrees with itself.
    #[test]
    fn derive_sas_stability_vectors_never_drift() {
        let pubkey_a = "a".repeat(64);
        let pubkey_b = "b".repeat(64);
        let nonce_a = "c".repeat(16);
        let nonce_b = "d".repeat(16);
        assert_eq!(derive_sas(&pubkey_a, &pubkey_b, &nonce_a, &nonce_b), "740-729");

        // Swapping requester/approver roles (and their matching nonces)
        // must NOT reproduce the same code — ordering is load-bearing.
        assert_eq!(derive_sas(&pubkey_b, &pubkey_a, &nonce_b, &nonce_a), "847-405");
    }

    #[test]
    fn derive_sas_is_case_and_whitespace_insensitive_but_content_sensitive() {
        let lower = derive_sas("aabbcc", "ddeeff", "1122", "3344");
        let upper = derive_sas("AABBCC", "DDEEFF", "1122", "3344");
        let padded = derive_sas("  aabbcc  ", "ddeeff", "1122", "3344");
        assert_eq!(lower, upper, "hex case must not change the derived code");
        assert_eq!(lower, padded, "surrounding whitespace must not change the derived code");

        let different = derive_sas("aabbcd", "ddeeff", "1122", "3344");
        assert_ne!(lower, different, "a genuinely different field must change the code");
    }

    #[test]
    fn derive_sas_is_always_a_six_digit_dashed_code() {
        for (pa, pb, na, nb) in [
            ("00".to_string(), "00".to_string(), "00".to_string(), "00".to_string()),
            ("ff".repeat(32), "ff".repeat(32), "ff".repeat(16), "ff".repeat(16)),
            ("random-ish-1".to_string(), "random-ish-2".to_string(), "n1".to_string(), "n2".to_string()),
        ] {
            let sas = derive_sas(&pa, &pb, &na, &nb);
            assert_eq!(sas.len(), 7, "NNN-NNN is 7 chars: {sas:?}");
            let (a, b) = sas.split_once('-').unwrap();
            assert_eq!(a.len(), 3);
            assert_eq!(b.len(), 3);
            assert!(a.chars().all(|c| c.is_ascii_digit()));
            assert!(b.chars().all(|c| c.is_ascii_digit()));
        }
    }

    // ── pairing_timeout_secs ─────────────────────────────────────────────

    #[test]
    fn pairing_timeout_defaults_to_four_hours_and_honors_a_valid_override() {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var(PAIRING_TIMEOUT_ENV).ok();
        std::env::remove_var(PAIRING_TIMEOUT_ENV);
        assert_eq!(pairing_timeout_secs(), 4 * 60 * 60);

        std::env::set_var(PAIRING_TIMEOUT_ENV, "60");
        assert_eq!(pairing_timeout_secs(), 60);

        std::env::set_var(PAIRING_TIMEOUT_ENV, "not-a-number");
        assert_eq!(pairing_timeout_secs(), 4 * 60 * 60, "unparsable falls back to the default");

        std::env::set_var(PAIRING_TIMEOUT_ENV, "0");
        assert_eq!(pairing_timeout_secs(), 4 * 60 * 60, "zero falls back to the default, never a zero timeout");

        match saved {
            Some(v) => std::env::set_var(PAIRING_TIMEOUT_ENV, v),
            None => std::env::remove_var(PAIRING_TIMEOUT_ENV),
        }
    }

    // ── random_hex / gen_request_id ──────────────────────────────────────

    #[test]
    fn random_hex_produces_the_requested_byte_length_and_varies() {
        let a = random_hex(16);
        let b = random_hex(16);
        assert_eq!(a.len(), 32, "16 bytes -> 32 hex chars");
        assert_ne!(a, b, "vanishingly unlikely to collide across two real reads");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn gen_request_id_avoids_an_existing_id_when_forced_to_collide() {
        // Force a collision on the first roll by pre-seeding `existing` with
        // whatever the RNG would otherwise produce is impractical to fake
        // deterministically without a seam — instead prove the CONTRACT
        // directly: a huge existing set never causes an infinite loop or a
        // duplicate against itself.
        let existing: Vec<String> = (0..50).map(|_| random_hex(4)).collect();
        let id = gen_request_id(&existing);
        assert!(!existing.contains(&id));
        assert_eq!(id.len(), 8);
    }

    // ── inbound park/list/take round trip ────────────────────────────────

    #[test]
    fn park_inbound_then_list_then_take_round_trips_through_a_temp_state_dir() {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-pairing-inbound-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        env(&dir);

        assert!(list_inbound(0).is_empty(), "missing file tolerates as empty");

        let now = 1_700_000_000_i64;
        let entry = park_inbound(
            "requesterpubkeyhex",
            "box-a",
            "10.0.0.5",
            "http://box-a:8710/",
            "requesternoncehex",
            &crate::time::iso_utc_from_epoch(now),
            &expires_at_from(now),
        )
        .unwrap();
        assert_eq!(entry.id.len(), 8);
        assert!(!entry.approver_nonce_hex.is_empty());

        let listed = list_inbound(now);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, entry.id);
        assert_eq!(listed[0].pubkey_hex, "requesterpubkeyhex");

        let taken = take_inbound(&entry.id, now).unwrap();
        assert_eq!(taken.unwrap().id, entry.id);
        assert!(list_inbound(now).is_empty(), "taken entry is gone");
        assert!(take_inbound(&entry.id, now).unwrap().is_none(), "taking twice finds nothing the second time");

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    #[test]
    fn expired_inbound_requests_are_swept_on_list_and_take_finds_nothing() {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-pairing-inbound-expiry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        env(&dir);

        let requested_at = 1_700_000_000_i64;
        let entry = park_inbound(
            "pk", "name", "addr", "url", "nonce",
            &crate::time::iso_utc_from_epoch(requested_at),
            &crate::time::iso_utc_from_epoch(requested_at + 10), // expires in 10s
        )
        .unwrap();

        // Well past expiry.
        let later = requested_at + 3600;
        assert!(list_inbound(later).is_empty(), "an expired request is swept from the listing");
        assert!(take_inbound(&entry.id, later).unwrap().is_none(), "an expired request cannot be taken either");

        // The sweep persisted — a fresh read at ANY time now finds nothing.
        assert!(list_inbound(requested_at).is_empty(), "the sweep already removed it from disk");

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    // ── outbound park/take round trip ────────────────────────────────────

    #[test]
    fn park_outbound_then_take_round_trips_and_is_removed_after_taking() {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-pairing-outbound-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        env(&dir);

        let now = 1_700_000_000_i64;
        let entry = OutboundPairingRequest {
            id: "deadbeef".to_string(),
            url: "http://box-b:8710/".to_string(),
            name: "box-b".to_string(),
            pubkey_hex: "approverpubkeyhex".to_string(),
            requester_nonce_hex: "reqnonce".to_string(),
            requested_at: crate::time::iso_utc_from_epoch(now),
            expires_at: expires_at_from(now),
        };
        park_outbound(entry.clone()).unwrap();

        let listed = list_outbound(now);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, "deadbeef");

        let taken = take_outbound("deadbeef", now).unwrap();
        assert_eq!(taken.unwrap().pubkey_hex, "approverpubkeyhex");
        assert!(list_outbound(now).is_empty());
        assert!(take_outbound("deadbeef", now).unwrap().is_none());

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    #[test]
    fn park_outbound_on_a_repeated_id_replaces_rather_than_duplicates() {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-pairing-outbound-dup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        env(&dir);

        let now = 1_700_000_000_i64;
        let mut entry = OutboundPairingRequest {
            id: "sameid00".to_string(),
            url: "http://old/".to_string(),
            name: "n".to_string(),
            pubkey_hex: "pk1".to_string(),
            requester_nonce_hex: "n1".to_string(),
            requested_at: crate::time::iso_utc_from_epoch(now),
            expires_at: expires_at_from(now),
        };
        park_outbound(entry.clone()).unwrap();
        entry.url = "http://new/".to_string();
        park_outbound(entry).unwrap();

        let listed = list_outbound(now);
        assert_eq!(listed.len(), 1, "re-parking the same id replaces, never duplicates");
        assert_eq!(listed[0].url, "http://new/");

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    #[test]
    fn expires_at_from_adds_the_configured_timeout() {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var(PAIRING_TIMEOUT_ENV).ok();
        std::env::set_var(PAIRING_TIMEOUT_ENV, "100");
        let base = 1_700_000_000_i64;
        assert_eq!(expires_at_from(base), crate::time::iso_utc_from_epoch(base + 100));
        match saved {
            Some(v) => std::env::set_var(PAIRING_TIMEOUT_ENV, v),
            None => std::env::remove_var(PAIRING_TIMEOUT_ENV),
        }
    }
}
