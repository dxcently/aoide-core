//! The pairing ceremony's own state (P-P2, `docs/architecture/PAIRING.md`
//! "The ceremony"): the two park-and-approve queues either side of a
//! request holds, the commit-then-reveal handshake that keeps the SAS
//! honest against an active on-path attacker, and the SAS (short
//! authentication string) derivation both sides compute independently from
//! the same public transcript.
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
//! **Commit-then-reveal, not "both nonces in the clear in one round trip"
//! (review-bounce fix, standard Bluetooth SSP idiom, PAIRING.md's "standard
//! numeric-comparison SAS construction, no invention").** The original
//! shape — A's request carrying `nonceHex` directly — let an active
//! on-path attacker control four of the SAS transcript's six fields AFTER
//! observing the real ones (both pubkeys, both nonces, choosable to land on
//! any six-digit code against fast SHA-256), showing both honest operators
//! the SAME code while each is actually paired to the attacker. Only the
//! FIRST MOVER needs to commit (Bluetooth SSP's own numeric-comparison
//! rule): A's `aoide/pairRequest` carries [`derive_commit`]`(pubkey_A,
//! nonce_A)` instead of `nonce_A` itself — A's nonce is FIXED the moment B
//! parks the commitment, before B (or anyone on-path) has seen it, so a
//! counterpart choosing its own values after seeing the commit cannot force
//! SAS equality. B may reveal its own nonce immediately in its synchronous
//! response (nothing to hide on B's side — it moves second). A then POSTs
//! `aoide/pairReveal {id, nonceHex}` right after, in the same `peer pair
//! request` invocation ([`reveal_inbound`]); B verifies the revealed nonce
//! against the stored commitment and DROPS the parked entry outright on a
//! mismatch — a wrong nonce means either a bug or a tamper, and there is
//! nothing left worth keeping parked either way. An inbound entry with no
//! revealed nonce yet ([`InboundPairingRequest::requester_nonce_hex`]
//! still `None`) has no SAS to show and cannot be approved — `peer pair
//! pending` lists it without a code, `peer pair approve` refuses it
//! outright (`docs/architecture/PAIRING.md`'s "awaiting reveal" wording).
//!
//! **Neither side commits a peer record on the FIRST human confirmation
//! alone (review-bounce fix, decision 4's mutual confirmation, for real).**
//! B's `peer pair approve` still commits B's own record right away — but,
//! since Design A (task #119, poll-based completion — B's own door may be
//! loopback-only, so nothing dials OUT to A anymore), that commit is now
//! PURELY LOCAL: B marks its own parked entry [`InboundPairingRequest::approved`]
//! ([`mark_inbound_approved`]) and leaves it parked for A to find later. A's
//! outbound entry does NOT auto-commit the moment A happens to poll and see
//! `approved: true` either — that would let a network round trip stand in
//! for A's OWN operator ever looking at the code, same as before. Instead A's
//! `peer pair approve <id>` POLLS B's door (`aoide/pairPoll`, over the SAME
//! forward dial the original request/reveal already used — no callback, no
//! reverse leg); on a verified `approved` response it calls
//! [`mark_outbound_awaiting_confirm`] to transition the entry to
//! [`OutboundState::AwaitingConfirm`] and falls straight through to the SAME
//! confirm-then-commit y/N prompt B's own approve already holds, only THEN
//! calling `upsert_paired_peer` — the poll REPLACES the callback as the
//! trigger for this transition; the state machine and the human-confirm gate
//! it protects are otherwise unchanged. `peer pair reject <id>` aborts an
//! outbound entry at EITHER state ([`OutboundState::AwaitingApproval`] or
//! [`OutboundState::AwaitingConfirm`]) — the ceremony's own missing abort
//! command, closed without a new command (golden count unchanged).
//!
//! **Ids are NOT the array-position ids `state/stage/pending.json` uses**
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
//! resolves either queue calls [`sweep`]/[`sweep_outbound`] first (via
//! [`list_inbound`]/[`list_outbound`]/[`take_inbound`]/[`take_outbound`]/
//! [`park_inbound`]'s own cap accounting) — an expired entry is simply
//! dropped from the file on the next touch; nothing here runs a background
//! thread. [`pairing_timeout_secs`] is the knob (`AOIDE_PAIRING_TIMEOUT`
//! env, default 4 hours — "hours, not minutes; it waits for a human",
//! PAIRING.md's own wording).
//!
//! **`park_inbound` is capped (review-bounce fix, P-N2c FIX 3b's exact
//! shape reused): [`pairing_park_cap`] concurrently parked inbound
//! requests, default 32, `AOIDE_PAIRING_PARK_CAP` override.** Unlike
//! `secrets::park::ParkRegistry` (an in-memory registry backing a
//! connection held open for the whole park), this queue is disk-persisted
//! and unauthenticated by design (module doc on `pair_request` in
//! `aoide-server::a2a`) — an unbounded queue of parked requests is an
//! unbounded `state/peer-pairing-inbound.json`, cheap for an on-path or
//! local attacker to grow with no credential at all. `park_inbound` checks
//! the (post-sweep) length against the cap and inserts under the SAME
//! process-local [`std::sync::Mutex`] acquisition — never a separate
//! `len()` check followed by a second unlocked insert — so two racing
//! `pair_request` calls on one broker process can never jointly overrun
//! the cap by one, the identical TOCTOU discipline `secrets::park::
//! ParkRegistry::park_if_room` already holds. **Cross-process (#119 review
//! finding 4), every load-modify-write of EITHER park file additionally
//! runs under [`crate::fs::with_stage_lock`]** — the same flock
//! `state/inbox.json`'s writers already reuse for a `state/` file
//! (`inbox::receive`'s doc: "one process-wide lock file is enough … a
//! second lock file would be a new abstraction for zero added
//! correctness"): the resident `a2a serve` process and a concurrent CLI
//! invocation (`peer pair approve`/`reject`, a poll release) mutate the
//! same `state/peer-pairing-{inbound,outbound}.json`, and an unserialized
//! pair of read-modify-writes would silently drop an `approved` flag or a
//! `tries` increment. `PARK_LOCK` stays alongside it as the in-process cap
//! guard: `with_stage_lock` is best-effort by contract (a lock hiccup runs
//! the closure unlocked), so the mutex still guarantees two same-process
//! parks can never jointly overrun the cap. Beyond
//! the cap, [`park_inbound`] refuses with a taught error naming the cap
//! and its env knob — the caller (`aoide-server::a2a::pair_request`) maps
//! that refusal to a JSON-RPC error, never a silent drop. Outbound entries
//! are operator-created (one `peer pair request` invocation, one entry)
//! and carry no equivalent cap — nothing unauthenticated can grow that
//! queue.
//!
//! **The SAS ([`derive_sas`]) is a transcript hash over the FOUR public
//! values every ceremony makes visible to both sides: the requester's
//! pubkey, the approver's pubkey, the requester's nonce, the approver's
//! nonce — in that fixed order, always** (PAIRING.md: "derived from a
//! transcript hash over (pubkey_A, pubkey_B, nonce_A, nonce_B)... standard
//! numeric-comparison SAS construction, no invention"). [`derive_commit`]
//! shares the SAME canonical field-hashing shape ([`transcript_digest`]) —
//! lowercased hex TEXT of each field (not decoded raw bytes), NUL-separated
//! after EVERY field including the last (closes the classic "field
//! concatenation ambiguity" the same way a length-prefixed encoding
//! would) — over exactly two fields (pubkey, nonce) instead of four,
//! rendered as the full 32-byte digest in hex rather than truncated/
//! reduced, since a commitment must be collision-resistant on its own,
//! never a short human-facing code. `derive_sas` itself takes
//! `transcript_digest`'s first 4 bytes, big-endian, mod 1,000,000,
//! rendered `NNN-NNN` — unchanged by this phase (the review that required
//! the commitment fix independently re-verified this derivation's own
//! pinned vectors); this exact derivation is pinned by
//! [`tests::derive_sas_stability_vectors_never_drift`] so it renders
//! identically on both boxes forever (PAIRING.md's own requirement).

use crate::fs::{atomic_write, state_dir, with_stage_lock};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Mutex;

/// `state/peer-pairing-inbound.json`/`-outbound.json` schema version.
pub const PAIRING_VERSION: &str = "0";

/// Env override for how long an unapproved pairing request stays parked
/// before [`sweep`]/[`sweep_outbound`] drop it — "hours, not minutes; it
/// waits for a human" (PAIRING.md). A blank or unparsable value falls back
/// to [`DEFAULT_PAIRING_TIMEOUT_SECS`], the same tolerant-fallback shape
/// `aoide_secrets::park::park_timeout` holds for its own (much shorter)
/// analogous knob.
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

/// Env override for the registry-wide max PARKED inbound requests at once
/// (review-bounce Finding 3 — an unauthenticated, unbounded queue is an
/// unbounded file). Same tolerant-fallback shape as [`PAIRING_TIMEOUT_ENV`].
pub const PAIRING_PARK_CAP_ENV: &str = "AOIDE_PAIRING_PARK_CAP";

/// The default inbound park cap: 32 concurrently parked requests — the same
/// number `secrets::park::DEFAULT_PARK_CAP` uses for its own analogous
/// unauthenticated-queue concern.
pub const DEFAULT_PAIRING_PARK_CAP: usize = 32;

/// Resolve the inbound park cap: [`PAIRING_PARK_CAP_ENV`] when set to a
/// valid positive integer, else [`DEFAULT_PAIRING_PARK_CAP`].
pub fn pairing_park_cap() -> usize {
    if let Ok(v) = std::env::var(PAIRING_PARK_CAP_ENV) {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            if let Ok(cap) = trimmed.parse::<usize>() {
                if cap > 0 {
                    return cap;
                }
            }
        }
    }
    DEFAULT_PAIRING_PARK_CAP
}

/// Guards [`park_inbound`]'s check-then-insert — module doc's cap section.
/// Poison-recovering like every other production lock in this workspace
/// (`aoide_secrets::park::ParkRegistry`'s own precedent): a panic inside
/// one caller must never wedge every OTHER pairing request behind a
/// poisoned lock forever.
static PARK_LOCK: Mutex<()> = Mutex::new(());

/// `n_bytes` random bytes off the system RNG, hex-encoded lowercase — the
/// ONE randomness primitive this module uses, for a fresh nonce (16 bytes,
/// the ceremony's `nonce_a`/`nonce_b`) and a fresh request id (4 bytes,
/// [`gen_request_id`]). `getrandom::fill` is already a workspace dependency
/// (`identity.rs`'s own keygen) — reused here rather than a second RNG
/// entry point. A read failure is vanishingly unlikely on Linux once the
/// kernel CSPRNG is seeded (the same assumption `identity::mint` already
/// makes for key generation); this function panics on that failure rather
/// than silently degrading a SECURITY-relevant nonce/id to something
/// weaker — unlike `aoide_secrets::park::random_nonce`'s own
/// `/dev/urandom`-read fallback (that nonce only needs to usually differ
/// across restarts, not resist prediction; a pairing nonce feeds directly
/// into the commitment/SAS transcript and must never be guessable).
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

/// The canonical field-hashing shape [`derive_sas`]/[`derive_commit`] both
/// build on (module doc): every field trimmed and lowercased before
/// hashing (so a caller need not pre-normalize hex case), a `\x00`
/// separator after EVERY field including the last. Returns the full
/// 32-byte SHA-256 digest — callers reduce it however their own contract
/// requires ([`derive_sas`]'s mod-1,000,000 truncation, [`derive_commit`]'s
/// full hex encoding).
fn transcript_digest(fields: &[&str]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update(field.trim().to_ascii_lowercase().as_bytes());
        hasher.update([0u8]);
    }
    hasher.finalize().into()
}

/// The SAS derivation (module doc) — pure, deterministic, order-sensitive.
/// Unchanged by the commit-then-reveal fix (module doc); still exactly
/// `(requester_pubkey, approver_pubkey, requester_nonce, approver_nonce)`.
pub fn derive_sas(
    requester_pubkey_hex: &str,
    approver_pubkey_hex: &str,
    requester_nonce_hex: &str,
    approver_nonce_hex: &str,
) -> String {
    let digest = transcript_digest(&[requester_pubkey_hex, approver_pubkey_hex, requester_nonce_hex, approver_nonce_hex]);
    let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    format!("{:03}-{:03}", n / 1000, n % 1000)
}

/// The commitment [`park_inbound`]'s `commit_hex` param carries and
/// [`reveal_inbound`] verifies (module doc, review-bounce Finding 1) — the
/// FULL SHA-256 digest, hex-encoded, over `(pubkey_hex, nonce_hex)`. Full
/// digest rather than a truncated code on purpose: a commitment must resist
/// collision/second-preimage on its own, unlike the human-facing SAS, which
/// only needs to resist an active real-time forger, not an offline search
/// against a fixed target.
pub fn derive_commit(pubkey_hex: &str, nonce_hex: &str) -> String {
    let digest = transcript_digest(&[pubkey_hex, nonce_hex]);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

// ── Inbound (approver-side): a request PARKED for this instance to approve ──

/// One pairing request parked on the APPROVER's own instance — everything
/// the approver needs to display it (`peer pair pending`), derive the SAS
/// once revealed (`derive_sas` against this instance's own identity), and
/// commit a peer record on approval (`peer pair approve`), all without any
/// further wire round trip to the requester until the approval callback
/// itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundPairingRequest {
    pub id: String,
    /// The requester's public key, hex, no separator.
    #[serde(rename = "pubkeyHex")]
    pub pubkey_hex: String,
    /// The requester's self-claimed local nickname (`peer pair request
    /// <url> --name <n>`, or that command's own URL-derived default) — used,
    /// self-asserted, as the approver's OWN nickname for this peer too
    /// (`peer pair approve` takes no separate `--name`).
    pub name: String,
    /// The connecting TCP peer's own address, as classified by
    /// [`crate` — server crate's] `PeerOrigin` at park time — display-only
    /// (PAIRING.md: "parks pending (id, ... origin addr)"); never a
    /// security decision in this phase (no pairing exists yet to gate on).
    #[serde(rename = "originAddr")]
    pub origin_addr: String,
    /// The requester's own self-reported A2A door URL — where the reveal
    /// and (eventually) the approval callback are POSTed.
    pub url: String,
    /// `SHA256(pubkeyHex, requesterNonceHex)` (module doc, [`derive_commit`])
    /// — the requester's own nonce is NOT parked until [`reveal_inbound`]
    /// verifies it against this commitment.
    #[serde(rename = "commitHex")]
    pub commit_hex: String,
    /// The requester's own nonce, hex — `None` until [`reveal_inbound`]
    /// verifies it matches [`Self::commit_hex`]; `peer pair pending` shows
    /// no SAS and `peer pair approve` refuses this entry while it stays
    /// `None`.
    #[serde(rename = "requesterNonceHex", default, skip_serializing_if = "Option::is_none")]
    pub requester_nonce_hex: Option<String>,
    /// THIS instance's (the approver's) own nonce, hex — generated fresh at
    /// park time and returned synchronously in the same response, so the
    /// requester can derive its own SAS immediately once it reveals its own
    /// nonce.
    #[serde(rename = "approverNonceHex")]
    pub approver_nonce_hex: String,
    #[serde(rename = "requestedAt")]
    pub requested_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
    /// Design A (poll-based completion, task #119): `true` once this
    /// instance's own operator has run `peer pair approve` on this entry —
    /// set by [`mark_inbound_approved`], never unset. An approved entry
    /// stays PARKED (never taken/removed the way the old callback-delivered
    /// design removed it on success) so the requester's own `aoide/pairPoll`
    /// can find it; it is cleaned up only by the ordinary expiry sweep
    /// ([`sweep`]/[`pairing_timeout_secs`]), same as every other inbound
    /// entry. `#[serde(default)]` so a file predating this field (none in
    /// production yet — this phase is new) loads `false`, the same additive
    /// discipline every other field in this struct already holds.
    #[serde(default)]
    pub approved: bool,
    /// Typed-code approval (task #120 P3): how many WRONG pairing codes have
    /// been entered against this entry so far — interactive prompt
    /// mismatches and scripted `--code` mismatches both count, cumulatively,
    /// persisted here so tries survive across `peer pair approve`
    /// invocations. Bumped by [`record_inbound_code_try`]; the CLI
    /// auto-denies (a clean [`take_inbound`] removal) the moment the count
    /// reaches 3. A crash between the third increment's save and the deny
    /// can persist a value at the limit — the approve path denies such an
    /// entry up front on next sight, so it is never approvable, but a
    /// stored `>= 3` is possible. `#[serde(default)]`
    /// loads `0` on a record predating the field — the same additive
    /// discipline [`Self::approved`] holds.
    #[serde(default)]
    pub tries: u32,
    /// The requester's OPTIONAL self-asserted reach-back hop claim (P-PV1,
    /// task #131) — the wire's `selfVia`, straight off `aoide/pairRequest`'s
    /// params. Loopback-only doors defeat the OLD assumption that the
    /// approver can derive a working `via` from the connection it observes:
    /// a request arriving over the requester's own ssh tunnel is seen from
    /// loopback, not the requester's real address, so nothing about the
    /// connection itself can ever answer "how do I dial this peer back."
    /// `self_via` is the requester's own claim of that hop — same trust
    /// class as [`Self::url`] (self-asserted DATA, a transport marker only;
    /// trust stays in pubkeys + SAS) — carried through so `peer pair
    /// approve`'s own commit ([`crate` client crate's `approve_inbound`])
    /// can record a peer `via` that actually reaches back out.
    /// `#[serde(default, skip_serializing_if = "Option::is_none")]` so a
    /// parked entry predating this field loads `None` and a `None` here
    /// never grows the file — the same additive discipline
    /// [`Self::requester_nonce_hex`] already holds.
    #[serde(rename = "selfVia", default, skip_serializing_if = "Option::is_none")]
    pub self_via: Option<String>,
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
/// pending`'s whole reply (inbound half) — an entry with
/// `requester_nonce_hex: None` has no SAS to show yet (module doc).
pub fn list_inbound(now_epoch: i64) -> Vec<InboundPairingRequest> {
    with_stage_lock(|| {
        let all = load_inbound_raw();
        let (kept, expired) = sweep(all, now_epoch);
        if expired > 0 {
            let _ = save_inbound(&kept);
        }
        kept
    })
}

/// Park a fresh inbound request — the approver's `aoide/pairRequest`
/// handler's whole job. Cap-checked under [`PARK_LOCK`] (module doc,
/// review-bounce Finding 3) with the whole load-modify-write inside
/// [`with_stage_lock`] like every other mutator here (module doc, #119
/// review finding 4): a full queue refuses BEFORE any id is minted
/// or anything is written. Returns the freshly-minted
/// [`InboundPairingRequest`] (including its new `id`,
/// `requester_nonce_hex: None`, and freshly-generated
/// `approver_nonce_hex`) so the caller can build the synchronous wire
/// response from it directly. `self_via` (P-PV1, task #131) is the
/// requester's OPTIONAL self-asserted reach-back hop claim off the wire's
/// `selfVia` — carried straight through onto [`InboundPairingRequest::
/// self_via`] with no validation here (the same "never eagerly parsed,
/// only at dial time" stance every other recorded `via` string already
/// holds); `None` when the wire carried no claim at all.
#[allow(clippy::too_many_arguments)]
pub fn park_inbound(
    pubkey_hex: &str,
    name: &str,
    origin_addr: &str,
    url: &str,
    commit_hex: &str,
    requested_at: &str,
    expires_at: &str,
    self_via: Option<&str>,
) -> Result<InboundPairingRequest, String> {
    let _guard = PARK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    with_stage_lock(|| {
        // `requested_at` is the caller's own "now" (module doc) — reused as the
        // sweep reference so a cap check never counts an already-expired entry
        // against the live queue.
        let now_epoch = crate::time::parse_iso_utc(requested_at).unwrap_or(i64::MAX);
        let (mut requests, _expired) = sweep(load_inbound_raw(), now_epoch);
        let cap = pairing_park_cap();
        if requests.len() >= cap {
            return Err(format!(
                "the pairing park queue is already at its cap of {cap} concurrently parked inbound \
                 requests ({PAIRING_PARK_CAP_ENV} raises it) — approve, reject, or wait for an \
                 existing request to expire before retrying"
            ));
        }
        let id = gen_request_id(&requests.iter().map(|r| r.id.clone()).collect::<Vec<_>>());
        let entry = InboundPairingRequest {
            id,
            pubkey_hex: pubkey_hex.to_string(),
            name: name.to_string(),
            origin_addr: origin_addr.to_string(),
            url: url.to_string(),
            commit_hex: commit_hex.to_string(),
            requester_nonce_hex: None,
            approver_nonce_hex: random_hex(16),
            requested_at: requested_at.to_string(),
            expires_at: expires_at.to_string(),
            approved: false,
            tries: 0,
            self_via: self_via.map(|s| s.to_string()),
        };
        requests.push(entry.clone());
        save_inbound(&requests)?;
        Ok(entry)
    })
}

/// Remove and return one inbound request by id, `None` if it never existed
/// OR has already expired (sweeping happens here too, so an approve/reject
/// against a just-expired id gets the same honest "unknown id" a genuinely
/// unknown one would). `peer pair reject`'s inbound-side lookup, and
/// `peer pair approve`'s final removal once a callback has succeeded.
pub fn take_inbound(id: &str, now_epoch: i64) -> Result<Option<InboundPairingRequest>, String> {
    with_stage_lock(|| {
        let all = load_inbound_raw();
        let (mut kept, _expired) = sweep(all, now_epoch);
        let idx = kept.iter().position(|r| r.id == id);
        let taken = idx.map(|i| kept.remove(i));
        save_inbound(&kept)?;
        Ok(taken)
    })
}

/// Why [`reveal_inbound`] refused — a machine-readable enum, never a string
/// a caller would need to pattern-match (the same "distinct machine flag,
/// not inferred from error text" discipline `aoide-secrets`'s `put`
/// overwrite refusal holds).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevealError {
    /// No parked inbound request has this id (unknown, already resolved,
    /// or expired).
    Unknown,
    /// The revealed nonce does not hash to the entry's stored commitment —
    /// the parked entry is DROPPED as part of this outcome (module doc):
    /// there is nothing left worth keeping parked once the commitment
    /// fails to check out.
    Mismatch,
    /// Reading or writing `state/peer-pairing-inbound.json` itself failed.
    Io(String),
}

/// Complete the commit-then-reveal handshake (module doc, review-bounce
/// Finding 1) for one parked inbound request: verify `nonce_hex` hashes to
/// the entry's stored `commit_hex` (`derive_commit(entry.pubkey_hex,
/// nonce_hex) == entry.commit_hex`) and, on a match, store it as
/// `requester_nonce_hex` so `peer pair pending`/`approve` can finally
/// derive a SAS for this entry. A MISMATCH drops the entry outright rather
/// than leaving it parked — `aoide-server::a2a::pair_reveal` is the wire
/// caller (`aoide/pairReveal`), `peer pair request`'s second POST (client
/// crate) is the one production caller of that method.
pub fn reveal_inbound(id: &str, nonce_hex: &str, now_epoch: i64) -> Result<InboundPairingRequest, RevealError> {
    with_stage_lock(|| {
        let all = load_inbound_raw();
        let (mut kept, _expired) = sweep(all, now_epoch);
        let idx = match kept.iter().position(|r| r.id == id) {
            Some(i) => i,
            None => {
                if let Err(e) = save_inbound(&kept) {
                    return Err(RevealError::Io(e));
                }
                return Err(RevealError::Unknown);
            }
        };
        let expected = derive_commit(&kept[idx].pubkey_hex, nonce_hex);
        if expected != kept[idx].commit_hex {
            kept.remove(idx);
            if let Err(e) = save_inbound(&kept) {
                return Err(RevealError::Io(e));
            }
            return Err(RevealError::Mismatch);
        }
        kept[idx].requester_nonce_hex = Some(nonce_hex.to_string());
        let out = kept[idx].clone();
        if let Err(e) = save_inbound(&kept) {
            return Err(RevealError::Io(e));
        }
        Ok(out)
    })
}

/// Why [`mark_inbound_approved`] refused — same machine-readable shape as
/// [`RevealError`]/[`ConfirmMarkError`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarkApprovedError {
    /// No parked inbound request has this id (unknown, already resolved, or
    /// expired).
    Unknown,
    /// Reading or writing `state/peer-pairing-inbound.json` itself failed.
    Io(String),
}

/// Design A (poll-based completion, task #119): the APPROVER's own `peer
/// pair approve <id>` calls this in place of the old callback delivery,
/// AFTER it has already confirmed the SAS and committed its own peer
/// record — the entry stays PARKED (never taken) with [`InboundPairingRequest::approved`]
/// flipped `true`, so the requester's own `aoide/pairPoll` can find and
/// release it later, however long after this CLI process exits. Idempotent:
/// re-marking an already-approved entry is a no-op success, never an error —
/// `approve_inbound`'s own idempotent-reapprove guard checks `approved`
/// itself before ever calling this, but this function stays safe to call
/// twice on its own merits too, the same tolerant-of-repetition posture
/// [`park_outbound`]'s replace-by-id already holds.
pub fn mark_inbound_approved(id: &str, now_epoch: i64) -> Result<InboundPairingRequest, MarkApprovedError> {
    with_stage_lock(|| {
        let all = load_inbound_raw();
        let (mut kept, _expired) = sweep(all, now_epoch);
        let idx = match kept.iter().position(|r| r.id == id) {
            Some(i) => i,
            None => {
                if let Err(e) = save_inbound(&kept) {
                    return Err(MarkApprovedError::Io(e));
                }
                return Err(MarkApprovedError::Unknown);
            }
        };
        kept[idx].approved = true;
        let out = kept[idx].clone();
        if let Err(e) = save_inbound(&kept) {
            return Err(MarkApprovedError::Io(e));
        }
        Ok(out)
    })
}

/// Typed-code approval (task #120 P3): record ONE wrong pairing code
/// entered against a parked inbound entry — increments
/// [`InboundPairingRequest::tries`], persists it, and returns the new
/// cumulative count so the caller (`aoide-client::commands::approve_inbound`,
/// the only production caller) can auto-deny at 3 without a second read.
/// Interactive prompt mismatches and scripted `--code` mismatches both land
/// here; the auto-deny itself is the caller's [`take_inbound`] removal,
/// never a state this function writes. Shares [`MarkApprovedError`]'s
/// refusal shape — the failure modes (unknown/expired id, file I/O) are
/// identical to [`mark_inbound_approved`]'s.
pub fn record_inbound_code_try(id: &str, now_epoch: i64) -> Result<u32, MarkApprovedError> {
    with_stage_lock(|| {
        let all = load_inbound_raw();
        let (mut kept, _expired) = sweep(all, now_epoch);
        let idx = match kept.iter().position(|r| r.id == id) {
            Some(i) => i,
            None => {
                if let Err(e) = save_inbound(&kept) {
                    return Err(MarkApprovedError::Io(e));
                }
                return Err(MarkApprovedError::Unknown);
            }
        };
        kept[idx].tries = kept[idx].tries.saturating_add(1);
        let out = kept[idx].tries;
        if let Err(e) = save_inbound(&kept) {
            return Err(MarkApprovedError::Io(e));
        }
        Ok(out)
    })
}

// ── Outbound (requester-side): a request THIS instance is awaiting on ──────

/// An outbound pairing request's own place in the ceremony (module doc,
/// review-bounce Finding 2) — never conflated with [`InboundPairingRequest`]
/// simply lacking a revealed nonce; an outbound entry only ever exists
/// AFTER its own reveal already succeeded (`park_outbound`'s one caller,
/// `peer pair request`, parks only on a successful reveal).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutboundState {
    /// Waiting on the approver's own human to confirm the SAS and approve
    /// locally — the state every outbound entry starts in. This instance
    /// learns of the approval only by polling `aoide/pairPoll` (task #119:
    /// there is no approver→requester callback).
    #[serde(rename = "awaiting-approval")]
    AwaitingApproval,
    /// A poll answered `approved` with a matching pubkey
    /// ([`mark_outbound_awaiting_confirm`]) — THIS instance's own operator
    /// still has to confirm the SAS before anything commits (`peer pair
    /// approve <id>` on this entry, the requester-side confirm path).
    #[serde(rename = "awaiting-confirm")]
    AwaitingConfirm,
}

impl Default for OutboundState {
    fn default() -> Self {
        Self::AwaitingApproval
    }
}

impl OutboundState {
    /// The wire/CLI-display string for this state — matches this type's
    /// own serde `rename`s exactly, exposed as a method so a caller
    /// building a `serde_json::json!` row doesn't need to round-trip
    /// through `serde_json::to_value` for one field.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AwaitingApproval => "awaiting-approval",
            Self::AwaitingConfirm => "awaiting-confirm",
        }
    }
}

/// One pairing request THIS instance (the requester) sent out and is
/// waiting on — either the approver's local approval, learned by polling
/// `aoide/pairPoll` ([`OutboundState::AwaitingApproval`]), or this
/// instance's OWN operator's confirm-then-commit
/// ([`OutboundState::AwaitingConfirm`], module doc).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundPairingRequest {
    /// Same id the approver parked it under (module doc — one shared id,
    /// no separate counters to reconcile).
    pub id: String,
    /// The approver's own A2A door URL — this becomes the peer record's
    /// `url` on commit.
    pub url: String,
    /// THIS instance's own local nickname for the approver
    /// (`peer pair request <url> --name <n>`, or its URL-derived default).
    pub name: String,
    /// The approver's public key, hex — learned from the synchronous
    /// `aoide/pairRequest` response.
    #[serde(rename = "pubkeyHex")]
    pub pubkey_hex: String,
    /// THIS instance's own nonce, hex — chosen locally before the
    /// commitment was ever sent, never transmitted until the reveal.
    #[serde(rename = "requesterNonceHex")]
    pub requester_nonce_hex: String,
    /// The approver's own nonce, hex — learned from the synchronous
    /// `aoide/pairRequest` response, stored here so this entry can
    /// re-derive its SAS at confirm time with no further wire call.
    #[serde(rename = "approverNonceHex")]
    pub approver_nonce_hex: String,
    #[serde(rename = "requestedAt")]
    pub requested_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
    /// This entry's own place in the ceremony (module doc) — `#[serde(default)]`
    /// so a file predating this field (there is none in production yet,
    /// this phase is new; kept for the same additive discipline every
    /// other wire-shape change in this crate holds) loads as
    /// [`OutboundState::AwaitingApproval`].
    #[serde(default)]
    pub state: OutboundState,
    /// The ssh-transport marker (P-S4, K1) this ceremony resolved for the
    /// approver at REQUEST time — a `--via` flag, or (`peer invite`) the
    /// discovery advertisement's observed source address — carried here because
    /// the actual peer-record commit happens LATER, in a SEPARATE `peer
    /// pair approve <id>` invocation (`approve_outbound`), which has no
    /// other way to recover what this instance resolved when the request
    /// was first sent. `#[serde(default)]` so a file predating this field
    /// (none in production yet — this phase is new, kept for the same
    /// additive discipline `state` above already holds) loads `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
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

/// Remember that THIS instance sent a request out and its own reveal
/// already succeeded — `peer pair request`'s own write
/// ([`OutboundState::AwaitingApproval`] by default). Replaces by id rather
/// than duplicating (operator-created, no cap needed — module doc).
pub fn park_outbound(entry: OutboundPairingRequest) -> Result<(), String> {
    with_stage_lock(move || {
        let mut requests = load_outbound_raw();
        requests.retain(|r| r.id != entry.id);
        requests.push(entry);
        save_outbound(&requests)
    })
}

/// Remove and return one outbound request by id — `peer pair reject`'s
/// outbound-side lookup (any state), and the requester-side confirm's
/// final removal once its own operator has committed.
pub fn take_outbound(id: &str, now_epoch: i64) -> Result<Option<OutboundPairingRequest>, String> {
    with_stage_lock(|| {
        let all = load_outbound_raw();
        let (mut kept, _expired) = sweep_outbound(all, now_epoch);
        let idx = kept.iter().position(|r| r.id == id);
        let taken = idx.map(|i| kept.remove(i));
        save_outbound(&kept)?;
        Ok(taken)
    })
}

/// List every currently-unexpired outbound request, sweeping expired ones
/// the same way [`list_inbound`] does. `peer pair pending`'s outbound half
/// (review-bounce Finding 2 — this used to be a diagnostic-only seam with
/// no CLI reader; it is now load-bearing).
pub fn list_outbound(now_epoch: i64) -> Vec<OutboundPairingRequest> {
    with_stage_lock(|| {
        let all = load_outbound_raw();
        let (kept, expired) = sweep_outbound(all, now_epoch);
        if expired > 0 {
            let _ = save_outbound(&kept);
        }
        kept
    })
}

/// Why [`mark_outbound_awaiting_confirm`] refused — same machine-readable
/// shape as [`RevealError`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmMarkError {
    /// No parked outbound request has this id (unknown, already completed,
    /// or expired).
    Unknown,
    /// The poll release's `pubkeyHex` does not match what this instance
    /// learned at request time — the entry is left EXACTLY as it was
    /// (never removed, never re-parked with different data — there was
    /// nothing to restore since nothing was ever taken off the queue for
    /// this check).
    Mismatch,
    /// Reading or writing `state/peer-pairing-outbound.json` itself failed.
    Io(String),
}

/// The requester-side effect of a successful `aoide/pairPoll` release
/// (task #119; formerly the `aoide/pairApprove` callback's handler-side
/// effect): on a pubkey match, transition the outbound entry to
/// [`OutboundState::AwaitingConfirm`] — deliberately NOT a commit. This
/// instance's OWN operator still has to run `peer pair approve <id>` and
/// confirm the SAS before `upsert_paired_peer` ever runs on this side
/// (module doc: mutual confirmation, for real).
pub fn mark_outbound_awaiting_confirm(id: &str, pubkey_hex: &str, now_epoch: i64) -> Result<OutboundPairingRequest, ConfirmMarkError> {
    with_stage_lock(|| {
        let all = load_outbound_raw();
        let (mut kept, _expired) = sweep_outbound(all, now_epoch);
        let idx = match kept.iter().position(|r| r.id == id) {
            Some(i) => i,
            None => {
                if let Err(e) = save_outbound(&kept) {
                    return Err(ConfirmMarkError::Io(e));
                }
                return Err(ConfirmMarkError::Unknown);
            }
        };
        if kept[idx].pubkey_hex != pubkey_hex {
            if let Err(e) = save_outbound(&kept) {
                return Err(ConfirmMarkError::Io(e));
            }
            return Err(ConfirmMarkError::Mismatch);
        }
        kept[idx].state = OutboundState::AwaitingConfirm;
        let out = kept[idx].clone();
        if let Err(e) = save_outbound(&kept) {
            return Err(ConfirmMarkError::Io(e));
        }
        Ok(out)
    })
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
    /// asserting it agrees with itself. UNCHANGED by the commit-then-reveal
    /// fix (module doc) — `derive_sas`'s own math never moved, only
    /// `park_inbound`'s callers stopped handing it a same-round-trip nonce.
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

    // ── derive_commit ────────────────────────────────────────────────────

    #[test]
    fn derive_commit_is_a_64_char_hex_digest_and_content_sensitive() {
        let c1 = derive_commit(&"a".repeat(64), &"c".repeat(16));
        assert_eq!(c1.len(), 64, "full SHA-256 digest, hex-encoded — never truncated like the SAS");
        assert!(c1.chars().all(|c| c.is_ascii_hexdigit()));

        let c2 = derive_commit(&"a".repeat(64), &"d".repeat(16));
        assert_ne!(c1, c2, "a different nonce must change the commitment");

        let c3 = derive_commit(&"b".repeat(64), &"c".repeat(16));
        assert_ne!(c1, c3, "a different pubkey must change the commitment");
    }

    #[test]
    fn derive_commit_is_case_and_whitespace_insensitive_like_derive_sas() {
        let lower = derive_commit("aabbcc", "1122");
        let upper = derive_commit("AABBCC", "1122");
        let padded = derive_commit("  aabbcc  ", "1122");
        assert_eq!(lower, upper);
        assert_eq!(lower, padded);
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

    // ── pairing_park_cap ─────────────────────────────────────────────────

    #[test]
    fn pairing_park_cap_defaults_to_32_and_honors_a_valid_override() {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var(PAIRING_PARK_CAP_ENV).ok();
        std::env::remove_var(PAIRING_PARK_CAP_ENV);
        assert_eq!(pairing_park_cap(), 32);

        std::env::set_var(PAIRING_PARK_CAP_ENV, "5");
        assert_eq!(pairing_park_cap(), 5);

        std::env::set_var(PAIRING_PARK_CAP_ENV, "0");
        assert_eq!(pairing_park_cap(), 32, "zero falls back to the default, never an always-refusing cap");

        std::env::set_var(PAIRING_PARK_CAP_ENV, "nope");
        assert_eq!(pairing_park_cap(), 32, "unparsable falls back to the default");

        match saved {
            Some(v) => std::env::set_var(PAIRING_PARK_CAP_ENV, v),
            None => std::env::remove_var(PAIRING_PARK_CAP_ENV),
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
        let commit = derive_commit("requesterpubkeyhex", "requesternoncehex");
        let entry = park_inbound(
            "requesterpubkeyhex",
            "box-a",
            "10.0.0.5",
            "http://box-a:8710/",
            &commit,
            &crate::time::iso_utc_from_epoch(now),
            &expires_at_from(now),
            None,
        )
        .unwrap();
        assert_eq!(entry.id.len(), 8);
        assert!(!entry.approver_nonce_hex.is_empty());
        assert!(entry.requester_nonce_hex.is_none(), "unrevealed at park time");

        let listed = list_inbound(now);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, entry.id);
        assert_eq!(listed[0].pubkey_hex, "requesterpubkeyhex");
        assert_eq!(listed[0].commit_hex, commit);

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
        let commit = derive_commit("pk", "nonce");
        let entry = park_inbound(
            "pk", "name", "addr", "url", &commit,
            &crate::time::iso_utc_from_epoch(requested_at),
            &crate::time::iso_utc_from_epoch(requested_at + 10), // expires in 10s
            None,
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

    #[test]
    fn park_inbound_refuses_beyond_the_cap_and_admits_again_after_a_take() {
        let _g = crate::env_lock().lock().unwrap();
        let saved_dir = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_cap = std::env::var(PAIRING_PARK_CAP_ENV).ok();
        let dir = std::env::temp_dir().join(format!("aoide-pairing-cap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        env(&dir);
        std::env::set_var(PAIRING_PARK_CAP_ENV, "2");

        let now = 1_700_000_000_i64;
        let requested_at = crate::time::iso_utc_from_epoch(now);
        let expires_at = expires_at_from(now);
        let park = |pk: &str| park_inbound(pk, "name", "addr", "url", &derive_commit(pk, "n"), &requested_at, &expires_at, None);

        let first = park("pk1").expect("first park is under the cap");
        park("pk2").expect("second park is exactly at the cap");
        let refused = park("pk3");
        assert!(refused.is_err(), "a third park must refuse at cap 2");
        assert_eq!(list_inbound(now).len(), 2, "the refused park wrote nothing");

        // Freeing a slot admits the next one again.
        take_inbound(&first.id, now).unwrap();
        park("pk4").expect("a freed slot admits a new park");
        assert_eq!(list_inbound(now).len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
        match saved_dir {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        match saved_cap {
            Some(v) => std::env::set_var(PAIRING_PARK_CAP_ENV, v),
            None => std::env::remove_var(PAIRING_PARK_CAP_ENV),
        }
    }

    // ── reveal_inbound ───────────────────────────────────────────────────

    #[test]
    fn reveal_inbound_on_a_matching_nonce_stores_it_and_round_trips() {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-pairing-reveal-ok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        env(&dir);

        let now = 1_700_000_000_i64;
        let requested_at = crate::time::iso_utc_from_epoch(now);
        let expires_at = expires_at_from(now);
        let commit = derive_commit("pk", "the-real-nonce");
        let entry = park_inbound("pk", "name", "addr", "url", &commit, &requested_at, &expires_at, None).unwrap();
        assert!(entry.requester_nonce_hex.is_none());

        let revealed = reveal_inbound(&entry.id, "the-real-nonce", now).unwrap();
        assert_eq!(revealed.requester_nonce_hex.as_deref(), Some("the-real-nonce"));

        let listed = list_inbound(now);
        assert_eq!(listed.len(), 1, "revealing never removes the entry");
        assert_eq!(listed[0].requester_nonce_hex.as_deref(), Some("the-real-nonce"));

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    #[test]
    fn reveal_inbound_on_a_wrong_nonce_is_refused_and_drops_the_entry() {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-pairing-reveal-mismatch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        env(&dir);

        let now = 1_700_000_000_i64;
        let requested_at = crate::time::iso_utc_from_epoch(now);
        let expires_at = expires_at_from(now);
        let commit = derive_commit("pk", "the-real-nonce");
        let entry = park_inbound("pk", "name", "addr", "url", &commit, &requested_at, &expires_at, None).unwrap();

        let err = reveal_inbound(&entry.id, "a-different-nonce", now).unwrap_err();
        assert_eq!(err, RevealError::Mismatch);

        assert!(list_inbound(now).is_empty(), "a mismatched reveal drops the parked entry outright");
        assert_eq!(reveal_inbound(&entry.id, "the-real-nonce", now).unwrap_err(), RevealError::Unknown, "gone — even the correct nonce now finds nothing");

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    #[test]
    fn reveal_inbound_on_an_unknown_id_is_refused() {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-pairing-reveal-unknown-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        env(&dir);

        assert_eq!(reveal_inbound("nosuchid", "n", 0).unwrap_err(), RevealError::Unknown);

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    // ── mark_inbound_approved (Design A, task #119) ──────────────────────

    #[test]
    fn mark_inbound_approved_sets_the_flag_and_leaves_the_entry_parked() {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-pairing-mark-approved-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        env(&dir);

        let now = 1_700_000_000_i64;
        let requested_at = crate::time::iso_utc_from_epoch(now);
        let expires_at = expires_at_from(now);
        let commit = derive_commit("pk", "nonce");
        let entry = park_inbound("pk", "name", "addr", "url", &commit, &requested_at, &expires_at, None).unwrap();
        reveal_inbound(&entry.id, "nonce", now).unwrap();
        assert!(!entry.approved, "unapproved at park time");

        let marked = mark_inbound_approved(&entry.id, now).unwrap();
        assert!(marked.approved);

        // Approving never removes the entry — the poll still needs to find
        // it (module doc: "the entry stays PARKED, never taken").
        let listed = list_inbound(now);
        assert_eq!(listed.len(), 1, "an approved entry stays parked for the poll to find");
        assert!(listed[0].approved);

        // Re-marking an already-approved entry is a no-op success, not an
        // error (module doc's own idempotence note).
        let remarked = mark_inbound_approved(&entry.id, now).unwrap();
        assert!(remarked.approved);

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    #[test]
    fn mark_inbound_approved_on_an_unknown_id_is_refused() {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-pairing-mark-approved-unknown-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        env(&dir);

        assert_eq!(mark_inbound_approved("nosuchid", 0).unwrap_err(), MarkApprovedError::Unknown);

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    #[test]
    fn mark_inbound_approved_on_an_expired_entry_is_refused_the_same_as_unknown() {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-pairing-mark-approved-expired-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        env(&dir);

        let requested_at = 1_700_000_000_i64;
        let commit = derive_commit("pk", "nonce");
        let entry = park_inbound(
            "pk", "name", "addr", "url", &commit,
            &crate::time::iso_utc_from_epoch(requested_at),
            &crate::time::iso_utc_from_epoch(requested_at + 10),
            None,
        )
        .unwrap();

        let later = requested_at + 3600;
        assert_eq!(mark_inbound_approved(&entry.id, later).unwrap_err(), MarkApprovedError::Unknown, "an expired entry is gone, same as never existed — the poll's own timeout expiry");

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    // ── record_inbound_code_try (typed-code approval, task #120 P3) ──────

    #[test]
    fn record_inbound_code_try_increments_cumulatively_and_persists() {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-pairing-code-try-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        env(&dir);

        let now = 1_700_000_000_i64;
        let commit = derive_commit("pk", "nonce");
        let entry = park_inbound(
            "pk", "name", "addr", "url", &commit,
            &crate::time::iso_utc_from_epoch(now),
            &expires_at_from(now),
            None,
        )
        .unwrap();
        assert_eq!(entry.tries, 0, "a fresh park starts at zero tries");

        assert_eq!(record_inbound_code_try(&entry.id, now).unwrap(), 1);
        assert_eq!(record_inbound_code_try(&entry.id, now).unwrap(), 2);
        // The count is READ back from disk, not carried in memory — a later
        // invocation (the whole reason it persists) sees the same total.
        assert_eq!(list_inbound(now)[0].tries, 2, "tries survive across loads");
        assert_eq!(record_inbound_code_try(&entry.id, now).unwrap(), 3);

        assert_eq!(record_inbound_code_try("nosuchid", now).unwrap_err(), MarkApprovedError::Unknown);

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    /// `tries` is additive (`#[serde(default)]`): a parked record predating
    /// the field loads `0`, never a deserialize failure — the same
    /// discipline `approved`'s own back-compat test below the outbound
    /// section pins for `via`.
    #[test]
    fn inbound_tries_is_additive_and_defaults_to_zero_on_a_legacy_record() {
        let now = 1_700_000_000_i64;
        let raw_old = serde_json::json!({
            "id": "legacy01", "pubkeyHex": "k", "name": "box-a",
            "originAddr": "10.0.0.5", "url": "http://box-a:8710/",
            "commitHex": "c", "approverNonceHex": "a",
            "requestedAt": crate::time::iso_utc_from_epoch(now), "expiresAt": expires_at_from(now),
        });
        let back: InboundPairingRequest = serde_json::from_value(raw_old).unwrap();
        assert_eq!(back.tries, 0);
        assert!(!back.approved);
    }

    // ── outbound park/take round trip ────────────────────────────────────

    fn sample_outbound(id: &str, state: OutboundState) -> OutboundPairingRequest {
        let now = 1_700_000_000_i64;
        OutboundPairingRequest {
            id: id.to_string(),
            url: "http://box-b/".to_string(),
            name: "box-b".to_string(),
            pubkey_hex: "approverpubkeyhex".to_string(),
            requester_nonce_hex: "reqnonce".to_string(),
            approver_nonce_hex: "apprnonce".to_string(),
            requested_at: crate::time::iso_utc_from_epoch(now),
            expires_at: expires_at_from(now),
            state,
            via: None,
        }
    }

    #[test]
    fn park_outbound_then_take_round_trips_and_is_removed_after_taking() {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-pairing-outbound-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        env(&dir);

        let now = 1_700_000_000_i64;
        let entry = sample_outbound("deadbeef", OutboundState::AwaitingApproval);
        park_outbound(entry.clone()).unwrap();

        let listed = list_outbound(now);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, "deadbeef");
        assert_eq!(listed[0].state, OutboundState::AwaitingApproval);

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

    /// The ssh-transport lane's `via` field (P-S4): additive, absent by
    /// default, round-trips when present — the same back-compat discipline
    /// `state`'s own `#[serde(default)]` already holds one field over.
    #[test]
    fn outbound_via_is_additive_absent_by_default_and_round_trips_when_present() {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-pairing-outbound-via-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        env(&dir);

        let now = 1_700_000_000_i64;
        let mut entry = sample_outbound("with-via", OutboundState::AwaitingApproval);
        entry.via = Some("ssh://khoa@192.168.1.202".to_string());
        park_outbound(entry).unwrap();

        let listed = list_outbound(now);
        assert_eq!(listed[0].via.as_deref(), Some("ssh://khoa@192.168.1.202"));

        // A raw record predating this field (no `via` key at all) loads as
        // `None`, never a deserialize failure.
        let raw_old = serde_json::json!({
            "id": "no-via", "url": "http://box-c/", "name": "box-c",
            "pubkeyHex": "k", "requesterNonceHex": "r", "approverNonceHex": "a",
            "requestedAt": crate::time::iso_utc_from_epoch(now), "expiresAt": expires_at_from(now),
        });
        let back: OutboundPairingRequest = serde_json::from_value(raw_old).unwrap();
        assert_eq!(back.via, None);

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    /// P-PV1 (task #131): the wire's OPTIONAL `selfVia` claim, threaded
    /// through `park_inbound` onto [`InboundPairingRequest::self_via`],
    /// round-trips through a real park/list exactly like
    /// [`outbound_via_is_additive_absent_by_default_and_round_trips_when_present`]'s
    /// outbound sibling — and a raw record predating this field (no
    /// `selfVia` key at all, the shape every parked entry had before this
    /// phase) loads `None`, never a deserialize failure.
    #[test]
    fn inbound_self_via_is_additive_absent_by_default_and_round_trips_when_present() {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-pairing-inbound-self-via-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        env(&dir);

        let now = 1_700_000_000_i64;
        let commit = derive_commit("pk", "n");
        let with_claim = park_inbound(
            "pk", "with-claim", "10.0.0.5", "http://with-claim/", &commit,
            &crate::time::iso_utc_from_epoch(now), &expires_at_from(now),
            Some("ssh://khoa@with-claim"),
        )
        .unwrap();
        assert_eq!(with_claim.self_via.as_deref(), Some("ssh://khoa@with-claim"));

        let no_claim = park_inbound(
            "pk2", "no-claim", "10.0.0.6", "http://no-claim/", &derive_commit("pk2", "n2"),
            &crate::time::iso_utc_from_epoch(now), &expires_at_from(now),
            None,
        )
        .unwrap();
        assert!(no_claim.self_via.is_none());

        let listed = list_inbound(now);
        let listed_with_claim = listed.iter().find(|r| r.id == with_claim.id).unwrap();
        assert_eq!(listed_with_claim.self_via.as_deref(), Some("ssh://khoa@with-claim"), "the claim survives a park-then-list round trip");
        let listed_no_claim = listed.iter().find(|r| r.id == no_claim.id).unwrap();
        assert!(listed_no_claim.self_via.is_none());

        // A raw record predating this field (no `selfVia` key at all) loads
        // as `None`, never a deserialize failure — the same additive
        // discipline every other optional field on this struct holds.
        let raw_old = serde_json::json!({
            "id": "predates-self-via", "url": "http://box-c/", "name": "box-c",
            "pubkeyHex": "k", "originAddr": "10.0.0.7", "commitHex": commit,
            "approverNonceHex": "a",
            "requestedAt": crate::time::iso_utc_from_epoch(now), "expiresAt": expires_at_from(now),
        });
        let back: InboundPairingRequest = serde_json::from_value(raw_old).unwrap();
        assert_eq!(back.self_via, None);

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
        let mut entry = sample_outbound("sameid00", OutboundState::AwaitingApproval);
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

    // ── mark_outbound_awaiting_confirm ───────────────────────────────────

    #[test]
    fn mark_outbound_awaiting_confirm_on_a_matching_pubkey_transitions_the_state() {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-pairing-confirm-ok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        env(&dir);

        let now = 1_700_000_000_i64;
        park_outbound(sample_outbound("id1", OutboundState::AwaitingApproval)).unwrap();

        let marked = mark_outbound_awaiting_confirm("id1", "approverpubkeyhex", now).unwrap();
        assert_eq!(marked.state, OutboundState::AwaitingConfirm);

        let listed = list_outbound(now);
        assert_eq!(listed.len(), 1, "marking never removes the entry — the requester still has to confirm");
        assert_eq!(listed[0].state, OutboundState::AwaitingConfirm);

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    #[test]
    fn mark_outbound_awaiting_confirm_on_a_pubkey_mismatch_leaves_the_entry_untouched() {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-pairing-confirm-mismatch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        env(&dir);

        let now = 1_700_000_000_i64;
        park_outbound(sample_outbound("id1", OutboundState::AwaitingApproval)).unwrap();

        let err = mark_outbound_awaiting_confirm("id1", "wrong-pubkey", now).unwrap_err();
        assert_eq!(err, ConfirmMarkError::Mismatch);

        let listed = list_outbound(now);
        assert_eq!(listed.len(), 1, "a mismatch never removes the entry — a legitimate retry can still resolve it");
        assert_eq!(listed[0].state, OutboundState::AwaitingApproval, "state stays exactly where it was");

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    #[test]
    fn mark_outbound_awaiting_confirm_on_an_unknown_id_is_refused() {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-pairing-confirm-unknown-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        env(&dir);

        assert_eq!(mark_outbound_awaiting_confirm("nosuchid", "pk", 0).unwrap_err(), ConfirmMarkError::Unknown);

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    // ── cross-process lock (with_stage_lock) on both park files ──────────

    /// A held `.stage.lock` flock BLOCKS a park-file mutator until released —
    /// the lock-is-taken assertion for the cross-process discipline (#119
    /// review finding 4). Two real OS processes are impractical in this test
    /// rig, but `flock(2)` locks are per-open-file-description, so a second
    /// fd in the SAME process contends exactly like a second process would —
    /// this is the closest in-process stand-in for the real `a2a serve` vs
    /// CLI race the lock exists to serialize.
    #[test]
    fn a_held_stage_flock_blocks_an_inbound_mutation_until_released() {
        let _g = crate::env_lock().lock().unwrap();
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-pairing-flock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        env(&dir);
        std::env::set_var("AOIDE_STAGE_DIR", dir.join("stage"));

        let now = 1_700_000_000_i64;
        let entry = park_inbound(
            "pk", "name", "addr", "url", &derive_commit("pk", "n"),
            &crate::time::iso_utc_from_epoch(now),
            &expires_at_from(now),
            None,
        )
        .unwrap();

        // Hold the SAME lock file with_stage_lock flocks, on our own fd.
        use std::os::unix::io::AsRawFd;
        std::fs::create_dir_all(dir.join("stage")).unwrap();
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(dir.join("stage/.stage.lock"))
            .unwrap();
        assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);

        let (tx, rx) = std::sync::mpsc::channel();
        let id = entry.id.clone();
        let t = std::thread::spawn(move || {
            let out = mark_inbound_approved(&id, now);
            tx.send(()).unwrap();
            out
        });

        // While the flock is held the mutator must not complete. (A slow
        // thread start can only make this assertion vacuously true, never
        // flaky-fail — the mutator physically cannot pass the flock.)
        std::thread::sleep(std::time::Duration::from_millis(150));
        assert!(
            rx.try_recv().is_err(),
            "mark_inbound_approved completed while the stage flock was held — the mutator is not taking the cross-process lock"
        );

        assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) }, 0);
        let marked = t.join().unwrap().unwrap();
        assert!(marked.approved);
        assert!(list_inbound(now)[0].approved, "the release let the write land");

        let _ = std::fs::remove_dir_all(&dir);
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    /// Concurrent-ish coverage over both files: racing read-modify-writes
    /// from separate threads (each `with_stage_lock` call opens its own fd,
    /// so they contend like separate processes) lose no update — every
    /// `tries` increment lands on the inbound file, every parked entry lands
    /// on the outbound file. Unserialized, either loss was the exact #119
    /// finding-4 symptom.
    #[test]
    fn racing_mutators_lose_no_increment_and_no_parked_entry() {
        let _g = crate::env_lock().lock().unwrap();
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-pairing-race-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        env(&dir);
        std::env::set_var("AOIDE_STAGE_DIR", dir.join("stage"));

        let now = 1_700_000_000_i64;
        let entry = park_inbound(
            "pk", "name", "addr", "url", &derive_commit("pk", "n"),
            &crate::time::iso_utc_from_epoch(now),
            &expires_at_from(now),
            None,
        )
        .unwrap();

        let tries_threads: Vec<_> = (0..8)
            .map(|_| {
                let id = entry.id.clone();
                std::thread::spawn(move || record_inbound_code_try(&id, now).unwrap())
            })
            .collect();
        let park_threads: Vec<_> = (0..6)
            .map(|i| {
                std::thread::spawn(move || {
                    park_outbound(sample_outbound(&format!("id{i:05x}"), OutboundState::AwaitingApproval)).unwrap()
                })
            })
            .collect();
        for t in tries_threads {
            t.join().unwrap();
        }
        for t in park_threads {
            t.join().unwrap();
        }

        assert_eq!(list_inbound(now)[0].tries, 8, "every increment landed — none lost to a racing read-modify-write");
        assert_eq!(list_outbound(now).len(), 6, "every parked outbound entry landed");

        let _ = std::fs::remove_dir_all(&dir);
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
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
