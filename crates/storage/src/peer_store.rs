//! The peer registry: `state/peers.json` (v0) — the set of OTHER aoide
//! instances this one has registered by URL (`aoide peer add`), and
//! `state/peer-cache/<name>.json` (v0) — the last-pulled `aoide/graphSummary`
//! response per peer (CONTRACTS.md §7).
//!
//! Lives under `state/` (tolerate-missing reads, atomic writes) rather than
//! the literal `song/stage/` location the originating plan sketched — a peer
//! roster is account/global external-registry state, not song-scoped
//! rehearsal state; see CONTRACTS.md §7's note on this judgment call.
//!
//! `aoide-server`'s A2A door (inbound, the non-loopback pending-gate fix)
//! and `aoide-client`'s `peer` commands (outbound, the pull/fold side) both
//! depend on this crate — neither may depend on the other (`server` must
//! never depend on `client`) — so the shared `Peer`/registry/cache shapes and
//! the autogate-address match live here, the one crate both already sit atop.

use crate::fs::{atomic_write, state_dir};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::IpAddr;

/// `state/peers.json` schema version (CONTRACTS.md §7, v0).
pub const PEERS_VERSION: &str = "0";

/// How long a pulled peer cache stays `fresh` before `build_graph`'s fold
/// (`aoide-conduct`) treats it as stale, in seconds. A single named constant
/// (CONTRACTS.md §7) rather than a magic number scattered across the fold +
/// `peer status`.
pub const PEER_CACHE_TTL_SECS: u64 = 5 * 60;

/// One registered peer aoide instance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Peer {
    pub name: String,
    pub url: String,
    /// The cross-device analogue of `graph send`'s "sender is the target's
    /// own parent" autogate rule (`conduct/graph/send.rs`): a peer marked
    /// `true` here skips the non-loopback pending queue on INBOUND
    /// `message/send` (CONTRACTS.md §6 amendment). Defaults false — an
    /// unmarked/unknown sender is never autogated.
    #[serde(default)]
    pub autogate: bool,
    /// Path to a file (on THIS instance) holding the shared secret this peer
    /// presents as `Authorization: Bearer <token>` on an inbound
    /// `message/send` — how the door tells WHICH registered peer is calling
    /// once IP alone can't (CONTRACTS.md §6 amendment, 2026-08-18: behind any
    /// reverse proxy/tunnel every caller is `127.0.0.1`, so the
    /// [`is_autogated_peer_addr`] IP match is permanently dead there). Absent
    /// by default — an unmarked peer authenticates by address only, exactly
    /// as before this field existed.
    #[serde(rename = "tokenFile", default, skip_serializing_if = "Option::is_none")]
    pub token_file: Option<String>,
    /// The name of a secret, resolved through the LOCAL secrets broker at
    /// OUTBOUND request time (task #84), that THIS instance presents as
    /// `Authorization: Bearer <value>` when it calls this peer's own A2A
    /// door — the opposite direction from [`Self::token_file`] above (what
    /// the PEER presents to us). Set via `peer add --bearer-secret <name>`.
    /// Absent by default; an unmarked peer's outbound requests carry no
    /// bearer at all, exactly as before this field existed. Resolved fresh
    /// on every request (`aoide-client`'s `commands::resolve_peer_bearer`)
    /// — never cached here or anywhere else, so revoking the underlying
    /// secret takes effect on the very next call.
    #[serde(rename = "bearerSecret", default, skip_serializing_if = "Option::is_none")]
    pub bearer_secret: Option<String>,
    /// At most one registered peer is marked `hub` — the always-on host
    /// (e.g. sakaki) this mesh's address resolution prefers as a
    /// last-resort remote target when a query matches nothing else (P-D5,
    /// `docs/architecture/AOIDED.md`'s "The hub option"). `#[serde(default)]`
    /// + `skip_serializing_if` on `false` is the SAME additive/v0-safe
    /// discipline `SessionRecord.headless` set the precedent for
    /// (`records.rs`): an old `peers.json` predating this field
    /// deserializes every peer's `hub` as `false`, and a peer that has
    /// never held the hub omits the key entirely rather than writing an
    /// explicit `"hub":false` into every entry. Set/moved/cleared only via
    /// [`set_hub`]/[`clear_hub`] below, which hold the "at most one" and
    /// idempotence invariants — nothing else in this tree writes the field
    /// directly.
    #[serde(default, skip_serializing_if = "is_false")]
    pub hub: bool,
    /// This peer's ed25519 public key, hex, no separator — set ONLY by the
    /// pairing ceremony (P-P2, `docs/architecture/PAIRING.md`), never by
    /// `peer add`. Absent for an unpaired peer (today's every registered
    /// peer, and every peer registered before this field existed); a
    /// `peers.json` predating P-P2 loads every entry's `pubkey` as `None`,
    /// the same additive/`skip_serializing_if` discipline `hub`/
    /// `bearerSecret` already hold.
    #[serde(rename = "pubkey", default, skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<String>,
    /// Whether the pairing ceremony has confirmed this peer's [`Self::pubkey`]
    /// against a human-compared SAS (P-P2). `false` for every peer registered
    /// through the legacy `peer add` path (unpaired) and for every peer that
    /// predates this field — same `#[serde(default)]`+`skip_serializing_if`
    /// shape `hub` set the precedent for: an old `peers.json` deserializes
    /// `verified: false` on every entry, and an unverified entry omits the
    /// key entirely rather than writing `"verified":false` everywhere.
    /// `verified` alone grants nothing; combined with a `"spawn"`-carrying
    /// `allows` (below) AND a TOKEN-rung resolution ([`resolve_peer`]'s
    /// stronger rung, never the address one), it is what the A2A door's
    /// spawn arm requires (P-P3, decision 6, `a2a.rs::spawn_admitted`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub verified: bool,
    /// This peer's capability set (P-P3, `docs/architecture/PAIRING.md`
    /// decision 5) — a CLOSED vocabulary ([`PEER_CAPABILITIES`]), never a
    /// per-capability serde bool scatter (the kill-list). `"spawn"` gates
    /// the A2A door's spawn arm (decision 6); `"read"` is reserved for a
    /// future graph/who-summary gate over A2A, not read by anything yet.
    /// Empty for every unpaired peer (today's every `peer add` entry) and
    /// for a legacy `peers.json` predating this field — same
    /// `#[serde(default)]`+`skip_serializing_if` discipline `hub`/`verified`
    /// already hold. Set ONLY by [`upsert_paired_peer`] (the ceremony's
    /// default-stamp, on first pairing) and [`set_peer_allow`] (`peer allow
    /// <name> <cap> on|off`) — never a raw `Peer { .. }` literal outside
    /// this module.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allows: Vec<String>,
    /// The ssh-transport lane's marker (P-S4, `docs/architecture/
    /// PAIRING.md`'s Transport section): an `ssh://[user@]host[:port]`
    /// target ([`crate::tunnel::parse_via`]'s own shape) a cross-box call to
    /// this peer should dial THROUGH — an internal loopback forward instead
    /// of `url`'s host directly. Absent by default (today's every peer, and
    /// every peer registered before this field existed) — the exact same
    /// `#[serde(default)]`+`skip_serializing_if` discipline `pubkey`/
    /// `bearer_secret` already hold: an old `peers.json` deserializes `via:
    /// None` on every entry, and a peer with no via omits the key entirely
    /// rather than writing `"via":null`. `None` means every call to this
    /// peer dials `url` directly — BYTE-IDENTICAL to before this field
    /// existed (§0.4's "off = unchanged" guarantee). Set by [`set_peer_via`]
    /// (the pairing ceremony's requester-side commit, `--via`/K1's
    /// src_addr-derived default) or `peer add --via`; never a raw `Peer
    /// { .. }` literal outside this module, the same discipline `allows`
    /// already holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    #[serde(rename = "addedAt", default)]
    pub added_at: String,
}

/// The closed capability vocabulary `allows` may ever contain (P-P3,
/// PAIRING.md decision 5) — the ONLY valid strings; [`valid_capability`] and
/// [`set_peer_allow`]'s taught refusal both name this set directly rather
/// than duplicating it.
pub const PEER_CAPABILITIES: &[&str] = &["read", "spawn"];

/// Is `cap` one of [`PEER_CAPABILITIES`]? Pure.
pub fn valid_capability(cap: &str) -> bool {
    PEER_CAPABILITIES.contains(&cap)
}

/// The default `allows` a peer gets the moment it FIRST becomes `verified`
/// (PAIRING.md decision 5: "a peer that completes the pairing ceremony gets
/// `["read","spawn"]` stamped at commit time") — [`upsert_paired_peer`]'s
/// only caller of this.
fn default_paired_allows() -> Vec<String> {
    vec!["read".to_string(), "spawn".to_string()]
}

/// `skip_serializing_if` helper for a plain (non-`Option`) `bool` field whose
/// common case is `false` — mirrors `records.rs`'s own private `is_false`
/// (not reused directly: that one is private to its module, and a peer's
/// hub flag has nothing to do with a session record).
fn is_false(b: &bool) -> bool {
    !*b
}

/// The `state/peers.json` container.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerRegistry {
    #[serde(rename = "schemaVersion", default)]
    pub schema_version: String,
    #[serde(default)]
    pub peers: Vec<Peer>,
}

/// The registry path: `state/peers.json` (CONTRACTS.md §7).
pub fn peers_path() -> std::path::PathBuf {
    state_dir().join("peers.json")
}

/// Read the registry, tolerating a missing/corrupt/wrong-shape file as an
/// empty list — an absent file is simply "no peers registered", never an
/// error.
pub fn load_peers() -> Vec<Peer> {
    match std::fs::read_to_string(peers_path()) {
        Ok(raw) => serde_json::from_str::<PeerRegistry>(&raw)
            .map(|r| r.peers)
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Atomic-write the registry (v0 shape) back to `state/peers.json`.
pub fn save_peers(peers: &[Peer]) -> Result<(), String> {
    let reg = PeerRegistry {
        schema_version: PEERS_VERSION.to_string(),
        peers: peers.to_vec(),
    };
    let body = serde_json::to_string_pretty(&reg)
        .map_err(|e| format!("serialize peers.json: {e}"))?
        + "\n";
    let path = peers_path();
    atomic_write(&path, &body).map_err(|e| format!("{}: {e}", path.display()))
}

/// Insert a NEW peer by `name`. `peer add` rejects a duplicate name cleanly
/// — returns `false` (nothing inserted) when the name is already
/// registered. Pure list mutation, so the CRUD is unit-testable off disk.
pub fn insert_peer(peers: &mut Vec<Peer>, peer: Peer) -> bool {
    if peers.iter().any(|p| p.name == peer.name) {
        return false;
    }
    peers.push(peer);
    true
}

/// Remove a peer by `name`. Returns whether anything was removed.
pub fn remove_peer(peers: &mut Vec<Peer>, name: &str) -> bool {
    let before = peers.len();
    peers.retain(|p| p.name != name);
    peers.len() != before
}

/// What [`upsert_paired_peer`] actually did — the pairing ceremony's own
/// "report exactly what changed" (house rule 2), mirroring [`HubChange`]'s
/// shape one field over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairChange {
    /// No peer named `name` existed — a fresh entry was inserted, unpaired
    /// fields (`autogate`/`token_file`/`bearer_secret`/`hub`) at their
    /// defaults.
    Inserted,
    /// A peer named `name` already existed (re-pairing) — its `pubkey`/
    /// `verified`/`url` were REPLACED; every other field (`autogate`,
    /// `token_file`, `bearer_secret`, `hub`) is left exactly as it was.
    Updated,
}

/// Commit the pairing ceremony's own outcome (P-P2, both call sites: the
/// approver writing the requester's record, and the requester's own door
/// writing the approver's record on the callback) — the ONE place either
/// side of the ceremony writes a peer's `pubkey`/`verified`/default
/// `allows`. A fresh insert takes every unpaired field's ordinary default
/// (`autogate: false`, no token/bearer, not the hub) PLUS the ceremony's
/// own default `allows` ([`default_paired_allows`], P-P3 decision 5:
/// `["read","spawn"]`) — completing the ceremony for the first time IS
/// "becoming verified," so the default stamp belongs here, not a second
/// call site. Re-pairing an EXISTING peer (decision: "replaces key material
/// only after the same SAS confirmation, never silently" — the caller's own
/// confirmation gate, not this function's) touches `pubkey`/`verified`/`url`
/// always, but `allows` ONLY when the peer was NOT already verified before
/// this call — a key rotation on an ALREADY-paired peer must never silently
/// re-grant a capability an operator revoked via `peer allow ... off`
/// (P-P3), so `allows` (like `autogate`/`token_file`/`bearer_secret`/`hub`)
/// is left exactly as it was once a peer has been verified at least once.
pub fn upsert_paired_peer(peers: &mut Vec<Peer>, name: &str, url: &str, pubkey_hex: &str, added_at: &str) -> PairChange {
    if let Some(p) = peers.iter_mut().find(|p| p.name == name) {
        let first_pairing = !p.verified;
        p.pubkey = Some(pubkey_hex.to_string());
        p.verified = true;
        p.url = url.to_string();
        if first_pairing {
            p.allows = default_paired_allows();
        }
        return PairChange::Updated;
    }
    peers.push(Peer {
        name: name.to_string(),
        url: url.to_string(),
        autogate: false,
        token_file: None,
        bearer_secret: None,
        hub: false,
        pubkey: Some(pubkey_hex.to_string()),
        verified: true,
        allows: default_paired_allows(),
        via: None,
        added_at: added_at.to_string(),
    });
    PairChange::Inserted
}

/// Set (or clear) a paired peer's `via` transport marker (P-S4) — a
/// SIBLING writer beside [`upsert_paired_peer`] rather than a new
/// parameter threaded through it. `upsert_paired_peer` is also called from
/// `aoide-server`'s own pairing integration tests (`a2a.rs`), a crate
/// outside this phase's blast radius and test plan — a purely additive
/// setter keeps that signature untouched and ripples nowhere, mirroring
/// how [`set_hub`]/[`set_peer_allow`] already sit beside [`insert_peer`]
/// as their own separate mutation functions rather than parameters folded
/// into it. `Err` when `name` names no registered peer — the same "a
/// missing name is a real error, not a silent no-op" stance [`set_hub`]/
/// [`clear_hub`] hold. `via: None` clears the marker (the common case: a
/// peer this ceremony never resolved a `--via`/observed-address for, or a
/// re-pairing whose caller chose not to carry one forward) — every other
/// field `upsert_paired_peer` leaves untouched on re-pairing stays that
/// way; only THIS call ever changes `via`.
pub fn set_peer_via(peers: &mut [Peer], name: &str, via: Option<&str>) -> Result<(), String> {
    let Some(p) = peers.iter_mut().find(|p| p.name == name) else {
        return Err(format!("no peer named `{name}`"));
    };
    p.via = via.map(|s| s.to_string());
    Ok(())
}

/// What [`set_peer_allow`] actually did — mirrors [`HubChange`]'s "report
/// exactly what changed" shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowChange {
    /// The capability was absent and is now present.
    Enabled,
    /// The capability was present and is now absent.
    Disabled,
    /// Already in the requested state — nothing written.
    NoOp,
}

/// Why [`set_peer_allow`] refused, distinctly from either half of a valid
/// call — `peer allow`'s CLI handler names which, per PAIRING.md decision 5
/// ("Unknown capability strings are refused... refuses an unknown peer and
/// an unknown cap").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowError {
    UnknownPeer,
    UnknownCapability,
}

/// `peer allow <name> <cap> on|off` (P-P3, PAIRING.md decision 5): flip one
/// capability in `name`'s `allows` set. The capability is validated against
/// [`PEER_CAPABILITIES`] BEFORE the peer lookup — an unknown cap is refused
/// the same way regardless of whether `name` exists, never a per-capability
/// bool field (the kill-list). Idempotent either direction: turning ON an
/// already-present capability, or OFF an already-absent one, is
/// [`AllowChange::NoOp`] and writes nothing — mirrors [`set_hub`]/
/// [`clear_hub`]'s exact idempotence discipline.
pub fn set_peer_allow(peers: &mut [Peer], name: &str, cap: &str, on: bool) -> Result<AllowChange, AllowError> {
    if !valid_capability(cap) {
        return Err(AllowError::UnknownCapability);
    }
    let Some(p) = peers.iter_mut().find(|p| p.name == name) else {
        return Err(AllowError::UnknownPeer);
    };
    let has = p.allows.iter().any(|a| a == cap);
    if on {
        if has {
            return Ok(AllowChange::NoOp);
        }
        p.allows.push(cap.to_string());
        Ok(AllowChange::Enabled)
    } else {
        if !has {
            return Ok(AllowChange::NoOp);
        }
        p.allows.retain(|a| a != cap);
        Ok(AllowChange::Disabled)
    }
}

/// WHICH signal resolved a caller to a [`Peer`] ([`resolve_peer`], P-P3
/// decision 6; a third rung joined in P-P4). The three rungs are not
/// interchangeable strength, weakest to strongest: `Addr` is a bare
/// TCP-source-IP-vs-`url` match — spoofable by anyone who can reach the
/// door from that address, or who merely sits behind the same NAT/proxy as
/// the real peer. `Token` is possession of that peer's own `token_file`
/// secret — it survives any reverse proxy/NAT, the same reason
/// [`is_autogated_peer_token`] is preferred over the address check for
/// autogate, but it is still a bare shared secret: not bound to any one
/// request, replayable, and identical across every request the true peer
/// or an impersonator ever sends. `Signature` (P-P4,
/// `docs/architecture/PAIRING.md`'s "Wire authentication" section) is an
/// ed25519 signature over that ONE request's own method/path/timestamp/
/// nonce/body-digest — the peer is resolved BY the stored pubkey that
/// verifies it (#63 P-ID5: identity is the key; the wire's claimed name is
/// attribution only) — the only
/// rung cryptographically bound to the specific request that carried it.
/// `Signature` is deliberately NOT produced by this function
/// ([`resolve_peer`]) — verifying one needs the raw HTTP request
/// (method/path/body/signature headers) that this pure, address-and-token-
/// only function never sees; it is yielded instead by the door's own
/// verification flow (`aoide-server::a2a::verify_signed_request`) once a
/// signature checks out, then fed to [`Peer`]-consuming code the exact same
/// way a `resolve_peer` result would be. All three rungs are fine for
/// ATTRIBUTION (Inject's `from` field, origin-stamping) and for autogate's
/// existing "skip the pending queue" question; the A2A door's spawn arm is
/// the one consumer narrow enough to require `Signature` specifically
/// (`a2a.rs::spawn_admitted` — Token admitted spawn from 2026-08-25 to
/// P-P4's landing, when the requirement moved to `Signature` alone; `Addr`
/// never admitted spawn at any point).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRung {
    Token,
    Addr,
    /// A verified per-request ed25519 signature (P-P4) — see this enum's
    /// own doc comment for the full grounding. Never produced by
    /// [`resolve_peer`] itself.
    Signature,
}

/// Resolve the CALLING peer's identity (P-P3, PAIRING.md decision 6) — the
/// specific registered [`Peer`] a caller's presented credential names, PLUS
/// which [`PeerRung`] matched, independent of that peer's own `autogate`
/// flag. Unlike [`is_autogated_peer_token`]/[`is_autogated_peer_addr`]
/// (which fold ONLY over `autogate`-marked peers, for the unrelated "skip
/// the pending queue" question), this looks at EVERY registered peer — a
/// gate that needs to know WHICH peer is calling (not merely "does some
/// autogate-marked peer match") goes through this instead.
///
/// Ladder, first match wins, first REGISTRY-ORDER match within a rung: a
/// presented bearer token that matches a peer's OWN `token_file`
/// ([`token_bytes_eq`], the mechanism that survives a reverse proxy — same
/// precedence [`is_autogated_peer_token`]'s own doc gives it) is tried
/// FIRST (`PeerRung::Token` on a hit); failing that, an `addr` whose host
/// resolves against a peer's registered `url` ([`peer_url_matches_addr`])
/// is tried second (`PeerRung::Addr` on a hit). `None` for an unmatched
/// token, a missing/unmatched address, or both — a caller presenting only
/// the door-wide bearer (which by construction matches no PEER's own
/// `token_file`) never resolves to a name here. `peer add` only refuses a
/// duplicate NAME (CONTRACTS.md §7) — two peers sharing a URL host, or two
/// `token_file`s that happen to hold identical bytes, are both possible,
/// and either ladder step then resolves to whichever of them iterates
/// first (registry insertion order — `peers.json`'s `peers` array order,
/// unchanged by this function).
pub fn resolve_peer<'a>(peers: &'a [Peer], addr: Option<IpAddr>, presented_token: Option<&str>) -> Option<(&'a Peer, PeerRung)> {
    if let Some(t) = presented_token {
        if let Some(p) = peers.iter().find(|p| {
            p.token_file
                .as_deref()
                .and_then(|path| std::fs::read_to_string(path).ok())
                .map(|raw| token_bytes_eq(raw.trim(), t))
                .unwrap_or(false)
        }) {
            return Some((p, PeerRung::Token));
        }
    }
    let addr = addr?;
    peers.iter().find(|p| peer_url_matches_addr(&p.url, addr)).map(|p| (p, PeerRung::Addr))
}

/// A default local nickname for a peer named only by URL (`aoide peer pair
/// request <url>` with no `--name`) — [`url_host`]'s bare authority,
/// lowercased and sanitized to [`valid_peer_name`]'s shape (`.`/`:` become
/// `-`, anything else not in `[a-z0-9-]` is dropped), leading/trailing/
/// duplicate hyphens collapsed. `None` when the URL has no parseable host
/// at all, or the sanitized result is empty/still invalid — the caller
/// (`aoide-client::commands::handle_peer_pair_request`) then requires an
/// explicit `--name` rather than guessing further. Pure.
pub fn default_peer_name_from_url(url: &str) -> Option<String> {
    let host = url_host(url)?;
    let host_only = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(&host);
    let mut out = String::new();
    let mut last_was_hyphen = false;
    for c in host_only.chars() {
        let mapped = if c.is_ascii_alphanumeric() {
            Some(c.to_ascii_lowercase())
        } else if c == '.' || c == '-' || c == '_' {
            Some('-')
        } else {
            None
        };
        match mapped {
            Some('-') if last_was_hyphen || out.is_empty() => {}
            Some(ch) => {
                out.push(ch);
                last_was_hyphen = ch == '-';
            }
            None => {}
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if valid_peer_name(&out) {
        Some(out)
    } else {
        None
    }
}

/// What [`set_hub`]/[`clear_hub`] actually did — the CLI's `peer hub`
/// Outcome message names the exact change (P-D5) rather than a bare
/// success bool, mirroring `insert_peer`/`remove_peer`'s "report what
/// happened" discipline one step further.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HubChange {
    /// No peer held the hub before; the named peer now does.
    Set,
    /// A DIFFERENT peer held the hub before (named here); it moved to the
    /// requested peer in the same write.
    Moved { from: String },
    /// `clear_hub` removed the hub designation from the named peer.
    Cleared,
    /// Nothing changed: `set_hub` on the peer already holding the hub, or
    /// `clear_hub` on a peer that wasn't holding it (including "no peer is
    /// the hub at all") — both idempotent no-ops, never an error.
    NoOp,
}

/// Set `name` as the sole hub peer, moving it from whichever OTHER peer (if
/// any) held it before, in the SAME write — at most one peer is ever marked
/// `hub` (`Peer::hub`'s doc). Idempotent: calling this twice in a row with
/// the same `name` is a [`HubChange::NoOp`] the second time. `Err` when
/// `name` names no registered peer — mirrors `remove_peer`'s "a missing
/// name is a clean error, not a silent no-op" discipline every other `peer`
/// command already holds.
pub fn set_hub(peers: &mut [Peer], name: &str) -> Result<HubChange, String> {
    if !peers.iter().any(|p| p.name == name) {
        return Err(format!("no peer named `{name}`"));
    }
    let previous_holder = peers.iter().find(|p| p.hub).map(|p| p.name.clone());
    if previous_holder.as_deref() == Some(name) {
        return Ok(HubChange::NoOp);
    }
    for p in peers.iter_mut() {
        p.hub = p.name == name;
    }
    Ok(match previous_holder {
        Some(from) => HubChange::Moved { from },
        None => HubChange::Set,
    })
}

/// Clear the hub designation from `name`, if it currently holds it. `Err`
/// when `name` names no registered peer. A [`HubChange::NoOp`] — never an
/// error — when `name` exists but isn't currently the hub, which also
/// covers "no peer is the hub at all" (the idempotent "clear on no-hub"
/// case `set_hub`'s sibling test battery exercises).
pub fn clear_hub(peers: &mut [Peer], name: &str) -> Result<HubChange, String> {
    let Some(p) = peers.iter_mut().find(|p| p.name == name) else {
        return Err(format!("no peer named `{name}`"));
    };
    if !p.hub {
        return Ok(HubChange::NoOp);
    }
    p.hub = false;
    Ok(HubChange::Cleared)
}

/// A valid peer nickname: `^[a-z0-9][a-z0-9-]*$` — the same shape as
/// `aoide_song::compose::valid_song_name` (this crate sits below `song` in
/// the dependency graph, so it defines its own copy rather than depending
/// upward). A peer's nickname is joined directly into
/// [`peer_cache_path`]'s `state/peer-cache/<name>.json` — this one check
/// rejects path traversal (`..`, `/`) by construction, the same way it does
/// for a song name.
pub fn valid_peer_name(name: &str) -> bool {
    let mut chars = name.chars();
    let first_ok = matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit());
    first_ok && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// The `scheme://host[:port]` authority of a URL (drops any path/query),
/// bare (no trailing slash) — pure. Lives here (not `aoide-client`) since
/// the SERVER side's inbound autogate match needs it too, and `server`
/// must never depend on `client`.
pub fn url_host(url: &str) -> Option<String> {
    let (_, rest) = url.trim().split_once("://")?;
    let host = rest.split('/').next().unwrap_or(rest);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// The path a request to `url` actually rides on the wire (curl sends
/// exactly this in the HTTP request line, and the door's own
/// `parse_http_request` captures exactly this into `HttpRequest.path`) —
/// P-P4's own reason this exists: a signer must build its canonical string
/// (`aoide_storage::wire_auth::canonical_string`) over the SAME path the
/// verifier will see, never a hardcoded `"/"` that would silently drift the
/// moment a peer's `url` carries a path prefix (a reverse proxy fronting
/// the door at e.g. `https://box/aoide/`). Query string and fragment are
/// dropped (this door parses none) and an empty/missing path becomes `"/"`
/// — the same default an HTTP client sends for a bare
/// `scheme://host[:port]` URL with no explicit path.
pub fn url_path(url: &str) -> String {
    let Some((_, rest)) = url.trim().split_once("://") else {
        return "/".to_string();
    };
    let after_host = rest.find('/').map(|i| &rest[i..]).unwrap_or("");
    let path = after_host.split(['?', '#']).next().unwrap_or("");
    if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    }
}

/// Does a peer's `url` host resolve to `addr`? An IP-literal host (the
/// common tailnet-IP / test case) compares directly — no I/O, no real DNS
/// call. Only a non-literal hostname (tailnet MagicDNS, plain DNS) falls
/// back to the system resolver (`ToSocketAddrs`), best-effort: a resolution
/// failure is simply "no match", never an error/panic — this must never
/// block or crash the A2A door on a peer whose name doesn't currently
/// resolve.
fn peer_url_matches_addr(url: &str, addr: IpAddr) -> bool {
    let Some(host) = url_host(url) else {
        return false;
    };
    let host_only = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(&host);
    if let Ok(ip) = host_only.parse::<IpAddr>() {
        return ip == addr;
    }
    use std::net::ToSocketAddrs;
    (host_only, 0u16)
        .to_socket_addrs()
        .map(|it| it.map(|sa| sa.ip()).any(|ip| ip == addr))
        .unwrap_or(false)
}

/// Does `addr` belong to a peer explicitly marked `autogate: true`? The pure
/// per-peer match ([`peer_url_matches_addr`]) is what's actually
/// unit-testable without DNS; this just folds it over the registered,
/// autogate-marked subset.
pub fn is_autogated_peer_addr(peers: &[Peer], addr: IpAddr) -> bool {
    peers.iter().filter(|p| p.autogate).any(|p| peer_url_matches_addr(&p.url, addr))
}

// ── Per-peer token identification (CONTRACTS.md §6 amendment, 2026-08-18) ───
//
// [`is_autogated_peer_addr`] above is the address-based match this crate
// shipped with (§6, 2026-08-14) — still here, still checked first, still the
// ONLY check when no peer has ever set `token_file` (so a registry with no
// tokens configured resolves identically to before this amendment). But
// behind any reverse proxy or tunnel, `peer_addr()` on the SERVER's end is
// the proxy's own loopback address for every caller, so IP can no longer
// tell two peers apart. A per-peer token is the identity signal that
// survives a proxy: [`is_autogated_peer_token`] below is the same autogate
// fold as [`is_autogated_peer_addr`], keyed on a presented bearer token
// instead of a source address.

/// Length-independent byte compare for a secret: unlike `==`/`eq`, the
/// comparison loop always runs to `max(expected.len(), presented.len())`
/// rather than returning the instant a byte (or the length) differs, so a
/// timing side-channel can't easily be walked to recover the secret one byte
/// at a time. Not a cryptographic constant-time primitive (no crate for
/// that here — house "zero new deps" discipline) — just cheap insurance
/// against the crudest form of that leak.
pub fn token_bytes_eq(expected: &str, presented: &str) -> bool {
    let e = expected.as_bytes();
    let p = presented.as_bytes();
    let len_diff = (e.len() != p.len()) as u8;
    let max_len = e.len().max(p.len());
    let mut diff: u8 = len_diff;
    for i in 0..max_len {
        diff |= e.get(i).copied().unwrap_or(0) ^ p.get(i).copied().unwrap_or(0);
    }
    diff == 0
}

/// Does `presented` (an inbound `Authorization: Bearer <token>` value) match
/// an autogate-marked peer's OWN token (`Peer.token_file`, read fresh off
/// disk — a peer's token can rotate without restarting `a2a serve`)? Mirrors
/// [`is_autogated_peer_addr`]'s fold exactly, keyed on token identity instead
/// of address. A peer with no `token_file` set never matches (tolerant —
/// same "absent means uninvolved" stance as an unmatched address), and a
/// peer whose file is missing/unreadable at match time never matches either
/// (fails safe, never a panic/error).
pub fn is_autogated_peer_token(peers: &[Peer], presented: &str) -> bool {
    peers
        .iter()
        .filter(|p| p.autogate)
        .filter_map(|p| p.token_file.as_deref())
        .any(|path| {
            std::fs::read_to_string(path)
                .map(|raw| token_bytes_eq(raw.trim(), presented))
                .unwrap_or(false)
        })
}

// ── Peer cache: the last-pulled `aoide/graphSummary` response ───────────────

/// One peer's cached pull result (`state/peer-cache/<name>.json`, v0).
/// Preserves the LAST GOOD `instance`/`graph` across a failed pull — `peer
/// pull` marks `stale`/`lastError` rather than deleting the file, so a
/// transient outage never blanks the peer out of the graph fold.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerCacheEntry {
    #[serde(rename = "schemaVersion", default)]
    pub schema_version: String,
    #[serde(default)]
    pub name: String,
    /// The peer's own `instance` envelope field, from its last SUCCESSFUL
    /// pull. Absent only if the peer has never been successfully pulled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<Value>,
    /// The peer's own resolved `graph.json` v0 document, verbatim, from its
    /// last successful pull.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph: Option<Value>,
    /// When this entry was last SUCCESSFULLY refreshed (absent = never).
    #[serde(rename = "fetchedAt", default, skip_serializing_if = "Option::is_none")]
    pub fetched_at: Option<String>,
    /// Set by a failed pull (unreachable, timeout, malformed response);
    /// cleared by the next successful one.
    #[serde(default)]
    pub stale: bool,
    /// A short reason for the most recent pull's failure, when `stale`.
    #[serde(rename = "lastError", default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// The peer-cache directory: `state/peer-cache/`.
pub fn peer_cache_dir() -> std::path::PathBuf {
    state_dir().join("peer-cache")
}

/// One peer's cache file: `state/peer-cache/<name>.json`.
pub fn peer_cache_path(name: &str) -> std::path::PathBuf {
    peer_cache_dir().join(format!("{name}.json"))
}

/// Read one peer's cache entry, tolerating a missing/corrupt file as `None`
/// (never pulled / unreadable — the caller treats both as "no data yet").
pub fn load_peer_cache(name: &str) -> Option<PeerCacheEntry> {
    let raw = std::fs::read_to_string(peer_cache_path(name)).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Atomic-write one peer's cache entry.
pub fn save_peer_cache(entry: &PeerCacheEntry) -> Result<(), String> {
    let body = serde_json::to_string_pretty(entry)
        .map_err(|e| format!("serialize peer-cache/{}.json: {e}", entry.name))?
        + "\n";
    let path = peer_cache_path(&entry.name);
    atomic_write(&path, &body).map_err(|e| format!("{}: {e}", path.display()))
}

/// Is `entry` fresh as of `now_epoch` (unix seconds)? `stale` (a failed pull
/// already marked it) always fails freshness outright; otherwise `fetchedAt`
/// must parse and sit within [`PEER_CACHE_TTL_SECS`] of `now_epoch`. Pure —
/// unit-tested directly against synthetic epochs, no real clock/sleep needed.
pub fn is_cache_fresh(entry: &PeerCacheEntry, now_epoch: i64) -> bool {
    if entry.stale {
        return false;
    }
    let Some(fetched_at) = entry.fetched_at.as_deref() else {
        return false;
    };
    let Some(fetched_epoch) = crate::time::parse_iso_utc(fetched_at) else {
        return false;
    };
    now_epoch.saturating_sub(fetched_epoch) <= PEER_CACHE_TTL_SECS as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_peer(name: &str, url: &str, autogate: bool) -> Peer {
        Peer {
            name: name.to_string(),
            url: url.to_string(),
            autogate,
            token_file: None,
            bearer_secret: None,
            hub: false,
            pubkey: None,
            verified: false,
            allows: Vec::new(),
            via: None,
            added_at: "2026-08-14T00:00:00Z".to_string(),
        }
    }

    // ── Registry CRUD (pure, in-memory) ──────────────────────────────────────

    #[test]
    fn insert_peer_rejects_a_duplicate_name_rather_than_replacing() {
        let mut peers: Vec<Peer> = Vec::new();
        assert!(insert_peer(&mut peers, fixture_peer("alpha", "http://a/", false)));
        assert_eq!(peers.len(), 1);
        // Re-adding the same name is rejected outright — `peer add` never
        // silently overwrites.
        assert!(!insert_peer(&mut peers, fixture_peer("alpha", "http://a-new/", true)));
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].url, "http://a/", "the original entry is untouched");
    }

    #[test]
    fn remove_peer_reports_whether_it_removed_anything() {
        let mut peers = vec![fixture_peer("alpha", "http://a/", false)];
        assert!(remove_peer(&mut peers, "alpha"));
        assert!(peers.is_empty());
        assert!(!remove_peer(&mut peers, "alpha"), "already gone — reports false, doesn't panic");
    }

    // ── Registry round-trip through a temp state dir ─────────────────────────

    #[test]
    fn load_save_peers_round_trip_through_a_temp_state_dir() {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-peer-reg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("AOIDE_STATE_DIR", &dir);

        assert!(load_peers().is_empty(), "missing file tolerates as empty");

        let peers = vec![fixture_peer("alpha", "http://a/", false), fixture_peer("beta", "http://b/", true)];
        save_peers(&peers).unwrap();
        assert_eq!(load_peers(), peers);

        let raw = std::fs::read_to_string(peers_path()).unwrap();
        let v: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["schemaVersion"], "0");
        assert_eq!(v["peers"].as_array().unwrap().len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    // ── `bearerSecret` — outbound bearer config (task #84) ───────────────────

    #[test]
    fn bearer_secret_round_trips_as_camel_case_and_omits_when_absent() {
        let mut with_secret = fixture_peer("alpha", "http://a/", false);
        with_secret.bearer_secret = Some("melete-door-token".to_string());
        let v = serde_json::to_value(&with_secret).unwrap();
        assert_eq!(v["bearerSecret"], "melete-door-token");
        let back: Peer = serde_json::from_value(v).unwrap();
        assert_eq!(back.bearer_secret.as_deref(), Some("melete-door-token"));

        // Absent by default: the key is omitted outright (skip_serializing_if),
        // and an OLD peers.json predating this field loads cleanly as `None`.
        let without = fixture_peer("beta", "http://b/", false);
        let v2 = serde_json::to_value(&without).unwrap();
        assert!(v2.get("bearerSecret").is_none(), "absent bearer_secret is omitted, not null");
        let old_shape = serde_json::json!({
            "name": "gamma", "url": "http://c/", "autogate": false, "addedAt": "2026-08-14T00:00:00Z"
        });
        let back2: Peer = serde_json::from_value(old_shape).unwrap();
        assert_eq!(back2.bearer_secret, None);
    }

    // ── `hub` — the P-D5 hub designation (additive, at-most-one) ─────────────

    #[test]
    fn hub_absent_deserializes_false_and_a_true_value_omits_the_key_only_when_false() {
        // A raw fixture with no `hub` key at all — an old `peers.json`
        // predating this field — must deserialize `false`, the same
        // additive discipline `SessionRecord.headless` established.
        let old_shape = serde_json::json!({
            "name": "gamma", "url": "http://c/", "autogate": false, "addedAt": "2026-08-14T00:00:00Z"
        });
        let back: Peer = serde_json::from_value(old_shape).unwrap();
        assert!(!back.hub, "absent hub deserializes false");

        let not_hub = fixture_peer("alpha", "http://a/", false);
        let v = serde_json::to_value(&not_hub).unwrap();
        assert!(v.get("hub").is_none(), "false hub is omitted, not written as `\"hub\":false`");

        let mut is_hub = fixture_peer("beta", "http://b/", false);
        is_hub.hub = true;
        let v2 = serde_json::to_value(&is_hub).unwrap();
        assert_eq!(v2["hub"], true);
        let back2: Peer = serde_json::from_value(v2).unwrap();
        assert!(back2.hub);
    }

    #[test]
    fn set_hub_is_idempotent_and_moves_the_previous_holder_in_one_write() {
        let mut peers = vec![
            fixture_peer("alpha", "http://a/", false),
            fixture_peer("beta", "http://b/", false),
        ];

        // No hub yet — setting alpha is a fresh `Set`.
        assert_eq!(set_hub(&mut peers, "alpha").unwrap(), HubChange::Set);
        assert!(peers[0].hub);
        assert!(!peers[1].hub);

        // Setting the SAME peer again is a no-op — idempotent.
        assert_eq!(set_hub(&mut peers, "alpha").unwrap(), HubChange::NoOp);
        assert!(peers[0].hub, "still the hub after the no-op re-set");

        // Setting a DIFFERENT peer moves it: the previous holder is
        // reported AND cleared in the same write — at most one hub ever.
        assert_eq!(
            set_hub(&mut peers, "beta").unwrap(),
            HubChange::Moved { from: "alpha".to_string() }
        );
        assert!(!peers[0].hub, "alpha lost the hub in the same write beta gained it");
        assert!(peers[1].hub);
    }

    #[test]
    fn set_hub_rejects_an_unknown_peer_name() {
        let mut peers = vec![fixture_peer("alpha", "http://a/", false)];
        let err = set_hub(&mut peers, "ghost").unwrap_err();
        assert!(err.contains("ghost"));
        assert!(!peers[0].hub, "the registry is untouched on an unknown-name error");
    }

    #[test]
    fn clear_hub_is_idempotent_and_a_no_op_when_no_peer_holds_it() {
        let mut peers = vec![
            fixture_peer("alpha", "http://a/", false),
            fixture_peer("beta", "http://b/", false),
        ];

        // Clearing on a fully hub-less registry is a no-op — the
        // "clear on no-hub" idempotent case.
        assert_eq!(clear_hub(&mut peers, "alpha").unwrap(), HubChange::NoOp);

        set_hub(&mut peers, "alpha").unwrap();
        assert_eq!(clear_hub(&mut peers, "alpha").unwrap(), HubChange::Cleared);
        assert!(!peers[0].hub);

        // Clearing again — already cleared — is a no-op, not a repeat
        // `Cleared`.
        assert_eq!(clear_hub(&mut peers, "alpha").unwrap(), HubChange::NoOp);

        // Clearing a peer that was never the hub (beta never held it) is
        // also a no-op, never an error.
        assert_eq!(clear_hub(&mut peers, "beta").unwrap(), HubChange::NoOp);
    }

    #[test]
    fn clear_hub_rejects_an_unknown_peer_name() {
        let mut peers = vec![fixture_peer("alpha", "http://a/", false)];
        assert!(clear_hub(&mut peers, "ghost").is_err());
    }

    // ── Peer nickname validation (path-traversal guard) ──────────────────────

    #[test]
    fn valid_peer_name_accepts_the_expected_shape_and_rejects_traversal() {
        assert!(valid_peer_name("yomi-strix"));
        assert!(valid_peer_name("ghost"));
        assert!(valid_peer_name("a1-2b"));
        assert!(!valid_peer_name(""));
        assert!(!valid_peer_name("../../evil"));
        assert!(!valid_peer_name("../etc"));
        assert!(!valid_peer_name("a/b"));
        assert!(!valid_peer_name("-leading-hyphen"));
        assert!(!valid_peer_name("Upper"));
        assert!(!valid_peer_name("under_score"));
    }

    // ── URL host parsing + autogate address matching (pure — no real DNS) ────

    #[test]
    fn url_host_extracts_the_bare_authority() {
        assert_eq!(url_host("http://10.0.0.5:8710/"), Some("10.0.0.5:8710".to_string()));
        assert_eq!(url_host("http://yomi-strix:8710/x/y"), Some("yomi-strix:8710".to_string()));
        assert_eq!(url_host("not-a-url"), None);
    }

    #[test]
    fn url_path_extracts_the_wire_path_p_p4() {
        assert_eq!(url_path("http://10.0.0.5:8710/"), "/");
        assert_eq!(url_path("http://10.0.0.5:8710"), "/", "no trailing slash at all still defaults to /");
        assert_eq!(url_path("https://box.example.com/aoide/"), "/aoide/");
        assert_eq!(url_path("http://box:8710/aoide?x=1#frag"), "/aoide", "query/fragment are dropped");
        assert_eq!(url_path("not-a-url"), "/", "unparseable input defaults to /, never panics");
    }

    #[test]
    fn autogate_address_match_is_ip_literal_and_needs_no_dns() {
        let peers = vec![
            fixture_peer("trusted", "http://10.0.0.5:8710/", true),
            fixture_peer("untrusted", "http://10.0.0.6:8710/", false),
        ];
        let trusted_ip: IpAddr = "10.0.0.5".parse().unwrap();
        let untrusted_ip: IpAddr = "10.0.0.6".parse().unwrap();
        let stranger_ip: IpAddr = "10.0.0.9".parse().unwrap();

        assert!(is_autogated_peer_addr(&peers, trusted_ip), "the autogate-marked peer's own address matches");
        assert!(
            !is_autogated_peer_addr(&peers, untrusted_ip),
            "a registered but NOT autogate-marked peer never matches"
        );
        assert!(!is_autogated_peer_addr(&peers, stranger_ip), "an unregistered address never matches");
        assert!(!is_autogated_peer_addr(&[], trusted_ip), "an empty registry matches nothing");
    }

    // ── Peer cache round-trip + staleness ────────────────────────────────────

    #[test]
    fn peer_cache_round_trips_and_preserves_last_good_data_on_a_stale_mark() {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-peer-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("AOIDE_STATE_DIR", &dir);

        assert!(load_peer_cache("ghost").is_none(), "never-pulled peer has no cache entry");

        let fresh = PeerCacheEntry {
            schema_version: "0".to_string(),
            name: "yomi-strix".to_string(),
            instance: Some(Value::from(serde_json::json!({ "name": "yomi-strix" }))),
            graph: Some(serde_json::json!({ "schemaVersion": "0", "nodes": [], "edges": [] })),
            fetched_at: Some("2026-08-14T00:00:00Z".to_string()),
            stale: false,
            last_error: None,
        };
        save_peer_cache(&fresh).unwrap();
        let back = load_peer_cache("yomi-strix").unwrap();
        assert_eq!(back.fetched_at.as_deref(), Some("2026-08-14T00:00:00Z"));
        assert!(!back.stale);

        // A failed pull marks stale but PRESERVES the last-good graph/instance
        // (the caller writes this, exercised here as the shape it must take).
        let mut marked = back.clone();
        marked.stale = true;
        marked.last_error = Some("connection refused".to_string());
        save_peer_cache(&marked).unwrap();
        let after = load_peer_cache("yomi-strix").unwrap();
        assert!(after.stale);
        assert_eq!(after.last_error.as_deref(), Some("connection refused"));
        assert!(after.graph.is_some(), "the last-good graph survives a stale mark");

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    #[test]
    fn cache_freshness_respects_the_ttl_and_the_stale_flag() {
        let base = PeerCacheEntry {
            schema_version: "0".to_string(),
            name: "p".to_string(),
            instance: None,
            graph: None,
            fetched_at: Some("2026-08-14T00:00:00Z".to_string()),
            stale: false,
            last_error: None,
        };
        let fetched_epoch = crate::time::parse_iso_utc(base.fetched_at.as_deref().unwrap()).unwrap();

        assert!(is_cache_fresh(&base, fetched_epoch), "just-fetched is fresh");
        assert!(
            is_cache_fresh(&base, fetched_epoch + PEER_CACHE_TTL_SECS as i64),
            "exactly at the TTL boundary is still fresh (inclusive)"
        );
        assert!(
            !is_cache_fresh(&base, fetched_epoch + PEER_CACHE_TTL_SECS as i64 + 1),
            "one second past the TTL is stale"
        );

        let mut marked_stale = base.clone();
        marked_stale.stale = true;
        assert!(!is_cache_fresh(&marked_stale, fetched_epoch), "an explicit stale mark always wins, even if fresh by TTL");

        let never_fetched = PeerCacheEntry { fetched_at: None, ..base };
        assert!(!is_cache_fresh(&never_fetched, fetched_epoch), "no fetchedAt is never fresh");
    }

    // ── Per-peer token identification (pure compare + the fold) ─────────────

    #[test]
    fn token_bytes_eq_matches_equal_secrets_and_rejects_every_kind_of_mismatch() {
        assert!(token_bytes_eq("s3cr3t", "s3cr3t"), "identical strings match");
        assert!(token_bytes_eq("", ""), "two empty strings match");
        assert!(!token_bytes_eq("s3cr3t", "s3cr3u"), "a single differing byte mismatches");
        assert!(!token_bytes_eq("s3cr3t", "s3cr3"), "a shorter presented value mismatches");
        assert!(!token_bytes_eq("s3cr3t", "s3cr3tt"), "a longer presented value mismatches");
        assert!(!token_bytes_eq("s3cr3t", ""), "an empty presented value never matches a real secret");
    }

    #[test]
    fn is_autogated_peer_token_matches_only_an_autogated_peers_own_token_file() {
        let _g = crate::env_lock().lock().unwrap();
        let dir = std::env::temp_dir().join(format!("aoide-peer-token-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let trusted_file = dir.join("trusted.token");
        std::fs::write(&trusted_file, "trusted-secret\n").unwrap();
        let untrusted_file = dir.join("untrusted.token");
        std::fs::write(&untrusted_file, "untrusted-secret\n").unwrap();

        let mut trusted = fixture_peer("trusted", "http://10.0.0.5:8710/", true);
        trusted.token_file = Some(trusted_file.to_string_lossy().into_owned());
        // Registered, autogate-marked, but WITHOUT a token file at all — must
        // never match any presented token (absent means uninvolved).
        let no_token_autogate = fixture_peer("no-token", "http://10.0.0.7:8710/", true);
        // Autogate-marked but its token file points nowhere real — a missing
        // file fails safe (never matches), never panics.
        let mut broken = fixture_peer("broken", "http://10.0.0.8:8710/", true);
        broken.token_file = Some(dir.join("does-not-exist.token").to_string_lossy().into_owned());
        // Has the SAME secret as `trusted` but is NOT autogate-marked — must
        // never match, since only autogate-marked peers are consulted.
        let mut untrusted = fixture_peer("untrusted", "http://10.0.0.6:8710/", false);
        untrusted.token_file = Some(untrusted_file.to_string_lossy().into_owned());

        let peers = vec![trusted, no_token_autogate, broken, untrusted];

        assert!(is_autogated_peer_token(&peers, "trusted-secret"), "matches the autogate-marked peer's own token");
        assert!(!is_autogated_peer_token(&peers, "untrusted-secret"), "an autogate-marked peer's token never matches a NON-autogated peer's secret");
        assert!(!is_autogated_peer_token(&peers, "wrong"), "an unrecognised token matches nothing");
        assert!(!is_autogated_peer_token(&[], "trusted-secret"), "an empty registry matches nothing");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── `pubkey`/`verified` — P-P2 additive fields ───────────────────────────

    #[test]
    fn pubkey_and_verified_round_trip_and_omit_when_absent_or_false() {
        let mut unpaired = fixture_peer("alpha", "http://a/", false);
        let v = serde_json::to_value(&unpaired).unwrap();
        assert!(v.get("pubkey").is_none(), "absent pubkey is omitted, not null");
        assert!(v.get("verified").is_none(), "false verified is omitted, not written");

        unpaired.pubkey = Some("ab".repeat(32));
        unpaired.verified = true;
        let v2 = serde_json::to_value(&unpaired).unwrap();
        assert_eq!(v2["pubkey"], "ab".repeat(32));
        assert_eq!(v2["verified"], true);
        let back: Peer = serde_json::from_value(v2).unwrap();
        assert_eq!(back.pubkey.as_deref(), Some("ab".repeat(32).as_str()));
        assert!(back.verified);
    }

    #[test]
    fn a_legacy_peers_json_predating_pairing_loads_pubkey_none_and_verified_false() {
        let old_shape = serde_json::json!({
            "name": "gamma", "url": "http://c/", "autogate": false, "addedAt": "2026-08-14T00:00:00Z"
        });
        let back: Peer = serde_json::from_value(old_shape).unwrap();
        assert_eq!(back.pubkey, None);
        assert!(!back.verified);
    }

    // ── `upsert_paired_peer` (the pairing ceremony's one write site for
    // ── pubkey/verified/default allows, P-P2 + P-P3) ─────────────────────────

    #[test]
    fn upsert_paired_peer_inserts_a_fresh_verified_entry_with_unpaired_fields_at_default() {
        let mut peers: Vec<Peer> = Vec::new();
        let change = upsert_paired_peer(&mut peers, "box-b", "http://b/", "deadbeef", "2026-08-25T00:00:00Z");
        assert_eq!(change, PairChange::Inserted);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].name, "box-b");
        assert_eq!(peers[0].url, "http://b/");
        assert_eq!(peers[0].pubkey.as_deref(), Some("deadbeef"));
        assert!(peers[0].verified);
        assert_eq!(peers[0].allows, vec!["read".to_string(), "spawn".to_string()], "a fresh pairing stamps the ceremony's default allows (decision 5)");
        assert!(!peers[0].autogate, "a fresh paired peer is never autogated by construction");
        assert!(peers[0].token_file.is_none());
        assert!(peers[0].bearer_secret.is_none());
        assert!(!peers[0].hub);
    }

    #[test]
    fn upsert_paired_peer_on_a_never_before_verified_name_replaces_pubkey_verified_url_and_stamps_default_allows() {
        let mut existing = fixture_peer("box-b", "http://old-b/", true);
        existing.token_file = Some("/tmp/tok".to_string());
        existing.bearer_secret = Some("secret-name".to_string());
        // `existing.verified` is false (fixture default) and `allows` is
        // empty — an unpaired `peer add` entry pairing for the FIRST time.
        let mut peers = vec![existing];

        let change = upsert_paired_peer(&mut peers, "box-b", "http://new-b/", "cafef00d", "2026-08-25T00:00:00Z");
        assert_eq!(change, PairChange::Updated);
        assert_eq!(peers.len(), 1, "re-pairing never duplicates the entry");
        assert_eq!(peers[0].url, "http://new-b/", "url is replaced");
        assert_eq!(peers[0].pubkey.as_deref(), Some("cafef00d"));
        assert!(peers[0].verified);
        assert_eq!(peers[0].allows, vec!["read".to_string(), "spawn".to_string()], "first-time verification stamps the default allows same as a fresh insert");
        assert!(peers[0].autogate, "autogate is untouched by re-pairing");
        assert_eq!(peers[0].token_file.as_deref(), Some("/tmp/tok"), "token_file untouched");
        assert_eq!(peers[0].bearer_secret.as_deref(), Some("secret-name"), "bearer_secret untouched");
    }

    #[test]
    fn upsert_paired_peer_on_an_already_verified_name_never_resets_allows() {
        // A key rotation (re-pairing) on a peer that was ALREADY verified —
        // its operator may have since revoked `spawn` via `peer allow ...
        // off`; re-pairing must never silently re-grant it.
        let mut existing = fixture_peer("box-b", "http://old-b/", false);
        existing.verified = true;
        existing.pubkey = Some("oldkey".to_string());
        existing.allows = vec!["read".to_string()]; // spawn already revoked.
        let mut peers = vec![existing];

        let change = upsert_paired_peer(&mut peers, "box-b", "http://new-b/", "newkey", "2026-08-25T00:00:00Z");
        assert_eq!(change, PairChange::Updated);
        assert_eq!(peers[0].pubkey.as_deref(), Some("newkey"), "key material still rotates");
        assert!(peers[0].verified);
        assert_eq!(peers[0].allows, vec!["read".to_string()], "already-verified peer's allows survive a key rotation untouched — a revoked spawn stays revoked");
    }

    // ── `allows` — P-P3 additive field ────────────────────────────────────────

    #[test]
    fn allows_round_trips_and_omits_when_empty() {
        let mut peer = fixture_peer("alpha", "http://a/", false);
        let v = serde_json::to_value(&peer).unwrap();
        assert!(v.get("allows").is_none(), "an empty allows set is omitted, not written as `[]`");

        peer.allows = vec!["read".to_string(), "spawn".to_string()];
        let v2 = serde_json::to_value(&peer).unwrap();
        assert_eq!(v2["allows"], serde_json::json!(["read", "spawn"]));
        let back: Peer = serde_json::from_value(v2).unwrap();
        assert_eq!(back.allows, vec!["read".to_string(), "spawn".to_string()]);
    }

    #[test]
    fn a_legacy_peers_json_predating_allows_loads_an_empty_set() {
        let old_shape = serde_json::json!({
            "name": "gamma", "url": "http://c/", "autogate": false, "addedAt": "2026-08-14T00:00:00Z"
        });
        let back: Peer = serde_json::from_value(old_shape).unwrap();
        assert!(back.allows.is_empty());
    }

    #[test]
    fn valid_capability_accepts_only_the_closed_set() {
        assert!(valid_capability("read"));
        assert!(valid_capability("spawn"));
        assert!(!valid_capability("write"));
        assert!(!valid_capability(""));
        assert!(!valid_capability("Spawn"), "case-sensitive — the closed set is exact strings");
    }

    // ── `set_peer_allow` (`peer allow <name> <cap> on|off`) ──────────────────

    #[test]
    fn set_peer_allow_enables_and_disables_idempotently() {
        let mut peers = vec![fixture_peer("alpha", "http://a/", false)];

        assert_eq!(set_peer_allow(&mut peers, "alpha", "spawn", true), Ok(AllowChange::Enabled));
        assert_eq!(peers[0].allows, vec!["spawn".to_string()]);
        // Re-enabling the same cap is a no-op — nothing duplicated.
        assert_eq!(set_peer_allow(&mut peers, "alpha", "spawn", true), Ok(AllowChange::NoOp));
        assert_eq!(peers[0].allows, vec!["spawn".to_string()]);

        assert_eq!(set_peer_allow(&mut peers, "alpha", "spawn", false), Ok(AllowChange::Disabled));
        assert!(peers[0].allows.is_empty());
        // Disabling an already-absent cap is also a no-op.
        assert_eq!(set_peer_allow(&mut peers, "alpha", "spawn", false), Ok(AllowChange::NoOp));
    }

    #[test]
    fn set_peer_allow_refuses_an_unknown_peer_or_an_unknown_capability() {
        let mut peers = vec![fixture_peer("alpha", "http://a/", false)];
        assert_eq!(set_peer_allow(&mut peers, "ghost", "spawn", true), Err(AllowError::UnknownPeer));
        assert_eq!(set_peer_allow(&mut peers, "alpha", "write", true), Err(AllowError::UnknownCapability));
        // An unknown capability is refused even against an unknown peer —
        // the capability check runs first, so it never depends on the
        // registry's own contents.
        assert_eq!(set_peer_allow(&mut peers, "ghost", "write", true), Err(AllowError::UnknownCapability));
        assert!(peers[0].allows.is_empty(), "no refusal mutates the registry");
    }

    // ── `resolve_peer` (P-P3 decision 6's identity ladder) ────────────────────

    #[test]
    fn resolve_peer_matches_a_presented_token_against_any_registered_peers_own_token_file_regardless_of_autogate() {
        let dir = std::env::temp_dir().join(format!("aoide-peer-resolve-token-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let token_path = dir.join("box-b.token");
        std::fs::write(&token_path, "secret-b\n").unwrap();

        // NOT autogate-marked — resolve_peer must still find it by token,
        // unlike is_autogated_peer_token which would refuse it.
        let mut paired = fixture_peer("box-b", "http://10.0.0.5:8710/", false);
        paired.verified = true;
        paired.token_file = Some(token_path.to_string_lossy().into_owned());
        let peers = vec![paired];

        let resolved = resolve_peer(&peers, None, Some("secret-b"));
        assert_eq!(resolved.map(|(p, rung)| (p.name.as_str(), rung)), Some(("box-b", PeerRung::Token)));
        assert!(resolve_peer(&peers, None, Some("wrong")).is_none());
        assert!(resolve_peer(&peers, None, None).is_none(), "no token, no address — nothing to resolve against");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_peer_falls_back_to_address_when_no_token_matches() {
        let peer = fixture_peer("box-b", "http://10.0.0.5:8710/", false);
        let peers = vec![peer];
        let ip: IpAddr = "10.0.0.5".parse().unwrap();

        assert_eq!(
            resolve_peer(&peers, Some(ip), None).map(|(p, rung)| (p.name.as_str(), rung)),
            Some(("box-b", PeerRung::Addr))
        );
        // A presented token that matches NO peer's own token_file still
        // falls through to the address ladder rather than short-circuiting
        // to None — the door-wide-bearer-only case (no peer token_file set
        // anywhere) resolves by address exactly as if no token was sent.
        assert_eq!(
            resolve_peer(&peers, Some(ip), Some("door-wide-bearer")).map(|(p, rung)| (p.name.as_str(), rung)),
            Some(("box-b", PeerRung::Addr))
        );

        let stranger: IpAddr = "10.0.0.9".parse().unwrap();
        assert!(resolve_peer(&peers, Some(stranger), None).is_none());
        assert!(resolve_peer(&[], Some(ip), None).is_none(), "an empty registry resolves nothing");
    }

    #[test]
    fn resolve_peer_ambiguity_is_a_deterministic_first_registry_order_match_not_last_or_random() {
        // `peer add` refuses only a duplicate NAME (CONTRACTS.md §7) — two
        // peers can share a url host, or hold token_files with byte-identical
        // contents, and resolve_peer must still answer deterministically
        // rather than "whichever the iterator happens to land on."
        let dir = std::env::temp_dir().join(format!("aoide-peer-resolve-ambiguous-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let token_path = dir.join("shared.token");
        std::fs::write(&token_path, "shared-secret\n").unwrap();

        let mut first = fixture_peer("first-registered", "http://10.0.0.5:8710/", false);
        first.token_file = Some(token_path.to_string_lossy().into_owned());
        let mut second = fixture_peer("second-registered", "http://10.0.0.5:8710/", false);
        second.token_file = Some(token_path.to_string_lossy().into_owned());
        let peers = vec![first, second];

        // Same URL host, same token bytes — the FIRST entry in registry
        // (array) order wins on either rung, every time, not the last one.
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        assert_eq!(
            resolve_peer(&peers, Some(ip), None).map(|(p, _)| p.name.as_str()),
            Some("first-registered"),
            "addr rung: first registry-order match wins"
        );
        assert_eq!(
            resolve_peer(&peers, None, Some("shared-secret")).map(|(p, _)| p.name.as_str()),
            Some("first-registered"),
            "token rung: first registry-order match wins"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── `default_peer_name_from_url` ─────────────────────────────────────────

    #[test]
    fn default_peer_name_from_url_sanitizes_a_bare_host_or_hostport() {
        assert_eq!(default_peer_name_from_url("http://yomi-strix:8710/"), Some("yomi-strix".to_string()));
        assert_eq!(default_peer_name_from_url("http://10.0.0.5:8710/"), Some("10-0-0-5".to_string()));
        assert_eq!(default_peer_name_from_url("http://SAKAKI.local/"), Some("sakaki-local".to_string()));
        assert_eq!(default_peer_name_from_url("not-a-url"), None);
    }

    // ── `via` — the ssh-transport lane's marker (P-S4, additive) ─────────────

    #[test]
    fn via_absent_deserializes_none_and_omits_when_absent_but_round_trips_when_present() {
        // A raw fixture with no `via` key at all — a `peers.json` predating
        // this field (today's every real file) — must deserialize `None`,
        // the same additive discipline `pubkey`/`bearerSecret` established.
        let old_shape = serde_json::json!({
            "name": "gamma", "url": "http://c/", "autogate": false, "addedAt": "2026-08-14T00:00:00Z"
        });
        let back: Peer = serde_json::from_value(old_shape).unwrap();
        assert_eq!(back.via, None, "absent via deserializes None");

        let without = fixture_peer("alpha", "http://a/", false);
        let v = serde_json::to_value(&without).unwrap();
        assert!(v.get("via").is_none(), "absent via is omitted, not written as `\"via\":null`");

        let mut with_via = fixture_peer("beta", "http://b/", false);
        with_via.via = Some("ssh://khoa@sakaki".to_string());
        let v2 = serde_json::to_value(&with_via).unwrap();
        assert_eq!(v2["via"], "ssh://khoa@sakaki");
        let back2: Peer = serde_json::from_value(v2).unwrap();
        assert_eq!(back2.via.as_deref(), Some("ssh://khoa@sakaki"));
    }

    #[test]
    fn upsert_paired_peer_leaves_via_none_on_a_fresh_insert() {
        let mut peers: Vec<Peer> = Vec::new();
        upsert_paired_peer(&mut peers, "box-b", "http://b/", "deadbeef", "2026-08-25T00:00:00Z");
        assert_eq!(peers[0].via, None, "a fresh pairing stamps no via — set_peer_via is the only writer");
    }

    #[test]
    fn set_peer_via_sets_and_clears_without_touching_any_other_field() {
        let mut peers = vec![fixture_peer("alpha", "http://a/", false)];
        peers[0].autogate = true;

        assert!(set_peer_via(&mut peers, "alpha", Some("ssh://khoa@sakaki")).is_ok());
        assert_eq!(peers[0].via.as_deref(), Some("ssh://khoa@sakaki"));
        assert!(peers[0].autogate, "unrelated fields are untouched");

        assert!(set_peer_via(&mut peers, "alpha", None).is_ok());
        assert_eq!(peers[0].via, None, "None clears a previously-set via");
    }

    #[test]
    fn set_peer_via_rejects_an_unknown_peer_name() {
        let mut peers = vec![fixture_peer("alpha", "http://a/", false)];
        let err = set_peer_via(&mut peers, "ghost", Some("ssh://sakaki")).unwrap_err();
        assert!(err.contains("ghost"));
    }
}
