//! The peer registry: `state/peers.json` (v0) — the set of OTHER aoide
//! instances this one has registered by URL (`aoide peer add`), and
//! `state/peer-cache/<name>.json` (v0) — the last-pulled `aoide/graphSummary`
//! response per peer (CONTRACTS.md §7).
//!
//! Mirrors `a2a_store.rs`'s exact shape/discipline (same `state/` dir, same
//! tolerate-missing reads, same atomic writes) rather than the literal
//! `song/stage/` location the originating plan sketched — a peer roster is
//! account/global external-registry state, not song-scoped rehearsal state,
//! exactly like `state/a2a-agents.json`; see CONTRACTS.md §7's note on this
//! judgment call.
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
    #[serde(rename = "addedAt", default)]
    pub added_at: String,
}

/// The `state/peers.json` container.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerRegistry {
    #[serde(rename = "schemaVersion", default)]
    pub schema_version: String,
    #[serde(default)]
    pub peers: Vec<Peer>,
}

/// The registry path: `state/peers.json` (CONTRACTS.md §7), mirroring
/// `a2a_store::agents_path`'s sibling `state/a2a-agents.json` exactly.
pub fn peers_path() -> std::path::PathBuf {
    state_dir().join("peers.json")
}

/// Read the registry, tolerating a missing/corrupt/wrong-shape file as an
/// empty list — an absent file is simply "no peers registered", never an
/// error (mirrors `a2a_store::load_agents`).
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

/// Insert a NEW peer by `name`. Unlike `a2a_store::upsert_agent` (dedupe /
/// replace on re-add), `peer add` rejects a duplicate name cleanly — returns
/// `false` (nothing inserted) when the name is already registered. Pure list
/// mutation, so the CRUD is unit-testable off disk.
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

/// The `scheme://host[:port]` authority of a URL (drops any path/query),
/// bare (no trailing slash) — pure. Mirrors `aoide-client`'s private
/// `wire::origin_of`, but lives here (not `aoide-client`) since the SERVER
/// side's inbound autogate match needs it too, and `server` must never
/// depend on `client`.
pub fn url_host(url: &str) -> Option<String> {
    let (_, rest) = url.trim().split_once("://")?;
    let host = rest.split('/').next().unwrap_or(rest);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
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
            added_at: "2026-08-14T00:00:00Z".to_string(),
        }
    }

    // ── Registry CRUD (pure, in-memory) ──────────────────────────────────────

    #[test]
    fn insert_peer_rejects_a_duplicate_name_rather_than_replacing() {
        let mut peers: Vec<Peer> = Vec::new();
        assert!(insert_peer(&mut peers, fixture_peer("alpha", "http://a/", false)));
        assert_eq!(peers.len(), 1);
        // Re-adding the same name is rejected outright — unlike a2a_store's
        // upsert-replace, `peer add` never silently overwrites.
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

    // ── URL host parsing + autogate address matching (pure — no real DNS) ────

    #[test]
    fn url_host_extracts_the_bare_authority() {
        assert_eq!(url_host("http://10.0.0.5:8710/"), Some("10.0.0.5:8710".to_string()));
        assert_eq!(url_host("http://yomi-strix:8710/x/y"), Some("yomi-strix:8710".to_string()));
        assert_eq!(url_host("not-a-url"), None);
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
}
