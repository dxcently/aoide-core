//! `aoide who [filter] [--json] [--all]` — live presence over this box's own
//! sessions plus every registered peer (messaging/presence plan, P-C2). A
//! PROJECTION, never a store: `build_graph`'s peer fold (`doc.rs:156-201`)
//! already folds registered peers with freshness off their pull CACHE; this
//! module never writes `state/peer-cache/<name>.json` — nothing here is a
//! second source of truth for it.
//!
//! ## Presence model (User-decided, verbatim from the plan)
//!
//! Every registered peer is ALWAYS-ON: a resident door means host-up ==
//! door-answering. So `who` probes every registered peer LIVE on EVERY
//! invocation — one [`std::thread`] per peer (no new deps), each bounded by
//! a short per-peer timeout (~2s) enforced by the transport itself (curl's
//! own `--max-time`, inside [`aoide_client::commands::pull_peer_live`]) —
//! never a manual join-with-timeout here. There is no pull timer anywhere;
//! the cache is consulted ONLY as the fallback for a peer this invocation's
//! live probe fails to reach, so an unreachable peer still renders (never
//! silently drops off the roster) with its last-known sessions labeled by
//! the cache's own `fetchedAt`.
//!
//! Node-level presence: `online` (probed successfully just now) |
//! `unreachable` (probe failed, a cache exists) | `never-pulled` (probe
//! failed, no cache ever written). Session-level presence: `online` (state
//! in `working`/`awaiting`/`idle`) | `stale` (`stopped`) | `done` — omitted
//! from a normal listing, kept with `--all`. A remote session from a LIVE
//! reply is classified exactly the same way a local one is — "as
//! trustworthy as local" per the plan — and a remote session surfaced from
//! the CACHE fallback is classified by its own last-known state too, simply
//! under a node header already saying `unreachable`.
//!
//! ## The probe seam (why tests need no network)
//!
//! [`probe_peers`] takes the peer list AND a `pull` closure — production
//! wires it to `aoide_client::commands::pull_peer_live` (2s), tests inject a
//! closure returning canned `Ok`/`Err` values instantly. This is the ONLY
//! way the per-peer-timeout behavior is exercisable in a sandbox at all: the
//! real 2s bound lives inside curl, one process this crate's tests never
//! spawn.
//!
//! ## Filter semantics
//!
//! An optional positional `filter` narrows what's DISPLAYED; it never
//! changes what gets probed (every peer is probed regardless — see
//! [`who_with`]). Resolution order: try `storage::addr::resolve` first —
//! `Local`/`Ambiguous` narrows to exactly those local session ids;
//! `Remote{peer, query}` narrows to that one peer node, additionally
//! substring-matching its sessions when `query` is non-empty. A query the
//! resolver can't place at all (`NotFound` — most commonly a plain
//! substring nobody typed as a full grammar token) falls back to a
//! case-sensitive substring match: a node whose own name contains it keeps
//! every session, otherwise only ITS sessions whose id/petname/label
//! contain it survive.

use super::model::{resolved_parent, HookRecord, SessionRecord};
use aoide_protocol::output::Outcome;
use aoide_protocol::Invocation;
use aoide_storage::addr::{self, LocalCandidate, Resolution};
use aoide_storage::peer_store::{Peer, PeerCacheEntry};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::Arc;

/// A `who`-probe pull closure: given a peer, return its live resolved graph
/// document (`{nodes, edges}`) or a reason it couldn't be fetched. Boxed so
/// production (`aoide_client::commands::pull_peer_live`) and tests (a canned
/// closure) share the exact same call shape.
pub(super) type PullFn = Arc<dyn Fn(&Peer) -> Result<Value, String> + Send + Sync>;

/// One session as `who` renders it — local or remote, uniformly.
#[derive(Debug, Clone, PartialEq)]
struct SessionView {
    session_id: String,
    label: String,
    petname: Option<String>,
    agent: String,
    state: String,
    presence: &'static str,
    cwd: String,
}

/// One node (this box, or one registered peer) as `who` renders it.
#[derive(Debug, Clone, PartialEq)]
struct NodeView {
    name: String,
    is_local: bool,
    presence: &'static str,
    fetched_at: Option<String>,
    error: Option<String>,
    sessions: Vec<SessionView>,
}

/// Session-level presence class (module doc's "Session-level presence").
fn session_presence(state: &str) -> &'static str {
    match state {
        "stopped" => "stale",
        "done" => "done",
        // working | awaiting | idle | anything unrecognized (never invents
        // a WORSE signal than "still here" — `canonical_state` already
        // folds every producer's vocabulary before it lands in a record).
        _ => "online",
    }
}

/// This box's own [`NodeView`] — always `online` (we're running on it right
/// now). `sessions`/`hooks` are the caller's already-loaded stage files
/// (`common::load_inputs`); pure otherwise.
fn build_local_node(sessions: &[SessionRecord], hooks: &[HookRecord], host: &str) -> NodeView {
    let merged = super::model::merged_sessions(sessions, hooks);
    let ids: HashSet<&str> = merged.iter().map(|s| s.session_id.as_str()).collect();
    let sessions = merged
        .iter()
        .map(|s| {
            let role = if resolved_parent(s, &ids).is_some() { "child" } else { "root" };
            SessionView {
                session_id: s.session_id.clone(),
                label: aoide_storage::display::session_label(s, host, role),
                petname: s.petname.clone(),
                agent: s.agent.clone(),
                state: s.state.clone(),
                presence: session_presence(&s.state),
                cwd: s.cwd.clone(),
            }
        })
        .collect();
    NodeView { name: host.to_string(), is_local: true, presence: "online", fetched_at: None, error: None, sessions }
}

/// Extract every `kind:"session"` node from a (local or peer) resolved graph
/// document into [`SessionView`]s, `role` (root/child, for
/// `display::session_label`) derived from the SAME document's own
/// `spawned` edges — the peer computed this document with its own
/// `build_graph`, so its edges carry exactly the shape ours do
/// (`doc.rs:122-134`). `host` is the label prefix — the peer's registered
/// name for a remote graph, mirroring the `peer/<rest>` grammar
/// `storage::addr` resolves queries against.
fn sessions_from_graph(graph: &Value, host: &str) -> Vec<SessionView> {
    let empty: Vec<Value> = Vec::new();
    let nodes = graph.get("nodes").and_then(Value::as_array).unwrap_or(&empty);
    let edges = graph.get("edges").and_then(Value::as_array).unwrap_or(&empty);
    nodes
        .iter()
        .filter(|n| n["kind"] == "session")
        .map(|n| {
            let full_id = n["id"].as_str().unwrap_or("");
            let session_id = full_id.strip_prefix("session:").unwrap_or(full_id).to_string();
            let role = if edges.iter().any(|e| e["kind"] == "spawned" && e["to"] == full_id) {
                "child"
            } else {
                "root"
            };
            let petname = n["petname"].as_str().map(String::from);
            let state = n["state"].as_str().unwrap_or("idle").to_string();
            let rec = aoide_storage::records::SessionRecord {
                session_id: session_id.clone(),
                petname: petname.clone(),
                ..Default::default()
            };
            SessionView {
                label: aoide_storage::display::session_label(&rec, host, role),
                agent: n["agent"].as_str().unwrap_or("").to_string(),
                presence: session_presence(&state),
                state,
                cwd: n["cwd"].as_str().unwrap_or("").to_string(),
                session_id,
                petname,
            }
        })
        .collect()
}

/// Pure: classify one peer's [`NodeView`] from its live-probe OUTCOME and
/// its already-loaded last cache entry (if any) — no I/O in here at all, so
/// it is trivially unit-testable with synthetic data. The caller
/// (`who_with`) does the real `peer_store::load_peer_cache` read and hands
/// the result in.
fn build_peer_node(peer: &Peer, probe: Result<Value, String>, cache: Option<PeerCacheEntry>) -> NodeView {
    match probe {
        Ok(graph) => NodeView {
            name: peer.name.clone(),
            is_local: false,
            presence: "online",
            fetched_at: None,
            error: None,
            sessions: sessions_from_graph(&graph, &peer.name),
        },
        Err(e) => match cache {
            Some(entry) => {
                let sessions =
                    entry.graph.as_ref().map(|g| sessions_from_graph(g, &peer.name)).unwrap_or_default();
                NodeView {
                    name: peer.name.clone(),
                    is_local: false,
                    presence: "unreachable",
                    fetched_at: entry.fetched_at,
                    error: Some(e),
                    sessions,
                }
            }
            None => NodeView {
                name: peer.name.clone(),
                is_local: false,
                presence: "never-pulled",
                fetched_at: None,
                error: Some(e),
                sessions: Vec::new(),
            },
        },
    }
}

/// Live-probe every peer in `peers`, one [`std::thread`] each, via the
/// injected `pull` closure — see the module doc's "The probe seam". Peer
/// identity is never at risk of a mismatch on a panicked probe: results are
/// re-paired with `peers` by INDEX (`zip`), never by anything the spawned
/// thread itself returns.
pub(super) fn probe_peers(peers: &[Peer], pull: PullFn) -> Vec<(Peer, Result<Value, String>)> {
    let handles: Vec<std::thread::JoinHandle<Result<Value, String>>> = peers
        .iter()
        .cloned()
        .map(|peer| {
            let pull = Arc::clone(&pull);
            std::thread::spawn(move || pull(&peer))
        })
        .collect();
    peers
        .iter()
        .cloned()
        .zip(handles)
        .map(|(peer, h)| {
            let res = h.join().unwrap_or_else(|_| Err("probe thread panicked".to_string()));
            (peer, res)
        })
        .collect()
}

fn session_matches_substring(sv: &SessionView, needle: &str) -> bool {
    sv.session_id.contains(needle)
        || sv.petname.as_deref().is_some_and(|p| p.contains(needle))
        || sv.label.contains(needle)
}

/// Narrow the DISPLAYED node/session set — see the module doc's "Filter
/// semantics". `locals` is the FULL (pre `--all`-trim) local session slice,
/// so a filter can still find a `done` session by id even when `--all`
/// would otherwise hide it from the final listing.
fn apply_filter(filter: &str, host: &str, nodes: Vec<NodeView>, locals: &[SessionRecord]) -> Vec<NodeView> {
    let ids: HashSet<&str> = locals.iter().map(|s| s.session_id.as_str()).collect();
    let candidates: Vec<LocalCandidate<'_>> = locals
        .iter()
        .map(|s| {
            let role = if resolved_parent(s, &ids).is_some() { "child" } else { "root" };
            LocalCandidate { session_id: &s.session_id, petname: s.petname.as_deref(), role }
        })
        .collect();
    let peer_names: Vec<&str> = nodes.iter().filter(|n| !n.is_local).map(|n| n.name.as_str()).collect();

    match addr::resolve(filter, host, &candidates, &peer_names) {
        Resolution::Local(id) => nodes
            .into_iter()
            .filter(|n| n.is_local)
            .map(|mut n| {
                n.sessions.retain(|sv| sv.session_id == id);
                n
            })
            .collect(),
        Resolution::Ambiguous(ids) => nodes
            .into_iter()
            .filter(|n| n.is_local)
            .map(|mut n| {
                n.sessions.retain(|sv| ids.contains(&sv.session_id));
                n
            })
            .collect(),
        Resolution::Remote { peer, query } => nodes
            .into_iter()
            .filter(|n| n.name == peer)
            .map(|mut n| {
                if !query.is_empty() {
                    n.sessions.retain(|sv| session_matches_substring(sv, &query));
                }
                n
            })
            .collect(),
        Resolution::NotFound => nodes
            .into_iter()
            .filter_map(|mut n| {
                if n.name.contains(filter) {
                    return Some(n);
                }
                n.sessions.retain(|sv| session_matches_substring(sv, filter));
                (!n.sessions.is_empty()).then_some(n)
            })
            .collect(),
    }
}

/// Node-level presence glyph — `online`/`unreachable`/`never-pulled` (this
/// module's doc, "Presence model"). Widened to `pub` (re-exported at
/// `graph.rs` alongside [`who`]) for a second consumer: the conductor's
/// ROSTER panel (messaging/presence plan, P-C4) paints the exact same three
/// glyphs over this same `presence` string and must not redraw its own copy
/// of this map — reuse it instead of forking it (crate `AGENTS.md`'s "no
/// cross-crate copying").
pub fn glyph(presence: &str) -> &'static str {
    match presence {
        "online" => "●",
        "unreachable" => "◐",
        "never-pulled" => "○",
        _ => "?",
    }
}

/// The Unicode roster render — mirrors `doc.rs::render`'s glyph/branch style
/// (`◆`/`●`/`├─`/`└─`) so every human surface reads the same grammar.
fn render_nodes(nodes: &[NodeView]) -> String {
    let mut out: Vec<String> = Vec::new();
    for n in nodes {
        let head = match n.presence {
            "unreachable" => {
                let seen = n.fetched_at.as_deref().unwrap_or("unknown");
                format!("{} {} — unreachable (last seen {seen})", glyph(n.presence), n.name)
            }
            "never-pulled" => format!("{} {} — never pulled", glyph(n.presence), n.name),
            _ if n.is_local => format!("{} {} (this host)", glyph(n.presence), n.name),
            _ => format!("{} {}", glyph(n.presence), n.name),
        };
        out.push(head);
        for (i, s) in n.sessions.iter().enumerate() {
            let branch = if i + 1 == n.sessions.len() { "└─ " } else { "├─ " };
            out.push(format!("{branch}{}  {}  {}  {}", s.label, s.agent, s.state, s.cwd));
        }
    }
    if out.is_empty() {
        return "(no local sessions, no peers registered)".to_string();
    }
    out.join("\n")
}

fn node_json(n: &NodeView) -> Value {
    json!({
        "name": n.name,
        "isLocal": n.is_local,
        "presence": n.presence,
        "fetchedAt": n.fetched_at,
        "error": n.error,
        "sessions": n.sessions.iter().map(|s| json!({
            "sessionId": s.session_id,
            "label": s.label,
            "petname": s.petname,
            "agent": s.agent,
            "state": s.state,
            "presence": s.presence,
            "cwd": s.cwd,
        })).collect::<Vec<_>>(),
    })
}

/// The testable core: everything `who` does EXCEPT choosing the real `pull`
/// closure. Loads local stage state (real file I/O — sanctioned, same as
/// every other `graph` verb) and `state/peers.json`/`peer-cache/` (also
/// real file I/O), but the one network-shaped step — probing peers — goes
/// through the injected `pull`, so a test never opens a socket.
pub(super) fn who_with(inv: &Invocation, pull: PullFn) -> Outcome {
    let cmd = "who";
    let (_, s, h) = match super::common::load_inputs(cmd) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let host = aoide_storage::display::local_host_name();
    let local_node = build_local_node(&s.sessions, &h.hooks, &host);

    let peers = aoide_storage::peer_store::load_peers();
    let probed = probe_peers(&peers, pull);

    let mut nodes = vec![local_node];
    for (peer, result) in probed {
        let cache = aoide_storage::peer_store::load_peer_cache(&peer.name);
        nodes.push(build_peer_node(&peer, result, cache));
    }

    // Filter narrows DISPLAY only — every peer above was already probed
    // regardless (module doc's "Filter semantics": probe all, filter
    // display).
    let filter = inv.args.first().map(|a| a.trim()).filter(|a| !a.is_empty());
    if let Some(f) = filter {
        nodes = apply_filter(f, &host, nodes, &s.sessions);
    }

    if !inv.flag_present("all") {
        for n in &mut nodes {
            n.sessions.retain(|sv| sv.presence != "done");
        }
    }

    let total_sessions: usize = nodes.iter().map(|n| n.sessions.len()).sum();
    let message = format!(
        "{} node(s), {} session(s)\n{}",
        nodes.len(),
        total_sessions,
        render_nodes(&nodes)
    );
    let data = json!({
        "host": host,
        "generatedAt": aoide_storage::time::now_iso_utc(),
        "nodes": nodes.iter().map(node_json).collect::<Vec<_>>(),
    });
    Outcome::ok(cmd, message).with_data(data)
}

/// Per-peer live-probe timeout (module doc's presence model — "short
/// per-peer timeout ~2s"). One named constant rather than a magic number at
/// the one call site that needs it.
const PEER_PROBE_TIMEOUT_SECS: u64 = 2;

/// `aoide who [filter] [--json] [--all]` — the real entry point: wires the
/// live probe to `aoide_client::commands::pull_peer_live` (the SAME
/// transport `peer pull` uses, per the crate's `Cargo.toml` note on the
/// `conduct → client` edge) and hands off to [`who_with`].
pub fn who(inv: &Invocation) -> Outcome {
    let pull: PullFn = Arc::new(|p: &Peer| aoide_client::commands::pull_peer_live(p, PEER_PROBE_TIMEOUT_SECS));
    who_with(inv, pull)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::testutil::*;

    fn peer(name: &str) -> Peer {
        Peer {
            name: name.to_string(),
            url: format!("http://{name}/"),
            autogate: false,
            token_file: None,
            added_at: "2026-08-14T00:00:00Z".to_string(),
        }
    }

    fn cache(name: &str, fetched_at: &str, graph: Value) -> PeerCacheEntry {
        PeerCacheEntry {
            schema_version: "0".to_string(),
            name: name.to_string(),
            instance: None,
            graph: Some(graph),
            fetched_at: Some(fetched_at.to_string()),
            stale: false,
            last_error: None,
        }
    }

    fn peer_graph(sessions: &[(&str, &str, &str, Option<&str>)]) -> Value {
        // (sessionId, state, cwd, petname)
        let nodes: Vec<Value> = sessions
            .iter()
            .map(|(id, state, cwd, petname)| {
                let mut n = json!({ "id": format!("session:{id}"), "kind": "session", "state": state, "cwd": cwd, "agent": "claude" });
                if let Some(p) = petname {
                    n["petname"] = json!(p);
                }
                n
            })
            .collect();
        json!({ "schemaVersion": "0", "nodes": nodes, "edges": [] })
    }

    // ── session_presence: the three-way session classification ──────────

    #[test]
    fn session_presence_classifies_the_five_canonical_states() {
        assert_eq!(session_presence("working"), "online");
        assert_eq!(session_presence("awaiting"), "online");
        assert_eq!(session_presence("idle"), "online");
        assert_eq!(session_presence("stopped"), "stale");
        assert_eq!(session_presence("done"), "done");
        // Never invents a worse signal for anything unrecognized.
        assert_eq!(session_presence("mystery"), "online");
    }

    // ── sessions_from_graph: role derived from the SAME document's edges ──

    #[test]
    fn sessions_from_graph_derives_role_from_spawned_edges() {
        let graph = json!({
            "schemaVersion": "0",
            "nodes": [
                { "id": "session:root1", "kind": "session", "state": "working", "cwd": "/x", "agent": "claude", "petname": "brave-otter" },
                { "id": "session:child1", "kind": "session", "state": "idle", "cwd": "/x", "agent": "claude" },
                { "id": "project:aoide", "kind": "project", "name": "aoide", "path": "/x" },
            ],
            "edges": [
                { "from": "session:root1", "to": "session:child1", "kind": "spawned" },
            ],
        });
        let sessions = sessions_from_graph(&graph, "yomi-strix");
        assert_eq!(sessions.len(), 2, "the project node is not a session");
        let root = sessions.iter().find(|s| s.session_id == "root1").unwrap();
        assert_eq!(root.label, "yomi-strix/root/brave-otter (…oot1)");
        assert_eq!(root.presence, "online");
        let child = sessions.iter().find(|s| s.session_id == "child1").unwrap();
        assert_eq!(child.label, "yomi-strix/child/child1");
        assert_eq!(child.presence, "online");
    }

    // ── build_peer_node: the pure probe-outcome + cache classifier ───────

    #[test]
    fn build_peer_node_online_when_the_live_probe_succeeds() {
        let p = peer("yomi-strix");
        let graph = peer_graph(&[("s1", "working", "/x", Some("brave-otter"))]);
        let node = build_peer_node(&p, Ok(graph), None);
        assert_eq!(node.presence, "online");
        assert!(node.fetched_at.is_none());
        assert!(node.error.is_none());
        assert_eq!(node.sessions.len(), 1);
        assert_eq!(node.sessions[0].session_id, "s1");
    }

    #[test]
    fn build_peer_node_unreachable_falls_back_to_the_cache() {
        let p = peer("yomi-strix");
        let graph = peer_graph(&[("s1", "idle", "/x", None)]);
        let node = build_peer_node(&p, Err("HTTP 000".to_string()), Some(cache("yomi-strix", "2026-08-14T00:05:00Z", graph)));
        assert_eq!(node.presence, "unreachable");
        assert_eq!(node.fetched_at.as_deref(), Some("2026-08-14T00:05:00Z"));
        assert_eq!(node.error.as_deref(), Some("HTTP 000"));
        assert_eq!(node.sessions.len(), 1, "last-known sessions still surface");
    }

    #[test]
    fn build_peer_node_never_pulled_when_probe_fails_and_no_cache_exists() {
        let p = peer("ghost");
        let node = build_peer_node(&p, Err("could not reach the agent".to_string()), None);
        assert_eq!(node.presence, "never-pulled");
        assert!(node.fetched_at.is_none());
        assert!(node.sessions.is_empty());
    }

    // ── probe_peers: parallel probe, results correctly paired by peer ────

    #[test]
    fn probe_peers_pairs_every_result_with_its_own_peer_regardless_of_completion_order() {
        let peers = vec![peer("alpha"), peer("beta"), peer("gamma")];
        let pull: PullFn = Arc::new(|p: &Peer| {
            if p.name == "beta" {
                Err("down".to_string())
            } else {
                Ok(json!({ "nodes": [], "edges": [] }))
            }
        });
        let results = probe_peers(&peers, pull);
        assert_eq!(results.len(), 3);
        let by_name: std::collections::HashMap<_, _> =
            results.into_iter().map(|(p, r)| (p.name, r)).collect();
        assert!(by_name["alpha"].is_ok());
        assert!(by_name["beta"].is_err());
        assert!(by_name["gamma"].is_ok());
    }

    // ── apply_filter: local id / peer+query / substring fallback ─────────

    fn sample_nodes() -> (Vec<NodeView>, Vec<SessionRecord>) {
        let locals = vec![
            session("sess-aaaa-1111", "/x", "working", "1", None),
            session("sess-bbbb-2222", "/x", "idle", "2", None),
        ];
        let mut locals = locals;
        locals[0].petname = Some("brave-otter".to_string());
        locals[1].petname = Some("calm-thorn".to_string());

        let local_node = build_local_node(&locals, &[], "sakaki");
        let peer_node = NodeView {
            name: "yomi-strix".to_string(),
            is_local: false,
            presence: "online",
            fetched_at: None,
            error: None,
            sessions: vec![SessionView {
                session_id: "sess-cccc-3333".to_string(),
                label: "yomi-strix/root/misty-comet (…3333)".to_string(),
                petname: Some("misty-comet".to_string()),
                agent: "claude".to_string(),
                state: "working".to_string(),
                presence: "online",
                cwd: "/y".to_string(),
            }],
        };
        (vec![local_node, peer_node], locals)
    }

    #[test]
    fn apply_filter_local_id_narrows_to_the_local_node_and_session_only() {
        let (nodes, locals) = sample_nodes();
        let out = apply_filter("brave-otter", "sakaki", nodes, &locals);
        assert_eq!(out.len(), 1, "the peer node is dropped entirely");
        assert!(out[0].is_local);
        assert_eq!(out[0].sessions.len(), 1);
        assert_eq!(out[0].sessions[0].session_id, "sess-aaaa-1111");
    }

    #[test]
    fn apply_filter_peer_slash_query_narrows_to_that_peer_and_substring_matches() {
        let (nodes, locals) = sample_nodes();
        let out = apply_filter("yomi-strix/misty", "sakaki", nodes, &locals);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "yomi-strix");
        assert_eq!(out[0].sessions.len(), 1);
    }

    #[test]
    fn apply_filter_peer_slash_with_no_matching_remainder_empties_that_peers_sessions() {
        let (nodes, locals) = sample_nodes();
        let out = apply_filter("yomi-strix/nonexistent", "sakaki", nodes, &locals);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "yomi-strix");
        assert!(out[0].sessions.is_empty());
    }

    #[test]
    fn apply_filter_notfound_substring_keeps_a_name_matched_node_whole() {
        let (nodes, locals) = sample_nodes();
        let out = apply_filter("yomi", "sakaki", nodes, &locals);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "yomi-strix");
        assert_eq!(out[0].sessions.len(), 1, "name match keeps every session, unfiltered");
    }

    #[test]
    fn apply_filter_notfound_substring_drops_nodes_with_no_match_at_all() {
        let (nodes, locals) = sample_nodes();
        let out = apply_filter("nothing-matches-this", "sakaki", nodes, &locals);
        assert!(out.is_empty());
    }

    // ── who_with: the full pipeline, injected pull, real local stage I/O ──

    struct Env {
        _guard: std::sync::MutexGuard<'static, ()>,
        stage: std::path::PathBuf,
        state: std::path::PathBuf,
        saved_stage: Option<String>,
        saved_state: Option<String>,
    }
    impl Env {
        fn set_up(tag: &str) -> Self {
            let guard = crate::env_lock().lock().unwrap();
            let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
            let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
            let stage = unique_stage(tag);
            let state = std::env::temp_dir().join(format!(
                "aoide-who-state-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
            ));
            std::env::set_var("AOIDE_STAGE_DIR", &stage);
            std::env::set_var("AOIDE_STATE_DIR", &state);
            Env { _guard: guard, stage, state, saved_stage, saved_state }
        }
    }
    impl Drop for Env {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.stage);
            let _ = std::fs::remove_dir_all(&self.state);
            match &self.saved_stage {
                Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
                None => std::env::remove_var("AOIDE_STAGE_DIR"),
            }
            match &self.saved_state {
                Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
                None => std::env::remove_var("AOIDE_STATE_DIR"),
            }
        }
    }

    fn never_called_pull() -> PullFn {
        Arc::new(|_: &Peer| panic!("no peers registered — pull must never be called"))
    }

    #[test]
    fn who_with_reports_local_sessions_with_no_peers_registered() {
        let _env = Env::set_up("no-peers");
        let sf = super::super::model::SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![session("s1", "/x", "working", "1", None)],
        };
        super::super::model::write_stage(&super::super::model::sessions_path(), &sf).unwrap();

        let out = who_with(&invocation(&["who"], &[]), never_called_pull());
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let data = out.data.unwrap();
        let nodes = data["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 1, "local node only");
        assert_eq!(nodes[0]["presence"], "online");
        assert_eq!(nodes[0]["sessions"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn who_with_omits_done_sessions_unless_all_is_passed() {
        let _env = Env::set_up("done-omitted");
        let sf = super::super::model::SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![
                session("s1", "/x", "working", "1", None),
                session("s2", "/x", "done", "2", None),
            ],
        };
        super::super::model::write_stage(&super::super::model::sessions_path(), &sf).unwrap();

        let out = who_with(&invocation(&["who"], &[]), never_called_pull());
        let data = out.data.unwrap();
        assert_eq!(data["nodes"][0]["sessions"].as_array().unwrap().len(), 1, "done is omitted");

        let out_all = who_with(&flag_invocation(&["who"], &[("all", "true")]), never_called_pull());
        let data_all = out_all.data.unwrap();
        assert_eq!(data_all["nodes"][0]["sessions"].as_array().unwrap().len(), 2, "--all keeps done");
    }

    #[test]
    fn who_with_probes_every_registered_peer_and_classifies_by_outcome() {
        let _env = Env::set_up("peers-probed");
        aoide_storage::peer_store::save_peers(&[peer("alpha"), peer("beta")]).unwrap();
        // `beta` has a stale cache to fall back on; `alpha` has none.
        aoide_storage::peer_store::save_peer_cache(&cache(
            "beta",
            "2026-08-14T00:00:00Z",
            peer_graph(&[("r1", "idle", "/z", None)]),
        ))
        .unwrap();

        let pull: PullFn = Arc::new(|p: &Peer| {
            if p.name == "alpha" {
                Ok(peer_graph(&[("r2", "working", "/a", None)]))
            } else {
                Err("unreachable".to_string())
            }
        });
        let out = who_with(&invocation(&["who"], &[]), pull);
        let data = out.data.unwrap();
        let nodes: Vec<&Value> = data["nodes"].as_array().unwrap().iter().collect();
        assert_eq!(nodes.len(), 3, "local + alpha + beta");

        let alpha = nodes.iter().find(|n| n["name"] == "alpha").unwrap();
        assert_eq!(alpha["presence"], "online");
        assert_eq!(alpha["sessions"].as_array().unwrap().len(), 1);

        let beta = nodes.iter().find(|n| n["name"] == "beta").unwrap();
        assert_eq!(beta["presence"], "unreachable");
        assert_eq!(beta["fetchedAt"], "2026-08-14T00:00:00Z");
        assert_eq!(beta["sessions"].as_array().unwrap().len(), 1, "last-known session still shown");
    }

    #[test]
    fn who_with_filter_never_changes_which_peers_get_probed() {
        let _env = Env::set_up("filter-probes-all");
        aoide_storage::peer_store::save_peers(&[peer("alpha"), peer("beta")]).unwrap();
        let probed = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let probed2 = Arc::clone(&probed);
        let pull: PullFn = Arc::new(move |p: &Peer| {
            probed2.lock().unwrap().push(p.name.clone());
            Ok(json!({ "nodes": [], "edges": [] }))
        });
        // A filter that only displays "alpha" must still have probed "beta".
        let out = who_with(&invocation(&["who"], &["alpha"]), pull);
        let mut names = probed.lock().unwrap().clone();
        names.sort();
        assert_eq!(names, vec!["alpha".to_string(), "beta".to_string()], "every peer was probed");
        let data = out.data.unwrap();
        let nodes = data["nodes"].as_array().unwrap();
        assert!(nodes.iter().all(|n| n["name"] != "beta"), "but only alpha is displayed");
    }
}
