//! The ROSTER core (messaging/presence plan, P-C2; folded under `session` at
//! the session-surface redesign, command-defrag lane X, 2026-08-28) — live
//! presence over this box's own sessions plus every registered peer. A
//! PROJECTION, never a store: `build_graph`'s peer fold (`doc.rs:156-201`)
//! already folds registered peers with freshness off their pull CACHE; this
//! module never writes `state/peer-cache/<name>.json` — nothing here is a
//! second source of truth for it.
//!
//! **The standalone `aoide who` command is RETIRED (hard cutover, no
//! alias — this exact spelling is now unknown, same as a typo).** Its
//! collection pipeline ([`collect_roster`]) and its host-grouped rendering
//! ([`render_nodes`]/[`node_json`]) both SURVIVE, unchanged in mechanism,
//! now reached at `aoide session --hosts` ([`session_roster`]/
//! [`session_roster_with`]) — the SAME `Roster` [`collect_roster`] builds
//! also feeds bare `session`'s PROJECT-grouped rendering
//! ([`group_by_project`]/[`render_groups`]), so `who`'s old byte-for-byte
//! output survives as one of two renderings behind one command instead of
//! living behind a command of its own. `conductor`'s ROSTER panel
//! (`conductor/src/app.rs`'s `spawn_roster_fetch`) dispatches
//! `session --hosts` now — same `Outcome` shape (`nodes`, byte-identical to
//! `who`'s), so that panel needed no rendering change, only its own dispatch
//! `Invocation`.
//!
//! ## Presence model (User-decided, verbatim from the plan)
//!
//! Every registered peer is ALWAYS-ON: a resident door means host-up ==
//! door-answering. So this module probes every registered peer LIVE on EVERY
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
//! ## Filter semantics (`--hosts` rendering only)
//!
//! An optional positional `filter` narrows what's DISPLAYED; it never
//! changes what gets probed (every peer is probed regardless — see
//! [`session_roster_with`]). Resolution order: try `storage::addr::resolve`
//! first — `Local`/`Ambiguous` narrows to exactly those local session ids;
//! `Remote{peer, query}` narrows to that one peer node, additionally
//! substring-matching its sessions when `query` is non-empty. A query the
//! resolver can't place at all (`NotFound` — most commonly a plain
//! substring nobody typed as a full grammar token) falls back to a
//! case-sensitive substring match: a node whose own name contains it keeps
//! every session, otherwise only ITS sessions whose id/petname/label
//! contain it survive. Applies to both groupings — it narrows `nodes`
//! BEFORE the host/project split, so a filter behaves identically either
//! way.
//!
//! ## Project attribution (bare `session`'s own grouping)
//!
//! [`project_bucket`] reuses whichever attribution the codebase already
//! computes — never a third one: a registered `projects.json` name
//! ([`super::model::anchor_for`], longest-prefix, PURE string matching, so
//! it resolves identically for a peer session's cwd under the fleet's
//! shared-path convention the same way `grant.rs`'s peer-spec relativization
//! already leans on) wins when present; else a `.aoide/project.json`
//! manifest found by walking up from the cwd ON THIS HOST'S OWN FILESYSTEM
//! (`aoide_storage::manifest::walk_up`) renders by that directory's own
//! basename — a peer's foreign cwd simply never resolves a manifest here
//! (the walk is real `Path::is_file()` checks against THIS filesystem), so
//! it falls through harmlessly rather than lying about a match. Neither
//! resolving lands the session in the trailing [`NO_PROJECT`] bucket.

use super::model::{resolved_parent, HookRecord, Project, SessionRecord};
use aoide_protocol::output::Outcome;
use aoide_protocol::Invocation;
use aoide_storage::addr::{self, LocalCandidate, Resolution};
use aoide_storage::peer_store::{Peer, PeerCacheEntry};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::Arc;

/// A roster-probe pull closure: given a peer, return its live resolved graph
/// document (`{nodes, edges}`) or a reason it couldn't be fetched. Boxed so
/// production (`aoide_client::commands::pull_peer_live`) and tests (a canned
/// closure) share the exact same call shape.
pub(super) type PullFn = Arc<dyn Fn(&Peer) -> Result<Value, String> + Send + Sync>;

/// One session as the roster renders it — local or remote, uniformly.
/// `pub(super)` (fields too) for three consumers: `session_pick`-turned-
/// `grant.rs`'s undying picker (U3) builds its peer rows off the same
/// [`sessions_from_graph`] extraction rather than re-parsing a peer's cached
/// graph document a second time, and `peer_list.rs`'s mesh roster (task
/// #120 P2) does likewise (this crate's own "no cross-crate copying"
/// discipline, applied in-file).
#[derive(Debug, Clone, PartialEq)]
pub(super) struct SessionView {
    pub(super) session_id: String,
    pub(super) label: String,
    pub(super) petname: Option<String>,
    pub(super) agent: String,
    pub(super) state: String,
    pub(super) presence: &'static str,
    pub(super) cwd: String,
    /// `SessionRecord::exempt` (task #20), carried through for the roster's
    /// one-word tag. Local rows read the real record; a peer row has no
    /// cross-host exempt story yet (`grant.rs`'s module doc — out of scope,
    /// not a regression) and always reads `false`.
    pub(super) exempt: bool,
}

/// One node (this box, or one registered peer) as the host-grouped rendering
/// shows it. `pub(super)` (fields too) for a second consumer: `peer_list.rs`'s
/// mesh roster (task #120 P2) classifies its paired rows off the SAME
/// probe-outcome/cache fold ([`build_peer_node`]) rather than re-deriving a
/// second presence model — same discipline as [`SessionView`]'s widening
/// note above.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct NodeView {
    pub(super) name: String,
    pub(super) is_local: bool,
    pub(super) presence: &'static str,
    pub(super) fetched_at: Option<String>,
    pub(super) error: Option<String>,
    pub(super) sessions: Vec<SessionView>,
}

/// Session-level presence class (module doc's "Presence model").
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
/// (`common::load_inputs`); pure otherwise. `pub(super)` for `peer_list.rs`
/// (see [`NodeView`]'s widening note).
pub(super) fn build_local_node(sessions: &[SessionRecord], hooks: &[HookRecord], host: &str) -> NodeView {
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
                exempt: s.exempt,
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
pub(super) fn sessions_from_graph(graph: &Value, host: &str) -> Vec<SessionView> {
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
                // No cross-host exempt story yet (module doc's widening
                // note on `SessionView::exempt`) — a peer's own graph.json
                // never carries the field either, so this always reads
                // `false`.
                exempt: false,
            }
        })
        .collect()
}

/// Pure: classify one peer's [`NodeView`] from its live-probe OUTCOME and
/// its already-loaded last cache entry (if any) — no I/O in here at all, so
/// it is trivially unit-testable with synthetic data. The caller
/// ([`collect_roster`], and `peer_list.rs`'s `peer_list_with` — see
/// [`NodeView`]'s widening note) does the real
/// `peer_store::load_peer_cache` read and hands the result in.
pub(super) fn build_peer_node(peer: &Peer, probe: Result<Value, String>, cache: Option<PeerCacheEntry>) -> NodeView {
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
/// module's doc, "Presence model"). `pub` (re-exported at `graph.rs`
/// alongside [`session_roster`]) for a second consumer: the conductor's
/// ROSTER panel (P-C4) paints the exact same three glyphs over this same
/// `presence` string and must not redraw its own copy of this map — reuse
/// it instead of forking it (crate `AGENTS.md`'s "no cross-crate copying").
pub fn glyph(presence: &str) -> &'static str {
    match presence {
        "online" => "●",
        "unreachable" => "◐",
        "never-pulled" => "○",
        _ => "?",
    }
}

/// The Unicode HOST-grouped render — mirrors `doc.rs::render`'s glyph/branch
/// style (`◆`/`●`/`├─`/`└─`) so every human surface reads the same grammar.
/// `session --hosts`'s renderer; byte-identical to the retired `who`
/// command's own output.
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
            let tag = if s.exempt { " exempt" } else { "" };
            out.push(format!("{branch}{}  {}  {}  {}{tag}", s.label, s.agent, s.state, s.cwd));
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
            "exempt": s.exempt,
        })).collect::<Vec<_>>(),
    })
}

/// The trailing catch-all bucket name for a session whose cwd resolves
/// neither a registered project nor a manifest (module doc's "Project
/// attribution") — always sorted last in [`group_by_project`]'s output.
const NO_PROJECT: &str = "(no project)";

/// Attribute one session's cwd to a project bucket for bare `session`'s
/// PROJECT-grouped listing — see the module doc's "Project attribution".
/// `None` means neither attribution resolved; the caller buckets that as
/// [`NO_PROJECT`].
pub(super) fn project_bucket(cwd: &str, projects: &[Project]) -> Option<String> {
    if let Some(i) = super::model::anchor_for(cwd, projects) {
        return Some(projects[i].name.clone());
    }
    let path = std::path::Path::new(cwd);
    if !path.is_absolute() {
        // A session's own cwd is always recorded absolute; a stray relative
        // string (malformed input, a test fixture) must never be walked
        // relative to THIS process's own cwd — that would attribute a
        // session by an accident of where the roster command happens to
        // run, not by anything the session itself carries.
        return None;
    }
    let (root, _manifest) = aoide_storage::manifest::walk_up(path)?;
    Some(root.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| root.to_string_lossy().into_owned()))
}

/// One project's bucket in bare `session`'s roster — a registered name, a
/// manifest directory's basename, or the trailing [`NO_PROJECT`] catch-all.
#[derive(Debug, Clone, PartialEq)]
struct ProjectGroup {
    name: String,
    sessions: Vec<SessionView>,
}

/// Fold every node's sessions into project buckets — a single pass over
/// `nodes` in the SAME order [`collect_roster`] built them (local first,
/// then each peer in probe order), so within a bucket session order mirrors
/// the host-grouped rendering's own order. Buckets are sorted
/// alphabetically by name, [`NO_PROJECT`] always trailing last (module
/// doc's "Project attribution" / the task brief's own wording).
fn group_by_project(nodes: Vec<NodeView>, projects: &[Project]) -> Vec<ProjectGroup> {
    let mut order: Vec<String> = Vec::new();
    let mut buckets: std::collections::HashMap<String, Vec<SessionView>> = std::collections::HashMap::new();
    for node in nodes {
        for sv in node.sessions {
            let name = project_bucket(&sv.cwd, projects).unwrap_or_else(|| NO_PROJECT.to_string());
            if !buckets.contains_key(&name) {
                order.push(name.clone());
            }
            buckets.entry(name).or_default().push(sv);
        }
    }
    let mut names: Vec<String> = order.into_iter().filter(|n| n != NO_PROJECT).collect();
    names.sort();
    if buckets.contains_key(NO_PROJECT) {
        names.push(NO_PROJECT.to_string());
    }
    names
        .into_iter()
        .map(|name| {
            let sessions = buckets.remove(&name).unwrap_or_default();
            ProjectGroup { name, sessions }
        })
        .collect()
}

/// The Unicode PROJECT-grouped render — same branch/line grammar
/// [`render_nodes`] uses (`◆`/`├─`/`└─`, `label  agent  state  cwd` per
/// session row), grouped by project bucket instead of by host.
fn render_groups(groups: &[ProjectGroup]) -> String {
    let mut out: Vec<String> = Vec::new();
    for g in groups {
        out.push(format!("◆ {}", g.name));
        for (i, s) in g.sessions.iter().enumerate() {
            let branch = if i + 1 == g.sessions.len() { "└─ " } else { "├─ " };
            let tag = if s.exempt { " exempt" } else { "" };
            out.push(format!("{branch}{}  {}  {}  {}{tag}", s.label, s.agent, s.state, s.cwd));
        }
    }
    if out.is_empty() {
        return "(no local sessions, no peers registered)".to_string();
    }
    out.join("\n")
}

fn group_json(g: &ProjectGroup) -> Value {
    json!({
        "name": g.name,
        "sessions": g.sessions.iter().map(|s| json!({
            "sessionId": s.session_id,
            "label": s.label,
            "petname": s.petname,
            "agent": s.agent,
            "state": s.state,
            "presence": s.presence,
            "cwd": s.cwd,
            "exempt": s.exempt,
        })).collect::<Vec<_>>(),
    })
}

/// Everything bare `session`'s two renderings share before they diverge —
/// local sessions/hooks/projects loaded once (`common::load_inputs`), every
/// registered peer probed LIVE exactly as the retired `who` command did
/// (module doc's "Presence model"). `host`/`--hosts` rendering and the
/// PROJECT rendering both call this and then diverge purely on how they
/// group/render `nodes`.
pub(super) struct Roster {
    pub(super) host: String,
    pub(super) projects: Vec<Project>,
    pub(super) locals: Vec<SessionRecord>,
    pub(super) nodes: Vec<NodeView>,
}

pub(super) fn collect_roster(cmd: &str, pull: PullFn) -> Result<Roster, Outcome> {
    let (p, s, h) = super::common::load_inputs(cmd)?;
    let host = aoide_storage::display::local_host_name();
    let local_node = build_local_node(&s.sessions, &h.hooks, &host);

    let peers = aoide_storage::peer_store::load_peers();
    let probed = probe_peers(&peers, pull);

    let mut nodes = vec![local_node];
    for (peer, result) in probed {
        let cache = aoide_storage::peer_store::load_peer_cache(&peer.name);
        nodes.push(build_peer_node(&peer, result, cache));
    }

    Ok(Roster { host, projects: p.projects, locals: s.sessions, nodes })
}

/// Per-peer live-probe timeout (module doc's presence model — "short
/// per-peer timeout ~2s"). One named constant rather than a magic number at
/// the two call sites that need it ([`session_roster`] below, and
/// `peer_list.rs`'s own production entry — the SAME probe, so the SAME
/// bound).
pub(super) const PEER_PROBE_TIMEOUT_SECS: u64 = 2;

/// The testable core: everything `session`'s bare listing does EXCEPT
/// choosing the real `pull` closure. `--hosts` renders exactly what the
/// retired `who` command used to (byte-identical message/JSON shape);
/// without it, sessions group by PROJECT instead. `filter`/`--all` apply to
/// either grouping, narrowing `nodes` BEFORE the host/project split.
pub(super) fn session_roster_with(inv: &Invocation, pull: PullFn) -> Outcome {
    let cmd = "session";
    let Roster { host, projects, locals, mut nodes } = match collect_roster(cmd, pull) {
        Ok(r) => r,
        Err(e) => return e,
    };

    let filter = inv.args.first().map(|a| a.trim()).filter(|a| !a.is_empty());
    if let Some(f) = filter {
        nodes = apply_filter(f, &host, nodes, &locals);
    }

    if !inv.flag_present("all") {
        for n in &mut nodes {
            n.sessions.retain(|sv| sv.presence != "done");
        }
    }

    if inv.flag_present("hosts") {
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
    } else {
        let groups = group_by_project(nodes, &projects);
        let total_sessions: usize = groups.iter().map(|g| g.sessions.len()).sum();
        let message = format!(
            "{} project(s), {} session(s)\n{}",
            groups.len(),
            total_sessions,
            render_groups(&groups)
        );
        let data = json!({
            "host": host,
            "generatedAt": aoide_storage::time::now_iso_utc(),
            "projects": groups.iter().map(group_json).collect::<Vec<_>>(),
        });
        Outcome::ok(cmd, message).with_data(data)
    }
}

/// `aoide session [filter] [--hosts] [--json] [--all]` — the real entry
/// point: wires the live probe to `aoide_client::commands::pull_peer_live`
/// (the SAME transport `peer pull` uses, per the crate's `Cargo.toml` note
/// on the `conduct → client` edge) and hands off to
/// [`session_roster_with`].
pub fn session_roster(inv: &Invocation) -> Outcome {
    let pull: PullFn = Arc::new(|p: &Peer| aoide_client::commands::pull_peer_live(p, PEER_PROBE_TIMEOUT_SECS));
    session_roster_with(inv, pull)
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
            bearer_secret: None,
            hub: false,
            pubkey: None,
            verified: false,
            allows: Vec::new(),
            via: None,
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

    fn project(name: &str, path: &str) -> Project {
        Project { name: name.to_string(), path: path.to_string(), ..Default::default() }
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

    // ── exempt (task #20): build_local_node carries the flag, both text
    // renders tag the row ──────────────────────────────────────────────

    #[test]
    fn build_local_node_carries_the_exempt_flag_off_the_record() {
        let sessions = vec![
            SessionRecord { exempt: true, ..session("s1", "/x", "idle", "1", None) },
            session("s2", "/x", "idle", "2", None),
        ];
        let node = build_local_node(&sessions, &[], "sakaki");
        let s1 = node.sessions.iter().find(|s| s.session_id == "s1").unwrap();
        let s2 = node.sessions.iter().find(|s| s.session_id == "s2").unwrap();
        assert!(s1.exempt);
        assert!(!s2.exempt);
    }

    #[test]
    fn render_nodes_tags_an_exempt_row_and_leaves_an_ordinary_one_bare() {
        let nodes = vec![NodeView {
            name: "sakaki".to_string(),
            is_local: true,
            presence: "online",
            fetched_at: None,
            error: None,
            sessions: vec![
                SessionView { session_id: "s1".into(), label: "l1".into(), petname: None, agent: "claude".into(), state: "idle".into(), presence: "online", cwd: "/x".into(), exempt: true },
                SessionView { session_id: "s2".into(), label: "l2".into(), petname: None, agent: "claude".into(), state: "idle".into(), presence: "online", cwd: "/x".into(), exempt: false },
            ],
        }];
        let rendered = render_nodes(&nodes);
        let lines: Vec<&str> = rendered.lines().collect();
        assert!(lines[1].ends_with(" exempt"), "{}", lines[1]);
        assert!(!lines[2].ends_with(" exempt"), "{}", lines[2]);
    }

    #[test]
    fn render_groups_tags_an_exempt_row_the_same_way() {
        let groups = vec![ProjectGroup {
            name: "aoide".to_string(),
            sessions: vec![SessionView {
                session_id: "s1".into(),
                label: "l1".into(),
                petname: None,
                agent: "claude".into(),
                state: "idle".into(),
                presence: "online",
                cwd: "/x".into(),
                exempt: true,
            }],
        }];
        let rendered = render_groups(&groups);
        assert!(rendered.lines().last().unwrap().ends_with(" exempt"), "{rendered}");
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
                exempt: false,
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

    // ── project_bucket / group_by_project: attribution + trailing bucket ──

    #[test]
    fn project_bucket_prefers_a_registered_project_over_a_manifest() {
        let projects = vec![project("aoide", "/home/k/Aoide")];
        assert_eq!(project_bucket("/home/k/Aoide/pkgs/aoide", &projects), Some("aoide".to_string()));
    }

    #[test]
    fn project_bucket_falls_back_to_a_manifest_directorys_own_basename() {
        let root = std::env::temp_dir().join(format!("aoide-who-manifest-bucket-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        aoide_storage::manifest::save_manifest(&root, &aoide_storage::manifest::Manifest::default()).unwrap();

        let nested = root.join("sub");
        std::fs::create_dir_all(&nested).unwrap();
        let bucket = project_bucket(nested.to_str().unwrap(), &[]);
        assert_eq!(bucket, root.file_name().map(|n| n.to_string_lossy().into_owned()));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn project_bucket_is_none_with_neither_a_registered_project_nor_a_manifest() {
        let root = std::env::temp_dir().join(format!("aoide-who-no-project-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        assert_eq!(project_bucket(root.to_str().unwrap(), &[]), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn group_by_project_sorts_named_buckets_alphabetically_with_no_project_trailing() {
        let nodes = vec![NodeView {
            name: "sakaki".to_string(),
            is_local: true,
            presence: "online",
            fetched_at: None,
            error: None,
            sessions: vec![
                SessionView { session_id: "s1".into(), label: "l1".into(), petname: None, agent: "claude".into(), state: "working".into(), presence: "online", cwd: "/z/nowhere".into(), exempt: false },
                SessionView { session_id: "s2".into(), label: "l2".into(), petname: None, agent: "claude".into(), state: "working".into(), presence: "online", cwd: "/proj/zeta/x".into(), exempt: false },
                SessionView { session_id: "s3".into(), label: "l3".into(), petname: None, agent: "claude".into(), state: "working".into(), presence: "online", cwd: "/proj/alpha/x".into(), exempt: false },
            ],
        }];
        let projects = vec![project("zeta", "/proj/zeta"), project("alpha", "/proj/alpha")];
        let groups = group_by_project(nodes, &projects);
        let names: Vec<&str> = groups.iter().map(|g| g.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "zeta", NO_PROJECT]);
        assert_eq!(groups[2].sessions[0].session_id, "s1");
    }

    #[test]
    fn group_by_project_attributes_a_remote_sessions_cwd_the_same_host_agnostic_way() {
        // A peer's session cwd matching a LOCALLY-registered project's path
        // string (the fleet's shared-path convention, `grant.rs`'s own peer
        // relativization leans on the same thing) attributes purely by
        // string match — no filesystem access, so it works identically for
        // a foreign host's cwd.
        let nodes = vec![NodeView {
            name: "yomi-strix".to_string(),
            is_local: false,
            presence: "online",
            fetched_at: None,
            error: None,
            sessions: vec![SessionView {
                session_id: "r1".into(),
                label: "yomi-strix/root/r1".into(),
                petname: None,
                agent: "claude".into(),
                state: "working".into(),
                presence: "online",
                cwd: "/home/k/Aoide/pkgs/aoide".into(),
                exempt: false,
            }],
        }];
        let projects = vec![project("aoide", "/home/k/Aoide")];
        let groups = group_by_project(nodes, &projects);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].name, "aoide");
    }

    // ── session_roster_with: the full pipeline, injected pull, real local stage I/O ──

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

    fn hosts_invocation(args: &[&str], flags: &[(&str, &str)]) -> Invocation {
        let mut f: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::from([("hosts".to_string(), "true".to_string())]);
        for (k, v) in flags {
            f.insert(k.to_string(), v.to_string());
        }
        Invocation {
            path: vec!["session".into()],
            args: args.iter().map(|s| s.to_string()).collect(),
            flags: f,
            door: aoide_protocol::Door::Cli,
        }
    }

    #[test]
    fn hosts_mode_reports_local_sessions_with_no_peers_registered() {
        let _env = Env::set_up("no-peers");
        let sf = super::super::model::SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![session("s1", "/x", "working", "1", None)],
        };
        super::super::model::write_stage(&super::super::model::sessions_path(), &sf).unwrap();

        let out = session_roster_with(&hosts_invocation(&[], &[]), never_called_pull());
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let data = out.data.unwrap();
        let nodes = data["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 1, "local node only");
        assert_eq!(nodes[0]["presence"], "online");
        assert_eq!(nodes[0]["sessions"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn hosts_mode_omits_done_sessions_unless_all_is_passed() {
        let _env = Env::set_up("done-omitted");
        let sf = super::super::model::SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![
                session("s1", "/x", "working", "1", None),
                session("s2", "/x", "done", "2", None),
            ],
        };
        super::super::model::write_stage(&super::super::model::sessions_path(), &sf).unwrap();

        let out = session_roster_with(&hosts_invocation(&[], &[]), never_called_pull());
        let data = out.data.unwrap();
        assert_eq!(data["nodes"][0]["sessions"].as_array().unwrap().len(), 1, "done is omitted");

        let out_all = session_roster_with(&hosts_invocation(&[], &[("all", "true")]), never_called_pull());
        let data_all = out_all.data.unwrap();
        assert_eq!(data_all["nodes"][0]["sessions"].as_array().unwrap().len(), 2, "--all keeps done");
    }

    #[test]
    fn hosts_mode_probes_every_registered_peer_and_classifies_by_outcome() {
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
        let out = session_roster_with(&hosts_invocation(&[], &[]), pull);
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
    fn hosts_mode_filter_never_changes_which_peers_get_probed() {
        let _env = Env::set_up("filter-probes-all");
        aoide_storage::peer_store::save_peers(&[peer("alpha"), peer("beta")]).unwrap();
        let probed = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let probed2 = Arc::clone(&probed);
        let pull: PullFn = Arc::new(move |p: &Peer| {
            probed2.lock().unwrap().push(p.name.clone());
            Ok(json!({ "nodes": [], "edges": [] }))
        });
        // A filter that only displays "alpha" must still have probed "beta".
        let out = session_roster_with(&hosts_invocation(&["alpha"], &[]), pull);
        let mut names = probed.lock().unwrap().clone();
        names.sort();
        assert_eq!(names, vec!["alpha".to_string(), "beta".to_string()], "every peer was probed");
        let data = out.data.unwrap();
        let nodes = data["nodes"].as_array().unwrap();
        assert!(nodes.iter().all(|n| n["name"] != "beta"), "but only alpha is displayed");
    }

    // ── session_roster_with: PROJECT grouping (bare, no --hosts) ──────────

    fn project_invocation() -> Invocation {
        flag_invocation(&["session"], &[])
    }

    #[test]
    fn bare_mode_groups_local_sessions_by_registered_project() {
        let _env = Env::set_up("project-grouping");
        let sf = super::super::model::SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![session("s1", "/proj/aoide/sub", "working", "1", None)],
        };
        super::super::model::write_stage(&super::super::model::sessions_path(), &sf).unwrap();
        let pf = super::super::model::ProjectsFile {
            schema_version: "0".to_string(),
            projects: vec![project("aoide", "/proj/aoide")],
        };
        super::super::model::write_stage(&super::super::model::projects_path(), &pf).unwrap();

        let out = session_roster_with(&project_invocation(), never_called_pull());
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let data = out.data.unwrap();
        let projects = data["projects"].as_array().unwrap();
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0]["name"], "aoide");
        assert_eq!(projects[0]["sessions"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn bare_mode_groups_a_manifest_only_dir_by_its_own_basename() {
        let _env = Env::set_up("project-grouping-manifest");
        let manifest_root = std::env::temp_dir().join(format!("aoide-who-manifest-only-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&manifest_root);
        std::fs::create_dir_all(&manifest_root).unwrap();
        aoide_storage::manifest::save_manifest(&manifest_root, &aoide_storage::manifest::Manifest::default()).unwrap();

        let cwd = manifest_root.to_string_lossy().into_owned();
        let sf = super::super::model::SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![session("s1", &cwd, "working", "1", None)],
        };
        super::super::model::write_stage(&super::super::model::sessions_path(), &sf).unwrap();

        let out = session_roster_with(&project_invocation(), never_called_pull());
        let data = out.data.unwrap();
        let projects = data["projects"].as_array().unwrap();
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0]["name"], manifest_root.file_name().unwrap().to_string_lossy().to_string());

        let _ = std::fs::remove_dir_all(&manifest_root);
    }

    #[test]
    fn bare_mode_buckets_a_session_matching_neither_attribution_as_no_project() {
        let _env = Env::set_up("project-grouping-none");
        let lonely = std::env::temp_dir().join(format!("aoide-who-lonely-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&lonely);
        std::fs::create_dir_all(&lonely).unwrap();

        let cwd = lonely.to_string_lossy().into_owned();
        let sf = super::super::model::SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![session("s1", &cwd, "working", "1", None)],
        };
        super::super::model::write_stage(&super::super::model::sessions_path(), &sf).unwrap();

        let out = session_roster_with(&project_invocation(), never_called_pull());
        let data = out.data.unwrap();
        let projects = data["projects"].as_array().unwrap();
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0]["name"], NO_PROJECT);

        let _ = std::fs::remove_dir_all(&lonely);
    }

    #[test]
    fn bare_mode_attributes_a_remote_session_to_a_registered_project_by_cwd() {
        let _env = Env::set_up("project-grouping-remote");
        let pf = super::super::model::ProjectsFile {
            schema_version: "0".to_string(),
            projects: vec![project("aoide", "/home/k/Aoide")],
        };
        super::super::model::write_stage(&super::super::model::projects_path(), &pf).unwrap();
        aoide_storage::peer_store::save_peers(&[peer("yomi-strix")]).unwrap();

        let pull: PullFn = Arc::new(|_: &Peer| Ok(peer_graph(&[("r1", "working", "/home/k/Aoide/pkgs/aoide", None)])));
        let out = session_roster_with(&project_invocation(), pull);
        let data = out.data.unwrap();
        let projects = data["projects"].as_array().unwrap();
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0]["name"], "aoide");
        assert_eq!(projects[0]["sessions"][0]["sessionId"], "r1");
    }
}
