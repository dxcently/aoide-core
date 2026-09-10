//! `aoide node list [--json]` — the one-glance mesh roster (task #120 P2,
//! User riders 4/5/6): every known node on one screen — this host, every
//! registered node, and every advertising instance heard on the LAN — one
//! row each, with its running sessions indented beneath. `node status`
//! keeps the deep per-node registry detail (full `Node` row + cache
//! staleness); this command is the wide shallow view, not a second copy of
//! that one.
//!
//! ## Reuse, not a second prober
//!
//! Everything here is a PURE fold ([`assemble_roster`]) over three inputs
//! other modules already own the machinery for:
//!
//! - **Presence + sessions** come from `who.rs`'s own roster core, called
//!   directly: [`probe_nodes`] (one bounded live pull per registered node,
//!   in parallel), [`build_mesh_node`] (probe-outcome/cache-fallback
//!   classification), [`build_local_node`] (this box's own stage). The
//!   probe closure is `session --hosts`'s exact production wiring (the
//!   retired standalone `who` command's own wiring, unchanged —
//!   `aoide_client::commands::pull_node_live`, [`NODE_PROBE_TIMEOUT_SECS`])
//!   — never a re-implementation, so `session --hosts` and `node list` can
//!   never disagree about which nodes are up.
//! - **Advertising instances** come from ONE bounded discovery sweep —
//!   `aoide_client::discover::run_sweep` ([`SWEEP_SECS`], P-P6/task #120's
//!   validated, deduped, [`aoide_client::discover::MAX_HEARD`]-capped
//!   fold), run CONCURRENTLY with the probes so the wall clock stays ~one
//!   window, not two. An empty sweep is normal (a default-deny firewall
//!   eats broadcast datagrams before any socket sees them —
//!   `modules/nucleus/aoided.nix`'s documented asymmetry); even a sweep
//!   that cannot LISTEN (bind failure) only annotates the roster
//!   (`data.sweep.error` + one trailing line), never fails the command —
//!   the paired half of the roster is still true.
//! - **Node rows** come from `aoide_storage::node_store` — `node status`'s
//!   own source.
//!
//! A heard advertisement is UNTRUSTED display data: it reaches this module
//! only through `run_sweep`, which admits nothing
//! `aoide_storage::advertise::parse_and_validate` refused, and the roster
//! renders only the validated `name` plus the OBSERVED source address —
//! never the claimed hop as a dial target (PAIRING.md's claim-vs-fact
//! rule). Discovery still grants nothing: an unknown advertiser renders as
//! a `◆` pair CANDIDATE row and nothing else — nothing here writes
//! `state/nodes.json` or `state/node-cache/`.
//!
//! ## The mark grammar
//!
//! `●` paired (or this host) and online · `○` paired but offline
//! (unreachable or never pulled) · `◆` advertising — appended to a paired
//! row's mark (`●◆`/`○◆`) when a heard name matches it, standing alone for
//! an unpaired candidate. The local row is marked advertising when the
//! sweep heard this instance itself (`discover::is_self_target` — the same
//! name/loopback guard `node invite` uses), and a self-heard advertisement
//! never becomes a candidate row.

use super::who::{
    build_local_node, build_mesh_node, probe_nodes, NodeView, PullFn, SessionView,
    NODE_PROBE_TIMEOUT_SECS,
};
use aoide_client::discover::{is_self_target, Heard, SweepResult};
use aoide_protocol::output::Outcome;
use aoide_protocol::Invocation;
use aoide_storage::node_store::Node;
use serde_json::{json, Value};
use std::sync::Arc;

/// The roster's sweep seam, mirroring `who.rs`'s `PullFn`: production wires
/// it to `aoide_client::discover::run_sweep` ([`SWEEP_SECS`]), tests inject
/// a closure returning canned heard-sets instantly — the only way the
/// sweep-window behavior is exercisable in a sandbox with no real
/// broadcast socket. `FnOnce` (boxed, not `Arc`d): one command runs one
/// sweep.
pub(super) type SweepFn = Box<dyn FnOnce() -> Result<SweepResult, String> + Send>;

/// One roster row — this host, a registered node, or an unpaired
/// advertiser. `presence` carries `who.rs`'s own three-way node vocabulary
/// (`online`/`unreachable`/`never-pulled`) for paired rows; a candidate row
/// is `online` by construction (it was heard within this very sweep).
#[derive(Debug, Clone, PartialEq)]
struct Row {
    name: String,
    is_local: bool,
    paired: bool,
    verified: bool,
    advertising: bool,
    presence: &'static str,
    /// The row's reachable address: for an ONLINE paired node its `via`
    /// ssh marker when set, else its registered `url` (doors are
    /// loopback-bound, so a tunneled node's `url` is `127.0.0.1` — the
    /// `via` hop is the address that actually distinguishes it); the
    /// observed sweep source for a candidate; `None` (rendered `—`) for
    /// this host and for an offline node.
    addr: Option<String>,
    /// An offline paired row's cache `fetchedAt` — both the "last seen"
    /// in its status text and the "as of" label on its cached sessions.
    last_seen: Option<String>,
    sessions: Vec<SessionView>,
}

/// The row's glance mark — see the module doc's "mark grammar".
fn mark(r: &Row) -> String {
    let mut m = String::new();
    if r.is_local || r.paired {
        m.push(if r.presence == "online" { '●' } else { '○' });
    }
    if r.advertising {
        m.push('◆');
    }
    m
}

/// The row's status column — `this host` / `paired · online` / `paired ·
/// last seen <when>` / `paired · never pulled` / `advertising · unpaired`,
/// with ` · advertising` appended to a paired/local row the sweep heard.
fn status_text(r: &Row) -> String {
    let mut s = if r.is_local {
        "this host".to_string()
    } else if r.paired {
        match r.presence {
            "online" => "paired · online".to_string(),
            "never-pulled" => "paired · never pulled".to_string(),
            _ => format!("paired · last seen {}", r.last_seen.as_deref().unwrap_or("unknown")),
        }
    } else {
        "advertising · unpaired".to_string()
    };
    if r.advertising && (r.is_local || r.paired) {
        s.push_str(" · advertising");
    }
    s
}

/// THE pure fold (the brief's testable core): local node + per-node
/// probe/cache classifications + one sweep's heard-set → the ordered row
/// list. Order is fixed: this host first, registered nodes in registry
/// order, unknown advertisers in heard order. No I/O.
fn assemble_roster(
    local: NodeView,
    nodes: Vec<(Node, NodeView)>,
    heard: &[Heard],
    host: &str,
) -> Vec<Row> {
    let mut rows = Vec::with_capacity(1 + nodes.len() + heard.len());
    rows.push(Row {
        name: local.name,
        is_local: true,
        paired: false,
        verified: false,
        advertising: heard.iter().any(|h| is_self_target(h, host)),
        presence: local.presence,
        addr: None,
        last_seen: None,
        sessions: local.sessions,
    });
    let node_names: Vec<String> = nodes.iter().map(|(p, _)| p.name.clone()).collect();
    for (mesh_node, node) in nodes {
        let advertising = heard.iter().any(|h| h.advertisement.name == node.name);
        let addr = (node.presence == "online")
            .then(|| mesh_node.via.clone().unwrap_or_else(|| mesh_node.url.clone()));
        rows.push(Row {
            name: node.name,
            is_local: false,
            paired: true,
            verified: mesh_node.verified,
            advertising,
            presence: node.presence,
            addr,
            last_seen: node.fetched_at,
            sessions: node.sessions,
        });
    }
    // The candidates: heard, not self, not registered. `heard` is already
    // distinct by (name, source) and MAX_HEARD-bounded (`run_sweep`'s own
    // fold) — two sources claiming one name stay two rows here for
    // UNPAIRED names, exactly as `node discover` keeps an impostor
    // visible beside the real thing. A heard name matching a PAIRED node
    // instead folds into that node's row as its advertising mark (above)
    // and its observed source is not rendered — a spoofer can light a
    // paired row's advertising mark, never touch its addr/verified/paired
    // fields (those come only from the registry and the probe).
    for h in heard {
        if is_self_target(h, host) || node_names.iter().any(|n| *n == h.advertisement.name) {
            continue;
        }
        rows.push(Row {
            name: h.advertisement.name.clone(),
            is_local: false,
            paired: false,
            verified: false,
            advertising: true,
            presence: "online",
            addr: Some(h.src_addr.clone()),
            last_seen: None,
            sessions: Vec::new(),
        });
    }
    rows
}

/// One session's roster identity: the petname when minted, `…<tail4>`
/// otherwise — the rider-6 "petname/short-id" column, off the same
/// `short_tail` every display grammar uses.
fn session_ident(s: &SessionView) -> String {
    match s.petname.as_deref() {
        Some(p) => p.to_string(),
        None => format!("…{}", aoide_storage::display::short_tail(&s.session_id)),
    }
}

/// The aligned human roster — `doc.rs`/`who.rs`'s glyph/branch grammar
/// (`●`/`○`/`◆`, `├─`/`└─`), columns padded so the whole mesh reads at one
/// glance. Cached sessions under an offline row carry `(as of <fetchedAt>)`.
fn render_roster(rows: &[Row]) -> String {
    let width = |s: &str| s.chars().count();
    let mark_w = rows.iter().map(|r| width(&mark(r))).max().unwrap_or(1);
    let name_w = rows.iter().map(|r| width(&r.name)).max().unwrap_or(0);
    let addr_w = rows.iter().map(|r| width(r.addr.as_deref().unwrap_or("—"))).max().unwrap_or(1);
    let mut out: Vec<String> = Vec::new();
    for r in rows {
        let m = mark(r);
        let addr = r.addr.as_deref().unwrap_or("—");
        out.push(format!(
            "{m}{}  {}{}  {addr}{}  {}",
            " ".repeat(mark_w - width(&m)),
            r.name,
            " ".repeat(name_w - width(&r.name)),
            " ".repeat(addr_w - width(addr)),
            status_text(r),
        ));
        let as_of = (r.paired && r.presence != "online" && !r.sessions.is_empty())
            .then(|| format!("  (as of {})", r.last_seen.as_deref().unwrap_or("unknown")))
            .unwrap_or_default();
        for (i, s) in r.sessions.iter().enumerate() {
            let branch = if i + 1 == r.sessions.len() { "└─" } else { "├─" };
            out.push(format!("   {branch} {}  {}  {}{as_of}", s.agent, s.state, session_ident(s)));
        }
    }
    out.join("\n")
}

fn row_json(r: &Row) -> Value {
    json!({
        "mark": mark(r),
        "name": r.name,
        "isLocal": r.is_local,
        "paired": r.paired,
        "verified": r.verified,
        "advertising": r.advertising,
        "presence": r.presence,
        "addr": r.addr,
        "lastSeen": r.last_seen,
        "sessions": r.sessions.iter().map(|s| json!({
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

/// The testable core, `who.rs::session_roster_with`'s exact shape one seam
/// wider: real local stage + node-store I/O, but BOTH network-shaped steps —
/// the per-node probes and the discovery sweep — arrive injected, so a test
/// never opens a socket. The sweep runs on its own thread beside the probe
/// fan-out (both are ~2s walls; serial would double the command's latency
/// for nothing).
pub(super) fn node_list_with(_inv: &Invocation, pull: PullFn, sweep: SweepFn) -> Outcome {
    let cmd = "node.list";
    let (_, s, h) = match super::common::load_inputs(cmd) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let host = aoide_storage::display::local_host_name();
    let sweep_handle = std::thread::spawn(sweep);

    let local = build_local_node(&s.sessions, &h.hooks, &host);
    let nodes = aoide_storage::node_store::load_nodes();
    let probed = probe_nodes(&nodes, pull);
    let mesh_nodes: Vec<(Node, NodeView)> = probed
        .into_iter()
        .map(|(mesh_node, result)| {
            let cache = aoide_storage::node_store::load_node_cache(&mesh_node.name);
            let node = build_mesh_node(&mesh_node, result, cache);
            (mesh_node, node)
        })
        .collect();

    let sweep_result =
        sweep_handle.join().unwrap_or_else(|_| Err("sweep thread panicked".to_string()));
    let (heard, dropped, sweep_error) = match sweep_result {
        Ok(r) => (r.heard, r.dropped, None),
        Err(e) => (Vec::new(), 0, Some(e)),
    };

    let mut rows = assemble_roster(local, mesh_nodes, &heard, &host);
    // RUNNING sessions (rider 6) — `done` never makes the roster (`session`'s
    // default view, minus its `--all` escape: the deep view owns that).
    for r in &mut rows {
        r.sessions.retain(|sv| sv.presence != "done");
    }

    let total_sessions: usize = rows.iter().map(|r| r.sessions.len()).sum();
    let mut message =
        format!("{} node(s), {} session(s)\n{}", rows.len(), total_sessions, render_roster(&rows));
    if let Some(e) = &sweep_error {
        message.push_str(&format!("\nsweep unavailable — {e}"));
    }
    let sweep_json = match &sweep_error {
        Some(e) => json!({ "error": e }),
        None => json!({ "heard": heard.len(), "dropped": dropped }),
    };
    let data = json!({
        "host": host,
        "generatedAt": aoide_storage::time::now_iso_utc(),
        "nodes": rows.iter().map(row_json).collect::<Vec<_>>(),
        "sweep": sweep_json,
    });
    Outcome::ok(cmd, message).with_data(data)
}

/// The sweep's listen window — short (the brief's ~2s): the roster wants
/// "who is advertising right now", not `node discover`'s fuller default
/// window, and advertisers repeat on a ~30s cadence either way, so any
/// single window is a sample, never a census.
const SWEEP_SECS: u64 = 2;

/// `aoide node list [--json]` — the real entry point: the roster core's
/// exact probe wiring (`session --hosts`'s own — the retired `who`
/// command's wiring, unchanged) plus one real `run_sweep`, handed to
/// [`node_list_with`].
pub fn node_list(inv: &Invocation) -> Outcome {
    let pull: PullFn =
        Arc::new(|p: &Node| aoide_client::commands::pull_node_live(p, NODE_PROBE_TIMEOUT_SECS));
    let sweep: SweepFn = Box::new(|| {
        aoide_client::discover::run_sweep(SWEEP_SECS)
            .map_err(|e| aoide_client::discover::describe_sweep_error(&e))
    });
    node_list_with(inv, pull, sweep)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::testutil::*;
    use aoide_storage::advertise::Advertisement;
    use aoide_storage::node_store::NodeCacheEntry;

    fn mesh_node(name: &str) -> Node {
        Node {
            name: name.to_string(),
            url: format!("http://{name}:8710/"),
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

    fn heard(name: &str, src: &str) -> Heard {
        Heard {
            advertisement: Advertisement {
                v: 2,
                name: name.to_string(),
                host: format!("{name}.lan"),
                user: "k".to_string(),
            },
            src_addr: src.to_string(),
            first_heard: "2026-08-28T00:00:00Z".to_string(),
            last_heard: "2026-08-28T00:00:01Z".to_string(),
            count: 1,
        }
    }

    fn sv(id: &str, state: &str, petname: Option<&str>) -> SessionView {
        SessionView {
            session_id: id.to_string(),
            label: format!("x/root/{id}"),
            petname: petname.map(String::from),
            agent: "claude".to_string(),
            state: state.to_string(),
            presence: if state == "done" { "done" } else { "online" },
            cwd: "/x".to_string(),
            project: None,
            exempt: false,
        }
    }

    fn local_node(host: &str, sessions: Vec<SessionView>) -> NodeView {
        NodeView {
            name: host.to_string(),
            is_local: true,
            presence: "online",
            fetched_at: None,
            error: None,
            sessions,
        }
    }

    fn node_graph(sessions: &[(&str, &str, Option<&str>)]) -> Value {
        let nodes: Vec<Value> = sessions
            .iter()
            .map(|(id, state, petname)| {
                let mut n = json!({ "id": format!("session:{id}"), "kind": "session", "state": state, "cwd": "/y", "agent": "claude" });
                if let Some(p) = petname {
                    n["petname"] = json!(p);
                }
                n
            })
            .collect();
        json!({ "schemaVersion": "0", "nodes": nodes, "edges": [] })
    }

    fn cache(name: &str, fetched_at: &str, graph: Value) -> NodeCacheEntry {
        NodeCacheEntry {
            schema_version: "0".to_string(),
            name: name.to_string(),
            instance: None,
            graph: Some(graph),
            fetched_at: Some(fetched_at.to_string()),
            stale: false,
            last_error: None,
        }
    }

    // ── assemble_roster: every mark combination ──────────────────────────

    #[test]
    fn paired_online_row_is_a_filled_dot_with_the_registered_url() {
        let p = mesh_node("sakaki");
        let node = build_mesh_node(&p, Ok(node_graph(&[("s1", "working", None)])), None);
        let rows = assemble_roster(local_node("yomi", vec![]), vec![(p, node)], &[], "yomi");
        let r = &rows[1];
        assert_eq!(mark(r), "●");
        assert_eq!(status_text(r), "paired · online");
        assert_eq!(r.addr.as_deref(), Some("http://sakaki:8710/"));
        assert_eq!(r.sessions.len(), 1);
    }

    #[test]
    fn an_online_tunneled_nodes_addr_is_its_via_hop_not_its_loopback_url() {
        let mut p = mesh_node("sakaki");
        p.url = "http://127.0.0.1:8710/".to_string();
        p.via = Some("ssh://k@192.168.1.202".to_string());
        let node = build_mesh_node(&p, Ok(node_graph(&[])), None);
        let rows = assemble_roster(local_node("yomi", vec![]), vec![(p, node)], &[], "yomi");
        assert_eq!(rows[1].addr.as_deref(), Some("ssh://k@192.168.1.202"));
    }

    #[test]
    fn paired_offline_row_is_a_hollow_dot_with_last_seen_and_no_addr() {
        let p = mesh_node("chiyo");
        let node = build_mesh_node(
            &p,
            Err("HTTP 000".to_string()),
            Some(cache("chiyo", "2026-08-27T10:00:00Z", node_graph(&[("s2", "idle", None)]))),
        );
        let rows = assemble_roster(local_node("yomi", vec![]), vec![(p, node)], &[], "yomi");
        let r = &rows[1];
        assert_eq!(mark(r), "○");
        assert_eq!(status_text(r), "paired · last seen 2026-08-27T10:00:00Z");
        assert!(r.addr.is_none());
        assert_eq!(r.sessions.len(), 1, "last-known sessions still attach");
    }

    #[test]
    fn paired_never_pulled_row_says_so_instead_of_a_fake_last_seen() {
        let p = mesh_node("osaka");
        let node = build_mesh_node(&p, Err("unreachable".to_string()), None);
        let rows = assemble_roster(local_node("yomi", vec![]), vec![(p, node)], &[], "yomi");
        assert_eq!(mark(&rows[1]), "○");
        assert_eq!(status_text(&rows[1]), "paired · never pulled");
    }

    #[test]
    fn advertising_marks_ride_on_paired_rows_online_and_offline() {
        let up = mesh_node("sakaki");
        let up_node = build_mesh_node(&up, Ok(node_graph(&[])), None);
        let down = mesh_node("chiyo");
        let down_node = build_mesh_node(&down, Err("down".to_string()), None);
        let heard = [heard("sakaki", "192.168.1.20"), heard("chiyo", "192.168.1.30")];
        let rows = assemble_roster(
            local_node("yomi", vec![]),
            vec![(up, up_node), (down, down_node)],
            &heard,
            "yomi",
        );
        assert_eq!(mark(&rows[1]), "●◆");
        assert_eq!(status_text(&rows[1]), "paired · online · advertising");
        assert_eq!(mark(&rows[2]), "○◆");
        assert_eq!(status_text(&rows[2]), "paired · never pulled · advertising");
        assert_eq!(rows.len(), 3, "a heard name matching a node never doubles as a candidate");
    }

    #[test]
    fn unknown_advertiser_becomes_a_candidate_row_with_the_observed_source() {
        let heard = [heard("stranger", "192.168.1.99")];
        let rows = assemble_roster(local_node("yomi", vec![]), vec![], &heard, "yomi");
        assert_eq!(rows.len(), 2);
        let r = &rows[1];
        assert_eq!(mark(r), "◆");
        assert_eq!(status_text(r), "advertising · unpaired");
        assert_eq!(r.addr.as_deref(), Some("192.168.1.99"), "observed source, never the claim");
        assert!(!r.paired);
        assert!(r.sessions.is_empty());
    }

    #[test]
    fn two_sources_claiming_one_unknown_name_stay_two_visible_candidate_rows() {
        // `run_sweep` dedupes by (name, source) — an impostor beside the
        // real thing must stay visible here too, never merged by name.
        let heard = [heard("stranger", "192.168.1.99"), heard("stranger", "192.168.1.98")];
        let rows = assemble_roster(local_node("yomi", vec![]), vec![], &heard, "yomi");
        assert_eq!(rows.len(), 3);
    }

    #[test]
    fn a_self_heard_advertisement_marks_the_local_row_and_never_a_candidate() {
        let heard = [heard("yomi", "192.168.1.175")];
        let rows = assemble_roster(local_node("yomi", vec![sv("s1", "working", None)]), vec![], &heard, "yomi");
        assert_eq!(rows.len(), 1, "self is never a candidate row");
        assert_eq!(mark(&rows[0]), "●◆");
        assert_eq!(status_text(&rows[0]), "this host · advertising");
    }

    #[test]
    fn the_local_row_leads_the_roster_as_this_host() {
        let rows = assemble_roster(local_node("yomi", vec![sv("s1", "working", Some("brave-otter"))]), vec![], &[], "yomi");
        assert!(rows[0].is_local);
        assert_eq!(mark(&rows[0]), "●");
        assert_eq!(status_text(&rows[0]), "this host");
        assert_eq!(rows[0].sessions.len(), 1);
    }

    // ── rendering: session lines, ident fallback, as-of labeling ─────────

    #[test]
    fn session_ident_prefers_the_petname_and_falls_back_to_the_short_tail() {
        assert_eq!(session_ident(&sv("sess-aaaa-1111", "working", Some("brave-otter"))), "brave-otter");
        assert_eq!(session_ident(&sv("sess-aaaa-1111", "working", None)), "…1111");
    }

    #[test]
    fn cached_sessions_under_an_offline_row_carry_the_as_of_label() {
        let p = mesh_node("chiyo");
        let node = build_mesh_node(
            &p,
            Err("down".to_string()),
            Some(cache("chiyo", "2026-08-27T10:00:00Z", node_graph(&[("s2", "idle", Some("calm-thorn"))]))),
        );
        let rows = assemble_roster(local_node("yomi", vec![]), vec![(p, node)], &[], "yomi");
        let rendered = render_roster(&rows);
        assert!(rendered.contains("└─ claude  idle  calm-thorn  (as of 2026-08-27T10:00:00Z)"), "{rendered}");
        // An ONLINE row's sessions carry no as-of — they are live.
        let p2 = mesh_node("sakaki");
        let node2 = build_mesh_node(&p2, Ok(node_graph(&[("s3", "working", None)])), None);
        let rows2 = assemble_roster(local_node("yomi", vec![]), vec![(p2, node2)], &[], "yomi");
        assert!(!render_roster(&rows2).contains("as of"));
    }

    // ── node_list_with: the full pipeline, both seams injected ───────────

    /// Same shape as `who.rs`'s test Env, with `testutil::EnvVars` as the
    /// restore half. Field order is load-bearing: fields drop in
    /// declaration order, so `_saved` restores the two vars BEFORE `_guard`
    /// releases the env lock.
    struct Env {
        stage: std::path::PathBuf,
        state: std::path::PathBuf,
        _saved: EnvVars,
        _guard: std::sync::MutexGuard<'static, ()>,
    }
    impl Env {
        fn set_up(tag: &str) -> Self {
            let guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
            let saved = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR"]);
            let stage = unique_stage(tag);
            let state = unique_stage(&format!("{tag}-state"));
            std::env::set_var("AOIDE_STAGE_DIR", &stage);
            std::env::set_var("AOIDE_STATE_DIR", &state);
            Env { stage, state, _saved: saved, _guard: guard }
        }
    }
    impl Drop for Env {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.stage);
            let _ = std::fs::remove_dir_all(&self.state);
        }
    }

    fn no_pull() -> PullFn {
        Arc::new(|_: &Node| panic!("no nodes registered — pull must never be called"))
    }

    fn empty_sweep() -> SweepFn {
        Box::new(|| Ok(SweepResult::default()))
    }

    #[test]
    fn empty_mesh_is_one_local_row_and_a_zero_count_never_an_error() {
        let _env = Env::set_up("pl-empty");
        let out = node_list_with(&invocation(&["node", "list"], &[]), no_pull(), empty_sweep());
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let data = out.data.unwrap();
        let nodes = data["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 1, "this host is always a row");
        assert_eq!(nodes[0]["isLocal"], true);
        assert_eq!(nodes[0]["sessions"].as_array().unwrap().len(), 0);
        assert_eq!(data["sweep"]["heard"], 0);
    }

    #[test]
    fn json_rows_carry_the_full_roster_shape() {
        let _env = Env::set_up("pl-shape");
        aoide_storage::node_store::save_nodes(&[mesh_node("sakaki")]).unwrap();
        let pull: PullFn = Arc::new(|_| Ok(json!({ "nodes": [], "edges": [] })));
        let stranger = heard("stranger", "192.168.1.99");
        let sweep: SweepFn = Box::new(move || Ok(SweepResult { heard: vec![stranger], dropped: 3 }));
        let out = node_list_with(&invocation(&["node", "list"], &[]), pull, sweep);
        let data = out.data.unwrap();
        let nodes = data["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 3, "local + paired + candidate");
        for key in ["mark", "name", "isLocal", "paired", "verified", "advertising", "presence", "addr", "lastSeen", "sessions"] {
            assert!(nodes[1].get(key).is_some(), "paired row missing {key}");
        }
        let cand = &nodes[2];
        assert_eq!(cand["mark"], "◆");
        assert_eq!(cand["paired"], false);
        assert_eq!(cand["advertising"], true);
        assert_eq!(cand["addr"], "192.168.1.99");
        assert_eq!(data["sweep"], json!({ "heard": 1, "dropped": 3 }));
    }

    #[test]
    fn the_roster_never_writes_nodes_json_or_any_state_file() {
        let _env = Env::set_up("pl-writeban");
        aoide_storage::node_store::save_nodes(&[mesh_node("sakaki")]).unwrap();
        let before = std::fs::read(aoide_storage::node_store::nodes_path()).unwrap();
        let state_files = |dir: &std::path::Path| -> Vec<String> {
            std::fs::read_dir(dir)
                .map(|rd| rd.filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned())).collect())
                .unwrap_or_default()
        };
        let listing_before = state_files(&_env.state);
        // A busy run: a live pull, a sweep hearing both an impostor of the
        // paired name and a stranger — none of it may persist anything.
        let pull: PullFn = Arc::new(|_| Ok(json!({ "nodes": [], "edges": [] })));
        let impostor = heard("sakaki", "192.168.1.66");
        let stranger = heard("stranger", "192.168.1.99");
        let sweep: SweepFn = Box::new(move || {
            Ok(SweepResult { heard: vec![impostor.clone(), stranger.clone()], dropped: 0 })
        });
        let out = node_list_with(&invocation(&["node", "list"], &[]), pull, sweep);
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let after = std::fs::read(aoide_storage::node_store::nodes_path()).unwrap();
        assert_eq!(before, after, "nodes.json must be byte-identical after a roster run");
        assert_eq!(listing_before, state_files(&_env.state), "no state file created or removed");
    }

    #[test]
    fn node_store_only_roster_renders_with_an_empty_sweep() {
        let _env = Env::set_up("pl-nosweep");
        aoide_storage::node_store::save_nodes(&[mesh_node("sakaki"), mesh_node("chiyo")]).unwrap();
        aoide_storage::node_store::save_node_cache(&cache(
            "chiyo",
            "2026-08-27T10:00:00Z",
            node_graph(&[("r1", "idle", None)]),
        ))
        .unwrap();
        let pull: PullFn = Arc::new(|p: &Node| {
            if p.name == "sakaki" {
                Ok(node_graph(&[("r2", "working", Some("misty-comet"))]))
            } else {
                Err("unreachable".to_string())
            }
        });
        let out = node_list_with(&invocation(&["node", "list"], &[]), pull, empty_sweep());
        assert!(out.message.contains("paired · online"), "{}", out.message);
        assert!(out.message.contains("paired · last seen 2026-08-27T10:00:00Z"), "{}", out.message);
        assert!(!out.message.contains("◆"), "no advertising marks from an empty sweep");
        let data = out.data.unwrap();
        assert_eq!(data["nodes"].as_array().unwrap().len(), 3);
        assert!(data["nodes"].as_array().unwrap().iter().all(|n| n["advertising"] == false));
    }

    #[test]
    fn a_sweep_that_cannot_listen_annotates_the_roster_instead_of_failing_it() {
        let _env = Env::set_up("pl-sweeperr");
        let sweep: SweepFn = Box::new(|| Err("port 8711 already bound".to_string()));
        let out = node_list_with(&invocation(&["node", "list"], &[]), no_pull(), sweep);
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "the paired half is still true");
        assert!(out.message.contains("sweep unavailable — port 8711 already bound"));
        assert_eq!(out.data.unwrap()["sweep"]["error"], "port 8711 already bound");
    }

    #[test]
    fn done_sessions_never_make_the_roster() {
        let _env = Env::set_up("pl-done");
        let sf = super::super::model::SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![
                session("s1", "/x", "working", "1", None),
                session("s2", "/x", "done", "2", None),
            ],
        };
        super::super::model::write_stage(&super::super::model::sessions_path(), &sf).unwrap();
        let out = node_list_with(&invocation(&["node", "list"], &[]), no_pull(), empty_sweep());
        let data = out.data.unwrap();
        assert_eq!(data["nodes"][0]["sessions"].as_array().unwrap().len(), 1, "running only");
    }
}
