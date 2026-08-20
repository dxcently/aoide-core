//! The DAG computation: `build_graph` (the `graph.json` v0 document), the
//! Unicode tree `render`, and the pure command cores (`would_cycle`,
//! `prune_done`) the verb handlers wire I/O around. `restage_graph` is the
//! write-side counterpart every mutating verb calls to keep `graph.json` a
//! pure function of the registries.

use super::model::{
    anchor_for, graph_path, hooks_path, load_stage, merged_sessions, projects_path,
    resolved_parent, sessions_path, sorted_projects, write_stage, HookRecord, HooksFile, Project,
    ProjectsFile, SessionRecord, SessionsFile, STAGE_GRAPH_VERSION,
};
use serde_json::{json, Value};
#[cfg(test)]
use serde_json::Map;
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;

/// Build the fully resolved graph document (`graph.json` v0 shape). A session
/// with a resolved parent carries only its `spawned` edge; root sessions carry
/// an `anchors` edge to their longest-prefix project (or none, unanchored).
pub fn build_graph(
    projects: &[Project],
    sessions: &[SessionRecord],
    hooks: &[HookRecord],
) -> Value {
    let projects = sorted_projects(projects);
    let sessions = merged_sessions(sessions, hooks);
    let ids: HashSet<&str> = sessions.iter().map(|s| s.session_id.as_str()).collect();

    let mut nodes: Vec<Value> = Vec::new();
    let mut edges: Vec<Value> = Vec::new();

    for p in &projects {
        nodes.push(json!({
            "id": format!("project:{}", p.name),
            "kind": "project",
            "name": p.name,
            "path": p.path,
        }));
    }
    for s in &sessions {
        let mut node = json!({
            "id": format!("session:{}", s.session_id),
            "kind": "session",
            "agent": s.agent,
            "cwd": s.cwd,
            "state": s.state,
            "windowAddress": s.window_address,
            "startedAt": s.started_at,
        });
        // Conductor-channel fields ride onto the node only when present, so a
        // legacy/observe-only session stays byte-for-byte as before and the
        // conductor can distinguish conductable nodes + label by title.
        if let Some(c) = s.conductable {
            node["conductable"] = json!(c);
        }
        if let Some(sock) = &s.socket {
            node["socket"] = json!(sock);
        }
        if let Some(t) = &s.title {
            node["title"] = json!(t);
        }
        if let Some(pid) = s.pid {
            node["pid"] = json!(pid);
        }
        // The workspace the session's window lives on — the hover-preview bridge
        // (concepts/Terminal-Commander). Rides onto the node only when known, so
        // a legacy/off-Hyprland record stays byte-for-byte as before.
        if let Some(ws) = s.workspace {
            node["workspace"] = json!(ws);
        }
        // The live current command / tool, when something is running.
        if let Some(act) = &s.activity {
            node["activity"] = json!(act);
        }
        // Session classification (agent/shell/subagent) — the node's own `kind`
        // already denotes project-vs-session, so this rides as `role`.
        if let Some(k) = &s.kind {
            node["role"] = json!(k);
        }
        // The minted `adjective-noun` display handle (petnames plan) — rides
        // onto the node only when present, so a legacy/petname-less record
        // stays byte-for-byte as before. Display-only: `session_id` above
        // stays the canonical key.
        if let Some(pn) = &s.petname {
            node["petname"] = json!(pn);
        }
        // The agent's latest words (transcript tail), when it has spoken.
        if let Some(say) = &s.say {
            node["say"] = json!(say);
        }
        // The agent's latest tool call (transcript-derived), when it has made
        // one. Rides beside `activity` rather than replacing it: `activity` is
        // what is running now, this is what was last reached for.
        if let Some(tool) = &s.tool {
            node["tool"] = json!(tool);
        }
        // The Claude model this session (agent or subagent) is running, when
        // known — absent for shells and until the first assistant turn lands.
        if let Some(m) = &s.model {
            node["model"] = json!(m);
        }
        // The context-window fill of this session's last request (input-side
        // token count off its transcript's freshest assistant `usage`), when
        // known — absent for shells and until the first assistant turn lands.
        // Rides alongside `model` for the same reason: the dock computes the
        // meter (percent + ceiling) itself from the raw count.
        if let Some(ctx) = s.context_tokens {
            node["contextTokens"] = json!(ctx);
        }
        // The context-window ceiling for the node's model (aoide's published fact),
        // so the dock's meter needs no client-side 200k/1M guess. Absent with `model`.
        if let Some(ceil) = s.context_ceiling {
            node["contextCeiling"] = json!(ceil);
        }
        // Blocked on a `sudo` password prompt — a conducted SHELL only; rides
        // onto the node only when true (never a dangling `needsSudo:false`).
        if let Some(true) = s.needs_sudo {
            node["needsSudo"] = json!(true);
        }
        nodes.push(node);
        if let Some(parent) = resolved_parent(s, &ids) {
            edges.push(json!({
                "from": format!("session:{parent}"),
                "to": format!("session:{}", s.session_id),
                "kind": "spawned",
            }));
        } else if let Some(i) = anchor_for(&s.cwd, &projects) {
            edges.push(json!({
                "from": format!("project:{}", projects[i].name),
                "to": format!("session:{}", s.session_id),
                "kind": "anchors",
            }));
        }
    }

    // Fold registered EXTERNAL A2A agents into the DAG (CONTRACTS.md §6, client
    // side). Each is a ROOT node of `kind:"a2a"` keyed by its card `name` — no
    // edges (they anchor to nothing), so the existing spawned/anchors machinery
    // is untouched. Additive and tolerate-missing: an absent/empty registry
    // (`state/a2a-agents.json`) adds nothing and this whole block is a no-op.
    for agent in aoide_storage::a2a_store::load_agents() {
        let mut node = json!({
            "id": format!("a2a:{}", agent.name),
            "kind": "a2a",
            "name": agent.name,
            "url": agent.url,
            "state": "idle",
        });
        if !agent.description.is_empty() {
            node["description"] = json!(agent.description);
        }
        nodes.push(node);
    }

    // Fold registered PEERS into the DAG (CONTRACTS.md §7): each a ROOT node
    // `kind:"peer"`, `id:"peer:<name>"` — one level richer than the a2a fold
    // above (which folds in one opaque node): a peer's own ALREADY-RESOLVED
    // graph document nests as `children` on its node, verbatim, never
    // flattened into this document's own `nodes`/`edges` — so a peer's ids
    // can never collide with local ones or another peer's, and no new edge
    // vocabulary is needed. Only a FRESH (non-stale, within
    // `PEER_CACHE_TTL_SECS`) cache contributes `children`; a stale or
    // never-pulled peer still surfaces (so `peer add` is visible
    // immediately) with an explicit `state` and no children — never a
    // crash, never a silently-dropped peer. Additive and tolerate-missing,
    // mirroring the a2a fold's discipline exactly.
    let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap_or(0);
    for peer in aoide_storage::peer_store::load_peers() {
        let mut node = json!({
            "id": format!("peer:{}", peer.name),
            "kind": "peer",
            "name": peer.name,
            "url": peer.url,
        });
        let cache = aoide_storage::peer_store::load_peer_cache(&peer.name);
        let fresh = cache
            .as_ref()
            .map(|c| aoide_storage::peer_store::is_cache_fresh(c, now_epoch))
            .unwrap_or(false);
        if let Some(entry) = &cache {
            if let Some(fa) = &entry.fetched_at {
                node["fetchedAt"] = json!(fa);
            }
            if let Some(err) = &entry.last_error {
                node["error"] = json!(err);
            }
        }
        if fresh {
            let entry = cache.expect("fresh implies a cache entry was loaded");
            let graph = entry.graph.unwrap_or_else(|| json!({ "nodes": [], "edges": [] }));
            node["state"] = json!("fresh");
            node["children"] = json!({
                "nodes": graph.get("nodes").cloned().unwrap_or_else(|| json!([])),
                "edges": graph.get("edges").cloned().unwrap_or_else(|| json!([])),
            });
        } else {
            node["state"] = json!("stale");
        }
        nodes.push(node);
    }

    json!({
        "schemaVersion": STAGE_GRAPH_VERSION,
        "nodes": nodes,
        "edges": edges,
    })
}

// ── The Unicode tree render ─────────────────────────────────────────────────

/// `--focus` marker: matches the full node id or the bare name/sessionId.
fn marker(focus: Option<&str>, id: &str, bare: &str) -> &'static str {
    match focus {
        Some(f) if f == id || f == bare => "▶ ",
        _ => "",
    }
}

/// Render the DAG as a Unicode box-drawing tree. Projects are `◆` roots,
/// sessions are `●` leaves; spawned children nest under their parent; sessions
/// anchored to no project group under a synthetic `(unanchored)` root.
pub fn render(
    projects: &[Project],
    sessions: &[SessionRecord],
    hooks: &[HookRecord],
    focus: Option<&str>,
) -> String {
    let projects = sorted_projects(projects);
    let sessions = merged_sessions(sessions, hooks);
    let ids: HashSet<&str> = sessions.iter().map(|s| s.session_id.as_str()).collect();

    // spawn-children by parent id (already in deterministic session order).
    let mut children: BTreeMap<String, Vec<&SessionRecord>> = BTreeMap::new();
    let mut roots: Vec<&SessionRecord> = Vec::new(); // sessions with no resolved parent
    for s in &sessions {
        match resolved_parent(s, &ids) {
            Some(p) => children.entry(p).or_default().push(s),
            None => roots.push(s),
        }
    }

    // Compact token-count formatting for the `⧉` context tag below: <1000 →
    // raw, ≥1000 → `Nk`, ≥1e6 → `N.NM` — mirrors the dock's own JS formatter
    // (LiveryState.qml `ctxCompact`) so the ASCII tree and the widget read
    // the same count the same way.
    fn compact_tokens(n: u64) -> String {
        if n < 1_000 {
            n.to_string()
        } else if n < 1_000_000 {
            format!("{}k", ((n as f64) / 1_000.0).round() as u64)
        } else {
            format!("{:.1}M", (n as f64) / 1_000_000.0)
        }
    }

    fn session_line(s: &SessionRecord, focus: Option<&str>, host: &str, role: &str) -> String {
        let id = format!("session:{}", s.session_id);
        // The canonical display grammar (petnames plan P3): `<host>/<role>/
        // <petname> (…<tail4>)`, degrading to `<host>/<role>/<sessionId>`
        // (full id) for a legacy/petname-less record — one function, every
        // human surface.
        let label = aoide_storage::display::session_label(s, host, role);
        // The running Claude model, when known — a compact `⟐ <model>` tag
        // (same glyph the gadget dock uses for a subagent's model text)
        // appended after cwd; omitted for shells and anything model-less.
        let model_tag = match s.model.as_deref() {
            Some(m) if !m.is_empty() => format!("  ⟐ {m}"),
            _ => String::new(),
        };
        // The context-window fill of the last request, when known — a compact
        // `⧉ 361k` tag (distinct glyph from the model's `⟐`, so the two never
        // read as the same kind of note); omitted until an assistant turn has
        // produced a usage block.
        let ctx_tag = match s.context_tokens {
            Some(t) if t > 0 => format!("  ⧉ {}", compact_tokens(t)),
            _ => String::new(),
        };
        // A compact marker for a shell blocked on `sudo` — parallel to the
        // model tag above, appended last so it reads as the row's most urgent
        // trailing note.
        let sudo_tag = match s.needs_sudo {
            Some(true) => "  [sudo]",
            _ => "",
        };
        format!(
            "{}● {}  {}  {}  {}{}{}{}",
            marker(focus, &id, &s.session_id),
            label,
            s.agent,
            s.state,
            s.cwd,
            model_tag,
            ctx_tag,
            sudo_tag
        )
    }

    // Recursive spawn-subtree render with a visited guard (a hand-edited
    // stage file could carry a cycle; the renderer must never loop).
    fn render_children(
        out: &mut Vec<String>,
        parent: &str,
        children: &BTreeMap<String, Vec<&SessionRecord>>,
        prefix: &str,
        focus: Option<&str>,
        visited: &mut HashSet<String>,
        host: &str,
    ) {
        let Some(kids) = children.get(parent) else {
            return;
        };
        for (i, kid) in kids.iter().enumerate() {
            if !visited.insert(kid.session_id.clone()) {
                continue;
            }
            let last = i + 1 == kids.len();
            let branch = if last { "└─ " } else { "├─ " };
            // Everything reached through `children` has a resolved parent by
            // construction (that's how it landed in this map) — role is
            // always "child" here, "root" only in the caller's own group.
            out.push(format!(
                "{prefix}{branch}{}",
                session_line(kid, focus, host, "child")
            ));
            let deeper = format!("{prefix}{}", if last { "   " } else { "│  " });
            render_children(out, &kid.session_id, children, &deeper, focus, visited, host);
        }
    }

    // Resolved ONCE per render call (not per node) — every line in this pass
    // shares the same host, matching the plan's "host resolved once per
    // render pass" rule.
    let host = aoide_storage::display::local_host_name();

    let mut out: Vec<String> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();

    // Root sessions grouped per anchoring project; leftovers are unanchored.
    let mut unanchored: Vec<&SessionRecord> = Vec::new();
    let mut per_project: Vec<Vec<&SessionRecord>> = vec![Vec::new(); projects.len()];
    for s in &roots {
        match anchor_for(&s.cwd, &projects) {
            Some(i) => per_project[i].push(s),
            None => unanchored.push(s),
        }
    }

    let mut render_group = |out: &mut Vec<String>, head: String, group: &[&SessionRecord]| {
        out.push(head);
        for (i, s) in group.iter().enumerate() {
            visited.insert(s.session_id.clone());
            let last = i + 1 == group.len();
            let branch = if last { "└─ " } else { "├─ " };
            // `group` is always a `roots` slice (per-project or unanchored) —
            // role is always "root" here; children get "child" one level down.
            out.push(format!(
                "{branch}{}",
                session_line(s, focus, &host, "root")
            ));
            let deeper = if last { "   " } else { "│  " };
            render_children(
                &mut *out,
                &s.session_id,
                &children,
                deeper,
                focus,
                &mut visited,
                &host,
            );
        }
    };

    for (i, p) in projects.iter().enumerate() {
        let id = format!("project:{}", p.name);
        let head = format!("{}◆ {}  {}", marker(focus, &id, &p.name), p.name, p.path);
        render_group(&mut out, head, &per_project[i]);
    }
    if !unanchored.is_empty() {
        render_group(&mut out, "◆ (unanchored)".to_string(), &unanchored);
    }

    if out.is_empty() {
        return "(empty graph — no projects registered, no sessions live)".to_string();
    }
    out.join("\n")
}

// ── Pure command cores (unit-tested; the handlers wire I/O around them) ────

/// Would linking `child → parent` create a cycle? Walks the parent chain from
/// `parent` upward; a visited guard also survives pre-existing bad data.
pub fn would_cycle(sessions: &[SessionRecord], child: &str, parent: &str) -> bool {
    let by_id: BTreeMap<&str, &SessionRecord> = sessions
        .iter()
        .map(|s| (s.session_id.as_str(), s))
        .collect();
    let mut seen: HashSet<String> = HashSet::new();
    let mut cur = parent.to_string();
    loop {
        if cur == child {
            return true;
        }
        if !seen.insert(cur.clone()) {
            return false; // pre-existing cycle not involving child — stop.
        }
        match by_id
            .get(cur.as_str())
            .and_then(|s| s.parent_session_id.clone())
        {
            Some(next) if !next.is_empty() => cur = next,
            _ => return false,
        }
    }
}

/// Transitive `kind=="subagent"` descendants of `roots` — NOT including the
/// roots themselves. A Task node carries no pid/window, so cascading it out
/// when its owning session ends/is pruned/is reaped is its PRIMARY cleanup
/// path — `is_session_dead` has no fast signal for one (the reaper's staleness
/// bands can condemn a stranded sub-node left `working` past a week of
/// silence, but that is the slow backstop, not the live cleanup). Walks
/// `parent_session_id` via a fixed-point loop so subagent-of-subagent nesting
/// resolves in one call. Shared by `prune_done` (below) and
/// `do_session_end_inner` (`session_store.rs`) — the two cascade paths that
/// used to diverge (this fix's root cause).
pub(in crate::graph) fn doomed_subagent_descendants(
    sessions: &[SessionRecord],
    roots: &HashSet<&str>,
) -> HashSet<String> {
    let mut doomed: HashSet<String> = HashSet::new();
    loop {
        let mut grew = false;
        for s in sessions {
            if s.kind.as_deref() == Some("subagent")
                && !roots.contains(s.session_id.as_str())
                && !doomed.contains(s.session_id.as_str())
            {
                if let Some(p) = &s.parent_session_id {
                    if roots.contains(p.as_str()) || doomed.contains(p.as_str()) {
                        doomed.insert(s.session_id.clone());
                        grew = true;
                    }
                }
            }
        }
        if !grew {
            break;
        }
    }
    doomed
}

/// The prune computation: drop `done` sessions (+ their hook records); clear
/// `parentSessionId` on surviving children of removed sessions.
pub fn prune_done(
    sessions: Vec<SessionRecord>,
    hooks: Vec<HookRecord>,
) -> (
    Vec<SessionRecord>,
    Vec<HookRecord>,
    Vec<String>,
    Vec<String>,
) {
    let doomed: HashSet<&str> = sessions
        .iter()
        .filter(|s| s.state == "done")
        .map(|s| s.session_id.as_str())
        .collect();
    drop_sessions(&sessions, &doomed, hooks)
}

/// Drop exactly `roots` (+ their subagent descendants, + their hook records)
/// from the roster; clear `parentSessionId` on surviving children of anything
/// removed. [`prune_done`] is this over the whole `done` set — factored apart
/// because the reaper needs the same drop over a NARROWER one (the superseded
/// `done` agent siblings of a terminal that still holds a live agent — see
/// `superseded_done_siblings` in `reap.rs`), and a second hand-rolled retain
/// there would have missed the cascade and the parent-clearing this owns. A
/// root absent from `sessions` contributes nothing.
///
/// `sessions` is borrowed (not consumed like `prune_done`'s) so the caller can
/// compute the root set against the same slice it passes in.
pub(crate) fn drop_sessions(
    sessions: &[SessionRecord],
    roots: &HashSet<&str>,
    hooks: Vec<HookRecord>,
) -> (
    Vec<SessionRecord>,
    Vec<HookRecord>,
    Vec<String>,
    Vec<String>,
) {
    let mut removed: Vec<String> = sessions
        .iter()
        .filter(|s| roots.contains(s.session_id.as_str()))
        .map(|s| s.session_id.clone())
        .collect();
    // Cascade: a subagent descendant of anything being dropped is ALSO
    // gone — closes the gap where this function (unlike `do_session_end_inner`)
    // only cleared the child's dangling `parentSessionId` instead of dropping
    // it, stranding un-reapable `kind:"subagent"` ghosts (state stuck
    // "working" forever — see `is_session_dead` in reap.rs).
    let gone_direct: HashSet<&str> = removed.iter().map(String::as_str).collect();
    let cascaded = doomed_subagent_descendants(sessions, &gone_direct);
    removed.extend(cascaded);
    let gone: HashSet<&str> = removed.iter().map(String::as_str).collect();

    let mut cleared: Vec<String> = Vec::new();
    let kept_sessions: Vec<SessionRecord> = sessions
        .iter()
        .filter(|s| !gone.contains(s.session_id.as_str()))
        .cloned()
        .map(|mut s| {
            if matches!(&s.parent_session_id, Some(p) if gone.contains(p.as_str())) {
                s.parent_session_id = None;
                cleared.push(s.session_id.clone());
            }
            s
        })
        .collect();
    let kept_hooks: Vec<HookRecord> = hooks
        .into_iter()
        .filter(|h| !gone.contains(h.session_id.as_str()))
        .collect();

    (kept_sessions, kept_hooks, removed, cleared)
}

/// Re-stage `graph.json` from the CURRENT registries so the document Quickshell
/// hot-reloads never drifts from what `graph view` (and a fresh `graph emit`)
/// would compute. Every mutation of projects/sessions calls this, so the staged
/// graph is always a pure function of the registries — the staged doc can no
/// longer go stale behind a `project add`/`remove`/`link`/`prune`.
pub(crate) fn restage_graph() -> Result<PathBuf, String> {
    let p: ProjectsFile = load_stage(&projects_path())?;
    let s: SessionsFile = load_stage(&sessions_path())?;
    let h: HooksFile = load_stage(&hooks_path())?;
    let doc = build_graph(&p.projects, &s.sessions, &h.hooks);
    let path = graph_path();
    write_stage(&path, &doc)?;
    Ok(path)
}

/// Resolve the CURRENT graph document straight off the stage registries —
/// the exact same three-file-load-then-`build_graph` shape [`restage_graph`]
/// runs (minus the write). `pub`, not `pub(crate)`: `aoide-server`'s
/// `aoide/graphSummary` (CONTRACTS.md §7) reuses this so the wire response
/// and a fresh `graph view --json` / `graph emit` can never diverge into two
/// graph vocabularies — the whole point of wrapping `build_graph`'s output
/// verbatim rather than inventing a second shape for the federation door.
pub fn resolve_graph_document() -> Result<Value, String> {
    let p: ProjectsFile = load_stage(&projects_path())?;
    let s: SessionsFile = load_stage(&sessions_path())?;
    let h: HooksFile = load_stage(&hooks_path())?;
    Ok(build_graph(&p.projects, &s.sessions, &h.hooks))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::testutil::*;

    #[test]
    fn link_cycle_rejection() {
        let sessions = vec![
            session("a", "/x", "running", "1", None),
            session("b", "/x", "running", "2", Some("a")),
            session("c", "/x", "running", "3", Some("b")),
        ];
        // a → c closes the chain c→b→a: cycle.
        assert!(would_cycle(&sessions, "a", "c"));
        // Self-parented chain data must not loop the walker.
        assert!(would_cycle(&sessions, "b", "b"));
        // A fresh parent is fine.
        assert!(!would_cycle(&sessions, "c", "a"));
        assert!(!would_cycle(&sessions, "a", "unregistered"));
    }
    #[test]
    fn render_is_deterministic_snapshot() {
        let projects = fixture_projects();
        let sessions = vec![
            // Deliberately unsorted; ordering must come from (startedAt, id).
            session("s4", "/tmp", "idle", "2026-01-04T00:00:00Z", None),
            session(
                "s2",
                "/home/k/Aoide/sub/x",
                "running",
                "2026-01-02T00:00:00Z",
                None,
            ),
            session(
                "s1",
                "/home/k/Aoide",
                "running",
                "2026-01-01T00:00:00Z",
                None,
            ),
            session(
                "s3",
                "/home/k/elsewhere",
                "idle",
                "2026-01-03T00:00:00Z",
                Some("s1"),
            ),
        ];
        // Hook state merge: s1's latest hook phase becomes its live state, folded
        // to the canonical vocab (working → idle here; latest updatedAt wins).
        let hooks = vec![
            HookRecord {
                session_id: "s1".into(),
                phase: "working".into(),
                updated_at: "2026-01-01T01:00:00Z".into(),
                extra: Map::new(),
            },
            HookRecord {
                session_id: "s1".into(),
                phase: "idle".into(),
                updated_at: "2026-01-01T02:00:00Z".into(),
                extra: Map::new(),
            },
        ];
        // Roster `running` folds to canonical `working`; the merged hook phase and
        // the resting states render verbatim from the one vocabulary. None of
        // these fixtures carry a minted petname, so every head degrades to
        // `<host>/<role>/<sessionId>` — s1/s2/s4 are roots, s3 is s1's child.
        let host = aoide_storage::display::local_host_name();
        let expected = format!(
            "\
◆ aoide  /home/k/Aoide
└─ ● {host}/root/s1  claude  idle  /home/k/Aoide
   └─ ● {host}/child/s3  claude  idle  /home/k/elsewhere
◆ nested  /home/k/Aoide/sub
└─ ● {host}/root/s2  claude  working  /home/k/Aoide/sub/x
◆ (unanchored)
└─ ● {host}/root/s4  claude  idle  /tmp"
        );
        assert_eq!(render(&projects, &sessions, &hooks, None), expected);
        // The focus marker singles out one node.
        let focused = render(&projects, &sessions, &hooks, Some("session:s2"));
        assert!(focused.contains(&format!("└─ ▶ ● {host}/root/s2  claude  working")));
        // Same inputs → same render (deterministic).
        assert_eq!(render(&projects, &sessions, &hooks, None), expected);
    }
    #[test]
    fn render_shows_model_tag_on_agent_and_subagent_nodes_when_known() {
        let projects = fixture_projects();
        let mut parent = session("s1", "/home/k/Aoide", "running", "1", None);
        parent.model = Some("claude-sonnet-5".into());
        let mut sub = session("s2", "/home/k/Aoide", "working", "2", Some("s1"));
        sub.kind = Some("subagent".into());
        sub.model = Some("claude-fable-5".into());
        // A shell (or any model-less record) carries no model — the tag stays
        // absent rather than printing an empty `⟐ `.
        let shell = session("s3", "/home/k/Aoide", "idle", "3", None);
        let sessions = vec![parent, sub, shell];
        let out = render(&projects, &sessions, &[], None);
        let host = aoide_storage::display::local_host_name();
        assert!(
            out.contains(&format!("● {host}/root/s1  claude  working  /home/k/Aoide  ⟐ claude-sonnet-5")),
            "agent node carries its model tag: {out}"
        );
        assert!(
            out.contains(&format!("● {host}/child/s2  claude  working  /home/k/Aoide  ⟐ claude-fable-5")),
            "subagent node carries its own (possibly different) model tag: {out}"
        );
        assert!(
            out.contains(&format!("● {host}/root/s3  claude  idle  /home/k/Aoide\n")),
            "model-less node has no dangling tag: {out}"
        );
        assert!(!out.contains('⟐') || out.matches('⟐').count() == 2, "exactly two model tags: {out}");
    }
    #[test]
    fn graph_document_edges_match_the_render_shape() {
        let projects = fixture_projects();
        let sessions = vec![
            session("s1", "/home/k/Aoide", "running", "1", None),
            session("s3", "/home/k/elsewhere", "idle", "2", Some("s1")),
        ];
        let doc = build_graph(&projects, &sessions, &[]);
        let edges = doc["edges"].as_array().unwrap();
        // s1 anchors under project:aoide; s3 hangs off s1 only (no anchor edge).
        assert!(edges.iter().any(|e| e["from"] == "project:aoide"
            && e["to"] == "session:s1"
            && e["kind"] == "anchors"));
        assert!(edges.iter().any(|e| e["from"] == "session:s1"
            && e["to"] == "session:s3"
            && e["kind"] == "spawned"));
        assert_eq!(edges.len(), 2);
        assert_eq!(doc["schemaVersion"], "0");
    }
    #[test]
    fn prune_clears_orphaned_parent_links() {
        let sessions = vec![
            session("p", "/x", "done", "1", None),
            session("c1", "/x", "running", "2", Some("p")),
            session("c2", "/x", "done", "3", Some("p")),
            session("free", "/x", "idle", "4", None),
        ];
        let hooks = vec![
            HookRecord {
                session_id: "p".into(),
                phase: "Stop".into(),
                updated_at: "1".into(),
                extra: Map::new(),
            },
            HookRecord {
                session_id: "c1".into(),
                phase: "PreToolUse".into(),
                updated_at: "2".into(),
                extra: Map::new(),
            },
        ];
        let (kept_s, kept_h, removed, cleared) = prune_done(sessions, hooks);
        assert_eq!(removed, vec!["p".to_string(), "c2".to_string()]);
        assert_eq!(cleared, vec!["c1".to_string()]);
        let ids: Vec<&str> = kept_s.iter().map(|s| s.session_id.as_str()).collect();
        assert_eq!(ids, vec!["c1", "free"]);
        assert!(kept_s.iter().all(|s| s.parent_session_id.is_none()));
        // p's hook record went with it; c1's survives.
        assert_eq!(kept_h.len(), 1);
        assert_eq!(kept_h[0].session_id, "c1");
    }
    #[test]
    fn prune_cascades_subagent_descendants_of_a_done_session() {
        let top = session("top", "/x", "done", "1", None);
        let mut sub1 = session("sub:t1", "/x", "working", "2", Some("top"));
        sub1.kind = Some("subagent".into());
        // subagent-of-subagent: multi-level nesting must cascade in one pass.
        let mut sub2 = session("sub:t2", "/x", "working", "3", Some("sub:t1"));
        sub2.kind = Some("subagent".into());
        let free = session("free", "/x", "idle", "4", None);
        let sessions = vec![top, sub1, sub2, free];

        let (kept_s, _kept_h, mut removed, _cleared) = prune_done(sessions, vec![]);
        removed.sort();
        assert_eq!(
            removed,
            vec!["sub:t1".to_string(), "sub:t2".to_string(), "top".to_string()]
        );
        let ids: Vec<&str> = kept_s.iter().map(|s| s.session_id.as_str()).collect();
        assert_eq!(ids, vec!["free"], "the whole subagent subtree cascades with its done parent");
    }
    #[test]
    fn graph_node_carries_workspace_only_when_known() {
        // The hover-preview bridge is pure data: build_graph stamps `workspace`
        // onto a session node when resolved, and omits it entirely otherwise so a
        // legacy/off-Hyprland record round-trips byte-for-byte.
        let mut with_ws = SessionRecord {
            session_id: "a".into(),
            window_address: "0xaaa".into(),
            ..Default::default()
        };
        with_ws.workspace = Some(4);
        let without_ws = SessionRecord {
            session_id: "b".into(),
            window_address: "0xbbb".into(),
            ..Default::default()
        };
        let doc = build_graph(&[], &[with_ws, without_ws], &[]);
        let nodes = doc["nodes"].as_array().unwrap();
        let node_a = nodes.iter().find(|n| n["id"] == "session:a").unwrap();
        let node_b = nodes.iter().find(|n| n["id"] == "session:b").unwrap();
        assert_eq!(node_a["workspace"], json!(4));
        assert!(node_b.get("workspace").is_none());
    }
    #[test]
    fn graph_node_carries_model_only_when_known() {
        // Mirrors the workspace test above: `model` rides onto a session node
        // (agent or subagent alike) only when the record has one, so a
        // legacy/model-less record round-trips byte-for-byte.
        let with_model = SessionRecord {
            session_id: "a".into(),
            window_address: "0xaaa".into(),
            model: Some("claude-fable-5".into()),
            ..Default::default()
        };
        let without_model = SessionRecord {
            session_id: "b".into(),
            window_address: "0xbbb".into(),
            ..Default::default()
        };
        let doc = build_graph(&[], &[with_model, without_model], &[]);
        let nodes = doc["nodes"].as_array().unwrap();
        let node_a = nodes.iter().find(|n| n["id"] == "session:a").unwrap();
        let node_b = nodes.iter().find(|n| n["id"] == "session:b").unwrap();
        assert_eq!(node_a["model"], json!("claude-fable-5"));
        assert!(node_b.get("model").is_none());
    }
    #[test]
    fn graph_node_carries_petname_only_when_known() {
        // Mirrors the model test above: `petname` rides onto a session node
        // only when the record has one minted, so a legacy/petname-less
        // record round-trips byte-for-byte.
        let with_petname = SessionRecord {
            session_id: "a".into(),
            window_address: "0xaaa".into(),
            petname: Some("brave-otter".into()),
            ..Default::default()
        };
        let without_petname = SessionRecord {
            session_id: "b".into(),
            window_address: "0xbbb".into(),
            ..Default::default()
        };
        let doc = build_graph(&[], &[with_petname, without_petname], &[]);
        let nodes = doc["nodes"].as_array().unwrap();
        let node_a = nodes.iter().find(|n| n["id"] == "session:a").unwrap();
        let node_b = nodes.iter().find(|n| n["id"] == "session:b").unwrap();
        assert_eq!(node_a["petname"], json!("brave-otter"));
        assert!(node_b.get("petname").is_none());
    }
    #[test]
    fn graph_node_carries_context_tokens_only_when_known() {
        // Mirrors the workspace/model tests above: `contextTokens` rides onto a
        // session node only when the record has one, so a legacy/pre-assistant-
        // turn record round-trips byte-for-byte.
        let with_ctx = SessionRecord {
            session_id: "a".into(),
            window_address: "0xaaa".into(),
            context_tokens: Some(361_416),
            ..Default::default()
        };
        let without_ctx = SessionRecord {
            session_id: "b".into(),
            window_address: "0xbbb".into(),
            ..Default::default()
        };
        let doc = build_graph(&[], &[with_ctx, without_ctx], &[]);
        let nodes = doc["nodes"].as_array().unwrap();
        let node_a = nodes.iter().find(|n| n["id"] == "session:a").unwrap();
        let node_b = nodes.iter().find(|n| n["id"] == "session:b").unwrap();
        assert_eq!(node_a["contextTokens"], json!(361_416));
        assert!(node_b.get("contextTokens").is_none());
    }
    #[test]
    fn render_shows_context_tag_when_known() {
        // The ASCII render's `⧉ <compact>` tag mirrors the model tag's `⟐`
        // precedent: present + compact-formatted when known, absent otherwise.
        let mut s = session("a", "/x", "working", "2024-01-01T00:00:00Z", None);
        s.context_tokens = Some(361_416);
        let out = render(&[], &[s], &[], None);
        assert!(out.contains("⧉ 361k"), "expected a compact context tag: {out}");

        let bare = session("b", "/x", "working", "2024-01-01T00:00:00Z", None);
        let out2 = render(&[], &[bare], &[], None);
        assert!(!out2.contains('⧉'), "no dangling context tag: {out2}");
    }
    #[test]
    fn graph_node_carries_needs_sudo_only_when_true() {
        // Mirrors the workspace/model tests above: `needsSudo` rides onto a
        // session node only when Some(true) — never a dangling `false`, and
        // absent entirely for a legacy/not-blocked record.
        let mut blocked = SessionRecord {
            session_id: "a".into(),
            window_address: "0xaaa".into(),
            ..Default::default()
        };
        blocked.needs_sudo = Some(true);
        let free = SessionRecord {
            session_id: "b".into(),
            window_address: "0xbbb".into(),
            ..Default::default()
        };
        let doc = build_graph(&[], &[blocked, free], &[]);
        let nodes = doc["nodes"].as_array().unwrap();
        let node_a = nodes.iter().find(|n| n["id"] == "session:a").unwrap();
        let node_b = nodes.iter().find(|n| n["id"] == "session:b").unwrap();
        assert_eq!(node_a["needsSudo"], json!(true));
        assert!(node_b.get("needsSudo").is_none());
    }
    #[test]
    fn build_graph_folds_registered_a2a_agents_as_root_nodes() {
        // CONTRACTS.md §6 client side: a registered external A2A agent folds
        // into the DAG as a `kind:"a2a"` root node keyed by its card name, with
        // no edges. Drive it through the on-disk registry via AOIDE_STATE_DIR.
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-a2a-fold-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("AOIDE_STATE_DIR", &dir);

        aoide_storage::a2a_store::save_agents(&[aoide_storage::a2a_store::A2aAgent {
            name: "peer".into(),
            url: "http://10.0.0.5:8710/".into(),
            description: "a friendly agent".into(),
            registered_at: "2026-08-01T00:00:00Z".into(),
        }])
        .unwrap();

        let doc = build_graph(&[], &[], &[]);
        let nodes = doc["nodes"].as_array().unwrap();
        let a2a = nodes.iter().find(|n| n["id"] == "a2a:peer").expect("a2a node folded in");
        assert_eq!(a2a["kind"], "a2a");
        assert_eq!(a2a["name"], "peer");
        assert_eq!(a2a["url"], "http://10.0.0.5:8710/");
        assert_eq!(a2a["state"], "idle");
        assert_eq!(a2a["description"], "a friendly agent");
        // An a2a agent is a root: it contributes no edges.
        assert!(doc["edges"].as_array().unwrap().is_empty());

        // An empty registry folds nothing (additive / no-op).
        aoide_storage::a2a_store::save_agents(&[]).unwrap();
        let doc = build_graph(&[], &[], &[]);
        assert!(doc["nodes"].as_array().unwrap().iter().all(|n| n["kind"] != "a2a"));

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }
    #[test]
    fn build_graph_folds_a_fresh_peer_as_a_root_node_with_nested_children() {
        // CONTRACTS.md §7: a registered peer with a FRESH (non-stale,
        // within-TTL) pulled cache folds in as a `kind:"peer"` root node
        // whose own resolved graph nests as `children` — never flattened
        // into this document's own top-level `nodes`/`edges` (unlike the
        // a2a fold's single opaque node, this is a whole subtree).
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-peer-fold-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("AOIDE_STATE_DIR", &dir);

        aoide_storage::peer_store::save_peers(&[aoide_storage::peer_store::Peer {
            name: "yomi-strix".into(),
            url: "http://yomi-strix:8710/".into(),
            autogate: false,
            token_file: None,
            added_at: "2026-08-14T00:00:00Z".into(),
        }])
        .unwrap();
        let peer_graph = json!({
            "schemaVersion": "0",
            "nodes": [{ "id": "project:remote", "kind": "project", "name": "remote", "path": "/x" }],
            "edges": [],
        });
        aoide_storage::peer_store::save_peer_cache(&aoide_storage::peer_store::PeerCacheEntry {
            schema_version: "0".into(),
            name: "yomi-strix".into(),
            instance: Some(json!({ "name": "yomi-strix", "url": "http://yomi-strix:8710/" })),
            graph: Some(peer_graph.clone()),
            fetched_at: Some(aoide_storage::time::now_iso_utc()),
            stale: false,
            last_error: None,
        })
        .unwrap();

        let doc = build_graph(&[], &[], &[]);
        let nodes = doc["nodes"].as_array().unwrap();
        let peer = nodes
            .iter()
            .find(|n| n["id"] == "peer:yomi-strix")
            .expect("peer node folded in");
        assert_eq!(peer["kind"], "peer");
        assert_eq!(peer["name"], "yomi-strix");
        assert_eq!(peer["url"], "http://yomi-strix:8710/");
        assert_eq!(peer["state"], "fresh");
        assert_eq!(peer["children"]["nodes"], peer_graph["nodes"].clone());
        // A fresh peer contributes no TOP-LEVEL nodes/edges of its own — its
        // subtree is nested, never merged into this document's flat lists,
        // so a peer's ids can never collide with a local session/project id.
        assert!(nodes.iter().all(|n| n["id"] != "project:remote"));
        assert!(doc["edges"].as_array().unwrap().is_empty());

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }
    #[test]
    fn build_graph_shows_a_stale_or_never_pulled_peer_with_no_children() {
        // A registered peer is visible IMMEDIATELY on `peer add`, before any
        // pull ever succeeds — and stays visible (never silently dropped)
        // once a pull goes stale. Either way: an explicit `state`, no
        // `children`, never a crash.
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-peer-fold-stale-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("AOIDE_STATE_DIR", &dir);

        // Never pulled: no cache file at all.
        aoide_storage::peer_store::save_peers(&[aoide_storage::peer_store::Peer {
            name: "never-pulled".into(),
            url: "http://never:8710/".into(),
            autogate: false,
            token_file: None,
            added_at: "2026-08-14T00:00:00Z".into(),
        }])
        .unwrap();
        let doc = build_graph(&[], &[], &[]);
        let nodes = doc["nodes"].as_array().unwrap();
        let node = nodes.iter().find(|n| n["id"] == "peer:never-pulled").unwrap();
        assert_eq!(node["state"], "stale");
        assert!(node.get("children").is_none());

        // Explicitly stale (a failed pull) — still visible, still no children,
        // and carries the last error for `peer status` to surface.
        aoide_storage::peer_store::save_peers(&[aoide_storage::peer_store::Peer {
            name: "flaky".into(),
            url: "http://flaky:8710/".into(),
            autogate: false,
            token_file: None,
            added_at: "2026-08-14T00:00:00Z".into(),
        }])
        .unwrap();
        aoide_storage::peer_store::save_peer_cache(&aoide_storage::peer_store::PeerCacheEntry {
            schema_version: "0".into(),
            name: "flaky".into(),
            instance: None,
            graph: None,
            fetched_at: None,
            stale: true,
            last_error: Some("connection refused".into()),
        })
        .unwrap();
        let doc = build_graph(&[], &[], &[]);
        let nodes = doc["nodes"].as_array().unwrap();
        let node = nodes.iter().find(|n| n["id"] == "peer:flaky").unwrap();
        assert_eq!(node["state"], "stale");
        assert_eq!(node["error"], "connection refused");
        assert!(node.get("children").is_none());

        // An expired-TTL (but not explicitly marked stale) cache is ALSO
        // reported stale by the fold.
        aoide_storage::peer_store::save_peers(&[aoide_storage::peer_store::Peer {
            name: "expired".into(),
            url: "http://expired:8710/".into(),
            autogate: false,
            token_file: None,
            added_at: "2026-08-14T00:00:00Z".into(),
        }])
        .unwrap();
        let ancient = aoide_storage::time::iso_utc_from_epoch(
            aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap()
                - aoide_storage::peer_store::PEER_CACHE_TTL_SECS as i64
                - 1,
        );
        aoide_storage::peer_store::save_peer_cache(&aoide_storage::peer_store::PeerCacheEntry {
            schema_version: "0".into(),
            name: "expired".into(),
            instance: Some(json!({})),
            graph: Some(json!({ "nodes": [], "edges": [] })),
            fetched_at: Some(ancient),
            stale: false,
            last_error: None,
        })
        .unwrap();
        let doc = build_graph(&[], &[], &[]);
        let nodes = doc["nodes"].as_array().unwrap();
        let node = nodes.iter().find(|n| n["id"] == "peer:expired").unwrap();
        assert_eq!(node["state"], "stale");
        assert!(node.get("children").is_none());

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }
    #[test]
    fn resolve_graph_document_matches_build_graph_off_the_current_stage() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("resolve-graph-doc");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // Empty stage: still resolves cleanly to the empty v0 shape, matching
        // what `build_graph(&[], &[], &[])` would produce.
        let doc = resolve_graph_document().unwrap();
        assert_eq!(doc, build_graph(&[], &[], &[]));

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn render_shows_sudo_marker_when_blocked() {
        let projects = fixture_projects();
        let mut blocked = session("s1", "/home/k/Aoide", "awaiting", "1", None);
        blocked.needs_sudo = Some(true);
        let free = session("s2", "/home/k/Aoide", "idle", "2", None);
        let sessions = vec![blocked, free];
        let out = render(&projects, &sessions, &[], None);
        let host = aoide_storage::display::local_host_name();
        assert!(
            out.contains(&format!("● {host}/root/s1  claude  awaiting  /home/k/Aoide  [sudo]")),
            "sudo-blocked node carries the marker: {out}"
        );
        assert!(
            !out.contains(&format!("{host}/root/s2  claude  idle  /home/k/Aoide  [sudo]")),
            "non-blocked node carries no marker: {out}"
        );
    }
    #[test]
    fn render_session_head_uses_the_display_grammar_petnamed_and_legacy() {
        // The canonical display grammar (petnames plan P3): a petnamed
        // record's tree head is `<host>/<role>/<petname> (…<tail4>)`; a
        // legacy (petname-less) record degrades to `<host>/<role>/
        // <sessionId>` — the FULL id, never a truncated fake. Root vs child
        // role comes from the DAG shape the tree already computes, not a
        // stored field. Trailing glyph vocabulary (⟐/⧉/[sudo]) is untouched
        // by this rendering change.
        let mut root = session("sess-0000-8948", "/home/k/Aoide", "idle", "1", None);
        root.petname = Some("brave-otter".into());
        let mut child = session("sess-0000-1234", "/home/k/Aoide", "idle", "2", Some("sess-0000-8948"));
        child.petname = Some("calm-thorn".into());
        let legacy = session("sess-legacy-full-id", "/home/k/Aoide", "idle", "3", None);
        let sessions = vec![root, child, legacy];

        let out = render(&fixture_projects(), &sessions, &[], None);
        let host = aoide_storage::display::local_host_name();
        assert!(
            out.contains(&format!("● {host}/root/brave-otter (…8948)  claude  idle")),
            "petnamed root renders host/role/petname/tail: {out}"
        );
        assert!(
            out.contains(&format!("● {host}/child/calm-thorn (…1234)  claude  idle")),
            "petnamed child renders host/role/petname/tail: {out}"
        );
        assert!(
            out.contains(&format!("● {host}/root/sess-legacy-full-id  claude  idle")),
            "legacy record degrades to host/role/full-id, never a truncated fake: {out}"
        );
    }
}
