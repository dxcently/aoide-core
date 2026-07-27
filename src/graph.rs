//! `aoide graph` — the project/session DAG viewer + manager
//! (concepts/Terminal-Commander).
//!
//! Projects are anchor nodes; agent terminal sessions hang under them
//! (anchored by cwd, longest path prefix wins) and under each other via
//! spawned-by edges (`parentSessionId` on the session record). One
//! computation feeds three outputs: the Unicode tree render, the `--json`
//! graph document, and the `song/stage/graph.json` stage file Quickshell
//! hot-reloads (CONTRACTS.md §4). Every stage write goes through
//! shellbridge's atomic writer — never a bare `fs::write`.

use crate::dispatch::Invocation;
use crate::output::Outcome;
use crate::shellbridge::{atomic_write, stage_dir};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;

/// graph.json / projects.json stage-file format version (CONTRACTS.md §4).
pub const STAGE_GRAPH_VERSION: &str = "0";

// ── Stage-file records (CONTRACTS.md §4 shapes) ─────────────────────────────

/// One registered project anchor root (`song/stage/projects.json`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Project {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub path: String,
}

/// One session record (`song/stage/sessions.json`, written by shellbridge).
/// `parentSessionId` is the optional additive spawned-by edge; `extra`
/// round-trips any fields this version does not know about.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionRecord {
    #[serde(rename = "sessionId", default)]
    pub session_id: String,
    #[serde(default)]
    pub agent: String,
    #[serde(rename = "windowAddress", default)]
    pub window_address: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub state: String,
    #[serde(rename = "startedAt", default)]
    pub started_at: String,
    #[serde(
        rename = "parentSessionId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub parent_session_id: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One hook record (`song/stage/hooks.json`, written by shellbridge).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HookRecord {
    #[serde(rename = "sessionId", default)]
    pub session_id: String,
    #[serde(default)]
    pub phase: String,
    #[serde(rename = "updatedAt", default)]
    pub updated_at: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `projects.json` container.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectsFile {
    #[serde(rename = "schemaVersion", default)]
    pub schema_version: String,
    #[serde(default)]
    pub projects: Vec<Project>,
}

/// `sessions.json` container.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionsFile {
    #[serde(rename = "schemaVersion", default)]
    pub schema_version: String,
    #[serde(default)]
    pub sessions: Vec<SessionRecord>,
}

/// `hooks.json` container.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HooksFile {
    #[serde(rename = "schemaVersion", default)]
    pub schema_version: String,
    #[serde(default)]
    pub hooks: Vec<HookRecord>,
}

// ── Stage-file I/O (missing file → empty registry; writes atomic) ──────────

fn projects_path() -> PathBuf {
    stage_dir().join("projects.json")
}
fn sessions_path() -> PathBuf {
    stage_dir().join("sessions.json")
}
fn hooks_path() -> PathBuf {
    stage_dir().join("hooks.json")
}
fn graph_path() -> PathBuf {
    stage_dir().join("graph.json")
}

/// Load one stage file; a missing file is an empty registry (tolerated), a
/// corrupt one is a structured error string.
fn load_stage<T: serde::de::DeserializeOwned + Default>(
    path: &std::path::Path,
) -> Result<T, String> {
    match std::fs::read_to_string(path) {
        Ok(s) => serde_json::from_str(&s)
            .map_err(|e| format!("{}: unreadable stage file: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Atomic write of one stage file (write-temp-then-rename, CONTRACTS.md §4).
fn write_stage<T: Serialize>(path: &std::path::Path, value: &T) -> Result<(), String> {
    let body = serde_json::to_string_pretty(value)
        .map_err(|e| format!("{}: serialize: {e}", path.display()))?;
    atomic_write(path, &body).map_err(|e| format!("{}: {e}", path.display()))
}

// ── The DAG computation (pure; shared by view / emit / render) ──────────────

/// Is `cwd` inside the project rooted at `root`? (path-component-aware).
fn cwd_under(cwd: &str, root: &str) -> bool {
    let root = if root.len() > 1 {
        root.trim_end_matches('/')
    } else {
        root
    };
    cwd == root || cwd.starts_with(&format!("{}/", root))
}

/// The anchoring project for a cwd: longest matching root wins, so nested
/// projects anchor correctly. Returns an index into `projects`.
pub fn anchor_for(cwd: &str, projects: &[Project]) -> Option<usize> {
    projects
        .iter()
        .enumerate()
        .filter(|(_, p)| cwd_under(cwd, &p.path))
        .max_by_key(|(_, p)| p.path.trim_end_matches('/').len())
        .map(|(i, _)| i)
}

/// Sessions with their live state merged in: the latest hook phase (by
/// `updatedAt`; ties → the later record wins) overrides the roster state.
pub fn merged_sessions(sessions: &[SessionRecord], hooks: &[HookRecord]) -> Vec<SessionRecord> {
    let mut latest: BTreeMap<&str, (&str, &str)> = BTreeMap::new(); // id → (updatedAt, phase)
    for h in hooks {
        match latest.get(h.session_id.as_str()) {
            Some((at, _)) if h.updated_at.as_str() < *at => {}
            _ => {
                latest.insert(&h.session_id, (&h.updated_at, &h.phase));
            }
        }
    }
    let mut merged: Vec<SessionRecord> = sessions.to_vec();
    for s in &mut merged {
        if let Some((_, phase)) = latest.get(s.session_id.as_str()) {
            if !phase.is_empty() {
                s.state = (*phase).to_string();
            }
        }
    }
    // Deterministic ordering everywhere downstream: (startedAt, sessionId).
    merged.sort_by(|a, b| {
        (a.started_at.as_str(), a.session_id.as_str())
            .cmp(&(b.started_at.as_str(), b.session_id.as_str()))
    });
    merged
}

fn sorted_projects(projects: &[Project]) -> Vec<Project> {
    let mut p = projects.to_vec();
    p.sort_by(|a, b| a.name.cmp(&b.name));
    p
}

/// Does the child's parent resolve to a registered session? (a dangling
/// `parentSessionId` falls back to project anchoring).
fn resolved_parent<'a>(s: &SessionRecord, ids: &HashSet<&'a str>) -> Option<String> {
    s.parent_session_id
        .as_deref()
        .filter(|p| ids.contains(p))
        .map(str::to_string)
}

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
        nodes.push(json!({
            "id": format!("session:{}", s.session_id),
            "kind": "session",
            "agent": s.agent,
            "cwd": s.cwd,
            "state": s.state,
            "windowAddress": s.window_address,
            "startedAt": s.started_at,
        }));
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

    fn session_line(s: &SessionRecord, focus: Option<&str>) -> String {
        let id = format!("session:{}", s.session_id);
        format!(
            "{}● {}  {}  {}  {}",
            marker(focus, &id, &s.session_id),
            s.session_id,
            s.agent,
            s.state,
            s.cwd
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
            out.push(format!("{prefix}{branch}{}", session_line(kid, focus)));
            let deeper = format!("{prefix}{}", if last { "   " } else { "│  " });
            render_children(out, &kid.session_id, children, &deeper, focus, visited);
        }
    }

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
            out.push(format!("{branch}{}", session_line(s, focus)));
            let deeper = if last { "   " } else { "│  " };
            render_children(
                &mut *out,
                &s.session_id,
                &children,
                deeper,
                focus,
                &mut visited,
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
    let removed: Vec<String> = sessions
        .iter()
        .filter(|s| s.state == "done")
        .map(|s| s.session_id.clone())
        .collect();
    let gone: HashSet<&str> = removed.iter().map(String::as_str).collect();

    let mut cleared: Vec<String> = Vec::new();
    let kept_sessions: Vec<SessionRecord> = sessions
        .into_iter()
        .filter(|s| !gone.contains(s.session_id.as_str()))
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

// ── Handlers (dispatched from dispatch.rs; both doors land here) ────────────

/// Positional-arg check → structured usage error (exit 2) on a miss.
fn require_args(inv: &Invocation, names: &[&str]) -> Result<Vec<String>, Outcome> {
    if inv.args.len() < names.len() {
        return Err(Outcome::usage(
            inv.dotted(),
            format!(
                "usage: aoide {} {} [--json]",
                inv.path.join(" "),
                names
                    .iter()
                    .map(|n| format!("<{n}>"))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
        ));
    }
    Ok(inv.args[..names.len()].to_vec())
}

fn stage_error(cmd: &str, msg: String) -> Outcome {
    Outcome::error(cmd, msg).with_data(json!({ "reason": "stage-file-unreadable-or-unwritable" }))
}

/// Load all three graph inputs, tolerating missing files.
fn load_inputs(cmd: &str) -> Result<(ProjectsFile, SessionsFile, HooksFile), Outcome> {
    let p: ProjectsFile = load_stage(&projects_path()).map_err(|e| stage_error(cmd, e))?;
    let s: SessionsFile = load_stage(&sessions_path()).map_err(|e| stage_error(cmd, e))?;
    let h: HooksFile = load_stage(&hooks_path()).map_err(|e| stage_error(cmd, e))?;
    Ok((p, s, h))
}

/// Re-stage `graph.json` from the CURRENT registries so the document Quickshell
/// hot-reloads never drifts from what `graph view` (and a fresh `graph emit`)
/// would compute. Every mutation of projects/sessions calls this, so the staged
/// graph is always a pure function of the registries — the staged doc can no
/// longer go stale behind a `project add`/`remove`/`link`/`prune`.
fn restage_graph() -> Result<PathBuf, String> {
    let p: ProjectsFile = load_stage(&projects_path())?;
    let s: SessionsFile = load_stage(&sessions_path())?;
    let h: HooksFile = load_stage(&hooks_path())?;
    let doc = build_graph(&p.projects, &s.sessions, &h.hooks);
    let path = graph_path();
    write_stage(&path, &doc)?;
    Ok(path)
}

/// `graph view` — render the DAG (tree in text, graph document in `--json`).
pub fn view(inv: &Invocation) -> Outcome {
    let (p, s, h) = match load_inputs("graph.view") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let focus = inv.flags.get("focus").map(String::as_str);
    let doc = build_graph(&p.projects, &s.sessions, &h.hooks);
    let tree = render(&p.projects, &s.sessions, &h.hooks, focus);
    let (n, e) = (
        doc["nodes"].as_array().map_or(0, Vec::len),
        doc["edges"].as_array().map_or(0, Vec::len),
    );
    Outcome::ok("graph.view", format!("{n} node(s), {e} edge(s)\n{tree}")).with_data(doc)
}

/// `graph project add <name> <path>` — register/update an anchor root.
pub fn project_add(inv: &Invocation) -> Outcome {
    let args = match require_args(inv, &["name", "path"]) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let (name, path) = (args[0].clone(), args[1].clone());
    let mut file: ProjectsFile = match load_stage(&projects_path()) {
        Ok(f) => f,
        Err(e) => return stage_error("graph.project.add", e),
    };

    let mut changed: Vec<String> = Vec::new();
    let message;
    match file.projects.iter_mut().find(|p| p.name == name) {
        Some(existing) if existing.path == path => {
            message = format!("project `{name}` already registered at {path} (no change)");
        }
        Some(existing) => {
            changed.push(format!("project {name}: path {} → {path}", existing.path));
            existing.path = path.clone();
            message = format!("updated project `{name}` → {path}");
        }
        None => {
            file.projects.push(Project {
                name: name.clone(),
                path: path.clone(),
            });
            changed.push(format!("registered project {name} → {path}"));
            message = format!("registered project `{name}` → {path}");
        }
    }

    if !changed.is_empty() {
        file.schema_version = STAGE_GRAPH_VERSION.to_string();
        file.projects.sort_by(|a, b| a.name.cmp(&b.name));
        if let Err(e) = write_stage(&projects_path(), &file) {
            return stage_error("graph.project.add", e);
        }
        // Keep the staged graph.json in lock-step with the registry.
        match restage_graph() {
            Ok(g) => changed.push(g.to_string_lossy().into_owned()),
            Err(e) => return stage_error("graph.project.add", e),
        }
    }
    Outcome::ok("graph.project.add", message)
        .changed(changed)
        .with_data(json!({ "name": name, "path": path, "file": projects_path().to_string_lossy() }))
}

/// `graph project remove <name>` — unregister; ok + no-op if absent.
pub fn project_remove(inv: &Invocation) -> Outcome {
    let args = match require_args(inv, &["name"]) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let name = args[0].clone();
    let mut file: ProjectsFile = match load_stage(&projects_path()) {
        Ok(f) => f,
        Err(e) => return stage_error("graph.project.remove", e),
    };

    let before = file.projects.len();
    file.projects.retain(|p| p.name != name);
    if file.projects.len() == before {
        return Outcome::ok(
            "graph.project.remove",
            format!("project `{name}` was not registered (no change)"),
        )
        .with_data(json!({ "name": name }));
    }
    file.schema_version = STAGE_GRAPH_VERSION.to_string();
    if let Err(e) = write_stage(&projects_path(), &file) {
        return stage_error("graph.project.remove", e);
    }
    let mut changed = vec![format!("removed project {name}")];
    match restage_graph() {
        Ok(g) => changed.push(g.to_string_lossy().into_owned()),
        Err(e) => return stage_error("graph.project.remove", e),
    }
    Outcome::ok("graph.project.remove", format!("removed project `{name}`"))
        .changed(changed)
        .with_data(json!({ "name": name, "file": projects_path().to_string_lossy() }))
}

/// `graph project list` — the registered anchor roots.
pub fn project_list(_inv: &Invocation) -> Outcome {
    let file: ProjectsFile = match load_stage(&projects_path()) {
        Ok(f) => f,
        Err(e) => return stage_error("graph.project.list", e),
    };
    let projects = sorted_projects(&file.projects);
    let mut message = format!("{} project(s) registered", projects.len());
    for p in &projects {
        message.push_str(&format!("\n◆ {}  {}", p.name, p.path));
    }
    Outcome::ok("graph.project.list", message).with_data(json!({ "projects": projects }))
}

/// `graph link <child> <parent>` — set the spawned-by edge on the child.
pub fn link(inv: &Invocation) -> Outcome {
    let args = match require_args(inv, &["child", "parent"]) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let (child, parent) = (args[0].clone(), args[1].clone());
    if child == parent {
        return Outcome::error(
            "graph.link",
            format!("refusing self-link: `{child}` → itself"),
        )
        .with_data(json!({ "reason": "self-link" }));
    }
    let mut file: SessionsFile = match load_stage(&sessions_path()) {
        Ok(f) => f,
        Err(e) => return stage_error("graph.link", e),
    };
    if !file.sessions.iter().any(|s| s.session_id == child) {
        return Outcome::error("graph.link", format!("child session `{child}` not found"))
            .with_data(json!({ "reason": "child-not-found", "child": child }));
    }
    if would_cycle(&file.sessions, &child, &parent) {
        return Outcome::error(
            "graph.link",
            format!("link `{child}` → `{parent}` would create a cycle"),
        )
        .with_data(json!({ "reason": "cycle", "child": child, "parent": parent }));
    }
    let parent_known = file.sessions.iter().any(|s| s.session_id == parent);

    let rec = file
        .sessions
        .iter_mut()
        .find(|s| s.session_id == child)
        .unwrap();
    let mut changed: Vec<String> = Vec::new();
    let message;
    if rec.parent_session_id.as_deref() == Some(parent.as_str()) {
        message = format!("`{child}` already linked to `{parent}` (no change)");
    } else {
        rec.parent_session_id = Some(parent.clone());
        changed.push(format!("session {child}: parentSessionId → {parent}"));
        message = format!("linked `{child}` (spawned by `{parent}`)");
        file.schema_version = if file.schema_version.is_empty() {
            STAGE_GRAPH_VERSION.to_string()
        } else {
            file.schema_version
        };
        if let Err(e) = write_stage(&sessions_path(), &file) {
            return stage_error("graph.link", e);
        }
        match restage_graph() {
            Ok(g) => changed.push(g.to_string_lossy().into_owned()),
            Err(e) => return stage_error("graph.link", e),
        }
    }

    let mut data = json!({ "child": child, "parent": parent });
    if !parent_known {
        data["warning"] = json!("parent session not (yet) registered; edge recorded anyway");
    }
    Outcome::ok("graph.link", message)
        .changed(changed)
        .with_data(data)
}

/// Normalise a Hyprland window address for comparison: lowercased, with any
/// leading `0x` stripped. The stored `windowAddress` and hyprctl's reported
/// addresses can disagree on case and on a present/absent `0x` prefix
/// (hyprctl reports e.g. `0x55…`); this makes the match tolerant of both.
fn normalize_addr(addr: &str) -> String {
    let a = addr.trim();
    let a = a
        .strip_prefix("0x")
        .or_else(|| a.strip_prefix("0X"))
        .unwrap_or(a);
    a.to_ascii_lowercase()
}

/// Does `want` name a live window in the parsed `hyprctl clients -j` array?
/// Pure over the already-decoded JSON so it is unit-testable without a
/// compositor. Matches on the normalised `address` field of any client.
fn window_present(clients: &[Value], want: &str) -> bool {
    let want = normalize_addr(want);
    clients.iter().any(|c| {
        c.get("address")
            .and_then(Value::as_str)
            .map(|a| normalize_addr(a) == want)
            .unwrap_or(false)
    })
}

/// `graph focus <node>` — jump to the session's window via hyprctl
/// (the Terminal-Commander session-jump flow).
///
/// `hyprctl dispatch focuswindow` exits 0 even when the target window is gone,
/// so we first list live clients (`hyprctl clients -j`) and verify the stored
/// `windowAddress` is actually present before dispatching. A vanished terminal
/// → structured `window-not-found` (exit 1), no dispatch.
pub fn focus(inv: &Invocation) -> Outcome {
    let args = match require_args(inv, &["node"]) {
        Ok(a) => a,
        Err(e) => return e,
    };
    // Accept both `session:<id>` node ids and bare session ids.
    let id = args[0]
        .strip_prefix("session:")
        .unwrap_or(&args[0])
        .to_string();
    let file: SessionsFile = match load_stage(&sessions_path()) {
        Ok(f) => f,
        Err(e) => return stage_error("graph.focus", e),
    };
    let Some(rec) = file.sessions.iter().find(|s| s.session_id == id) else {
        return Outcome::error("graph.focus", format!("unknown session `{id}`"))
            .with_data(json!({ "reason": "session-not-found", "node": id }));
    };
    if rec.window_address.is_empty() {
        return Outcome::error(
            "graph.focus",
            format!("session `{id}` has no windowAddress to focus"),
        )
        .with_data(json!({ "reason": "no-window-address", "node": id }));
    }
    let addr = rec.window_address.clone();

    // Verify the window exists before dispatching: focuswindow can't tell us.
    match std::process::Command::new("hyprctl")
        .args(["clients", "-j"])
        .output()
    {
        Err(e) => {
            return Outcome::error("graph.focus", format!("hyprctl unavailable: {e}"))
                .with_data(json!({ "reason": "hyprctl-unavailable", "node": id }));
        }
        Ok(out) if !out.status.success() => {
            return Outcome::error(
                "graph.focus",
                format!("hyprctl clients failed (exit {:?})", out.status.code()),
            )
            .with_data(json!({
                "reason": "hyprctl-failed",
                "node": id,
                "stderr": String::from_utf8_lossy(&out.stderr),
            }));
        }
        Ok(out) => {
            let clients: Vec<Value> = match serde_json::from_slice(&out.stdout) {
                Ok(Value::Array(a)) => a,
                _ => {
                    return Outcome::error("graph.focus", "hyprctl clients: unparseable JSON")
                        .with_data(json!({ "reason": "hyprctl-failed", "node": id }));
                }
            };
            if !window_present(&clients, &addr) {
                return Outcome::error(
                    "graph.focus",
                    format!("window {addr} for session `{id}` is gone (terminal closed?)"),
                )
                .with_data(json!({
                    "reason": "window-not-found",
                    "node": id,
                    "windowAddress": addr,
                }));
            }
        }
    }

    let dispatch = format!("address:{addr}");
    match std::process::Command::new("hyprctl")
        .args(["dispatch", "focuswindow", &dispatch])
        .output()
    {
        Err(e) => Outcome::error("graph.focus", format!("hyprctl unavailable: {e}"))
            .with_data(json!({ "reason": "hyprctl-unavailable", "node": id })),
        Ok(out) if !out.status.success() => Outcome::error(
            "graph.focus",
            format!("hyprctl dispatch failed (exit {:?})", out.status.code()),
        )
        .with_data(json!({
            "reason": "hyprctl-failed",
            "node": id,
            "stderr": String::from_utf8_lossy(&out.stderr),
        })),
        Ok(_) => Outcome::ok("graph.focus", format!("focused session `{id}`"))
            .changed([format!("focused window {addr}")])
            .with_data(json!({ "node": id, "windowAddress": addr, "dispatcher": "hyprctl" })),
    }
}

/// `graph prune` — drop `done` sessions (+ their hooks); clear orphaned
/// `parentSessionId`s. Idempotent; writes only when something changed.
pub fn prune(_inv: &Invocation) -> Outcome {
    let mut s_file: SessionsFile = match load_stage(&sessions_path()) {
        Ok(f) => f,
        Err(e) => return stage_error("graph.prune", e),
    };
    let mut h_file: HooksFile = match load_stage(&hooks_path()) {
        Ok(f) => f,
        Err(e) => return stage_error("graph.prune", e),
    };

    let (kept_s, kept_h, removed, cleared) = prune_done(
        std::mem::take(&mut s_file.sessions),
        std::mem::take(&mut h_file.hooks),
    );

    if removed.is_empty() {
        return Outcome::ok("graph.prune", "nothing to prune (no `done` sessions)")
            .with_data(json!({ "removed": [], "clearedParents": [] }));
    }

    s_file.sessions = kept_s;
    h_file.hooks = kept_h;
    if let Err(e) = write_stage(&sessions_path(), &s_file) {
        return stage_error("graph.prune", e);
    }
    if let Err(e) = write_stage(&hooks_path(), &h_file) {
        return stage_error("graph.prune", e);
    }

    let mut changed: Vec<String> = removed
        .iter()
        .map(|id| format!("removed session {id}"))
        .collect();
    changed.extend(
        cleared
            .iter()
            .map(|id| format!("cleared parentSessionId of {id}")),
    );
    match restage_graph() {
        Ok(g) => changed.push(g.to_string_lossy().into_owned()),
        Err(e) => return stage_error("graph.prune", e),
    }
    Outcome::ok(
        "graph.prune",
        format!(
            "pruned {} session(s); cleared {} orphaned parent link(s)",
            removed.len(),
            cleared.len()
        ),
    )
    .changed(changed)
    .with_data(json!({ "removed": removed, "clearedParents": cleared }))
}

/// `graph emit` — stage the resolved DAG for Quickshell hot-reload
/// (mirrors the `drachma emit stage` pattern; atomic write).
pub fn emit(_inv: &Invocation) -> Outcome {
    let (p, s, h) = match load_inputs("graph.emit") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let doc = build_graph(&p.projects, &s.sessions, &h.hooks);
    let path = graph_path();
    if let Err(e) = write_stage(&path, &doc) {
        return stage_error("graph.emit", e);
    }
    let (n, e) = (
        doc["nodes"].as_array().map_or(0, Vec::len),
        doc["edges"].as_array().map_or(0, Vec::len),
    );
    Outcome::ok(
        "graph.emit",
        format!("staged graph.json ({n} node(s), {e} edge(s))"),
    )
    .changed([path.to_string_lossy().into_owned()])
    .with_data(json!({
        "path": path.to_string_lossy(),
        "nodes": n,
        "edges": e,
    }))
}

// ── Tests (pure cores: anchoring, cycles, render determinism, prune) ────────

#[cfg(test)]
mod tests {
    use super::*;

    fn session(
        id: &str,
        cwd: &str,
        state: &str,
        started: &str,
        parent: Option<&str>,
    ) -> SessionRecord {
        SessionRecord {
            session_id: id.into(),
            agent: "claude".into(),
            window_address: format!("0x{id}"),
            cwd: cwd.into(),
            state: state.into(),
            started_at: started.into(),
            parent_session_id: parent.map(str::to_string),
            extra: Map::new(),
        }
    }

    fn fixture_projects() -> Vec<Project> {
        vec![
            Project {
                name: "nested".into(),
                path: "/home/k/Aoide/sub".into(),
            },
            Project {
                name: "aoide".into(),
                path: "/home/k/Aoide".into(),
            },
        ]
    }

    #[test]
    fn anchoring_longest_prefix_wins() {
        let p = sorted_projects(&fixture_projects()); // [aoide, nested]
                                                      // Inside the nested project → the deeper root wins.
        assert_eq!(
            anchor_for("/home/k/Aoide/sub/x", &p).map(|i| p[i].name.as_str()),
            Some("nested")
        );
        // At the outer root → the outer project.
        assert_eq!(
            anchor_for("/home/k/Aoide", &p).map(|i| p[i].name.as_str()),
            Some("aoide")
        );
        // Component-aware: /home/k/Aoide-extra is NOT under /home/k/Aoide.
        assert_eq!(anchor_for("/home/k/Aoide-extra", &p), None);
        assert_eq!(anchor_for("/tmp/elsewhere", &p), None);
    }

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
        // Hook state merge: s1's latest hook phase becomes its live state.
        let hooks = vec![
            HookRecord {
                session_id: "s1".into(),
                phase: "PreToolUse".into(),
                updated_at: "2026-01-01T01:00:00Z".into(),
                extra: Map::new(),
            },
            HookRecord {
                session_id: "s1".into(),
                phase: "Stop".into(),
                updated_at: "2026-01-01T02:00:00Z".into(),
                extra: Map::new(),
            },
        ];
        let expected = "\
◆ aoide  /home/k/Aoide
└─ ● s1  claude  Stop  /home/k/Aoide
   └─ ● s3  claude  idle  /home/k/elsewhere
◆ nested  /home/k/Aoide/sub
└─ ● s2  claude  running  /home/k/Aoide/sub/x
◆ (unanchored)
└─ ● s4  claude  idle  /tmp";
        assert_eq!(render(&projects, &sessions, &hooks, None), expected);
        // The focus marker singles out one node.
        let focused = render(&projects, &sessions, &hooks, Some("session:s2"));
        assert!(focused.contains("└─ ▶ ● s2  claude  running"));
        // Same inputs → same render (deterministic).
        assert_eq!(render(&projects, &sessions, &hooks, None), expected);
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
    fn focus_address_matching_is_prefix_and_case_tolerant() {
        // hyprctl reports `0x…` lowercase; the stored windowAddress may differ
        // on case and on a present/absent `0x` prefix — all must match.
        let clients = vec![
            json!({ "address": "0x55aabbccdd00", "class": "kitty" }),
            json!({ "address": "0x1234ef", "class": "foot" }),
        ];
        assert!(window_present(&clients, "0x55aabbccdd00")); // exact
        assert!(window_present(&clients, "55aabbccdd00")); // missing 0x prefix
        assert!(window_present(&clients, "0x55AABBCCDD00")); // upper case
        assert!(window_present(&clients, "55AABBCCDD00")); // both
        assert!(window_present(&clients, "0X1234EF")); // 0X + upper
                                                       // A vanished window is absent.
        assert!(!window_present(&clients, "0xdeadbeef"));
        assert!(!window_present(&clients, ""));
        // Client entry without an address field is ignored, not a false match.
        let noaddr = vec![json!({ "class": "kitty" })];
        assert!(!window_present(&noaddr, "0x1"));

        // Normalisation is idempotent and prefix-agnostic.
        assert_eq!(normalize_addr("0xABC"), "abc");
        assert_eq!(normalize_addr("abc"), "abc");
        assert_eq!(normalize_addr("  0Xabc  "), "abc");
    }

    fn unique_stage(tag: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "aoide-graph-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn invocation(path: &[&str], args: &[&str]) -> Invocation {
        Invocation {
            path: path.iter().map(|s| s.to_string()).collect(),
            args: args.iter().map(|s| s.to_string()).collect(),
            flags: BTreeMap::new(),
            door: crate::daemon::Door::Cli,
        }
    }

    /// Defect: `graph view` showed 0 nodes while the staged graph.json still
    /// held a project node from an earlier emit — the staged doc had gone stale
    /// because `project add` mutated projects.json without re-staging graph.json.
    /// Now every mutation re-stages, so graph.json always equals what `view`
    /// (a fresh `build_graph` over the registries) computes.
    #[test]
    fn project_add_restages_graph_json_consistent_with_view() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("restage");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // Register a project. graph.json must now exist and carry the node.
        let out = project_add(&invocation(
            &["graph", "project", "add"],
            &["aoide", "/home/k/Aoide"],
        ));
        assert_eq!(out.status, crate::output::Status::Ok);

        let staged: Value =
            serde_json::from_str(&std::fs::read_to_string(stage.join("graph.json")).unwrap())
                .unwrap();
        let nodes = staged["nodes"].as_array().unwrap();
        assert!(
            nodes.iter().any(|n| n["id"] == "project:aoide"),
            "staged graph.json carries the freshly-registered project"
        );

        // The staged doc equals exactly what `graph view` computes from the
        // current registries — no drift.
        let view = view(&invocation(&["graph", "view"], &[]));
        assert_eq!(&staged, view.data.as_ref().unwrap());

        // A fresh emit would stage the very same document (idempotent).
        let (p, s, h) = load_inputs("test").unwrap();
        assert_eq!(staged, build_graph(&p.projects, &s.sessions, &h.hooks));

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn session_records_round_trip_unknown_fields() {
        // shellbridge may grow fields this version does not know; a graph
        // rewrite (link/prune) must not drop them.
        let raw = r#"{ "sessionId": "s", "agent": "claude", "windowAddress": "0x1",
                       "cwd": "/x", "state": "running", "startedAt": "t",
                       "futureField": 42 }"#;
        let rec: SessionRecord = serde_json::from_str(raw).unwrap();
        let back = serde_json::to_value(&rec).unwrap();
        assert_eq!(back["futureField"], 42);
        assert!(back.get("parentSessionId").is_none());
    }
}
