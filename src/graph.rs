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
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
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
    /// Conductor-channel additive fields (v0-safe; absent on a legacy record).
    /// `conductable` marks a session spawned under `aoide conduct` (it owns a
    /// PTY + control socket); `socket` is that per-session injection socket
    /// (`$XDG_RUNTIME_DIR/aoide/session-<id>.sock`); `title` is the auto-renamed
    /// one-line task the last delivered `graph send` wrote onto the node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conductable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
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
        // baton can distinguish conductable nodes + label by title.
        if let Some(c) = s.conductable {
            node["conductable"] = json!(c);
        }
        if let Some(sock) = &s.socket {
            node["socket"] = json!(sock);
        }
        if let Some(t) = &s.title {
            node["title"] = json!(t);
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

// ── Session-registration verbs (the write path shellbridge does not yet own) ─
//
// shellbridge only ever SEEDS empty sessions.json/hooks.json (its socket accept
// loop is future work), so nothing registers a live session — the desktop
// widgets and `baton` read a graph that is always starved of data. These verbs
// are the missing write door: a session harness (or a Claude Code hook) upserts
// its own record, and every mutation re-stages graph.json so the read path
// (build_graph → graph.json → QML FileView / baton) lights up immediately.

/// UTC wall-clock now as ISO-8601 `YYYY-MM-DDTHH:MM:SSZ`.
///
/// The same `SystemTime`→epoch-seconds idiom daemon.rs stamps audit records
/// with, formatted for the `startedAt` field the stage shapes carry. The civil
/// date is hand-rolled (Howard Hinnant's `civil_from_days`, the exact inverse of
/// [`crate::baton::theme::parse_iso_utc`], the reader) so the offline lock never
/// grows a chrono just to write one timestamp — and a stamp we write always
/// round-trips back through the reader baton/theme already ships.
fn now_iso_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    iso_utc_from_epoch(secs)
}

/// Format Unix epoch seconds as ISO-8601 UTC (pure; unit-tested).
fn iso_utc_from_epoch(secs: i64) -> String {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // civil_from_days: the inverse of parse_iso_utc's days computation.
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// UPSERT a session record by id (pure; the handler wires I/O around it).
///
/// A fresh id is inserted `state="running"`, `startedAt=now`, `agent` defaulting
/// to `claude`. A re-start of an existing id updates only the fields provided
/// (a `None` leaves the stored value), re-marks it `running`, and NEVER clobbers
/// `startedAt` — the record is bounded to one per id, never duplicated. Returns
/// `true` when a new record was inserted.
pub fn upsert_session(
    sessions: &mut Vec<SessionRecord>,
    id: &str,
    agent: Option<&str>,
    cwd: Option<&str>,
    window: Option<&str>,
    parent: Option<&str>,
    conductable: Option<bool>,
    socket: Option<&str>,
    title: Option<&str>,
    now: &str,
) -> bool {
    if let Some(s) = sessions.iter_mut().find(|s| s.session_id == id) {
        if let Some(a) = agent {
            s.agent = a.to_string();
        }
        if let Some(c) = cwd {
            s.cwd = c.to_string();
        }
        if let Some(w) = window {
            s.window_address = w.to_string();
        }
        if let Some(p) = parent {
            s.parent_session_id = Some(p.to_string());
        }
        if let Some(c) = conductable {
            s.conductable = Some(c);
        }
        if let Some(sock) = socket {
            s.socket = Some(sock.to_string());
        }
        if let Some(t) = title {
            s.title = Some(t.to_string());
        }
        s.state = "running".to_string(); // `start` means running; startedAt kept.
        false
    } else {
        sessions.push(SessionRecord {
            session_id: id.to_string(),
            agent: agent.unwrap_or("claude").to_string(),
            window_address: window.unwrap_or_default().to_string(),
            cwd: cwd.unwrap_or_default().to_string(),
            state: "running".to_string(),
            started_at: now.to_string(),
            parent_session_id: parent.map(str::to_string),
            conductable,
            socket: socket.map(str::to_string),
            title: title.map(str::to_string),
            extra: Map::new(),
        });
        true
    }
}

/// UPSERT the single hook record for a session (pure; bounded one-per-id).
///
/// `merged_sessions` keys the live phase by (latest `updatedAt`), so a single
/// rolling record per session is all it needs — no unbounded append.
pub fn upsert_hook(hooks: &mut Vec<HookRecord>, id: &str, phase: &str, now: &str) {
    if let Some(h) = hooks.iter_mut().find(|h| h.session_id == id) {
        h.phase = phase.to_string();
        h.updated_at = now.to_string();
    } else {
        hooks.push(HookRecord {
            session_id: id.to_string(),
            phase: phase.to_string(),
            updated_at: now.to_string(),
            extra: Map::new(),
        });
    }
}

/// A required `--flag` → structured usage error (exit 2) when absent/empty.
fn require_flag(inv: &Invocation, name: &str) -> Result<String, Outcome> {
    match inv.flags.get(name).filter(|v| !v.is_empty()) {
        Some(v) => Ok(v.clone()),
        None => Err(Outcome::usage(
            inv.dotted(),
            format!(
                "usage: aoide {} --{name} <value> [--json]",
                inv.path.join(" ")
            ),
        )),
    }
}

/// Core of `graph session start`: cycle-check a parent, UPSERT, re-stage.
#[allow(clippy::too_many_arguments)]
fn do_session_start(
    id: &str,
    agent: Option<&str>,
    cwd: Option<&str>,
    window: Option<&str>,
    parent: Option<&str>,
    conductable: Option<bool>,
    socket: Option<&str>,
    title: Option<&str>,
) -> Outcome {
    let cmd = "graph.session.start";
    let mut file: SessionsFile = match load_stage(&sessions_path()) {
        Ok(f) => f,
        Err(e) => return stage_error(cmd, e),
    };
    // Reuse `link`'s cycle guard: an id parented under its own descendant (or
    // itself) is refused before we mutate anything.
    if let Some(p) = parent {
        if would_cycle(&file.sessions, id, p) {
            return Outcome::error(
                cmd,
                format!("parenting `{id}` under `{p}` would create a cycle"),
            )
            .with_data(json!({ "reason": "cycle", "sessionId": id, "parent": p }));
        }
    }

    let now = now_iso_utc();
    let inserted = upsert_session(
        &mut file.sessions,
        id,
        agent,
        cwd,
        window,
        parent,
        conductable,
        socket,
        title,
        &now,
    );
    let (r_agent, r_started) = file
        .sessions
        .iter()
        .find(|s| s.session_id == id)
        .map(|s| (s.agent.clone(), s.started_at.clone()))
        .unwrap_or_default();
    if file.schema_version.is_empty() {
        file.schema_version = STAGE_GRAPH_VERSION.to_string();
    }
    if let Err(e) = write_stage(&sessions_path(), &file) {
        return stage_error(cmd, e);
    }

    let mut changed = vec![if inserted {
        format!("registered session {id} (running)")
    } else {
        format!("updated session {id}")
    }];
    match restage_graph() {
        Ok(g) => changed.push(g.to_string_lossy().into_owned()),
        Err(e) => return stage_error(cmd, e),
    }
    let message = if inserted {
        format!("started session `{id}` (agent {r_agent}, running)")
    } else {
        format!("re-started session `{id}` (fields updated; startedAt preserved)")
    };
    Outcome::ok(cmd, message).changed(changed).with_data(json!({
        "sessionId": id,
        "agent": r_agent,
        "startedAt": r_started,
        "inserted": inserted,
        "file": sessions_path().to_string_lossy(),
    }))
}

/// Core of `graph session phase`: UPSERT the hook record, re-stage.
fn do_session_phase(id: &str, phase: &str) -> Outcome {
    let cmd = "graph.session.phase";
    let mut file: HooksFile = match load_stage(&hooks_path()) {
        Ok(f) => f,
        Err(e) => return stage_error(cmd, e),
    };
    let now = now_iso_utc();
    upsert_hook(&mut file.hooks, id, phase, &now);
    if file.schema_version.is_empty() {
        file.schema_version = STAGE_GRAPH_VERSION.to_string();
    }
    if let Err(e) = write_stage(&hooks_path(), &file) {
        return stage_error(cmd, e);
    }
    let mut changed = vec![format!("session {id}: phase → {phase}")];
    match restage_graph() {
        Ok(g) => changed.push(g.to_string_lossy().into_owned()),
        Err(e) => return stage_error(cmd, e),
    }
    Outcome::ok(cmd, format!("session `{id}` phase = {phase}"))
        .changed(changed)
        .with_data(json!({
            "sessionId": id,
            "phase": phase,
            "updatedAt": now,
            "file": hooks_path().to_string_lossy(),
        }))
}

/// Conditional sibling of [`do_session_phase`]: UPSERT `phase` for `id` ONLY when
/// its CURRENT hook phase equals `expected`, else an ok no-op that writes nothing.
/// hooks.json is loaded ONCE — the guard read and the write share the same load,
/// so the current phase is never read twice. This is the door the ambiguous idle
/// Notification walks: only a still-`running` turn becomes `blocked`.
fn do_session_phase_if(id: &str, phase: &str, expected: &str) -> Outcome {
    let cmd = "graph.session.phase";
    let mut file: HooksFile = match load_stage(&hooks_path()) {
        Ok(f) => f,
        Err(e) => return stage_error(cmd, e),
    };
    let current = file
        .hooks
        .iter()
        .find(|h| h.session_id == id)
        .map(|h| h.phase.clone())
        .unwrap_or_default();
    if current != expected {
        return Outcome::ok(
            cmd,
            format!("session `{id}` phase unchanged (current `{current}` ≠ `{expected}`)"),
        )
        .with_data(json!({
            "sessionId": id,
            "phase": current,
            "skipped": true,
            "expected": expected,
        }));
    }
    let now = now_iso_utc();
    upsert_hook(&mut file.hooks, id, phase, &now);
    if file.schema_version.is_empty() {
        file.schema_version = STAGE_GRAPH_VERSION.to_string();
    }
    if let Err(e) = write_stage(&hooks_path(), &file) {
        return stage_error(cmd, e);
    }
    let mut changed = vec![format!("session {id}: phase → {phase}")];
    match restage_graph() {
        Ok(g) => changed.push(g.to_string_lossy().into_owned()),
        Err(e) => return stage_error(cmd, e),
    }
    Outcome::ok(cmd, format!("session `{id}` phase = {phase}"))
        .changed(changed)
        .with_data(json!({
            "sessionId": id,
            "phase": phase,
            "updatedAt": now,
            "file": hooks_path().to_string_lossy(),
        }))
}

/// Core of `graph session end`: mark the session `done` (and its hook phase
/// `done`), re-stage. An unknown id is an ok no-op (matching `project remove`).
fn do_session_end(id: &str) -> Outcome {
    let cmd = "graph.session.end";
    let mut s_file: SessionsFile = match load_stage(&sessions_path()) {
        Ok(f) => f,
        Err(e) => return stage_error(cmd, e),
    };
    if !s_file.sessions.iter().any(|s| s.session_id == id) {
        return Outcome::ok(
            cmd,
            format!("session `{id}` was not registered (no change)"),
        )
        .with_data(json!({ "sessionId": id }));
    }
    for s in s_file.sessions.iter_mut() {
        if s.session_id == id {
            s.state = "done".to_string();
        }
    }
    if s_file.schema_version.is_empty() {
        s_file.schema_version = STAGE_GRAPH_VERSION.to_string();
    }
    if let Err(e) = write_stage(&sessions_path(), &s_file) {
        return stage_error(cmd, e);
    }

    // Mirror the terminal state into hooks.json so the merged live phase agrees.
    let mut h_file: HooksFile = match load_stage(&hooks_path()) {
        Ok(f) => f,
        Err(e) => return stage_error(cmd, e),
    };
    let now = now_iso_utc();
    upsert_hook(&mut h_file.hooks, id, "done", &now);
    if h_file.schema_version.is_empty() {
        h_file.schema_version = STAGE_GRAPH_VERSION.to_string();
    }
    if let Err(e) = write_stage(&hooks_path(), &h_file) {
        return stage_error(cmd, e);
    }

    let mut changed = vec![
        format!("session {id}: state → done"),
        format!("session {id}: phase → done"),
    ];
    match restage_graph() {
        Ok(g) => changed.push(g.to_string_lossy().into_owned()),
        Err(e) => return stage_error(cmd, e),
    }
    Outcome::ok(cmd, format!("ended session `{id}`"))
        .changed(changed)
        .with_data(json!({ "sessionId": id, "file": sessions_path().to_string_lossy() }))
}

/// `graph session start --id <id> [--agent --cwd --window --parent]` — UPSERT a
/// running session record (idempotent; startedAt preserved on re-start).
pub fn session_start(inv: &Invocation) -> Outcome {
    let id = match require_flag(inv, "id") {
        Ok(v) => v,
        Err(o) => return o,
    };
    do_session_start(
        &id,
        inv.flags.get("agent").map(String::as_str),
        inv.flags.get("cwd").map(String::as_str),
        inv.flags.get("window").map(String::as_str),
        inv.flags.get("parent").map(String::as_str),
        None,
        None,
        None,
    )
}

/// `graph session phase --id <id> --phase <phase>` — UPSERT the live hook phase.
pub fn session_phase(inv: &Invocation) -> Outcome {
    let id = match require_flag(inv, "id") {
        Ok(v) => v,
        Err(o) => return o,
    };
    let phase = match require_flag(inv, "phase") {
        Ok(v) => v,
        Err(o) => return o,
    };
    do_session_phase(&id, &phase)
}

/// `graph session end --id <id>` — mark the session done (ok no-op if unknown).
pub fn session_end(inv: &Invocation) -> Outcome {
    let id = match require_flag(inv, "id") {
        Ok(v) => v,
        Err(o) => return o,
    };
    do_session_end(&id)
}

/// `graph wrap [--agent --parent --id] -- <command…>` — run ANY agent command
/// as a registered session. The universal door for hookless agents: spawn with
/// INHERITED stdio (a wrapped TUI runs undisturbed), register the session
/// running, wait, and mark it done whatever happened — a crashed agent still
/// resolves instead of haunting the roster. The child sees AOIDE_SESSION_ID,
/// so anything hookable inside it can self-report richer phases through
/// `graph session phase --id "$AOIDE_SESSION_ID" --phase blocked`.
///
/// Ordering: spawn FIRST, register second — a failed exec must never register
/// a ghost session. Exit mirrors the child (Ok on success, Error otherwise)
/// with the real code in data.exitCode; the process code stays canonical.
pub fn session_wrap(inv: &Invocation) -> Outcome {
    let cmd = "graph.wrap";
    if inv.args.is_empty() {
        return Outcome::usage(
            cmd,
            "usage: aoide graph wrap [--agent <name>] [--parent <sessionId>] [--id <id>] -- <command …>",
        );
    }
    let program = &inv.args[0];
    let agent = inv.flags.get("agent").cloned().unwrap_or_else(|| {
        std::path::Path::new(program)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| program.clone())
    });
    let id = inv.flags.get("id").cloned().unwrap_or_else(|| {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        format!("wrap-{}-{ts}", std::process::id())
    });
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.to_string_lossy().into_owned());

    let mut child = match std::process::Command::new(program)
        .args(&inv.args[1..])
        .env("AOIDE_SESSION_ID", &id)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return Outcome::error(cmd, format!("failed to spawn `{program}`: {e}")),
    };

    let _ = do_session_start(
        &id,
        Some(&agent),
        cwd.as_deref(),
        None,
        inv.flags.get("parent").map(String::as_str),
        None,
        None,
        None,
    );

    let status = child.wait();
    let _ = do_session_end(&id);

    match status {
        Ok(st) if st.success() => {
            Outcome::ok(cmd, format!("`{agent}` finished (session `{id}`)"))
                .changed(vec![format!("session {id}: running → done")])
                .with_data(json!({ "sessionId": id, "agent": agent, "exitCode": 0 }))
        }
        Ok(st) => {
            let code = st.code().unwrap_or(-1); // -1: killed by signal
            Outcome::error(cmd, format!("`{agent}` exited {code} (session `{id}`)"))
                .changed(vec![format!("session {id}: running → done")])
                .with_data(json!({ "sessionId": id, "agent": agent, "exitCode": code }))
        }
        Err(e) => Outcome::error(cmd, format!("wait on `{agent}` failed: {e} (session `{id}`)"))
            .with_data(json!({ "sessionId": id, "agent": agent })),
    }
}

// ── Conductor channel: `conduct` (PTY wrap) + `graph send` (injection) ──────
//
// `conduct` is the controllable sibling of `wrap`: it runs the agent on its own
// PTY so a central controller (or the baton) can type INTO the running agent
// through a per-session control socket, while a wrapped TUI still runs
// undisturbed. `graph send` is the one injection door — gated through aoided's
// audit path (pending by default; `--yes`/autogate delivers). The unsafe libc
// here is confined to `spawn_on_pty`, the raw-mode guard, the winsize ioctls,
// and the `poll()` multiplexer; each is documented where the ordering matters.

/// The command's basename (the agent-name default), e.g. `/usr/bin/claude` →
/// `claude`.
fn command_basename(program: &str) -> String {
    std::path::Path::new(program)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| program.to_string())
}

fn unix_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The per-session conductor control socket:
/// `$XDG_RUNTIME_DIR/aoide/session-<id>.sock` — the same user-scoped runtime-dir
/// convention as shellbridge's socket (never networked). A missing
/// `XDG_RUNTIME_DIR` falls back to `/run/user/1000` like [`crate::shellbridge`].
fn conduct_socket_path(id: &str) -> PathBuf {
    let runtime = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/run/user/1000".into());
    PathBuf::from(runtime)
        .join("aoide")
        .join(format!("session-{id}.sock"))
}

// SIGWINCH latch: the handler only flips a flag (async-signal-safe); the poll
// loop services it (re-reading the real tty size and pushing it to the master).
static WINCH: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
extern "C" fn on_winch(_sig: libc::c_int) {
    WINCH.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Install the SIGWINCH handler WITHOUT `SA_RESTART`, so a resize interrupts
/// `poll()` (returns `EINTR`) and the loop can propagate the new size promptly.
fn install_winch_handler() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_winch as *const () as libc::sighandler_t;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGWINCH, &sa, std::ptr::null_mut());
    }
}

/// The current window size of a tty fd, or `None` when it is not a terminal
/// (a pipe / redirected stdin in a test) or reports a zero geometry.
fn tty_winsize(fd: RawFd) -> Option<libc::winsize> {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws as *mut libc::winsize) };
    if rc == 0 && (ws.ws_row != 0 || ws.ws_col != 0) {
        Some(ws)
    } else {
        None
    }
}

/// Push a window size onto the pty master (TIOCSWINSZ → the child sees SIGWINCH).
fn set_winsize(master: RawFd, ws: &libc::winsize) {
    unsafe {
        libc::ioctl(master, libc::TIOCSWINSZ, ws as *const libc::winsize);
    }
}

/// RAII raw-mode guard for the REAL controlling tty. `enter` saves the current
/// termios and switches to raw (so the wrapped TUI gets keystrokes unbuffered,
/// unechoed, and Ctrl-C flows to it as a byte instead of a signal). Drop —
/// which runs on normal return AND on unwind (panic=unwind) — restores it, so no
/// exit path can leave a wedged terminal. When the fd is not a tty (a test / a
/// pipe) the guard is inert: conduct still runs, it just touches no terminal.
struct TtyRaw {
    fd: RawFd,
    saved: libc::termios,
    active: bool,
}
impl TtyRaw {
    fn enter(fd: RawFd) -> Self {
        unsafe {
            let mut saved: libc::termios = std::mem::zeroed();
            if libc::isatty(fd) != 1 || libc::tcgetattr(fd, &mut saved) != 0 {
                return TtyRaw {
                    fd,
                    saved,
                    active: false,
                };
            }
            let mut raw = saved;
            libc::cfmakeraw(&mut raw);
            let _ = libc::tcsetattr(fd, libc::TCSANOW, &raw);
            TtyRaw {
                fd,
                saved,
                active: true,
            }
        }
    }
    fn restore(&mut self) {
        if self.active {
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved);
            }
            self.active = false;
        }
    }
}
impl Drop for TtyRaw {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Open a PTY and spawn `program args` on the SLAVE as a fresh session that owns
/// the slave as its controlling terminal. Returns the (reapable) child plus the
/// MASTER fd (owned, so it closes on every drop path).
///
/// The child's `pre_exec` ordering is load-bearing and each step is a raw libc
/// call (async-signal-safe): `setsid()` starts a new session with NO controlling
/// tty; `ioctl(slave, TIOCSCTTY)` then acquires the slave as this session's ctty
/// (only a session leader without a ctty may do this — hence setsid FIRST); the
/// slave is dup'd over fds 0/1/2 so the child's std streams ARE the pty; and the
/// master + spare slave fd are closed in the child. All of this precedes exec.
fn spawn_on_pty(
    program: &str,
    args: &[String],
    session_id: &str,
    ws: Option<libc::winsize>,
) -> std::io::Result<(std::process::Child, OwnedFd)> {
    use std::os::unix::process::CommandExt;

    let mut master: RawFd = -1;
    let mut slave: RawFd = -1;
    let wsp = ws
        .as_ref()
        .map(|w| w as *const libc::winsize)
        .unwrap_or(std::ptr::null());
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            wsp,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Own the master at once: it is now closed on any early return / on drop.
    let master_owned = unsafe { OwnedFd::from_raw_fd(master) };

    let slave_fd = slave;
    let master_fd = master;
    let mut cmd = std::process::Command::new(program);
    cmd.args(args).env("AOIDE_SESSION_ID", session_id);
    unsafe {
        cmd.pre_exec(move || {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(slave_fd, libc::TIOCSCTTY, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            for target in 0..3 {
                if libc::dup2(slave_fd, target) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            libc::close(master_fd);
            if slave_fd > 2 {
                libc::close(slave_fd);
            }
            Ok(())
        });
    }
    let spawned = cmd.spawn();
    // The parent never speaks on the slave — close it whatever spawn returned.
    unsafe {
        libc::close(slave);
    }
    let child = spawned?;
    Ok((child, master_owned))
}

fn pollfd(fd: RawFd, events: libc::c_short) -> libc::pollfd {
    libc::pollfd {
        fd,
        events,
        revents: 0,
    }
}

/// Write every byte of `data` to `fd`, retrying on `EINTR`. A best-effort mirror
/// helper for the multiplexer (a torn write on abrupt child exit is tolerated).
fn write_all_fd(fd: RawFd, mut data: &[u8]) {
    while !data.is_empty() {
        let n = unsafe { libc::write(fd, data.as_ptr() as *const libc::c_void, data.len()) };
        if n <= 0 {
            let err = std::io::Error::last_os_error();
            if n < 0 && err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        data = &data[n as usize..];
    }
}

/// The single-thread `poll()` multiplexer. Shuttles: real stdin → master (you
/// type normally), master → real stdout (you read normally), and each accepted
/// injection connection → master (INJECTION). A pending SIGWINCH re-sizes the
/// master. Returns the child's real exit code once the master hangs up (the
/// child's slave closed) and the child is reaped.
fn conduct_multiplex(
    master: RawFd,
    listener: Option<&UnixListener>,
    child: &mut std::process::Child,
) -> i32 {
    use std::sync::atomic::Ordering;
    let stdin_fd = libc::STDIN_FILENO;
    let stdout_fd = libc::STDOUT_FILENO;
    let listener_fd = listener.map(|l| l.as_raw_fd());
    let mut conns: Vec<RawFd> = Vec::new();
    let mut stdin_eof = false;
    let mut buf = [0u8; 8192];

    loop {
        // Service a pending resize before blocking again.
        if WINCH.swap(false, Ordering::SeqCst) {
            if let Some(ws) = tty_winsize(stdin_fd) {
                set_winsize(master, &ws);
            }
        }

        let mut fds: Vec<libc::pollfd> = Vec::new();
        if !stdin_eof {
            fds.push(pollfd(stdin_fd, libc::POLLIN));
        }
        fds.push(pollfd(master, libc::POLLIN));
        if let Some(lfd) = listener_fd {
            fds.push(pollfd(lfd, libc::POLLIN));
        }
        for &c in &conns {
            fds.push(pollfd(c, libc::POLLIN));
        }

        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue; // a signal (SIGWINCH) — reloop to service the latch.
            }
            break;
        }

        let revents = |want: RawFd| -> libc::c_short {
            fds.iter()
                .find(|p| p.fd == want)
                .map(|p| p.revents)
                .unwrap_or(0)
        };

        // master → stdout, and hangup detection (the child's slave closed).
        let mrev = revents(master);
        if mrev & libc::POLLIN != 0 {
            let n =
                unsafe { libc::read(master, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n > 0 {
                write_all_fd(stdout_fd, &buf[..n as usize]);
            } else {
                break;
            }
        }
        if mrev & (libc::POLLHUP | libc::POLLERR) != 0 {
            let n =
                unsafe { libc::read(master, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n > 0 {
                write_all_fd(stdout_fd, &buf[..n as usize]);
            }
            break;
        }

        // real stdin → master.
        if !stdin_eof {
            let srev = revents(stdin_fd);
            if srev & libc::POLLIN != 0 {
                let n = unsafe {
                    libc::read(stdin_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                };
                if n > 0 {
                    write_all_fd(master, &buf[..n as usize]);
                } else {
                    stdin_eof = true; // our own stdin closed; keep bridging the rest.
                }
            } else if srev & (libc::POLLHUP | libc::POLLERR) != 0 {
                stdin_eof = true;
            }
        }

        // listener → accept new injection connections.
        if let (Some(lfd), Some(l)) = (listener_fd, listener) {
            if revents(lfd) & libc::POLLIN != 0 {
                loop {
                    match l.accept() {
                        Ok((stream, _)) => {
                            let _ = stream.set_nonblocking(true);
                            let fd = stream.as_raw_fd();
                            std::mem::forget(stream); // fd owned raw; closed on drain-EOF below.
                            conns.push(fd);
                        }
                        Err(_) => break, // EAGAIN — no more pending.
                    }
                }
            }
        }

        // injection connections → master.
        let mut still: Vec<RawFd> = Vec::new();
        for &c in &conns {
            let cr = revents(c);
            if cr & libc::POLLIN != 0 {
                let n =
                    unsafe { libc::read(c, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if n > 0 {
                    write_all_fd(master, &buf[..n as usize]);
                    still.push(c);
                } else {
                    unsafe {
                        libc::close(c);
                    } // EOF — this injection is done.
                }
            } else if cr & (libc::POLLHUP | libc::POLLERR) != 0 {
                loop {
                    let n =
                        unsafe { libc::read(c, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                    if n > 0 {
                        write_all_fd(master, &buf[..n as usize]);
                    } else {
                        break;
                    }
                }
                unsafe {
                    libc::close(c);
                }
            } else {
                still.push(c);
            }
        }
        conns = still;
    }

    for c in conns {
        unsafe {
            libc::close(c);
        }
    }
    match child.wait() {
        Ok(st) => st.code().unwrap_or(-1),
        Err(_) => -1,
    }
}

/// `aoide conduct [--agent A] [--parent P] [--id I] -- <command …>` — the
/// PTY-backed, controllable sibling of `graph wrap`. Same registration semantics
/// (spawn FIRST so a failed exec registers no ghost; running → done; exit
/// mirrored, real code in `data.exitCode`; `AOIDE_SESSION_ID` exported) PLUS: its
/// own PTY + controlling tty, a per-session injection socket, and the
/// `conductable`/`socket` fields on the record so `graph send` can steer it.
pub fn session_conduct(inv: &Invocation) -> Outcome {
    let cmd = "conduct";
    if inv.args.is_empty() {
        return Outcome::usage(
            cmd,
            "usage: aoide conduct [--agent <name>] [--parent <sessionId>] [--id <id>] -- <command …>",
        );
    }
    let program = inv.args[0].clone();
    let agent = inv
        .flags
        .get("agent")
        .cloned()
        .unwrap_or_else(|| command_basename(&program));
    let id = inv
        .flags
        .get("id")
        .cloned()
        .unwrap_or_else(|| format!("conduct-{}-{}", std::process::id(), unix_ts()));
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    let socket_path = conduct_socket_path(&id);

    // Seed the pty with the real tty's geometry so a TUI opens correctly sized.
    let ws = tty_winsize(libc::STDIN_FILENO);

    // Spawn FIRST: a failed exec must register no session (parity with `wrap`).
    let (mut child, master) = match spawn_on_pty(&program, &inv.args[1..], &id, ws) {
        Ok(v) => v,
        Err(e) => return Outcome::error(cmd, format!("failed to conduct `{program}`: {e}")),
    };
    let master_fd = master.as_raw_fd();

    // Bind the per-session injection socket (best-effort: a bind failure leaves
    // the session running but un-injectable — recorded as conductable=false).
    if let Some(parent) = socket_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(&socket_path); // clear a stale socket from a prior crash.
    let listener = UnixListener::bind(&socket_path).ok();
    if let Some(l) = &listener {
        let _ = l.set_nonblocking(true);
    }
    let conductable = listener.is_some();
    let socket_str = socket_path.to_string_lossy().into_owned();

    // Register running + conductable with its socket, so `graph send` resolves it.
    let _ = do_session_start(
        &id,
        Some(&agent),
        cwd.as_deref(),
        None,
        inv.flags.get("parent").map(String::as_str),
        Some(conductable),
        if conductable {
            Some(socket_str.as_str())
        } else {
            None
        },
        None,
    );

    // Raw-mode the real tty + arm resize passthrough. The TtyRaw guard restores
    // the terminal on EVERY path below — normal return and unwind alike.
    install_winch_handler();
    let mut tty = TtyRaw::enter(libc::STDIN_FILENO);
    if let Some(ws) = ws {
        set_winsize(master_fd, &ws);
    }

    let exit_code = conduct_multiplex(master_fd, listener.as_ref(), &mut child);

    // Restore tty, unlink socket, resolve the session — whatever happened.
    tty.restore();
    let _ = std::fs::remove_file(&socket_path);
    let _ = do_session_end(&id);

    let changed = vec![format!("session {id}: running → done")];
    let data = json!({
        "sessionId": id,
        "agent": agent,
        "exitCode": exit_code,
        "conductable": conductable,
        "socket": socket_str,
    });
    if exit_code == 0 {
        Outcome::ok(cmd, format!("`{agent}` finished (conducted session `{id}`)"))
            .changed(changed)
            .with_data(data)
    } else {
        Outcome::error(
            cmd,
            format!("`{agent}` exited {exit_code} (conducted session `{id}`)"),
        )
        .changed(changed)
        .with_data(data)
    }
}

// ── `graph send`: the gated injection door ──────────────────────────────────

/// A pending (unapproved) injection, staged for the baton to surface for a
/// one-key approve/deny. Written atomically to `song/stage/pending.json`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PendingSend {
    #[serde(rename = "sessionId", default)]
    pub session_id: String,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub submit: bool,
    #[serde(rename = "queuedAt", default)]
    pub queued_at: String,
}

/// `pending.json` container.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PendingFile {
    #[serde(rename = "schemaVersion", default)]
    pub schema_version: String,
    #[serde(default)]
    pub pending: Vec<PendingSend>,
}

fn pending_path() -> PathBuf {
    stage_dir().join("pending.json")
}

/// The v1 gate decision for a send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendGate {
    /// Explicit `--yes` on this send.
    Yes,
    /// A standing autogate policy authorised it (no human in the loop).
    Autogate,
    /// No authorisation — held pending for approval.
    Pending,
}
impl SendGate {
    fn delivers(self) -> bool {
        !matches!(self, SendGate::Pending)
    }
    fn label(self) -> &'static str {
        match self {
            SendGate::Yes => "yes",
            SendGate::Autogate => "autogate",
            SendGate::Pending => "pending",
        }
    }
}

/// v1 autogate policy: a single documented global switch. `AOIDE_CONDUCT_AUTOGATE`
/// in {1,true,yes,all} declares an orchestration-mode where sends deliver
/// without a human (still audited). Richer per-parent / per-agent rules (an
/// orchestrator freely commanding its own spawned children) are a later phase;
/// this is the minimal, documented v1 surface.
fn autogate_env() -> bool {
    matches!(
        std::env::var("AOIDE_CONDUCT_AUTOGATE").ok().as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("all")
    )
}

fn send_gate(yes: bool) -> SendGate {
    if yes {
        SendGate::Yes
    } else if autogate_env() {
        SendGate::Autogate
    } else {
        SendGate::Pending
    }
}

/// A one-line, length-bounded form of the injected text — the auto-rename title.
fn one_line_title(text: &str) -> String {
    let first = text.lines().next().unwrap_or("").trim();
    const MAX: usize = 60;
    if first.chars().count() > MAX {
        let mut t: String = first.chars().take(MAX - 1).collect();
        t.push('…');
        t
    } else {
        first.to_string()
    }
}

fn record_pending(id: &str, text: &str, submit: bool) -> Result<(), String> {
    let mut file: PendingFile = load_stage(&pending_path())?;
    file.schema_version = STAGE_GRAPH_VERSION.to_string();
    file.pending.push(PendingSend {
        session_id: id.to_string(),
        text: text.to_string(),
        submit,
        queued_at: now_iso_utc(),
    });
    write_stage(&pending_path(), &file)
}

/// Auto-rename: write `title` onto the session record and re-stage the graph so
/// the node relabels. A missing id is a silent no-op (the send still succeeded).
fn set_session_title(id: &str, title: &str) -> Result<(), String> {
    let mut file: SessionsFile = load_stage(&sessions_path())?;
    let mut found = false;
    for s in file.sessions.iter_mut() {
        if s.session_id == id {
            s.title = Some(title.to_string());
            found = true;
        }
    }
    if !found {
        return Ok(());
    }
    if file.schema_version.is_empty() {
        file.schema_version = STAGE_GRAPH_VERSION.to_string();
    }
    write_stage(&sessions_path(), &file)?;
    restage_graph().map(|_| ())
}

/// One audit line per send outcome, through aoided's audit path. The injected
/// text rides as `untrusted_data` (never the message) — forwarded agent-bound
/// text is data, never re-interpreted as a command (the house rule).
fn audit_send(inv: &Invocation, status: &str, message: &str, text: &str) {
    let log = inv
        .flags
        .get("audit-log")
        .map(PathBuf::from)
        .unwrap_or_else(crate::daemon::default_audit_log);
    let _ = crate::daemon::append_audit(
        &log,
        &crate::daemon::AuditRecord {
            ts: unix_ts(),
            door: inv.door,
            class: crate::daemon::EventClass::Audit,
            command: "graph.send".to_string(),
            status: status.to_string(),
            message: message.to_string(),
            untrusted_data: Some(text.to_string()),
        },
    );
}

/// `aoide graph send --id <id> [--submit] [--yes] -- <text …>` — the one
/// injection door. Resolves the target's control socket from sessions.json;
/// errors cleanly (exit 1) if the id is unknown or not conductable. Gate: WITHOUT
/// `--yes` and no autogate, the send is recorded PENDING (atomic stage write) and
/// NOT delivered; WITH `--yes` (or an autogate match) it connects to the socket,
/// writes `<text>` (+ `\n` on `--submit`), auto-renames the node to a one-line
/// form of the text, and returns delivered. Every outcome writes an audit line.
pub fn session_send(inv: &Invocation) -> Outcome {
    let cmd = "graph.send";
    let id = match require_flag(inv, "id") {
        Ok(v) => v,
        Err(o) => return o,
    };
    if inv.args.is_empty() {
        return Outcome::usage(
            cmd,
            "usage: aoide graph send --id <id> [--submit] [--yes] -- <text …>",
        );
    }
    let text = inv.args.join(" ");
    let submit = inv.flag_present("submit");
    let yes = inv.flag_present("yes");

    let file: SessionsFile = match load_stage(&sessions_path()) {
        Ok(f) => f,
        Err(e) => return stage_error(cmd, e),
    };
    let Some(rec) = file.sessions.iter().find(|s| s.session_id == id) else {
        let out = Outcome::error(cmd, format!("unknown session `{id}`"))
            .with_data(json!({ "reason": "session-not-found", "id": id }));
        audit_send(inv, "error", &out.message, &text);
        return out;
    };
    let is_conductable = rec.conductable == Some(true);
    let socket = rec.socket.clone().filter(|s| !s.is_empty());
    if !is_conductable || socket.is_none() {
        let out = Outcome::error(
            cmd,
            format!("session `{id}` is not conductable (no control socket)"),
        )
        .with_data(json!({ "reason": "not-conductable", "id": id }));
        audit_send(inv, "error", &out.message, &text);
        return out;
    }
    let socket = socket.unwrap();

    // The gate.
    let gate = send_gate(yes);
    if !gate.delivers() {
        if let Err(e) = record_pending(&id, &text, submit) {
            return stage_error(cmd, e);
        }
        let out = Outcome::ok(
            cmd,
            format!("send to `{id}` held pending approval (no --yes / autogate)"),
        )
        .changed(vec![format!("pending send queued for {id}")])
        .with_data(json!({
            "id": id,
            "state": "pending",
            "delivered": false,
            "submit": submit,
            "gate": gate.label(),
        }));
        audit_send(inv, "pending", &out.message, &text);
        return out;
    }

    // Deliver: connect + write the payload (+ newline on --submit).
    let mut payload = text.clone();
    if submit {
        payload.push('\n');
    }
    match UnixStream::connect(&socket) {
        Ok(mut stream) => {
            use std::io::Write as _;
            if let Err(e) = stream
                .write_all(payload.as_bytes())
                .and_then(|_| stream.flush())
            {
                let out = Outcome::error(cmd, format!("failed to inject into `{id}`: {e}"))
                    .with_data(json!({ "reason": "socket-write-failed", "id": id, "socket": socket }));
                audit_send(inv, "error", &out.message, &text);
                return out;
            }
        }
        Err(e) => {
            let out = Outcome::error(cmd, format!("control socket for `{id}` unreachable: {e}"))
                .with_data(json!({ "reason": "socket-unreachable", "id": id, "socket": socket }));
            audit_send(inv, "error", &out.message, &text);
            return out;
        }
    }

    // Auto-rename the node to a one-line form of the delivered task.
    let title = one_line_title(&text);
    let mut changed = vec![format!("injected {} byte(s) into {id}", payload.len())];
    match set_session_title(&id, &title) {
        Ok(()) => changed.push(format!("session {id}: title → {title}")),
        Err(e) => changed.push(format!("(title update failed: {e})")), // delivery already happened.
    }

    let out = Outcome::ok(cmd, format!("delivered to `{id}` ({})", gate.label()))
        .changed(changed)
        .with_data(json!({
            "id": id,
            "state": "delivered",
            "delivered": true,
            "submit": submit,
            "title": title,
            "gate": gate.label(),
        }));
    audit_send(inv, "delivered", &out.message, &text);
    out
}

/// The action a Claude-Code hook payload maps to (or nothing, for events we
/// deliberately ignore — the door is a no-op for everything unmapped).
#[derive(Debug)]
enum HookAction {
    Start { id: String, cwd: Option<String> },
    Phase { id: String, phase: String },
    /// Conditional phase: set `phase` ONLY if the session's CURRENT hook phase is
    /// `running`, else a no-op. Guards the ambiguous idle Notification — a
    /// "waiting for your input" ping only means "blocked" when the turn is still
    /// mid-flight (`running`, e.g. an unanswered AskUserQuestion); a settled
    /// `waiting` session must not be flipped by the ~60s idle heartbeat.
    PhaseIfRunning { id: String, phase: String },
    End { id: String },
}

/// Map ONE hook payload (`session_id`, `hook_event_name`, optional `cwd`) to a
/// session-registration action, or `None` when the event is unknown/missing or
/// the `session_id` is absent/empty. Pure over the decoded JSON so the mapping
/// is unit-testable without touching stdin or the stage.
fn map_hook(payload: &Value) -> Option<HookAction> {
    let id = payload
        .get("session_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())?;
    let event = payload.get("hook_event_name").and_then(Value::as_str)?;
    let cwd = payload
        .get("cwd")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    match event {
        "SessionStart" => Some(HookAction::Start { id: id.to_string(), cwd }),
        // The tool ran (PostToolUse) or a new prompt/tool began: the turn is
        // live. PostToolUse is also HALF the blocked-clearing set — an approved
        // permission runs the tool, and this edge lifts the fermata.
        "UserPromptSubmit" | "PreToolUse" | "PostToolUse" => Some(HookAction::Phase {
            id: id.to_string(),
            phase: "running".to_string(),
        }),
        "Stop" => Some(HookAction::Phase {
            id: id.to_string(),
            phase: "waiting".to_string(),
        }),
        // The one hook with no clean edge: `message` disambiguates its two moods.
        // "permission" → a real mid-turn blocker (publish blocked at once). The
        // ~60s "waiting for your input" idle ping is ambiguous — only a still-
        // running turn (an unseen AskUserQuestion) becomes blocked; a settled
        // waiting/done session is left untouched. Anything else is a no-op.
        "Notification" => {
            let msg = payload
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_ascii_lowercase();
            if msg.contains("permission") {
                Some(HookAction::Phase {
                    id: id.to_string(),
                    phase: "blocked".to_string(),
                })
            } else if msg.contains("waiting for your input") {
                Some(HookAction::PhaseIfRunning {
                    id: id.to_string(),
                    phase: "blocked".to_string(),
                })
            } else {
                None
            }
        }
        "SessionEnd" => Some(HookAction::End { id: id.to_string() }),
        _ => None,
    }
}

/// Drive one hook payload (already read as a string) to its registration.
///
/// Split from `session_hook` so the whole path — parse, map, execute — is
/// testable without a real stdin. Empty/malformed input or an unmapped event is
/// an ok no-op; a mapped action runs the matching core but its outcome is ALWAYS
/// folded into an ok envelope: this door runs inside interactive-session hooks
/// and must never exit non-zero (a stage hiccup must not break the session).
fn hook_from_str(buf: &str) -> Outcome {
    let cmd = "graph.session.hook";
    let noop = |reason: &str| {
        Outcome::ok(cmd, format!("no-op ({reason})"))
            .with_data(json!({ "action": "none", "reason": reason }))
    };
    let payload: Value = match serde_json::from_str(buf.trim()) {
        Ok(v) => v,
        Err(_) => return noop("empty-or-malformed-stdin"),
    };
    let Some(action) = map_hook(&payload) else {
        return noop("unmapped-or-missing-event");
    };
    let inner = match action {
        HookAction::Start { id, cwd } => {
            do_session_start(&id, Some("claude"), cwd.as_deref(), None, None, None, None, None)
        }
        HookAction::Phase { id, phase } => do_session_phase(&id, &phase),
        HookAction::PhaseIfRunning { id, phase } => do_session_phase_if(&id, &phase, "running"),
        HookAction::End { id } => do_session_end(&id),
    };
    // Fold the inner outcome into an ok envelope — exit 0, no matter what.
    Outcome::ok(cmd, inner.message)
        .changed(inner.changed)
        .with_data(json!({
            "action": "applied",
            "innerStatus": format!("{:?}", inner.status),
            "innerData": inner.data,
        }))
}

/// `graph session hook` — the hook door for agent harnesses. Reads ONE JSON
/// object from stdin and maps Claude-Code hook events to the session verbs.
/// Never exits non-zero (see [`hook_from_str`]).
pub fn session_hook(_inv: &Invocation) -> Outcome {
    use std::io::Read;
    let mut buf = String::new();
    let _ = std::io::stdin().lock().read_to_string(&mut buf);
    hook_from_str(&buf)
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
            conductable: None,
            socket: None,
            title: None,
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

    fn wrap_invocation(args: &[&str], flags: &[(&str, &str)]) -> Invocation {
        Invocation {
            path: vec!["graph".into(), "wrap".into()],
            args: args.iter().map(|s| s.to_string()).collect(),
            flags: flags
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            door: crate::daemon::Door::Cli,
        }
    }

    fn conduct_invocation(args: &[&str], flags: &[(&str, &str)]) -> Invocation {
        Invocation {
            path: vec!["conduct".into()],
            args: args.iter().map(|s| s.to_string()).collect(),
            flags: flags
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            door: crate::daemon::Door::Cli,
        }
    }

    fn send_invocation(args: &[&str], flags: &[(&str, &str)]) -> Invocation {
        Invocation {
            path: vec!["graph".into(), "send".into()],
            args: args.iter().map(|s| s.to_string()).collect(),
            flags: flags
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            door: crate::daemon::Door::Cli,
        }
    }

    /// Restore a set of env vars on drop — survives a panicking assertion so the
    /// process-global env never leaks between the env-locked tests.
    struct EnvVars {
        keys: Vec<(&'static str, Option<String>)>,
    }
    impl EnvVars {
        fn save(keys: &[&'static str]) -> Self {
            EnvVars {
                keys: keys.iter().map(|k| (*k, std::env::var(k).ok())).collect(),
            }
        }
    }
    impl Drop for EnvVars {
        fn drop(&mut self) {
            for (k, v) in &self.keys {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    /// The conductor injection path end-to-end: `conduct` a fake echo child on a
    /// real PTY, connect to its per-session control socket, inject bytes, and
    /// assert the CHILD received them on its stdin (it writes them to a proof
    /// file). Also checks the record registered conductable + resolved done, and
    /// the socket was unlinked on exit.
    #[test]
    fn conduct_injects_socket_bytes_into_the_child() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "XDG_RUNTIME_DIR"]);

        let root = unique_stage("conduct-inject");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root); // socket → <root>/aoide/session-*.sock

        let id = "conduct-test";
        let socket = conduct_socket_path(id);
        let proof = root.join("proof.txt");

        // The child reads ONE line from its (pty) stdin and writes it to a file,
        // then exits — proof the injected bytes reached the child's stdin.
        let script = format!("IFS= read -r line; printf '%s' \"$line\" > {}", proof.display());

        // Inject from a helper thread once the socket appears; `conduct` blocks
        // in THIS thread until the child exits.
        let socket_c = socket.clone();
        let injector = std::thread::spawn(move || {
            for _ in 0..300 {
                if socket_c.exists() {
                    if let Ok(mut s) = UnixStream::connect(&socket_c) {
                        use std::io::Write as _;
                        let _ = s.write_all(b"MARKER-42\n");
                        let _ = s.flush();
                        return;
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        });

        let out = session_conduct(&conduct_invocation(&["sh", "-c", &script], &[("id", id)]));
        injector.join().unwrap();

        assert_eq!(out.status, crate::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["exitCode"], 0);
        assert_eq!(out.data.as_ref().unwrap()["conductable"], true);

        // The child received the injected line on its stdin.
        let got = std::fs::read_to_string(&proof).unwrap_or_default();
        assert_eq!(got, "MARKER-42", "child received the injected bytes");

        // Registered conductable with its socket, then resolved done.
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        let rec = s.sessions.iter().find(|r| r.session_id == id).unwrap();
        assert_eq!(rec.state, "done");
        assert_eq!(rec.conductable, Some(true));
        assert!(rec
            .socket
            .as_deref()
            .unwrap()
            .ends_with("session-conduct-test.sock"));
        // Socket unlinked on exit.
        assert!(!socket.exists(), "the control socket is unlinked on exit");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A non-zero child exit is mirrored: Error outcome, real code in
    /// data.exitCode, and the session still resolves done.
    #[test]
    fn conduct_mirrors_a_nonzero_child_exit() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "XDG_RUNTIME_DIR"]);

        let root = unique_stage("conduct-fail");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);

        let out = session_conduct(&conduct_invocation(
            &["sh", "-c", "exit 7"],
            &[("id", "conduct-fail"), ("agent", "sevens")],
        ));
        assert_eq!(out.status, crate::output::Status::Error);
        assert_eq!(out.data.as_ref().unwrap()["exitCode"], 7);

        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        let rec = s.sessions.iter().find(|r| r.session_id == "conduct-fail").unwrap();
        assert_eq!(rec.state, "done");
        assert_eq!(rec.agent, "sevens");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// `graph send --id X --yes -- hi` connects to the socket, delivers the text
    /// (+ newline on --submit), auto-renames the node title, and audits it.
    #[test]
    fn send_yes_delivers_and_autorenames_the_title() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
        ]);

        let root = unique_stage("send-yes");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE"); // no standing autogate.

        let id = "send-target";
        let socket = conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        // A stand-in listener plays the conducted process.
        let listener = UnixListener::bind(&socket).unwrap();

        // Register a conductable session pointing at that socket.
        do_session_start(
            id,
            Some("claude"),
            Some("/w"),
            None,
            None,
            Some(true),
            Some(socket.to_str().unwrap()),
            None,
        );

        // Accept + read the injected payload to EOF in a thread.
        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });

        let out = session_send(&send_invocation(
            &["hello", "world"],
            &[("id", id), ("submit", "true"), ("yes", "true")],
        ));
        let got = acc.join().unwrap();

        assert_eq!(out.status, crate::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["delivered"], true);
        assert_eq!(out.data.as_ref().unwrap()["gate"], "yes");
        // --submit appended a newline.
        assert_eq!(String::from_utf8(got).unwrap(), "hello world\n");

        // Title auto-renamed on the record + restaged graph node.
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(
            s.sessions.iter().find(|r| r.session_id == id).unwrap().title.as_deref(),
            Some("hello world")
        );

        // An audit line for the delivery was written.
        let log = std::fs::read_to_string(root.join("log")).unwrap_or_default();
        assert!(
            log.contains("graph.send") && log.contains("delivered"),
            "audit log carries the delivered send: {log}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// `graph send --id X -- hi` with NO --yes (and no autogate) is held pending:
    /// recorded in pending.json, nothing delivered, title untouched.
    #[test]
    fn send_without_yes_is_held_pending_not_delivered() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
        ]);

        let root = unique_stage("send-pending");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");

        let id = "pend-target";
        let socket = conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap(); // so we can assert nothing connected.

        do_session_start(
            id,
            Some("claude"),
            Some("/w"),
            None,
            None,
            Some(true),
            Some(socket.to_str().unwrap()),
            None,
        );

        let out = session_send(&send_invocation(&["do", "a", "thing"], &[("id", id)]));
        assert_eq!(out.status, crate::output::Status::Ok);
        assert_eq!(out.data.as_ref().unwrap()["state"], "pending");
        assert_eq!(out.data.as_ref().unwrap()["delivered"], false);

        // Nothing connected to the listener.
        assert!(
            matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "a held-pending send delivers nothing"
        );

        // Recorded in pending.json.
        let pf: PendingFile = load_stage(&pending_path()).unwrap();
        assert!(
            pf.pending
                .iter()
                .any(|p| p.session_id == id && p.text == "do a thing"),
            "the send is recorded pending"
        );

        // Title NOT changed (delivery never happened).
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert!(s.sessions.iter().find(|r| r.session_id == id).unwrap().title.is_none());

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A send to an unknown id, or to a registered-but-not-conductable session,
    /// is a clean structured error (exit 1) — even with --yes.
    #[test]
    fn send_unknown_or_unconductable_is_a_clean_error() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_AUDIT_LOG"]);

        let root = unique_stage("send-err");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));

        // Unknown id.
        let out = session_send(&send_invocation(&["hi"], &[("id", "ghost"), ("yes", "true")]));
        assert_eq!(out.status, crate::output::Status::Error);
        assert_eq!(out.data.as_ref().unwrap()["reason"], "session-not-found");

        // Registered but not conductable (a plain wrap/hook session).
        do_session_start("plain", Some("claude"), None, None, None, None, None, None);
        let out = session_send(&send_invocation(&["hi"], &[("id", "plain"), ("yes", "true")]));
        assert_eq!(out.status, crate::output::Status::Error);
        assert_eq!(out.data.as_ref().unwrap()["reason"], "not-conductable");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The universal wrapper end-to-end: a successful child registers and
    /// resolves done (and SEES its session id); a failing child propagates its
    /// code through data.exitCode as an Error outcome but STILL resolves done;
    /// a spawn failure registers nothing — no ghost sessions.
    #[test]
    fn wrap_registers_resolves_and_mirrors_the_child() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("wrap");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // Success: the child asserts AOIDE_SESSION_ID is present in its env.
        let out = session_wrap(&wrap_invocation(
            &["sh", "-c", "test -n \"$AOIDE_SESSION_ID\""],
            &[("id", "wrap-ok")],
        ));
        assert_eq!(out.status, crate::output::Status::Ok);
        assert_eq!(out.data.as_ref().unwrap()["exitCode"], 0);
        let s: SessionsFile =
            serde_json::from_str(&std::fs::read_to_string(stage.join("sessions.json")).unwrap())
                .unwrap();
        let rec = s.sessions.iter().find(|r| r.session_id == "wrap-ok").unwrap();
        assert_eq!(rec.state, "done");
        assert_eq!(rec.agent, "sh"); // basename default

        // Failure: exit code mirrored in data, session still resolves done.
        let out = session_wrap(&wrap_invocation(
            &["sh", "-c", "exit 7"],
            &[("id", "wrap-fail"), ("agent", "sevens")],
        ));
        assert_eq!(out.status, crate::output::Status::Error);
        assert_eq!(out.data.as_ref().unwrap()["exitCode"], 7);
        let s: SessionsFile =
            serde_json::from_str(&std::fs::read_to_string(stage.join("sessions.json")).unwrap())
                .unwrap();
        let rec = s
            .sessions
            .iter()
            .find(|r| r.session_id == "wrap-fail")
            .unwrap();
        assert_eq!(rec.state, "done");
        assert_eq!(rec.agent, "sevens");

        // Spawn failure: error outcome, and NO session registered.
        let out = session_wrap(&wrap_invocation(
            &["/nonexistent-aoide-wrap-test"],
            &[("id", "wrap-ghost")],
        ));
        assert_eq!(out.status, crate::output::Status::Error);
        let s: SessionsFile =
            serde_json::from_str(&std::fs::read_to_string(stage.join("sessions.json")).unwrap())
                .unwrap();
        assert!(s.sessions.iter().all(|r| r.session_id != "wrap-ghost"));

        // No command at all → usage.
        let out = session_wrap(&wrap_invocation(&[], &[]));
        assert_eq!(out.status, crate::output::Status::Usage);

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
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

    fn flag_invocation(path: &[&str], flags: &[(&str, &str)]) -> Invocation {
        Invocation {
            path: path.iter().map(|s| s.to_string()).collect(),
            args: vec![],
            flags: flags
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            door: crate::daemon::Door::Cli,
        }
    }

    #[test]
    fn iso_utc_formats_and_round_trips_through_the_reader() {
        // The Unix epoch and a known instant, formatted exactly.
        assert_eq!(iso_utc_from_epoch(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_utc_from_epoch(1_700_000_000), "2023-11-14T22:13:20Z");
        // Whatever we stamp must parse back through baton's reader (the inverse).
        let stamp = now_iso_utc();
        let epoch = crate::baton::theme::parse_iso_utc(&stamp)
            .expect("a stamp we write is readable by the reader that consumes it");
        // And that epoch re-formats to the very same string (round-trip closed).
        assert_eq!(iso_utc_from_epoch(epoch), stamp);
    }

    #[test]
    fn upsert_session_is_idempotent_and_preserves_started_at() {
        let mut sessions: Vec<SessionRecord> = Vec::new();
        // First start: inserted, running, agent defaulted, startedAt stamped.
        assert!(upsert_session(
            &mut sessions,
            "s1",
            None,
            Some("/w"),
            None,
            None,
            None,
            None,
            None,
            "2026-01-01T00:00:00Z"
        ));
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].agent, "claude");
        assert_eq!(sessions[0].state, "running");
        assert_eq!(sessions[0].started_at, "2026-01-01T00:00:00Z");

        // Re-start with a NEW now + agent + conductor fields: no duplicate,
        // fields updated, but startedAt is NEVER clobbered.
        assert!(!upsert_session(
            &mut sessions,
            "s1",
            Some("melete"),
            None,
            Some("0xabc"),
            Some("parent"),
            Some(true),
            Some("/run/user/1000/aoide/session-s1.sock"),
            Some("do the thing"),
            "2026-02-02T00:00:00Z"
        ));
        assert_eq!(sessions.len(), 1, "re-start never duplicates");
        assert_eq!(sessions[0].agent, "melete");
        assert_eq!(sessions[0].window_address, "0xabc");
        assert_eq!(sessions[0].parent_session_id.as_deref(), Some("parent"));
        assert_eq!(sessions[0].conductable, Some(true));
        assert_eq!(
            sessions[0].socket.as_deref(),
            Some("/run/user/1000/aoide/session-s1.sock")
        );
        assert_eq!(sessions[0].title.as_deref(), Some("do the thing"));
        assert_eq!(
            sessions[0].started_at, "2026-01-01T00:00:00Z",
            "startedAt preserved across re-start"
        );
    }

    #[test]
    fn upsert_hook_keeps_one_bounded_record_per_session() {
        let mut hooks: Vec<HookRecord> = Vec::new();
        upsert_hook(&mut hooks, "s1", "running", "2026-01-01T00:00:01Z");
        upsert_hook(&mut hooks, "s1", "waiting", "2026-01-01T00:00:02Z");
        upsert_hook(&mut hooks, "s2", "running", "2026-01-01T00:00:03Z");
        assert_eq!(hooks.len(), 2, "one record per session id, never appended");
        let s1 = hooks.iter().find(|h| h.session_id == "s1").unwrap();
        assert_eq!(s1.phase, "waiting");
        assert_eq!(s1.updated_at, "2026-01-01T00:00:02Z");
        // merged_sessions tolerates the one-per-session shape: latest phase wins.
        let sessions = vec![session("s1", "/w", "running", "t", None)];
        let merged = merged_sessions(&sessions, &hooks);
        assert_eq!(merged[0].state, "waiting");
    }

    #[test]
    fn hook_event_mapping_covers_the_lifecycle_and_ignores_the_rest() {
        let start = map_hook(
            &json!({ "session_id": "s", "hook_event_name": "SessionStart", "cwd": "/w" }),
        )
        .unwrap();
        assert!(matches!(start, HookAction::Start { cwd: Some(_), .. }));
        assert!(matches!(
            map_hook(&json!({ "session_id": "s", "hook_event_name": "UserPromptSubmit" })).unwrap(),
            HookAction::Phase { ref phase, .. } if phase == "running"
        ));
        assert!(matches!(
            map_hook(&json!({ "session_id": "s", "hook_event_name": "PreToolUse" })).unwrap(),
            HookAction::Phase { ref phase, .. } if phase == "running"
        ));
        // PostToolUse joins the running arm — the tool ran, and this edge is HALF
        // the blocked-clearing set (approval → tool runs → PostToolUse).
        assert!(matches!(
            map_hook(&json!({ "session_id": "s", "hook_event_name": "PostToolUse" })).unwrap(),
            HookAction::Phase { ref phase, .. } if phase == "running"
        ));
        assert!(matches!(
            map_hook(&json!({ "session_id": "s", "hook_event_name": "Stop" })).unwrap(),
            HookAction::Phase { ref phase, .. } if phase == "waiting"
        ));
        assert!(matches!(
            map_hook(&json!({ "session_id": "s", "hook_event_name": "SessionEnd" })).unwrap(),
            HookAction::End { .. }
        ));
        // Notification with a permission message → an unconditional `blocked`.
        assert!(matches!(
            map_hook(&json!({
                "session_id": "s",
                "hook_event_name": "Notification",
                "message": "Claude needs your permission to use Bash"
            }))
            .unwrap(),
            HookAction::Phase { ref phase, .. } if phase == "blocked"
        ));
        // The ambiguous idle ping → the CONDITIONAL variant (guarded downstream).
        assert!(matches!(
            map_hook(&json!({
                "session_id": "s",
                "hook_event_name": "Notification",
                "message": "Claude is waiting for your input"
            }))
            .unwrap(),
            HookAction::PhaseIfRunning { ref phase, .. } if phase == "blocked"
        ));
        // "permission" match is case-insensitive.
        assert!(matches!(
            map_hook(&json!({
                "session_id": "s",
                "hook_event_name": "Notification",
                "message": "PERMISSION required"
            }))
            .unwrap(),
            HookAction::Phase { ref phase, .. } if phase == "blocked"
        ));
        // A Notification with an unrecognised or absent message → no action.
        assert!(map_hook(
            &json!({ "session_id": "s", "hook_event_name": "Notification", "message": "hello" })
        )
        .is_none());
        assert!(map_hook(&json!({ "session_id": "s", "hook_event_name": "Notification" })).is_none());
        // Unknown event, missing event, and empty/absent session_id → no action.
        assert!(map_hook(&json!({ "session_id": "s", "hook_event_name": "Zzz" })).is_none());
        assert!(map_hook(&json!({ "session_id": "s" })).is_none());
        assert!(map_hook(&json!({ "hook_event_name": "SessionStart" })).is_none());
        assert!(map_hook(&json!({ "session_id": "", "hook_event_name": "SessionStart" })).is_none());
    }

    #[test]
    fn hook_garbage_stdin_is_an_ok_noop_never_nonzero() {
        // Every one of these is empty/garbage/unmapped: an ok no-op that touches
        // no stage file (so the live stage is safe even without an override).
        for bad in [
            "",
            "   ",
            "not json at all",
            "{",
            "[]",
            "42",
            "\"a string\"",
            r#"{ "session_id": "x" }"#,                       // no event
            r#"{ "hook_event_name": "SessionStart" }"#,        // no id
            r#"{ "session_id": "x", "hook_event_name": "Zzz" }"#, // unmapped
        ] {
            let out = hook_from_str(bad);
            assert_eq!(out.status, crate::output::Status::Ok, "input: {bad:?}");
            assert_eq!(out.render(false).1, crate::output::exit::OK);
            assert_eq!(out.data.unwrap()["action"], "none", "input: {bad:?}");
        }
    }

    #[test]
    fn session_start_upserts_restages_and_anchors_under_a_project() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("sess-start");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        project_add(&invocation(
            &["graph", "project", "add"],
            &["aoide", "/home/k/Aoide"],
        ));
        let out = session_start(&flag_invocation(
            &["graph", "session", "start"],
            &[("id", "s1"), ("cwd", "/home/k/Aoide/sub")],
        ));
        assert_eq!(out.status, crate::output::Status::Ok);

        let s_file: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s_file.sessions.len(), 1);
        assert_eq!(s_file.sessions[0].state, "running");
        let started = s_file.sessions[0].started_at.clone();
        assert!(!started.is_empty());

        // Every mutation re-stages: graph.json carries the session node + the
        // project-anchored edge, and equals exactly what `view` computes.
        let staged: Value =
            serde_json::from_str(&std::fs::read_to_string(stage.join("graph.json")).unwrap())
                .unwrap();
        assert!(staged["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["id"] == "session:s1"));
        assert!(staged["edges"].as_array().unwrap().iter().any(|e| {
            e["from"] == "project:aoide" && e["to"] == "session:s1" && e["kind"] == "anchors"
        }));
        let view = view(&invocation(&["graph", "view"], &[]));
        assert_eq!(&staged, view.data.as_ref().unwrap());

        // Re-start updates the agent but preserves startedAt and never dupes.
        session_start(&flag_invocation(
            &["graph", "session", "start"],
            &[("id", "s1"), ("agent", "melete")],
        ));
        let s2: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s2.sessions.len(), 1);
        assert_eq!(s2.sessions[0].agent, "melete");
        assert_eq!(s2.sessions[0].started_at, started);

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn session_start_refuses_a_cyclic_parent() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("sess-cycle");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        session_start(&flag_invocation(&["graph", "session", "start"], &[("id", "a")]));
        session_start(&flag_invocation(
            &["graph", "session", "start"],
            &[("id", "b"), ("parent", "a")],
        ));
        // a parented under b would close b→a→…: refused (exit 1), no mutation.
        let out = session_start(&flag_invocation(
            &["graph", "session", "start"],
            &[("id", "a"), ("parent", "b")],
        ));
        assert_eq!(out.status, crate::output::Status::Error);
        assert_eq!(out.data.unwrap()["reason"], "cycle");
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert!(s.sessions.iter().find(|x| x.session_id == "a").unwrap().parent_session_id.is_none());

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn hook_lifecycle_start_running_waiting_end() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("sess-hook");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // SessionStart registers the session (agent claude, cwd from payload).
        let out = hook_from_str(
            r#"{ "session_id": "h1", "hook_event_name": "SessionStart", "cwd": "/proj", "extra": 9 }"#,
        );
        assert_eq!(out.status, crate::output::Status::Ok);
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s.sessions.len(), 1);
        assert_eq!(s.sessions[0].agent, "claude");
        assert_eq!(s.sessions[0].cwd, "/proj");

        // PreToolUse → running, Stop → waiting (latest hook phase wins).
        hook_from_str(r#"{ "session_id": "h1", "hook_event_name": "PreToolUse" }"#);
        hook_from_str(r#"{ "session_id": "h1", "hook_event_name": "Stop" }"#);
        let (_, ss, hh) = load_inputs("test").unwrap();
        assert_eq!(merged_sessions(&ss.sessions, &hh.hooks)[0].state, "waiting");

        // SessionEnd → done in both files.
        hook_from_str(r#"{ "session_id": "h1", "hook_event_name": "SessionEnd" }"#);
        let s2: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s2.sessions[0].state, "done");
        let h2: HooksFile = load_stage(&hooks_path()).unwrap();
        assert_eq!(h2.hooks.iter().find(|h| h.session_id == "h1").unwrap().phase, "done");

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn hook_notification_blocks_and_the_clearing_set_lifts_it() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("sess-blocked");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let live_phase = |id: &str| -> String {
            let h: HooksFile = load_stage(&hooks_path()).unwrap();
            h.hooks
                .iter()
                .find(|r| r.session_id == id)
                .map(|r| r.phase.clone())
                .unwrap_or_default()
        };

        // Register, then drive to a live turn.
        hook_from_str(r#"{ "session_id": "b1", "hook_event_name": "SessionStart", "cwd": "/p" }"#);
        hook_from_str(r#"{ "session_id": "b1", "hook_event_name": "PreToolUse" }"#);
        assert_eq!(live_phase("b1"), "running");

        // A permission Notification blocks unconditionally.
        hook_from_str(
            r#"{ "session_id": "b1", "hook_event_name": "Notification",
                 "message": "Claude needs your permission to use Bash" }"#,
        );
        assert_eq!(live_phase("b1"), "blocked");

        // PostToolUse (the approval → tool-ran edge) lifts the fermata → running.
        hook_from_str(r#"{ "session_id": "b1", "hook_event_name": "PostToolUse" }"#);
        assert_eq!(live_phase("b1"), "running");

        // The ambiguous idle ping, mid-turn (running), is a real mid-turn
        // question → blocked.
        hook_from_str(
            r#"{ "session_id": "b1", "hook_event_name": "Notification",
                 "message": "Claude is waiting for your input" }"#,
        );
        assert_eq!(live_phase("b1"), "blocked");

        // Stop settles the turn → waiting.
        hook_from_str(r#"{ "session_id": "b1", "hook_event_name": "Stop" }"#);
        assert_eq!(live_phase("b1"), "waiting");

        // The SAME idle ping on a SETTLED (waiting) session is a no-op — the ~60s
        // heartbeat must NOT flip a quietly-finished turn to blocked.
        let out = hook_from_str(
            r#"{ "session_id": "b1", "hook_event_name": "Notification",
                 "message": "Claude is waiting for your input" }"#,
        );
        assert_eq!(out.status, crate::output::Status::Ok);
        assert_eq!(live_phase("b1"), "waiting");

        // A garbage/absent-message Notification is an ok no-op (action:none), and
        // never touches the phase.
        let noop = hook_from_str(
            r#"{ "session_id": "b1", "hook_event_name": "Notification", "message": "hi" }"#,
        );
        assert_eq!(noop.data.unwrap()["action"], "none");
        assert_eq!(live_phase("b1"), "waiting");

        // blocked flows through the merge opaquely as the node state.
        hook_from_str(
            r#"{ "session_id": "b1", "hook_event_name": "Notification",
                 "message": "permission needed" }"#,
        );
        let (_, ss, hh) = load_inputs("test").unwrap();
        assert_eq!(merged_sessions(&ss.sessions, &hh.hooks)[0].state, "blocked");

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn session_end_unknown_id_is_ok_noop() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("sess-end-unknown");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = session_end(&flag_invocation(
            &["graph", "session", "end"],
            &[("id", "ghost")],
        ));
        assert_eq!(out.status, crate::output::Status::Ok);
        assert!(out.changed.is_empty(), "unknown id → no change");
        // No session file was written (nothing to end).
        assert!(!sessions_path().exists());

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn session_start_requires_the_id_flag() {
        let out = session_start(&flag_invocation(&["graph", "session", "start"], &[]));
        assert_eq!(out.status, crate::output::Status::Usage);
        assert_eq!(out.render(false).1, crate::output::exit::USAGE);
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
