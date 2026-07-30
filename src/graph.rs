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
    /// The lifecycle-OWNING process's pid (the `conduct`/`wrap` process itself,
    /// NOT the wrapped child) — the liveness anchor for the reaper. While this
    /// process lives, normal-exit cleanup (`do_session_end`) is guaranteed; when
    /// it is SIGKILLed (SUPER+Q kills the whole terminal process tree,
    /// uncatchably) the record orphans `running` and `/proc/<pid>` vanishes,
    /// which is exactly the signal `is_session_dead` reaps on. Additive/v0-safe:
    /// absent on a legacy record and on hook-only sessions that never had one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// The Hyprland workspace id this session's window currently lives on,
    /// stamped by the `socket2` window-event listener alongside `windowAddress`
    /// (and re-stamped when the window moves between workspaces). Additive and
    /// v0-safe: absent on a legacy record and whenever the window/workspace
    /// could not be resolved (off-Hyprland, or the window not yet open). The
    /// gadget-dock roster reads it to preview-highlight the bar's WorkspaceRow
    /// on hover (concepts/Terminal-Commander) — a pure-data bridge, no dispatch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<i64>,
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
        if let Some(pid) = s.pid {
            node["pid"] = json!(pid);
        }
        // The workspace the session's window lives on — the hover-preview bridge
        // (concepts/Terminal-Commander). Rides onto the node only when known, so
        // a legacy/off-Hyprland record stays byte-for-byte as before.
        if let Some(ws) = s.workspace {
            node["workspace"] = json!(ws);
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

/// The Hyprland workspace id of the client whose `address` matches `want` in a
/// decoded `hyprctl clients -j` array (`workspace.id` in the client JSON).
/// Pure over the decoded JSON — unit-testable without a compositor. Address
/// comparison is `0x`/case-tolerant via [`normalize_addr`] (the stored
/// `windowAddress` and hyprctl can disagree on both). `None` when the window is
/// absent from the list or carries no numeric `workspace.id` — the caller then
/// leaves the stored `workspace` untouched (degrade gracefully, never a panic).
fn client_workspace_for_address(clients: &[Value], want: &str) -> Option<i64> {
    let want = normalize_addr(want);
    if want.is_empty() {
        return None;
    }
    clients.iter().find_map(|c| {
        let a = c.get("address").and_then(Value::as_str)?;
        if normalize_addr(a) != want {
            return None;
        }
        c.get("workspace")
            .and_then(|w| w.get("id"))
            .and_then(Value::as_i64)
    })
}

// ── Liveness reaping: mark KILLED sessions done so they cannot haunt forever ─
//
// A terminal killed with SUPER+Q / SIGKILL cannot run its own cleanup — the
// `conduct`/`wrap` process is torn down uncatchably, so `do_session_end` never
// fires and the record is stranded `running` forever (22 dead `conduct-*` piled
// up in ~8 minutes of use). The reaper detects such orphans out-of-band and
// resolves them, so conduct-by-default is viable. A FALSE reap of a LIVE session
// is worse than a stale record, so the predicate never guesses.

/// Does `/proc/<pid>` still exist? The real liveness probe for [`is_session_dead`]
/// (injected as a closure in tests so the predicate stays pure).
fn proc_exists(pid: u32) -> bool {
    std::path::Path::new("/proc").join(pid.to_string()).exists()
}

/// Is a session DEAD — orphaned so that NO process will ever clean it up? Pure
/// and unit-tested (feed a fake live-address set + a fake `proc_exists`).
///
/// DEAD when EITHER independent signal fires:
///   * **window gone** — a non-empty `windowAddress` that is NOT among the live
///     `hyprctl clients -j` addresses (the SUPER+Q kill: the window vanished), OR
///   * **process gone** — a recorded `pid` whose `/proc/<pid>` no longer exists
///     (the process-killed case).
///
/// The never-false-reap guards:
///   * `live_addresses` is an `Option`: `None` means the compositor could not be
///     queried (no Hyprland, hyprctl missing/failed) — the window signal is then
///     UNKNOWN and contributes nothing, so we never reap a windowed session we
///     merely failed to see. Only a `Some(live)` we actually gathered can fire it.
///   * A session with NEITHER signal (empty `windowAddress` AND no `pid` — e.g. a
///     hook-only session that has not yet discovered a window/pid) is left alone:
///     absence of evidence is never evidence of death.
pub fn is_session_dead(
    rec: &SessionRecord,
    live_addresses: Option<&HashSet<String>>,
    proc_exists: impl Fn(u32) -> bool,
) -> bool {
    let window_signal = match live_addresses {
        Some(live) => {
            !rec.window_address.is_empty()
                && !live.contains(&normalize_addr(&rec.window_address))
        }
        None => false, // compositor not queried — window liveness is unknown.
    };
    let pid_signal = matches!(rec.pid, Some(p) if !proc_exists(p));
    window_signal || pid_signal
}

/// Query `hyprctl clients -j` into a decoded JSON array. Returns `None` whenever
/// the compositor cannot be consulted authoritatively: no
/// `HYPRLAND_INSTANCE_SIGNATURE`, a missing/failed `hyprctl`, or unparseable
/// JSON. This is the single clients-reading seam every consumer shares — the
/// reaper's live set, phase-② discovery, and the window-event listener — so they
/// all degrade identically off-Hyprland (never a panic, never a false result).
fn hyprctl_clients() -> Option<Vec<Value>> {
    if std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE").is_none() {
        return None;
    }
    let out = std::process::Command::new("hyprctl")
        .args(["clients", "-j"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    match serde_json::from_slice(&out.stdout) {
        Ok(Value::Array(a)) => Some(a),
        _ => None,
    }
}

/// Gather the normalised live window addresses from `hyprctl clients -j`.
/// Returns `None` (→ pid-only liveness) whenever the compositor cannot be
/// consulted authoritatively (see [`hyprctl_clients`]). This is the seam that
/// keeps the reaper safe off-Hyprland — it degrades to the pid signal instead of
/// blindly reaping every windowed session it could not see.
fn live_window_addresses() -> Option<HashSet<String>> {
    Some(
        hyprctl_clients()?
            .iter()
            .filter_map(|c| c.get("address").and_then(Value::as_str))
            .filter(|a| !a.is_empty())
            .map(normalize_addr)
            .collect(),
    )
}

/// The reaper's transient-read grace (pure, unit-tested). Given the set of live
/// window addresses the compositor just reported and the current sessions,
/// decide the window-liveness set this reap pass should actually trust.
///
/// During a reload/restart (a quickshell restart, `hyprctl reload`, a nixos
/// switch) `hyprctl clients -j` can momentarily answer SUCCESS with ZERO windows
/// while the terminals are in fact alive — the compositor is mid-reload. Reaping
/// the whole windowed roster off that snapshot is exactly the transient drop this
/// fix targets, so an EMPTY gathered set against a roster that still holds
/// windowed, not-`done` sessions is treated as degenerate and DOWNGRADED to
/// `None` (pid-only liveness) for the pass — a vanished `/proc/<pid>` is still
/// authoritative, so a genuinely-closed terminal (its owning pid gone too) is
/// still reaped, while a live-but-momentarily-unlisted window is spared. A
/// non-empty set, or an empty set with nothing windowed to protect, passes
/// through unchanged.
///
/// Bounded edge (acceptable): a not-`done`, windowed, PID-LESS session whose
/// terminal genuinely closed while the desktop is at zero windows carries neither
/// a pid signal nor — under this downgrade — a window signal, so it is NOT reaped
/// on that pass. It self-heals the moment ANY window exists (the snapshot is no
/// longer empty, the stale address is then absent from a real set, and the window
/// signal fires as normal). A lone stale record briefly lingering is the right
/// trade for never mass-sweeping a live roster off a mid-reload read.
fn effective_live_addresses(
    gathered: Option<HashSet<String>>,
    sessions: &[SessionRecord],
) -> Option<HashSet<String>> {
    match &gathered {
        Some(set)
            if set.is_empty()
                && sessions
                    .iter()
                    .any(|s| s.state != "done" && !s.window_address.is_empty()) =>
        {
            None
        }
        _ => gathered,
    }
}

/// `graph reap` — the automatic liveness sweep. Marks every DEAD (killed,
/// orphaned) session `done` (and its hook record), then reuses [`prune_done`] to
/// drop them + clear orphaned parent links, re-staging `graph.json` atomically.
/// Cheap: one `hyprctl` call + a stage read, and a stage WRITE only when
/// something was actually reaped. NEVER errors non-zero on "nothing to reap" and
/// NEVER on an unavailable compositor (it falls back to pid-only liveness).
pub fn reap(_inv: &Invocation) -> Outcome {
    let cmd = "graph.reap";
    let mut s_file: SessionsFile = match load_stage(&sessions_path()) {
        Ok(f) => f,
        Err(e) => return stage_error(cmd, e),
    };
    let mut h_file: HooksFile = match load_stage(&hooks_path()) {
        Ok(f) => f,
        Err(e) => return stage_error(cmd, e),
    };

    let gathered = live_window_addresses();
    let hyprctl_available = gathered.is_some();
    // Apply the transient-read grace: a degenerate empty snapshot during a reload
    // window falls back to pid-only liveness so we never sweep the live roster off
    // a momentary "zero windows" answer.
    let live = effective_live_addresses(gathered, &s_file.sessions);
    // Only STILL-live records can be dead-by-liveness; an already-`done` session
    // is prune's job, not a reap. This is the set the liveness predicate killed.
    let reaped: Vec<String> = s_file
        .sessions
        .iter()
        .filter(|s| s.state != "done")
        .filter(|s| is_session_dead(s, live.as_ref(), proc_exists))
        .map(|s| s.session_id.clone())
        .collect();

    if reaped.is_empty() {
        return Outcome::ok(cmd, "nothing to reap (all sessions live)").with_data(json!({
            "reaped": [],
            "hyprctlAvailable": hyprctl_available,
        }));
    }

    // Mark each reaped session done in BOTH files, then let prune_done drop them
    // (and any pre-existing `done`) + clear orphaned parentSessionIds.
    let dead: HashSet<&str> = reaped.iter().map(String::as_str).collect();
    let now = now_iso_utc();
    for s in s_file.sessions.iter_mut() {
        if dead.contains(s.session_id.as_str()) {
            s.state = "done".to_string();
        }
    }
    for id in &reaped {
        upsert_hook(&mut h_file.hooks, id, "done", &now);
    }

    let (kept_s, kept_h, removed, cleared) = prune_done(
        std::mem::take(&mut s_file.sessions),
        std::mem::take(&mut h_file.hooks),
    );
    s_file.sessions = kept_s;
    h_file.hooks = kept_h;
    if s_file.schema_version.is_empty() {
        s_file.schema_version = STAGE_GRAPH_VERSION.to_string();
    }
    if h_file.schema_version.is_empty() {
        h_file.schema_version = STAGE_GRAPH_VERSION.to_string();
    }
    if let Err(e) = write_stage(&sessions_path(), &s_file) {
        return stage_error(cmd, e);
    }
    if let Err(e) = write_stage(&hooks_path(), &h_file) {
        return stage_error(cmd, e);
    }

    let mut changed: Vec<String> = reaped
        .iter()
        .map(|id| format!("reaped dead session {id} (killed; running → done → dropped)"))
        .collect();
    changed.extend(
        cleared
            .iter()
            .map(|id| format!("cleared parentSessionId of {id}")),
    );
    match restage_graph() {
        Ok(g) => changed.push(g.to_string_lossy().into_owned()),
        Err(e) => return stage_error(cmd, e),
    }
    Outcome::ok(
        cmd,
        format!(
            "reaped {} dead session(s); dropped {} total; cleared {} orphaned parent link(s)",
            reaped.len(),
            removed.len(),
            cleared.len()
        ),
    )
    .changed(changed)
    .with_data(json!({
        "reaped": reaped,
        "removed": removed,
        "clearedParents": cleared,
        "hyprctlAvailable": hyprctl_available,
    }))
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

    // Verify + dispatch through the shared focus fn (the same path the
    // shellbridge socket loop drives on a widget click).
    match focus_window(&addr) {
        Ok(()) => Outcome::ok("graph.focus", format!("focused session `{id}`"))
            .changed([format!("focused window {addr}")])
            .with_data(json!({ "node": id, "windowAddress": addr, "dispatcher": "hyprctl" })),
        Err(e) => Outcome::error("graph.focus", format!("{}: {}", id, e.message)).with_data(json!({
            "reason": e.reason,
            "node": id,
            "windowAddress": addr,
        })),
    }
}

/// A structured failure from [`focus_window`]. `reason` is a stable machine
/// code (`hyprctl-unavailable` / `hyprctl-failed` / `window-not-found` /
/// `no-window-address`) reused verbatim by `graph focus`'s error envelope.
#[derive(Debug, Clone)]
pub struct FocusError {
    pub reason: &'static str,
    pub message: String,
}

/// The shared verify-then-dispatch used by BOTH `graph focus` (CLI) and the
/// shellbridge socket loop (a widget click). `hyprctl dispatch focuswindow`
/// exits 0 even when the target window is already gone, so we first list live
/// clients (`hyprctl clients -j`) and confirm the address is actually present
/// before dispatching — a vanished terminal is a `window-not-found` error, not
/// a silent no-op. Returns `Ok(())` only on a dispatched focus; every failure
/// (empty address, missing/failed hyprctl, unparseable JSON, absent window) is
/// a structured `Err` — this fn NEVER panics, so a socket loop can call it on
/// arbitrary input without risk.
pub fn focus_window(addr: &str) -> Result<(), FocusError> {
    let addr = addr.trim();
    if addr.is_empty() {
        return Err(FocusError {
            reason: "no-window-address",
            message: "empty window address".to_string(),
        });
    }

    // Verify the window exists before dispatching: focuswindow can't tell us.
    let clients: Vec<Value> = match std::process::Command::new("hyprctl")
        .args(["clients", "-j"])
        .output()
    {
        Err(e) => {
            return Err(FocusError {
                reason: "hyprctl-unavailable",
                message: format!("hyprctl unavailable: {e}"),
            });
        }
        Ok(out) if !out.status.success() => {
            return Err(FocusError {
                reason: "hyprctl-failed",
                message: format!("hyprctl clients failed (exit {:?})", out.status.code()),
            });
        }
        Ok(out) => match serde_json::from_slice(&out.stdout) {
            Ok(Value::Array(a)) => a,
            _ => {
                return Err(FocusError {
                    reason: "hyprctl-failed",
                    message: "hyprctl clients: unparseable JSON".to_string(),
                });
            }
        },
    };
    if !window_present(&clients, addr) {
        return Err(FocusError {
            reason: "window-not-found",
            message: format!("window {addr} is gone (terminal closed?)"),
        });
    }

    let dispatch = format!("address:{addr}");
    match std::process::Command::new("hyprctl")
        .args(["dispatch", "focuswindow", &dispatch])
        .output()
    {
        Err(e) => Err(FocusError {
            reason: "hyprctl-unavailable",
            message: format!("hyprctl unavailable: {e}"),
        }),
        Ok(out) if !out.status.success() => Err(FocusError {
            reason: "hyprctl-failed",
            message: format!("hyprctl dispatch failed (exit {:?})", out.status.code()),
        }),
        Ok(_) => Ok(()),
    }
}

/// Resolve a `sessionId` to a live jump and dispatch it — the socket-reachable
/// counterpart to the CLI [`focus`]. shellbridge drives this on a roster
/// row-click: QML sends only the sessionId (which every row already holds), and
/// the DAEMON owns the id→window resolution, so a widget never carries a stale or
/// empty address (the bug this fixes: the old socket verb took a window address,
/// but the widgets passed a sessionId, so every tracked-row jump silently
/// no-op'd as `window-not-found`). Prefers the exact `windowAddress` (which also
/// brings its workspace forward); if that isn't resolved yet but the `workspace`
/// is known, falls back to switching to that workspace. Never panics — a socket
/// loop calls it on arbitrary input.
pub fn focus_session(id: &str) -> Result<(), FocusError> {
    let id = id.strip_prefix("session:").unwrap_or(id).trim();
    if id.is_empty() {
        return Err(FocusError {
            reason: "no-session-id",
            message: "empty session id".to_string(),
        });
    }
    let file: SessionsFile = match load_stage(&sessions_path()) {
        Ok(f) => f,
        Err(_) => {
            return Err(FocusError {
                reason: "stage-unreadable",
                message: "could not read sessions.json".to_string(),
            });
        }
    };
    let Some(rec) = file.sessions.iter().find(|s| s.session_id == id) else {
        return Err(FocusError {
            reason: "session-not-found",
            message: format!("unknown session `{id}`"),
        });
    };
    // Prefer the exact window — focuswindow also brings its workspace forward.
    if !rec.window_address.trim().is_empty() {
        return focus_window(&rec.window_address);
    }
    // The window isn't resolved yet (discovery is best-effort), but if we know
    // the workspace we can still take the user there.
    if let Some(ws) = rec.workspace {
        return focus_workspace(ws);
    }
    Err(FocusError {
        reason: "no-window-address",
        message: format!("session `{id}` has no window or workspace to focus"),
    })
}

/// Switch to a Hyprland workspace by numeric id (`hyprctl dispatch workspace
/// <id>`) — the fallback jump for a session whose window address isn't resolved
/// yet but whose workspace is known. Structured `Err` on a missing/failed
/// hyprctl; never panics.
pub fn focus_workspace(ws: i64) -> Result<(), FocusError> {
    match std::process::Command::new("hyprctl")
        .args(["dispatch", "workspace", &ws.to_string()])
        .output()
    {
        Err(e) => Err(FocusError {
            reason: "hyprctl-unavailable",
            message: format!("hyprctl unavailable: {e}"),
        }),
        Ok(out) if !out.status.success() => Err(FocusError {
            reason: "hyprctl-failed",
            message: format!(
                "hyprctl dispatch workspace failed (exit {:?})",
                out.status.code()
            ),
        }),
        Ok(_) => Ok(()),
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
    pid: Option<u32>,
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
        if let Some(p) = pid {
            s.pid = Some(p);
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
            pid,
            // Workspace is stamped later by the window-event listener (it needs a
            // resolved window first); a fresh record starts without one.
            workspace: None,
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
    pid: Option<u32>,
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
        pid,
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
        // The lifecycle-OWNING pid is THIS wrap process, not `child`: while wrap
        // lives it always runs the `do_session_end` below (even on a child crash),
        // so only wrap's OWN death — a SIGKILL it cannot catch — orphans the
        // record, and that is precisely the pid the reaper should watch.
        Some(std::process::id()),
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

// ── Phase ②: window-address discovery (pid-ancestry ↔ hyprctl clients) ──────
//
// A conducted terminal's window is the ancestor process that owns a Hyprland
// client: conduct is exec'd (same pid) by the shell wrapper, itself a child of
// the terminal (kitty). Walking conduct's pid up the ppid chain and matching a
// pid against `hyprctl clients -j` finds that window — the first ancestor with a
// client wins. All of this is BEST-EFFORT: it must never fail or slow a conduct,
// so every impure step is guarded and an empty result just leaves the address
// unset (exactly as before this phase).

/// Read the parent pid of `pid` from `/proc/<pid>/stat`. The `comm` (2nd) field
/// is wrapped in parens and may itself contain spaces or `)`, so ppid is parsed
/// as the 2nd whitespace field AFTER the FINAL `)` (state, then ppid) — the only
/// robust way to split a stat line. `None` on any read/parse miss.
fn parent_pid(pid: i32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = &stat[stat.rfind(')')? + 1..];
    let mut fields = after.split_whitespace();
    let _state = fields.next()?; // the process state char
    fields.next()?.parse().ok() // ppid
}

/// The pid-ancestry chain of `pid`, self first, walking up the ppid chain via
/// `/proc`. Bounded (a bad `/proc` or a self-parenting loop can never spin) and
/// stops at init (ppid ≤ 1) — the terminal is always a mid-chain ancestor.
fn pid_ancestry(pid: i32) -> Vec<i32> {
    let mut chain = Vec::new();
    let mut cur = pid;
    for _ in 0..64 {
        chain.push(cur);
        match parent_pid(cur) {
            Some(p) if p > 1 && p != cur => cur = p,
            _ => break,
        }
    }
    chain
}

/// Pure core: the window address of the nearest ancestor in `ancestry` that owns
/// a client in the decoded `hyprctl clients -j` array. Walks the ancestry from
/// self outward and returns the first client whose `pid` matches and whose
/// `address` is non-empty. Pure over the decoded JSON + the pid list, so it is
/// unit-testable with a fake client list and a fake ancestry — no `/proc`, no
/// compositor. `None` when no ancestor owns a window.
#[cfg(test)]
fn match_window_for_ancestry(ancestry: &[i32], clients: &[Value]) -> Option<String> {
    match_window_and_pid(ancestry, clients).map(|(addr, _)| addr)
}

/// Address-and-pid variant of the ancestor↔client match: also returns the
/// matched client's `pid` — the terminal window's owning process. The hook door
/// records this pid on the session so the reaper has a `/proc` liveness signal
/// that vanishes with the window (never a false reap: the pid lives exactly as
/// long as the window).
fn match_window_and_pid(ancestry: &[i32], clients: &[Value]) -> Option<(String, u32)> {
    for &pid in ancestry {
        for c in clients {
            if c.get("pid").and_then(Value::as_i64) == Some(pid as i64) {
                if let Some(addr) = c.get("address").and_then(Value::as_str) {
                    if !addr.is_empty() {
                        return Some((addr.to_string(), pid as u32));
                    }
                }
            }
        }
    }
    None
}

/// Best-effort discovery of THIS conduct process's terminal window address (see
/// the phase ② note). Guarded end-to-end: no Hyprland instance signature, a
/// missing/failed `hyprctl`, unparseable JSON, or no ancestor match each yield
/// `None` — never an error, never a slow path beyond one quick `hyprctl` call.
fn discover_window_address() -> Option<String> {
    discover_window().map(|(addr, _, _)| addr)
}

/// Best-effort discovery of THIS process's terminal window address AND that
/// window's owning pid (see [`discover_window_address`]). Shared by `conduct`
/// (which wants only the address) and the hook door (which records both so a
/// hook-registered Claude session becomes `graph focus`-jumpable). Guarded
/// end-to-end: no Hyprland instance signature, a missing/failed `hyprctl`,
/// unparseable JSON, or no ancestor match each yield `None` — never an error,
/// never a slow path beyond one quick `hyprctl` call.
fn discover_window() -> Option<(String, u32, Option<i64>)> {
    // Cheap gate + one quick `hyprctl` call, both inside the shared seam.
    let clients = hyprctl_clients()?;
    let ancestry = pid_ancestry(std::process::id() as i32);
    let (addr, pid) = match_window_and_pid(&ancestry, &clients)?;
    // Stamp the window's workspace off the SAME clients snapshot (no second
    // hyprctl call); `None` when the client carries no numeric workspace id.
    let workspace = client_workspace_for_address(&clients, &addr);
    Some((addr, pid, workspace))
}

/// Best-effort backfill of a hook-registered session's `windowAddress` (+ owning
/// pid) when it is still empty. The hook runs as a subprocess of the agent in
/// its terminal, so [`discover_window`]'s pid-ancestry ↔ `hyprctl clients` walk
/// finds that terminal window — giving a Claude Code session (which registers
/// via `SessionStart` with no window) something for `graph focus` to jump to.
/// Cheaply gated on `HYPRLAND_INSTANCE_SIGNATURE` and on the address being
/// empty (so once discovered, later hooks skip all work); a miss leaves the
/// address empty exactly as before. Only ever fills `windowAddress`/`pid` — it
/// never touches the session `state` (that is the hook phase's job).
fn ensure_session_window(id: &str) {
    if std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE").is_none() {
        return;
    }
    let mut file: SessionsFile = match load_stage(&sessions_path()) {
        Ok(f) => f,
        Err(_) => return,
    };
    let needs_window =
        matches!(file.sessions.iter().find(|s| s.session_id == id), Some(s) if s.window_address.is_empty());
    if !needs_window {
        return;
    }
    let Some((addr, pid, workspace)) = discover_window() else {
        return;
    };
    if let Some(s) = file.sessions.iter_mut().find(|s| s.session_id == id) {
        s.window_address = addr;
        s.pid = Some(pid);
        // Stamp the workspace too when known (absent → left None, degrades
        // gracefully); the listener keeps it fresh on later moves.
        if workspace.is_some() {
            s.workspace = workspace;
        }
    }
    if file.schema_version.is_empty() {
        file.schema_version = STAGE_GRAPH_VERSION.to_string();
    }
    let _ = write_stage(&sessions_path(), &file);
    let _ = restage_graph();
}

// ── Authoritative window capture: the Hyprland event listener ────────────────
//
// The hook-time backfill above is LAZY — a session's `windowAddress` only lands
// on the *next* hook fire, so at click time it is frequently empty and the
// widget's `graph focus` jump fails. The fix is EVENT-DRIVEN, creation-time
// capture: the shellbridge service runs a background thread reading Hyprland's
// `socket2` event stream and, the moment a window opens (or moves / retitles /
// closes), it (re)resolves every tracked session's window authoritatively. This
// is the PRIMARY source of `windowAddress`; the hook backfill stays as a
// belt-and-suspenders fallback. All of it is best-effort and off-Hyprland-safe:
// no instance signature → the listener logs once and returns, and the accept
// loop keeps serving regardless.

/// Path to the Hyprland event socket (`socket2`):
/// `$XDG_RUNTIME_DIR/hypr/$HYPRLAND_INSTANCE_SIGNATURE/.socket2.sock`. Returns
/// `None` when not under a Hyprland session (no signature, or no runtime dir) —
/// the listener then degrades to "disabled" rather than crashing.
pub fn hypr_event_socket_path() -> Option<PathBuf> {
    let sig = std::env::var("HYPRLAND_INSTANCE_SIGNATURE").ok()?;
    if sig.trim().is_empty() {
        return None;
    }
    let runtime = std::env::var("XDG_RUNTIME_DIR").ok()?;
    Some(
        PathBuf::from(runtime)
            .join("hypr")
            .join(sig)
            .join(".socket2.sock"),
    )
}

/// One parsed Hyprland `socket2` event we act on (window lifecycle only). Every
/// other event line maps to `None` and is ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HyprWindowEvent {
    /// A window opened / moved / retitled — (re)resolve pending session windows.
    /// `address` is the raw event address (no `0x` prefix); we resolve off the
    /// live `hyprctl clients` list rather than trusting it, so it is advisory.
    Appeared { address: String },
    /// A window closed — clear its address off whatever session stored it, so the
    /// roster stops advertising a dead jump target (the reaper then removes the
    /// record via its pid signal).
    Closed { address: String },
}

/// Parse ONE `socket2` line (`EVENT>>DATA`) into a [`HyprWindowEvent`], or `None`
/// for the many events we ignore. Pure and total (unit-tested): a line without
/// `>>`, an unhandled event name, or an empty address all yield `None` — never a
/// panic. The address is Hyprland's bare hex (e.g. `55aabb`); [`normalize_addr`]
/// reconciles it with `hyprctl`'s `0x…` form at compare time.
pub fn parse_hypr_window_event(line: &str) -> Option<HyprWindowEvent> {
    let (event, data) = line.split_once(">>")?;
    match event {
        // openwindow>>ADDR,WORKSPACE,CLASS,TITLE · movewindow>>ADDR,WORKSPACE
        // movewindowv2>>ADDR,WSID,WSNAME · windowtitle>>ADDR
        // windowtitlev2>>ADDR,TITLE — in every case ADDR is the first field.
        "openwindow" | "movewindow" | "movewindowv2" | "windowtitle" | "windowtitlev2" => {
            let addr = data.split(',').next().unwrap_or("").trim();
            if addr.is_empty() {
                return None;
            }
            Some(HyprWindowEvent::Appeared {
                address: addr.to_string(),
            })
        }
        // closewindow>>ADDR — the whole payload is the address.
        "closewindow" => {
            let addr = data.trim();
            if addr.is_empty() {
                return None;
            }
            Some(HyprWindowEvent::Closed {
                address: addr.to_string(),
            })
        }
        _ => None,
    }
}

/// (Re)resolve the `windowAddress` of every tracked session that has a recorded
/// lifecycle `pid` but no window yet, stamping the canonical `hyprctl` address
/// via the SAME pid-ancestry ↔ clients match discovery uses — AND keep every
/// already-resolved session's `workspace` id current off the same clients
/// snapshot, so a terminal dragged to another workspace re-stamps here (the
/// `movewindow`/`movewindowv2` event re-runs this pass; concepts/Terminal-
/// Commander's hover-preview bridge). Runs in the shellbridge process, so it
/// walks each session's RECORDED pid (a conduct session's own pid — the window
/// client is one of its ancestors), never its own. Cheap-guarded: zero `hyprctl`
/// work when no session has either a pending window OR a resolved one. It only
/// ever FILLS an empty address (never overwrites a good one) and only ever
/// updates `workspace` to a PRESENT id (a window momentarily absent from the
/// clients list leaves its stored workspace be — never cleared); it never
/// touches `pid` or `state`. Returns true iff `sessions.json` changed.
pub fn resolve_pending_session_windows() -> bool {
    let mut file: SessionsFile = match load_stage(&sessions_path()) {
        Ok(f) => f,
        Err(_) => return false,
    };
    // Work to do if a session still needs its window (empty address + a pid to
    // walk) OR already has one whose workspace we can (re)stamp. The latter is
    // what keeps `workspace` fresh across a move; without it a steady-state
    // roster would never re-stamp.
    let has_pending = file
        .sessions
        .iter()
        .any(|s| s.window_address.is_empty() && s.pid.is_some());
    let has_windowed = file.sessions.iter().any(|s| !s.window_address.is_empty());
    if !has_pending && !has_windowed {
        return false;
    }
    let Some(clients) = hyprctl_clients() else {
        return false;
    };
    let mut changed = false;
    for s in file.sessions.iter_mut() {
        if s.window_address.is_empty() {
            // Pending window: resolve it via pid-ancestry, stamping workspace off
            // the same snapshot (None → left absent, degrades gracefully).
            let Some(pid) = s.pid else {
                continue;
            };
            let ancestry = pid_ancestry(pid as i32);
            if let Some((addr, _)) = match_window_and_pid(&ancestry, &clients) {
                let ws = client_workspace_for_address(&clients, &addr);
                s.window_address = addr;
                if s.workspace != ws {
                    s.workspace = ws;
                }
                changed = true;
            }
        } else if let Some(ws) = client_workspace_for_address(&clients, &s.window_address) {
            // Resolved window still live: keep its workspace current (the
            // drag-between-workspaces re-stamp). Only a present, changed id is
            // written; a vanished window leaves the stored workspace intact.
            if s.workspace != Some(ws) {
                s.workspace = Some(ws);
                changed = true;
            }
        }
    }
    if !changed {
        return false;
    }
    if file.schema_version.is_empty() {
        file.schema_version = STAGE_GRAPH_VERSION.to_string();
    }
    if write_stage(&sessions_path(), &file).is_ok() {
        let _ = restage_graph();
        return true;
    }
    false
}

/// Clear a closed window's address off any session that stored it (normalised
/// compare, so `0x…`/case differences still match). The record is left in place
/// for the reaper to resolve via its pid signal. Returns true iff a session was
/// cleared.
pub fn clear_closed_window(address: &str) -> bool {
    let want = normalize_addr(address);
    if want.is_empty() {
        return false;
    }
    let mut file: SessionsFile = match load_stage(&sessions_path()) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut changed = false;
    for s in file.sessions.iter_mut() {
        if !s.window_address.is_empty() && normalize_addr(&s.window_address) == want {
            s.window_address.clear();
            changed = true;
        }
    }
    if !changed {
        return false;
    }
    if write_stage(&sessions_path(), &file).is_ok() {
        let _ = restage_graph();
        return true;
    }
    false
}

/// Run the Hyprland window→session event listener FOREVER — the shellbridge
/// service spawns this on a background thread so it can never block or kill the
/// socket accept loop. It connects to the `socket2` event stream and keeps
/// `sessions.json` authoritative: an opened/moved/retitled window (re)resolves
/// pending session windows, a closed window is cleared. Degrades gracefully — no
/// Hyprland signature logs once and returns (headless/non-Hypr aoide is
/// unaffected); a failed connect or a dropped socket logs and retries after a
/// short backoff. NEVER panics.
pub fn run_hypr_window_listener() {
    use std::io::{BufRead, BufReader};
    let Some(sock) = hypr_event_socket_path() else {
        eprintln!(
            "[aoide/shellbridge] no HYPRLAND_INSTANCE_SIGNATURE — window-event listener disabled"
        );
        return;
    };
    loop {
        match UnixStream::connect(&sock) {
            Ok(stream) => {
                // On every (re)connect, sweep any windows that opened while we
                // were not listening (service start mid-session, or a reconnect).
                resolve_pending_session_windows();
                for line in BufReader::new(stream).lines() {
                    let Ok(line) = line else {
                        break; // socket dropped → fall through to reconnect.
                    };
                    match parse_hypr_window_event(&line) {
                        Some(HyprWindowEvent::Appeared { .. }) => {
                            resolve_pending_session_windows();
                        }
                        Some(HyprWindowEvent::Closed { address }) => {
                            clear_closed_window(&address);
                        }
                        None => {}
                    }
                }
            }
            Err(e) => {
                eprintln!("[aoide/shellbridge] hypr event socket connect failed ({e}); retrying");
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}

/// `aoide conduct [--agent A] [--parent P] [--id I] -- <command …>` — the
/// PTY-backed, controllable sibling of `graph wrap`. Same registration semantics
/// (spawn FIRST so a failed exec registers no ghost; running → done; exit
/// mirrored, real code in `data.exitCode`; `AOIDE_SESSION_ID` exported) PLUS: its
/// own PTY + controlling tty, a per-session injection socket, the
/// `conductable`/`socket` fields on the record so `graph send` can steer it, and
/// a best-effort `windowAddress` (phase ② discovery) so `graph focus` can jump.
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

    // Phase ②: best-effort window-address discovery (never fails/slows conduct).
    let window = discover_window_address();

    // Register running + conductable with its socket, so `graph send` resolves it.
    let _ = do_session_start(
        &id,
        Some(&agent),
        cwd.as_deref(),
        window.as_deref(),
        inv.flags.get("parent").map(String::as_str),
        Some(conductable),
        if conductable {
            Some(socket_str.as_str())
        } else {
            None
        },
        None,
        // Record THIS conduct process's pid (not the PTY child's): conduct owns
        // the session lifecycle — the `do_session_end` at the bottom of this fn
        // always resolves the record on any NORMAL exit. Only conduct's own
        // uncatchable death (SUPER+Q SIGKILLs the whole kitty→shell→conduct tree)
        // leaves the record stranded `running`, and then `/proc/<this-pid>`
        // vanishes: the reaper's pid signal. (It is also the pid already embedded
        // in the default `conduct-<pid>-<ts>` id.)
        Some(std::process::id()),
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

/// The gate decision for a send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendGate {
    /// Explicit `--yes` on this send.
    Yes,
    /// The global orchestration-mode switch authorised it (no human in the loop).
    Autogate,
    /// The sender is the target's parent — an orchestrator freely commanding a
    /// child it spawned (the "freely orchestrated" default). No human in the loop.
    AutogateParent,
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
            SendGate::AutogateParent => "autogate-parent",
            SendGate::Pending => "pending",
        }
    }
}

/// Global autogate switch: `AOIDE_CONDUCT_AUTOGATE` in {1,true,yes,all} declares
/// an orchestration-mode where every send delivers without a human (still
/// audited) — the box-wide "freely orchestrated" toggle.
fn autogate_env() -> bool {
    matches!(
        std::env::var("AOIDE_CONDUCT_AUTOGATE").ok().as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("all")
    )
}

/// The parent-autogate rule (pure, unit-tested): the sender may freely command a
/// child it spawned. True when the target session's `parentSessionId` equals the
/// SENDER's own `AOIDE_SESSION_ID` — both present and non-empty. A cross-tree or
/// unrelated send (no id, empty id, or a mismatch) is NOT autogated and stays
/// pending. This is what lets an orchestrator steer the children it conducted
/// without a prompt while every other send remains gated.
fn sender_is_parent(sender_session: Option<&str>, target_parent: Option<&str>) -> bool {
    match (sender_session, target_parent) {
        (Some(s), Some(p)) => !s.is_empty() && s == p,
        _ => false,
    }
}

/// Resolve the gate: `--yes`, then the global autogate switch, then the
/// parent-of-target rule, else pending.
fn send_gate(yes: bool, sender_is_parent: bool) -> SendGate {
    if yes {
        SendGate::Yes
    } else if autogate_env() {
        SendGate::Autogate
    } else if sender_is_parent {
        SendGate::AutogateParent
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
    let target_parent = rec.parent_session_id.clone();
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

    // The gate. The sender's own session id (from the env `aoide conduct` exports)
    // vs the target's parent decides the parent-autogate rule.
    let sender = std::env::var("AOIDE_SESSION_ID").ok();
    let is_parent = sender_is_parent(sender.as_deref(), target_parent.as_deref());
    let gate = send_gate(yes, is_parent);
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
            // Best-effort: the hook is a subprocess of the agent's terminal, so
            // discover that window (+ its owning pid) now and register it — this
            // is what makes a hook-only Claude session `graph focus`-jumpable.
            // Workspace is stamped later by the shellbridge window-event listener
            // (resolve_pending_session_windows), which is authoritative and keeps
            // it fresh across moves — do_session_start carries only window + pid.
            let (window, pid) = match discover_window() {
                Some((addr, pid, _workspace)) => (Some(addr), Some(pid)),
                None => (None, None),
            };
            do_session_start(
                &id,
                Some("claude"),
                cwd.as_deref(),
                window.as_deref(),
                None,
                None,
                None,
                None,
                pid,
            )
        }
        HookAction::Phase { id, phase } => {
            // Backfill a still-empty windowAddress on any later hook — covers a
            // session that registered before the window mapped (or before this
            // discovery shipped), so it becomes jumpable without a restart.
            ensure_session_window(&id);
            do_session_phase(&id, &phase)
        }
        HookAction::PhaseIfRunning { id, phase } => {
            ensure_session_window(&id);
            do_session_phase_if(&id, &phase, "running")
        }
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
            pid: None,
            workspace: None,
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

    #[test]
    fn window_discovery_matches_the_nearest_ancestor_client() {
        // conduct(pid 100) ← shell(same pid, exec) ← kitty(pid 42) ← hypr(pid 7).
        // kitty owns the window; the compositor (7) does not.
        let clients = vec![
            json!({ "pid": 42, "address": "0xKITTY", "class": "kitty" }),
            json!({ "pid": 999, "address": "0xOTHER", "class": "firefox" }),
        ];
        let ancestry = vec![100, 42, 7];
        assert_eq!(
            match_window_for_ancestry(&ancestry, &clients),
            Some("0xKITTY".to_string())
        );

        // The NEAREST ancestor with a window wins (self before its parents), even
        // if a further-up ancestor also owns a client.
        let nested = vec![
            json!({ "pid": 42, "address": "0xOUTER" }),
            json!({ "pid": 100, "address": "0xINNER" }),
        ];
        assert_eq!(
            match_window_for_ancestry(&[100, 42, 7], &nested),
            Some("0xINNER".to_string())
        );

        // No ancestor owns a window → None (address stays unset, as before).
        assert_eq!(match_window_for_ancestry(&[100, 42, 7], &[json!({ "pid": 5, "address": "0xX" })]), None);
        // A client whose pid matches but whose address is empty/absent is skipped.
        assert_eq!(
            match_window_for_ancestry(&[42], &[json!({ "pid": 42, "address": "" })]),
            None
        );
        assert_eq!(
            match_window_for_ancestry(&[42], &[json!({ "pid": 42, "class": "kitty" })]),
            None
        );
        // Empty inputs never match.
        assert_eq!(match_window_for_ancestry(&[], &clients), None);
        assert_eq!(match_window_for_ancestry(&ancestry, &[]), None);
    }

    #[test]
    fn window_discovery_also_returns_the_owning_pid() {
        // The hook door records the matched terminal pid (helps the reaper): a
        // `/proc` liveness signal that vanishes with the window, never a false
        // reap. The pid returned is the matched ancestor/client pid.
        let clients = vec![
            json!({ "pid": 42, "address": "0xKITTY", "class": "kitty" }),
            json!({ "pid": 999, "address": "0xOTHER" }),
        ];
        assert_eq!(
            match_window_and_pid(&[100, 42, 7], &clients),
            Some(("0xKITTY".to_string(), 42))
        );
        // Nearest ancestor wins, and its pid comes back with it.
        let nested = vec![
            json!({ "pid": 42, "address": "0xOUTER" }),
            json!({ "pid": 100, "address": "0xINNER" }),
        ];
        assert_eq!(
            match_window_and_pid(&[100, 42, 7], &nested),
            Some(("0xINNER".to_string(), 100))
        );
        // No match → None (address AND pid stay unset, never a partial record).
        assert_eq!(match_window_and_pid(&[5], &clients), None);
        assert_eq!(match_window_and_pid(&[42], &[json!({ "pid": 42, "address": "" })]), None);
    }

    #[test]
    fn client_workspace_lookup_reads_workspace_id_and_tolerates_address_form() {
        // `hyprctl clients -j` carries `workspace: { id, name }`; the lookup pulls
        // the numeric id for the matching window. Address match is 0x/case
        // tolerant, exactly like window_present (the stored addr may differ).
        let clients = vec![
            json!({ "address": "0x55aabb", "workspace": { "id": 3, "name": "3" } }),
            json!({ "address": "0x1234ef", "workspace": { "id": 7, "name": "seven" } }),
            // Special workspaces carry NEGATIVE ids — surfaced verbatim.
            json!({ "address": "0xdeadbe", "workspace": { "id": -99, "name": "special:magic" } }),
        ];
        assert_eq!(client_workspace_for_address(&clients, "0x55aabb"), Some(3));
        assert_eq!(client_workspace_for_address(&clients, "55AABB"), Some(3)); // no 0x + upper
        assert_eq!(client_workspace_for_address(&clients, "0X1234EF"), Some(7));
        assert_eq!(client_workspace_for_address(&clients, "0xdeadbe"), Some(-99));

        // A window absent from the list → None (leave the stored workspace be).
        assert_eq!(client_workspace_for_address(&clients, "0xnope"), None);
        // An empty address never matches.
        assert_eq!(client_workspace_for_address(&clients, ""), None);
        // A client without a workspace object (or without a numeric id) → None,
        // never a panic — degrade gracefully when Hyprland omits the field.
        let noworkspace = vec![
            json!({ "address": "0xaa" }),
            json!({ "address": "0xbb", "workspace": {} }),
            json!({ "address": "0xcc", "workspace": { "name": "3" } }),
        ];
        assert_eq!(client_workspace_for_address(&noworkspace, "0xaa"), None);
        assert_eq!(client_workspace_for_address(&noworkspace, "0xbb"), None);
        assert_eq!(client_workspace_for_address(&noworkspace, "0xcc"), None);
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
    fn session_record_workspace_round_trips_and_stays_absent_when_unset() {
        // serde: `workspace` serialises as an integer when set, and is skipped
        // (skip_serializing_if) when None — additive/v0-safe on the wire.
        let mut rec = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        rec.workspace = Some(2);
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"workspace\":2"), "serialised: {json}");
        let back: SessionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.workspace, Some(2));

        // A record without a workspace omits the key entirely (no null noise) and
        // a legacy record with no `workspace` field parses to None.
        let bare = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        let bare_json = serde_json::to_string(&bare).unwrap();
        assert!(!bare_json.contains("workspace"), "serialised: {bare_json}");
        let legacy: SessionRecord =
            serde_json::from_str(r#"{ "sessionId": "s", "windowAddress": "0x1" }"#).unwrap();
        assert_eq!(legacy.workspace, None);
    }

    #[test]
    fn hypr_event_parses_window_lifecycle_and_ignores_the_rest() {
        // openwindow>>ADDR,WORKSPACE,CLASS,TITLE — address is the first field
        // (Hyprland emits it WITHOUT the `0x` prefix; a title may contain commas).
        assert_eq!(
            parse_hypr_window_event("openwindow>>55aabbccdd00,1,kitty,shell — /home/x, y"),
            Some(HyprWindowEvent::Appeared {
                address: "55aabbccdd00".to_string()
            })
        );
        // movewindow / movewindowv2 re-check (session may have registered late).
        assert_eq!(
            parse_hypr_window_event("movewindow>>55aabb,2"),
            Some(HyprWindowEvent::Appeared {
                address: "55aabb".to_string()
            })
        );
        assert_eq!(
            parse_hypr_window_event("movewindowv2>>55aabb,2,two"),
            Some(HyprWindowEvent::Appeared {
                address: "55aabb".to_string()
            })
        );
        // windowtitle (old, ADDR only) and windowtitlev2 (ADDR,TITLE).
        assert_eq!(
            parse_hypr_window_event("windowtitle>>55aabb"),
            Some(HyprWindowEvent::Appeared {
                address: "55aabb".to_string()
            })
        );
        assert_eq!(
            parse_hypr_window_event("windowtitlev2>>55aabb,a new title"),
            Some(HyprWindowEvent::Appeared {
                address: "55aabb".to_string()
            })
        );
        // closewindow>>ADDR — the whole payload is the address.
        assert_eq!(
            parse_hypr_window_event("closewindow>>55aabb"),
            Some(HyprWindowEvent::Closed {
                address: "55aabb".to_string()
            })
        );
        // Events we don't act on → None.
        assert_eq!(parse_hypr_window_event("workspace>>2"), None);
        assert_eq!(parse_hypr_window_event("activewindow>>kitty,shell"), None);
        assert_eq!(parse_hypr_window_event("focusedmon>>DP-1,2"), None);
        // Malformed / empty-address lines → None (never a panic, never a blank).
        assert_eq!(parse_hypr_window_event("no-delimiter-here"), None);
        assert_eq!(parse_hypr_window_event("openwindow>>"), None);
        assert_eq!(parse_hypr_window_event("openwindow>> ,1,kitty,t"), None);
        assert_eq!(parse_hypr_window_event("closewindow>>   "), None);
        assert_eq!(parse_hypr_window_event(""), None);
    }

    #[test]
    fn hypr_event_socket_path_needs_a_signature() {
        // `hypr_event_socket_path()` reads process-global env; serialise it
        // against the other env-touching tests with the crate-wide lock.
        let _guard = crate::env_lock().lock().unwrap();
        let saved_sig = std::env::var("HYPRLAND_INSTANCE_SIGNATURE").ok();
        let saved_rt = std::env::var("XDG_RUNTIME_DIR").ok();

        // No signature → no socket (listener disables itself off-Hyprland).
        std::env::remove_var("HYPRLAND_INSTANCE_SIGNATURE");
        assert_eq!(hypr_event_socket_path(), None);

        // A blank signature is treated as absent, not as a path segment.
        std::env::set_var("HYPRLAND_INSTANCE_SIGNATURE", "   ");
        std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");
        assert_eq!(hypr_event_socket_path(), None);

        // Signature + runtime dir → the documented socket2 path.
        std::env::set_var("HYPRLAND_INSTANCE_SIGNATURE", "abc123_99");
        assert_eq!(
            hypr_event_socket_path(),
            Some(PathBuf::from(
                "/run/user/1000/hypr/abc123_99/.socket2.sock"
            ))
        );

        match saved_sig {
            Some(v) => std::env::set_var("HYPRLAND_INSTANCE_SIGNATURE", v),
            None => std::env::remove_var("HYPRLAND_INSTANCE_SIGNATURE"),
        }
        match saved_rt {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
    }

    #[test]
    fn focus_window_rejects_an_empty_address_without_touching_hyprctl() {
        // The shared focus fn is called by the socket loop on arbitrary input;
        // an empty/blank address is a structured error, never a panic and never
        // a stray `hyprctl` dispatch.
        let err = focus_window("").expect_err("empty address must error");
        assert_eq!(err.reason, "no-window-address");
        let err = focus_window("   ").expect_err("blank address must error");
        assert_eq!(err.reason, "no-window-address");
    }

    #[test]
    fn focus_window_never_succeeds_for_a_nonexistent_window() {
        // A bogus address is never a live client, so the verify step fails —
        // either `window-not-found` (hyprctl present) or `hyprctl-unavailable`
        // (no compositor / hyprctl absent, e.g. the build sandbox). Both are
        // structured Errs: the fn must NEVER report a false focus and NEVER
        // panic, whatever the environment.
        let err = focus_window("0xdeadbeefcafe").expect_err("bogus address must not focus");
        assert!(
            matches!(
                err.reason,
                "window-not-found" | "hyprctl-unavailable" | "hyprctl-failed"
            ),
            "unexpected reason {}",
            err.reason
        );
    }

    #[test]
    fn pid_ancestry_starts_at_self_and_is_bounded() {
        // Real /proc: our own ancestry begins with our pid and includes a parent.
        let me = std::process::id() as i32;
        let chain = pid_ancestry(me);
        assert_eq!(chain.first(), Some(&me), "self is first in the chain");
        assert!(chain.len() >= 2, "we always have at least one ancestor");
        assert!(chain.len() <= 64, "the walk is bounded");
        // A nonexistent pid yields just the seed (no /proc entry to walk up).
        assert_eq!(pid_ancestry(2_000_000_000), vec![2_000_000_000]);
    }

    #[test]
    fn parent_autogate_decision_is_exact_and_guarded() {
        // The sender IS the target's parent → autogated (freely orchestrated).
        assert!(sender_is_parent(Some("orch"), Some("orch")));
        // Mismatched ids (cross-tree / unrelated) → NOT autogated.
        assert!(!sender_is_parent(Some("orch"), Some("other")));
        // A missing sender or a parentless target → NOT autogated.
        assert!(!sender_is_parent(None, Some("orch")));
        assert!(!sender_is_parent(Some("orch"), None));
        // Empty ids never match (a blank env var is not a parent claim).
        assert!(!sender_is_parent(Some(""), Some("")));
        assert!(!sender_is_parent(Some(""), Some("orch")));

        // The gate resolves in priority order: --yes ▸ global env ▸ parent ▸ pending.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_CONDUCT_AUTOGATE"]);
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        assert_eq!(send_gate(true, false), SendGate::Yes); // --yes wins outright
        assert_eq!(send_gate(false, true), SendGate::AutogateParent);
        assert_eq!(send_gate(false, false), SendGate::Pending);
        assert!(SendGate::AutogateParent.delivers());
        assert_eq!(SendGate::AutogateParent.label(), "autogate-parent");
        std::env::set_var("AOIDE_CONDUCT_AUTOGATE", "1");
        // The global switch outranks the parent rule (both deliver; label differs).
        assert_eq!(send_gate(false, true), SendGate::Autogate);
        assert_eq!(send_gate(false, false), SendGate::Autogate);
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

    /// The parent-autogate: a send from the target's PARENT (the sender's
    /// AOIDE_SESSION_ID equals the child's parentSessionId) delivers WITHOUT
    /// --yes and without the global autogate — an orchestrator freely commands a
    /// child it spawned. The gate label is `autogate-parent` and it is audited.
    #[test]
    fn send_delivers_when_sender_is_the_targets_parent() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);

        let root = unique_stage("send-parent");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE"); // no global autogate.
        // The SENDER is the orchestrator session `orch`.
        std::env::set_var("AOIDE_SESSION_ID", "orch");

        let id = "child-of-orch";
        let socket = conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();

        // Register a conductable CHILD whose parent is the sender (`orch`).
        do_session_start(
            id,
            Some("claude"),
            Some("/w"),
            None,
            Some("orch"),
            Some(true),
            Some(socket.to_str().unwrap()),
            None,
            None,
        );

        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });

        // No --yes: delivery is authorised purely by the parent relationship.
        let out = session_send(&send_invocation(&["go"], &[("id", id), ("submit", "true")]));
        let got = acc.join().unwrap();

        assert_eq!(out.status, crate::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["delivered"], true);
        assert_eq!(out.data.as_ref().unwrap()["gate"], "autogate-parent");
        assert_eq!(String::from_utf8(got).unwrap(), "go\n");

        // An UNRELATED sender (different session) to the same child stays pending.
        std::env::set_var("AOIDE_SESSION_ID", "stranger");
        let out = session_send(&send_invocation(&["hi"], &[("id", id)]));
        assert_eq!(out.data.as_ref().unwrap()["state"], "pending");
        assert_eq!(out.data.as_ref().unwrap()["delivered"], false);

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
        do_session_start("plain", Some("claude"), None, None, None, None, None, None, None);
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
            None,
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
        // A record with no pid serialises WITHOUT the key (additive/v0-safe).
        assert!(back.get("pid").is_none());
    }

    // ── Reaper: the liveness predicate + the `graph reap` sweep ─────────────

    #[test]
    fn is_session_dead_combines_signals_and_never_false_reaps() {
        let live: HashSet<String> = ["aaa", "bbb"].iter().map(|s| s.to_string()).collect();
        let alive = |_p: u32| true; // /proc/<pid> exists
        let dead_proc = |_p: u32| false; // /proc/<pid> is gone
        let rec = |window: &str, pid: Option<u32>| SessionRecord {
            window_address: window.into(),
            pid,
            ..Default::default()
        };

        // Window-gone (the SUPER+Q kill): a non-empty window absent from the live
        // set is dead even when the pid is alive. The match is 0x/case-tolerant.
        assert!(is_session_dead(&rec("0xCCC", None), Some(&live), alive));
        assert!(is_session_dead(&rec("0xCCC", Some(9)), Some(&live), alive));
        // A live window (normalised match) with a live pid → NOT dead.
        assert!(!is_session_dead(&rec("0xAAA", Some(9)), Some(&live), alive));

        // Process-gone: a pid whose /proc vanished is dead regardless of window
        // (here the window IS live, so ONLY the pid signal fires).
        assert!(is_session_dead(&rec("0xAAA", Some(9)), Some(&live), dead_proc));

        // NEVER-FALSE-REAP #1 — neither signal (no window, no pid): left alone.
        assert!(!is_session_dead(&rec("", None), Some(&live), dead_proc));

        // NEVER-FALSE-REAP #2 — compositor NOT queried (None): the window signal
        // is suppressed, so a windowed session we could not SEE is never reaped;
        // only the authoritative pid signal remains.
        assert!(!is_session_dead(&rec("0xCCC", None), None, alive));
        assert!(!is_session_dead(&rec("0xCCC", Some(9)), None, alive)); // pid alive → alive
        assert!(is_session_dead(&rec("0xCCC", Some(9)), None, dead_proc)); // pid gone → dead
    }

    #[test]
    fn reap_drops_killed_sessions_but_spares_the_living() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "HYPRLAND_INSTANCE_SIGNATURE"]);
        // Force pid-only liveness: with no compositor the window signal is
        // suppressed, so the reap decision rests purely on /proc/<pid> — fully
        // deterministic in a test (no hyprctl, no real windows).
        std::env::remove_var("HYPRLAND_INSTANCE_SIGNATURE");
        let stage = unique_stage("reap");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // A pid that can NEVER exist (above every Linux pid_max) is the killed
        // session; this very process's pid is the living one; and a hook-only
        // session carries NEITHER signal and must be spared.
        let dead_pid = u32::MAX;
        let now = "2026-01-01T00:00:00Z";
        let mut sessions = Vec::new();
        upsert_session(
            &mut sessions, "live", None, Some("/w"), None, None, None, None, None,
            Some(std::process::id()), now,
        );
        upsert_session(
            &mut sessions, "killed", None, Some("/w"), None, None, None, None, None,
            Some(dead_pid), now,
        );
        upsert_session(
            &mut sessions, "hookonly", None, Some("/w"), None, None, None, None, None,
            None, now,
        );
        write_stage(
            &sessions_path(),
            &SessionsFile { schema_version: "0".into(), sessions },
        )
        .unwrap();
        let mut hooks = Vec::new();
        upsert_hook(&mut hooks, "killed", "running", now);
        write_stage(
            &hooks_path(),
            &HooksFile { schema_version: "0".into(), hooks },
        )
        .unwrap();

        let out = reap(&invocation(&["graph", "reap"], &[]));
        assert_eq!(out.status, crate::output::Status::Ok);
        let data = out.data.unwrap();
        assert_eq!(data["reaped"], json!(["killed"]));
        assert_eq!(data["hyprctlAvailable"], json!(false)); // pid-only fallback

        // The killed session AND its hook are gone; live + hook-only survive.
        let s2: SessionsFile = load_stage(&sessions_path()).unwrap();
        let ids: Vec<&str> = s2.sessions.iter().map(|s| s.session_id.as_str()).collect();
        assert!(ids.contains(&"live"), "a live session is never reaped");
        assert!(ids.contains(&"hookonly"), "a signal-less session is never reaped");
        assert!(!ids.contains(&"killed"), "the killed session was reaped");
        let h2: HooksFile = load_stage(&hooks_path()).unwrap();
        assert!(h2.hooks.iter().all(|h| h.session_id != "killed"));

        // graph.json was re-staged and no longer carries the reaped node.
        let g: Value =
            serde_json::from_str(&std::fs::read_to_string(stage.join("graph.json")).unwrap())
                .unwrap();
        assert!(g["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|n| n["id"] != "session:killed"));

        // Idempotent + never non-zero: a second sweep finds nothing to reap.
        let again = reap(&invocation(&["graph", "reap"], &[]));
        assert_eq!(again.status, crate::output::Status::Ok);
        assert_eq!(again.data.unwrap()["reaped"], json!([]));

        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn reap_spares_a_live_but_hook_silent_session() {
        // The regression this whole fix pins: the reaper reaps by REAL liveness
        // (window / pid), NEVER by hook silence. A session whose pid is alive but
        // that has emitted NO hook — its hook stream went quiet across a
        // reload/restart window — must survive the sweep. (hooks.json is left
        // absent, so the session is maximally hook-silent.)
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "HYPRLAND_INSTANCE_SIGNATURE"]);
        std::env::remove_var("HYPRLAND_INSTANCE_SIGNATURE"); // pid-only liveness
        let stage = unique_stage("reap-hooksilent");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let now = "2026-01-01T00:00:00Z";
        let mut sessions = Vec::new();
        upsert_session(
            &mut sessions, "quiet", None, Some("/w"), Some("0xdead"), None, None, None, None,
            Some(std::process::id()), now,
        );
        write_stage(
            &sessions_path(),
            &SessionsFile { schema_version: "0".into(), sessions },
        )
        .unwrap();

        let out = reap(&invocation(&["graph", "reap"], &[]));
        assert_eq!(out.status, crate::output::Status::Ok);
        assert_eq!(
            out.data.unwrap()["reaped"],
            json!([]),
            "a live-but-hook-silent session is never reaped"
        );
        let s2: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert!(
            s2.sessions.iter().any(|s| s.session_id == "quiet"),
            "the hook-silent session survives the reaper pass"
        );

        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn reaper_grace_ignores_a_degenerate_empty_clients_snapshot() {
        // A momentary empty `hyprctl clients` read during a reload window must not
        // mass-reap the windowed roster: the grace downgrades it to pid-only.
        let windowed = vec![SessionRecord {
            window_address: "0xabc".into(),
            state: "running".into(),
            ..Default::default()
        }];
        // Empty gathered set + a windowed live session → degrade to None (pid-only).
        assert!(effective_live_addresses(Some(HashSet::new()), &windowed).is_none());

        // A NON-empty set is trusted as gathered (the normal path).
        let set: HashSet<String> = ["0xabc".to_string()].into_iter().collect();
        assert_eq!(
            effective_live_addresses(Some(set.clone()), &windowed),
            Some(set)
        );

        // Empty set but nothing windowed to protect (a genuinely empty desktop, or
        // an all-`done` roster) → the empty set passes through; pid signal governs.
        let done_only = vec![SessionRecord {
            window_address: "0xabc".into(),
            state: "done".into(),
            ..Default::default()
        }];
        assert_eq!(
            effective_live_addresses(Some(HashSet::new()), &done_only),
            Some(HashSet::new())
        );

        // No compositor at all stays None (unchanged).
        assert!(effective_live_addresses(None, &windowed).is_none());
    }
}
