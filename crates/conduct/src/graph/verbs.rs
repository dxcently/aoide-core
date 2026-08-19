//! The read/manage verb handlers: `view`, `project add/remove/list`, `link`,
//! `prune`, `emit`. Every mutation re-stages `graph.json` via
//! [`super::doc::restage_graph`] so the read path never drifts.

use super::common::{load_inputs, require_args, stage_error};
use super::doc::{build_graph, prune_done, render, restage_graph, would_cycle};
use super::model::{
    graph_path, hooks_path, load_stage, projects_path, sessions_path, sorted_projects,
    write_stage, HooksFile, Project, ProjectsFile, SessionsFile, STAGE_GRAPH_VERSION,
};
use aoide_protocol::Invocation;
use aoide_protocol::output::Outcome;
use serde_json::json;
#[cfg(test)]
use serde_json::Value;

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

/// `graph project add <name> [<path>]` — register/update an anchor root.
/// `path` defaults to the current working directory, so a bare
/// `aoide graph project add <name>` registers the dir you're in — and a
/// session started there anchors to it by cwd prefix.
pub fn project_add(inv: &Invocation) -> Outcome {
    let args = match require_args(inv, &["name"]) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let name = args[0].clone();
    let path = match inv.args.get(1) {
        Some(p) => p.clone(),
        None => match std::env::current_dir() {
            Ok(d) => d.to_string_lossy().into_owned(),
            Err(e) => {
                return Outcome::error(
                    "graph.project.add",
                    format!("no path given and the working directory is unavailable: {e}"),
                )
            }
        },
    };
    // Anchoring is string-prefix matching (`model.rs::cwd_under`), so a
    // relative or nonexistent path can never anchor a session to anything —
    // registering one is always a mistake (yesterday's `path: "intergration"`
    // incident: accepted verbatim, the session never anchored). Reject it as
    // a usage error with a correct example; no legitimate case is lost.
    let p = std::path::Path::new(&path);
    if !p.is_absolute() || !p.is_dir() {
        let why = if !p.is_absolute() {
            "not an absolute path"
        } else {
            "no such directory"
        };
        return Outcome::usage(
            "graph.project.add",
            format!(
                "invalid project path `{path}` ({why}) — anchoring matches by absolute path prefix\n\
                 usage: aoide graph project add <name> [<path>] [--json]\n\
                 example: aoide graph project add {name} \"$HOME/{name}\"",
            ),
        )
        .with_data(json!({ "reason": "invalid-path", "path": path }));
    }
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
/// (mirrors the `livery emit stage` pattern; atomic write).
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::anchor_for;
    use crate::graph::testutil::*;

    #[test]
    fn local_only_verbs_ignore_peer_ids_exactly_like_a2a_ids_today() {
        // CONTRACTS.md §7: `link`/`prune` (and, by the same construction,
        // `focus`/`reap`) must keep ignoring `peer:*` ids exactly as they
        // already ignore `a2a:*` ids — neither reads `peer_store` at all, so
        // a registered peer (with its own cache) sitting alongside real
        // sessions must never appear as a `link`/`prune` target and must
        // never break either verb. This is the "confirm it, don't assume it
        // generalizes for free" test the plan called for.
        let _guard = crate::env_lock().lock().unwrap();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let stage = unique_stage("peer-ids-ignored");
        let state = std::env::temp_dir().join(format!(
            "aoide-peer-ids-ignored-state-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);

        aoide_storage::peer_store::save_peers(&[aoide_storage::peer_store::Peer {
            name: "yomi-strix".into(),
            url: "http://yomi-strix:8710/".into(),
            autogate: false,
            token_file: None,
            added_at: "2026-08-14T00:00:00Z".into(),
        }])
        .unwrap();

        // A real local session to link/prune against.
        let sf = SessionsFile {
            schema_version: "0".into(),
            sessions: vec![
                session("s1", "/x", "working", "1", None),
                session("s2", "/x", "done", "2", None),
            ],
        };
        write_stage(&sessions_path(), &sf).unwrap();

        // `link` never resolves `peer:yomi-strix` as a valid child (it isn't
        // a session id) — this is the SAME rejection an unknown local id gets.
        let out = link(&invocation(&["graph", "link"], &["peer:yomi-strix", "s1"]));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert_eq!(out.data.as_ref().unwrap()["reason"], "child-not-found");

        // `prune` runs clean (drops the `done` s2) with the peer registry
        // sitting alongside — it never touches `peer_store`, so a peer being
        // registered changes nothing about what gets pruned.
        let out = prune(&invocation(&["graph", "prune"], &[]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        assert_eq!(out.data.as_ref().unwrap()["removed"], json!(["s2"]));

        // The peer registry itself is untouched by either verb.
        assert_eq!(aoide_storage::peer_store::load_peers().len(), 1);

        // And the resolved graph document still folds the peer in as its own
        // root node alongside whatever local nodes/edges link/prune left.
        let (p, s, h) = load_inputs("test").unwrap();
        let doc = build_graph(&p.projects, &s.sessions, &h.hooks);
        assert!(doc["nodes"].as_array().unwrap().iter().any(|n| n["id"] == "peer:yomi-strix"));

        let _ = std::fs::remove_dir_all(&stage);
        let _ = std::fs::remove_dir_all(&state);
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    #[test]
    fn project_add_restages_graph_json_consistent_with_view() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("restage");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // Register a project. graph.json must now exist and carry the node.
        // (The path must be a real absolute dir — `project_add` rejects
        // anything else now — so the per-test stage dir stands in.)
        let out = project_add(&invocation(
            &["graph", "project", "add"],
            &["aoide", stage.to_str().unwrap()],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);

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
    fn project_add_rejects_a_relative_path_as_a_usage_error() {
        // The "intergration"-incident guard: anchoring is prefix matching, so
        // a relative path can never anchor — refuse it (exit 2), loudly.
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("reject-relative");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = project_add(&invocation(&["graph", "project", "add"], &["aoide", "intergration"]));
        assert_eq!(out.status, aoide_protocol::output::Status::Usage);
        assert_eq!(out.render(false).1, aoide_protocol::output::exit::USAGE);
        assert!(out.message.contains("intergration"), "the offending value is shown: {}", out.message);
        assert!(out.message.contains("not an absolute path"), "{}", out.message);
        // Nothing was registered.
        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        assert!(file.projects.is_empty());

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn project_add_rejects_a_nonexistent_absolute_path_as_a_usage_error() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("reject-nonexistent");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let bogus = stage.join("does-not-exist").to_string_lossy().into_owned();
        let out = project_add(&invocation(&["graph", "project", "add"], &["aoide", &bogus]));
        assert_eq!(out.status, aoide_protocol::output::Status::Usage);
        assert_eq!(out.render(false).1, aoide_protocol::output::exit::USAGE);
        assert!(out.message.contains(&bogus), "the offending value is shown: {}", out.message);
        assert!(out.message.contains("no such directory"), "{}", out.message);
        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        assert!(file.projects.is_empty());

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn project_add_defaults_path_to_cwd() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_cwd = std::env::current_dir().ok();
        let stage = unique_stage("cwd-default");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // Bare `project add <name>` registers the cwd as the anchor root.
        std::env::set_current_dir(&stage).unwrap();
        let out = project_add(&invocation(&["graph", "project", "add"], &["aoide"]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);

        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        let p = file.projects.iter().find(|p| p.name == "aoide").unwrap();
        assert_eq!(
            p.path,
            stage.to_string_lossy().into_owned(),
            "bare `project add <name>` registers the cwd"
        );

        // A session started in that cwd anchors under the project.
        let (ps, _, _) = load_inputs("test").unwrap();
        assert_eq!(anchor_for(&stage.to_string_lossy(), &ps.projects), Some(0));

        if let Some(c) = saved_cwd {
            std::env::set_current_dir(c).unwrap();
        }
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
}
