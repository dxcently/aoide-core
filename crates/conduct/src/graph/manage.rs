//! The read/manage command handlers: `view`, `project add/edit/remove/list`,
//! `link`, `prune`. Every mutation re-stages `graph.json` via
//! [`super::doc::restage_graph`] so the read path never drifts.

use super::common::{load_inputs, require_args, stage_error};
use super::doc::{build_graph, prune_done, render, restage_graph, would_cycle};
use super::model::{
    hooks_path, load_stage, projects_path, sessions_path, sorted_projects,
    write_stage, HooksFile, Project, ProjectsFile, SessionsFile, STAGE_GRAPH_VERSION,
};
use aoide_protocol::Invocation;
use aoide_protocol::output::Outcome;
use serde_json::json;
#[cfg(test)]
use serde_json::Value;

/// Bare `graph` — render the DAG (tree in text, graph document in `--json`).
pub fn view(inv: &Invocation) -> Outcome {
    let (p, s, h) = match load_inputs("graph") {
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
    Outcome::ok("graph", format!("{n} node(s), {e} edge(s)\n{tree}")).with_data(doc)
}

/// Validate one candidate root the same way every path this command touches
/// is validated: absolute, and an existing directory. Anchoring is string-
/// prefix matching (`model.rs::cwd_under`), so a relative or nonexistent
/// path can never anchor a session to anything — registering one is always
/// a mistake (yesterday's `path: "intergration"` incident: accepted
/// verbatim, the session never anchored). Shared by `project_add` and
/// `project_edit` so both refuse an offending path with the byte-identical
/// message and `data`.
fn validate_root(cmd: &str, name: &str, path: &str) -> Result<(), Outcome> {
    let p = std::path::Path::new(path);
    if !p.is_absolute() || !p.is_dir() {
        let why = if !p.is_absolute() {
            "not an absolute path"
        } else {
            "no such directory"
        };
        return Err(Outcome::usage(
            cmd,
            format!(
                "invalid project path `{path}` ({why}) — anchoring matches by absolute path prefix\n\
                 usage: aoide project {cmd_tail} <name> <path...> [--json]\n\
                 example: aoide project {cmd_tail} {name} \"$HOME/{name}\"",
                cmd_tail = cmd.rsplit('.').next().unwrap_or(cmd),
            ),
        )
        .with_data(json!({ "reason": "invalid-path", "path": path })));
    }
    Ok(())
}

/// `project add <name> [<path>...]` — register a project, or grow an
/// existing one with more anchor roots. With no path, the current working
/// directory supplies exactly one root, so a bare `aoide project add <name>`
/// registers the dir you're in — and a session started there anchors to it
/// by cwd prefix. `--new` refuses a name that already exists instead of
/// adding to it.
pub fn project_add(inv: &Invocation) -> Outcome {
    let args = match require_args(inv, &["name"]) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let name = args[0].clone();
    let paths: Vec<String> = if inv.args.len() > 1 {
        inv.args[1..].to_vec()
    } else {
        match std::env::current_dir() {
            Ok(d) => vec![d.to_string_lossy().into_owned()],
            Err(e) => {
                return Outcome::error(
                    "project.add",
                    format!("no path given and the working directory is unavailable: {e}"),
                )
            }
        }
    };
    let mut file: ProjectsFile = match load_stage(&projects_path()) {
        Ok(f) => f,
        Err(e) => return stage_error("project.add", e),
    };

    // `--new` refuses a name that already exists BEFORE any path validation
    // or write — the invocation was well-formed, the world disagreed.
    if inv.flag_present("new") && file.projects.iter().any(|p| p.name == name) {
        return Outcome::error(
            "project.add",
            format!(
                "project `{name}` already exists — omit --new to add a root to it, or use `project edit` to replace its roots"
            ),
        )
        .with_data(json!({ "reason": "exists", "name": name }));
    }

    // Validate EVERY root before mutating anything — one bad path in the
    // list refuses the whole invocation and writes nothing.
    for path in &paths {
        if let Err(e) = validate_root("project.add", &name, path) {
            return e;
        }
    }

    // `--auto-resume` (P-D8, `docs/architecture/AOIDED.md`'s "L5"): opts this
    // project into the daemon's boot-time auto-resume sweep. Only ever sets
    // it true here — `project edit` never touches it (see this crate's own
    // `AGENTS.md`).
    let auto_resume = inv.flag_present("auto-resume");

    let mut changed: Vec<String> = Vec::new();
    let mut added_roots: Vec<String> = Vec::new();
    let message;
    match file.projects.iter_mut().find(|p| p.name == name) {
        Some(existing) => {
            let mut this_changed = false;
            for path in &paths {
                if existing.path.is_empty() {
                    changed.push(format!("project {name}: path → {path}"));
                    existing.path = path.clone();
                    added_roots.push(path.clone());
                    this_changed = true;
                } else if !existing.roots().contains(&path.as_str()) {
                    existing.roots.push(path.clone());
                    changed.push(format!("project {name}: added root {path}"));
                    added_roots.push(path.clone());
                    this_changed = true;
                }
            }
            if auto_resume && !existing.auto_resume {
                changed.push(format!("project {name}: autoResume → true"));
                existing.auto_resume = true;
                this_changed = true;
            }
            message = if !added_roots.is_empty() {
                if added_roots.len() == 1 {
                    format!("added root {} to project `{name}`", added_roots[0])
                } else {
                    format!("added roots {} to project `{name}`", added_roots.join(", "))
                }
            } else if this_changed {
                format!(
                    "project `{name}`: autoResume → true (root {} already registered)",
                    paths.join(", ")
                )
            } else {
                format!("project `{name}` already has root {} (no change)", paths.join(", "))
            };
        }
        None => {
            let mut iter = paths.iter();
            let first = iter.next().cloned().unwrap_or_default();
            let mut rest: Vec<String> = Vec::new();
            for path in iter {
                if path != &first && !rest.contains(path) {
                    rest.push(path.clone());
                }
            }
            let rest_len = rest.len();
            file.projects.push(Project {
                name: name.clone(),
                path: first.clone(),
                roots: rest,
                auto_resume,
            });
            changed.push(format!("registered project {name} → {first}"));
            if auto_resume {
                changed.push(format!("project {name}: autoResume → true"));
            }
            message = if rest_len > 0 {
                format!("registered project `{name}` → {first} (+{rest_len} more root(s))")
            } else {
                format!("registered project `{name}` → {first}")
            };
        }
    }

    let final_auto_resume = auto_resume
        || file
            .projects
            .iter()
            .any(|p| p.name == name && p.auto_resume);
    if !changed.is_empty() {
        file.schema_version = STAGE_GRAPH_VERSION.to_string();
        file.projects.sort_by(|a, b| a.name.cmp(&b.name));
        if let Err(e) = write_stage(&projects_path(), &file) {
            return stage_error("project.add", e);
        }
        // Keep the staged graph.json in lock-step with the registry.
        match restage_graph() {
            Ok(g) => changed.push(g.to_string_lossy().into_owned()),
            Err(e) => return stage_error("project.add", e),
        }
    }
    // Read the record back out post-write so `path`/`roots` describe the
    // FINAL state, never the just-appended locals.
    let (final_path, final_roots): (String, Vec<String>) = file
        .projects
        .iter()
        .find(|p| p.name == name)
        .map(|p| (p.path.clone(), p.roots().into_iter().map(str::to_string).collect()))
        .unwrap_or_default();
    Outcome::ok("project.add", message).changed(changed).with_data(json!({
        "name": name,
        "path": final_path,
        "roots": final_roots,
        "autoResume": final_auto_resume,
        "file": projects_path().to_string_lossy(),
    }))
}

/// `project remove <name> [<path>]` — unregister a whole project, or one of
/// its roots (dropping the project when that root was its last). No PATH is
/// today's behaviour byte-for-byte. Matching is exact string equality
/// against the stored root — no trailing-slash normalization, no
/// canonicalization, and no `is_dir` check: a root whose directory has
/// since been deleted must still be removable.
pub fn project_remove(inv: &Invocation) -> Outcome {
    let args = match require_args(inv, &["name"]) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let name = args[0].clone();
    let path = inv.args.get(1).cloned();
    let mut file: ProjectsFile = match load_stage(&projects_path()) {
        Ok(f) => f,
        Err(e) => return stage_error("project.remove", e),
    };

    let Some(existing) = file.projects.iter().find(|p| p.name == name) else {
        return Outcome::ok(
            "project.remove",
            format!("project `{name}` was not registered (no change)"),
        )
        .with_data(json!({ "name": name }));
    };
    let roots: Vec<String> = existing.roots().into_iter().map(str::to_string).collect();

    let Some(path) = path else {
        // No PATH: today's behaviour, byte-for-byte — drop the whole project.
        file.projects.retain(|p| p.name != name);
        file.schema_version = STAGE_GRAPH_VERSION.to_string();
        if let Err(e) = write_stage(&projects_path(), &file) {
            return stage_error("project.remove", e);
        }
        let mut changed = vec![format!("removed project {name}")];
        match restage_graph() {
            Ok(g) => changed.push(g.to_string_lossy().into_owned()),
            Err(e) => return stage_error("project.remove", e),
        }
        return Outcome::ok("project.remove", format!("removed project `{name}`"))
            .changed(changed)
            .with_data(json!({ "name": name, "file": projects_path().to_string_lossy() }));
    };

    if !roots.contains(&path) {
        return Outcome::ok(
            "project.remove",
            format!("project `{name}` has no root {path} (no change)"),
        )
        .with_data(json!({ "name": name, "path": path }));
    }

    if roots.len() == 1 {
        // PATH is the only root — drop the whole project.
        file.projects.retain(|p| p.name != name);
        file.schema_version = STAGE_GRAPH_VERSION.to_string();
        if let Err(e) = write_stage(&projects_path(), &file) {
            return stage_error("project.remove", e);
        }
        let mut changed = vec![format!("removed project {name}")];
        match restage_graph() {
            Ok(g) => changed.push(g.to_string_lossy().into_owned()),
            Err(e) => return stage_error("project.remove", e),
        }
        return Outcome::ok(
            "project.remove",
            format!("removed project `{name}` (last root {path})"),
        )
        .changed(changed)
        .with_data(json!({
            "name": name,
            "path": path,
            "roots": Vec::<String>::new(),
            "file": projects_path().to_string_lossy(),
        }));
    }

    // PATH is one of several — rebuild from `roots()`, promoting the next
    // root into `path` when `path` itself was removed, leaving `path`
    // untouched otherwise.
    let existing = file.projects.iter_mut().find(|p| p.name == name).unwrap();
    let all: Vec<String> = existing.roots().iter().map(|s| s.to_string()).collect();
    let mut remaining: Vec<String> = all.into_iter().filter(|r| r != &path).collect();
    existing.path = remaining.remove(0);
    existing.roots = remaining;

    file.schema_version = STAGE_GRAPH_VERSION.to_string();
    if let Err(e) = write_stage(&projects_path(), &file) {
        return stage_error("project.remove", e);
    }
    let mut changed = vec![format!("project {name}: removed root {path}")];
    match restage_graph() {
        Ok(g) => changed.push(g.to_string_lossy().into_owned()),
        Err(e) => return stage_error("project.remove", e),
    }
    let (new_path, roots_after): (String, Vec<String>) = file
        .projects
        .iter()
        .find(|p| p.name == name)
        .map(|p| (p.path.clone(), p.roots().into_iter().map(str::to_string).collect()))
        .unwrap_or_default();
    Outcome::ok("project.remove", format!("removed root {path} from project `{name}`"))
        .changed(changed)
        .with_data(json!({
            "name": name,
            "path": new_path,
            "roots": roots_after,
            "file": projects_path().to_string_lossy(),
        }))
}

/// `project edit <name> <path> [<path>…]` — replace a project's roots
/// outright. The first path becomes `path`, the rest become `roots`;
/// duplicates collapse, order is the order given. The name is immutable
/// (`add`/`remove` are the only ways a project appears or disappears) and
/// `autoResume` is never touched.
pub fn project_edit(inv: &Invocation) -> Outcome {
    let args = match require_args(inv, &["name", "path"]) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let name = args[0].clone();
    let paths: Vec<String> = inv.args[1..].to_vec();

    let mut file: ProjectsFile = match load_stage(&projects_path()) {
        Ok(f) => f,
        Err(e) => return stage_error("project.edit", e),
    };
    if !file.projects.iter().any(|p| p.name == name) {
        return Outcome::error(
            "project.edit",
            format!("no project named `{name}` — register it first with `project add`"),
        )
        .with_data(json!({ "reason": "unknown", "name": name }));
    }

    // Validate EVERY path before any mutation — one bad path refuses the
    // whole edit.
    for path in &paths {
        if let Err(e) = validate_root("project.edit", &name, path) {
            return e;
        }
    }

    // Dedupe preserving first-seen order.
    let mut deduped: Vec<String> = Vec::new();
    for path in &paths {
        if !deduped.contains(path) {
            deduped.push(path.clone());
        }
    }
    let new_path = deduped[0].clone();
    let new_roots = deduped[1..].to_vec();
    let desired: Vec<&str> = std::iter::once(new_path.as_str())
        .chain(new_roots.iter().map(String::as_str))
        .collect();

    let existing = file.projects.iter().find(|p| p.name == name).unwrap();
    if existing.roots() == desired {
        return Outcome::ok(
            "project.edit",
            format!("project `{name}` already has exactly those roots (no change)"),
        )
        .with_data(json!({
            "name": name,
            "path": new_path,
            "roots": desired,
        }));
    }

    let existing = file.projects.iter_mut().find(|p| p.name == name).unwrap();
    existing.path = new_path;
    existing.roots = new_roots;

    file.schema_version = STAGE_GRAPH_VERSION.to_string();
    if let Err(e) = write_stage(&projects_path(), &file) {
        return stage_error("project.edit", e);
    }
    let (final_path, final_roots, final_auto_resume): (String, Vec<String>, bool) = file
        .projects
        .iter()
        .find(|p| p.name == name)
        .map(|p| (p.path.clone(), p.roots().into_iter().map(str::to_string).collect(), p.auto_resume))
        .unwrap_or_default();
    let mut changed: Vec<String> = final_roots
        .iter()
        .map(|r| format!("project {name}: root {r}"))
        .collect();
    match restage_graph() {
        Ok(g) => changed.push(g.to_string_lossy().into_owned()),
        Err(e) => return stage_error("project.edit", e),
    }
    Outcome::ok(
        "project.edit",
        format!("replaced the roots of project `{name}` → {}", final_roots.join(", ")),
    )
    .changed(changed)
    .with_data(json!({
        "name": name,
        "path": final_path,
        "roots": final_roots,
        "autoResume": final_auto_resume,
        "file": projects_path().to_string_lossy(),
    }))
}

/// `project list` — the registered anchor roots.
pub fn project_list(_inv: &Invocation) -> Outcome {
    let file: ProjectsFile = match load_stage(&projects_path()) {
        Ok(f) => f,
        Err(e) => return stage_error("project.list", e),
    };
    let projects = sorted_projects(&file.projects);
    let mut message = format!("{} project(s) registered", projects.len());
    for p in &projects {
        message.push_str(&format!("\n◆ {}  {}", p.name, p.path));
        for r in p.roots().into_iter().skip(1) {
            message.push_str(&format!("\n     {r}"));
        }
    }
    Outcome::ok("project.list", message).with_data(json!({ "projects": projects }))
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

/// `session prune` — drop `done` sessions (+ their hooks); clear orphaned
/// `parentSessionId`s. Idempotent; writes only when something changed.
pub fn prune(_inv: &Invocation) -> Outcome {
    let mut s_file: SessionsFile = match load_stage(&sessions_path()) {
        Ok(f) => f,
        Err(e) => return stage_error("session.prune", e),
    };
    let mut h_file: HooksFile = match load_stage(&hooks_path()) {
        Ok(f) => f,
        Err(e) => return stage_error("session.prune", e),
    };

    let (kept_s, kept_h, removed, cleared) = prune_done(
        std::mem::take(&mut s_file.sessions),
        std::mem::take(&mut h_file.hooks),
    );

    if removed.is_empty() {
        return Outcome::ok("session.prune", "nothing to prune (no `done` sessions)")
            .with_data(json!({ "removed": [], "clearedParents": [] }));
    }

    s_file.sessions = kept_s;
    h_file.hooks = kept_h;
    if let Err(e) = write_stage(&sessions_path(), &s_file) {
        return stage_error("session.prune", e);
    }
    if let Err(e) = write_stage(&hooks_path(), &h_file) {
        return stage_error("session.prune", e);
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
        Err(e) => return stage_error("session.prune", e),
    }
    Outcome::ok(
        "session.prune",
        format!(
            "pruned {} session(s); cleared {} orphaned parent link(s)",
            removed.len(),
            cleared.len()
        ),
    )
    .changed(changed)
    .with_data(json!({ "removed": removed, "clearedParents": cleared }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::anchor_for;
    use crate::graph::testutil::*;

    #[test]
    fn local_only_commands_ignore_node_ids() {
        // CONTRACTS.md §7: `link`/`prune` (and, by the same construction,
        // `focus`/`reap`) must keep ignoring `node:*` ids — neither reads
        // `node_store` at all, so a registered node (with its own cache)
        // sitting alongside real sessions must never appear as a
        // `link`/`prune` target and must never break either command. This
        // is the "confirm it, don't assume it generalizes for free" test
        // the plan called for.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let stage = unique_stage("node-ids-ignored");
        let state = std::env::temp_dir().join(format!(
            "aoide-node-ids-ignored-state-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);

        aoide_storage::node_store::save_nodes(&[aoide_storage::node_store::Node {
            name: "yomi-strix".into(),
            url: "http://yomi-strix:8710/".into(),
            autogate: false,
            token_file: None,
            bearer_secret: None,
            hub: false,
            pubkey: None,
            verified: false,
            allows: Vec::new(),
            via: None,
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

        // `link` never resolves `node:yomi-strix` as a valid child (it isn't
        // a session id) — this is the SAME rejection an unknown local id gets.
        let out = link(&invocation(&["graph", "link"], &["node:yomi-strix", "s1"]));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert_eq!(out.data.as_ref().unwrap()["reason"], "child-not-found");

        // `prune` runs clean (drops the `done` s2) with the node registry
        // sitting alongside — it never touches `node_store`, so a node being
        // registered changes nothing about what gets pruned.
        let out = prune(&invocation(&["session", "prune"], &[]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        assert_eq!(out.data.as_ref().unwrap()["removed"], json!(["s2"]));

        // The node registry itself is untouched by either command.
        assert_eq!(aoide_storage::node_store::load_nodes().len(), 1);

        // And the resolved graph document still folds the node in as its own
        // root node alongside whatever local nodes/edges link/prune left.
        let (p, s, h) = load_inputs("test").unwrap();
        let doc = build_graph(&p.projects, &s.sessions, &h.hooks);
        assert!(doc["nodes"].as_array().unwrap().iter().any(|n| n["id"] == "node:yomi-strix"));

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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("restage");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // Register a project. graph.json must now exist and carry the node.
        // (The path must be a real absolute dir — `project_add` rejects
        // anything else now — so the per-test stage dir stands in.)
        let out = project_add(&invocation(
            &["project", "add"],
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

        // The staged doc equals exactly what bare `graph` computes from the
        // current registries — no drift.
        let view = view(&invocation(&["graph"], &[]));
        assert_eq!(&staged, view.data.as_ref().unwrap());

        // A fresh restage would produce the very same document (idempotent).
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("reject-relative");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = project_add(&invocation(&["project", "add"], &["aoide", "intergration"]));
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("reject-nonexistent");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let bogus = stage.join("does-not-exist").to_string_lossy().into_owned();
        let out = project_add(&invocation(&["project", "add"], &["aoide", &bogus]));
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_cwd = std::env::current_dir().ok();
        let stage = unique_stage("cwd-default");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // Bare `project add <name>` registers the cwd as the anchor root.
        std::env::set_current_dir(&stage).unwrap();
        let out = project_add(&invocation(&["project", "add"], &["aoide"]));
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

    fn project_invocation(cmd: &[&str], args: &[&str], flags: &[(&str, &str)]) -> Invocation {
        Invocation {
            path: cmd.iter().map(|s| s.to_string()).collect(),
            args: args.iter().map(|s| s.to_string()).collect(),
            flags: flags
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            door: aoide_protocol::Door::Cli,
        }
    }

    #[test]
    fn project_add_registers_every_positional_root_in_order() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("add-multi-root");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let (a, b, c) = (stage.join("a"), stage.join("b"), stage.join("c"));
        for d in [&a, &b, &c] {
            std::fs::create_dir_all(d).unwrap();
        }
        let (a, b, c) = (
            a.to_string_lossy().into_owned(),
            b.to_string_lossy().into_owned(),
            c.to_string_lossy().into_owned(),
        );

        let out = project_add(&invocation(&["project", "add"], &["aoide", &a, &b, &c]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);

        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        let p = file.projects.iter().find(|p| p.name == "aoide").unwrap();
        assert_eq!(p.path, a);
        assert_eq!(p.roots, vec![b.clone(), c.clone()]);
        assert_eq!(p.roots(), vec![a.as_str(), b.as_str(), c.as_str()]);

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn project_add_on_an_existing_name_appends_a_root_and_keeps_path_first() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("add-appends-root");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let (a, b) = (stage.join("a"), stage.join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let (a, b) = (a.to_string_lossy().into_owned(), b.to_string_lossy().into_owned());

        assert_eq!(
            project_add(&invocation(&["project", "add"], &["aoide", &a])).status,
            aoide_protocol::output::Status::Ok
        );
        let out = project_add(&invocation(&["project", "add"], &["aoide", &b]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);

        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        let p = file.projects.iter().find(|p| p.name == "aoide").unwrap();
        assert_eq!(p.path, a);
        assert_eq!(p.roots(), vec![a.as_str(), b.as_str()]);

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn project_add_appends_and_dedupes_a_mixed_root_list() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("add-mixed-dedupe");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let (a, b, c) = (stage.join("a"), stage.join("b"), stage.join("c"));
        for d in [&a, &b, &c] {
            std::fs::create_dir_all(d).unwrap();
        }
        let (a, b, c) = (
            a.to_string_lossy().into_owned(),
            b.to_string_lossy().into_owned(),
            c.to_string_lossy().into_owned(),
        );

        project_add(&invocation(&["project", "add"], &["aoide", &a, &b]));
        let out = project_add(&invocation(&["project", "add"], &["aoide", &b, &c]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);

        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        let p = file.projects.iter().find(|p| p.name == "aoide").unwrap();
        assert_eq!(p.roots(), vec![a.as_str(), b.as_str(), c.as_str()]);

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn project_add_of_a_root_already_present_changes_nothing() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("add-no-change");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let a = stage.join("a");
        std::fs::create_dir_all(&a).unwrap();
        let a = a.to_string_lossy().into_owned();

        project_add(&invocation(&["project", "add"], &["aoide", &a]));
        let before = std::fs::read(projects_path()).unwrap();
        let out = project_add(&invocation(&["project", "add"], &["aoide", &a]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        assert!(out.changed.is_empty(), "{:?}", out.changed);
        assert_eq!(std::fs::read(projects_path()).unwrap(), before);

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn project_add_with_new_refuses_an_existing_name_without_writing() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("add-new-refuses-existing");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let (a, b) = (stage.join("a"), stage.join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let (a, b) = (a.to_string_lossy().into_owned(), b.to_string_lossy().into_owned());

        project_add(&invocation(&["project", "add"], &["aoide", &a]));
        let before = std::fs::read(projects_path()).unwrap();
        let out = project_add(&project_invocation(
            &["project", "add"],
            &["aoide", &b],
            &[("new", "true")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert_eq!(out.data.as_ref().unwrap()["reason"], "exists");
        assert_eq!(std::fs::read(projects_path()).unwrap(), before);

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn project_add_with_new_registers_an_unregistered_name() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("add-new-registers");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let a = stage.join("a");
        std::fs::create_dir_all(&a).unwrap();
        let a = a.to_string_lossy().into_owned();

        let out = project_add(&project_invocation(
            &["project", "add"],
            &["aoide", &a],
            &[("new", "true")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        assert!(file.projects.iter().any(|p| p.name == "aoide" && p.path == a));

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn project_add_refuses_the_whole_call_when_any_root_is_invalid() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("add-refuses-invalid");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let a = stage.join("a");
        std::fs::create_dir_all(&a).unwrap();
        let a = a.to_string_lossy().into_owned();

        let out = project_add(&invocation(
            &["project", "add"],
            &["aoide", &a, "not-absolute"],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Usage);
        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        assert!(
            file.projects.is_empty(),
            "one bad root refuses the whole call, writing nothing"
        );

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn project_add_reports_the_roots_in_its_outcome_data() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("add-reports-data");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let (a, b, c) = (stage.join("a"), stage.join("b"), stage.join("c"));
        for d in [&a, &b, &c] {
            std::fs::create_dir_all(d).unwrap();
        }
        let (a, b, c) = (
            a.to_string_lossy().into_owned(),
            b.to_string_lossy().into_owned(),
            c.to_string_lossy().into_owned(),
        );

        let out = project_add(&invocation(&["project", "add"], &["aoide", &a, &b, &c]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let data = out.data.as_ref().unwrap();
        assert_eq!(data["path"], a);
        assert_eq!(data["roots"], json!([a, b, c]));

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn project_remove_with_a_path_drops_only_that_root() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("remove-drops-one-root");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let (a, b, c) = (stage.join("a"), stage.join("b"), stage.join("c"));
        for d in [&a, &b, &c] {
            std::fs::create_dir_all(d).unwrap();
        }
        let (a, b, c) = (
            a.to_string_lossy().into_owned(),
            b.to_string_lossy().into_owned(),
            c.to_string_lossy().into_owned(),
        );
        project_add(&invocation(&["project", "add"], &["aoide", &a, &b, &c]));

        let out = project_remove(&invocation(&["project", "remove"], &["aoide", &b]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        let p = file.projects.iter().find(|p| p.name == "aoide").unwrap();
        assert_eq!(p.path, a);
        assert_eq!(p.roots(), vec![a.as_str(), c.as_str()]);

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn project_remove_of_the_path_promotes_the_next_root() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("remove-promotes-next");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let (a, b, c) = (stage.join("a"), stage.join("b"), stage.join("c"));
        for d in [&a, &b, &c] {
            std::fs::create_dir_all(d).unwrap();
        }
        let (a, b, c) = (
            a.to_string_lossy().into_owned(),
            b.to_string_lossy().into_owned(),
            c.to_string_lossy().into_owned(),
        );
        project_add(&invocation(&["project", "add"], &["aoide", &a, &b, &c]));

        let out = project_remove(&invocation(&["project", "remove"], &["aoide", &a]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        let p = file.projects.iter().find(|p| p.name == "aoide").unwrap();
        assert_eq!(p.path, b, "the next root is promoted into path");
        assert_eq!(p.roots(), vec![b.as_str(), c.as_str()]);

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn project_remove_of_the_last_root_drops_the_project() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("remove-drops-last-root");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let a = stage.join("a");
        std::fs::create_dir_all(&a).unwrap();
        let a = a.to_string_lossy().into_owned();
        project_add(&invocation(&["project", "add"], &["aoide", &a]));

        let out = project_remove(&invocation(&["project", "remove"], &["aoide", &a]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        assert!(!file.projects.iter().any(|p| p.name == "aoide"));

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn project_remove_without_a_path_drops_every_root() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("remove-no-path-drops-all");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let (a, b) = (stage.join("a"), stage.join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let (a, b) = (a.to_string_lossy().into_owned(), b.to_string_lossy().into_owned());
        project_add(&invocation(&["project", "add"], &["aoide", &a, &b]));

        let out = project_remove(&invocation(&["project", "remove"], &["aoide"]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        assert!(
            !file.projects.iter().any(|p| p.name == "aoide"),
            "no PATH drops the whole project, every root included"
        );

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn project_remove_of_an_unregistered_root_is_an_ok_no_op() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("remove-unregistered-noop");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let (a, b) = (stage.join("a"), stage.join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let (a, b) = (a.to_string_lossy().into_owned(), b.to_string_lossy().into_owned());
        project_add(&invocation(&["project", "add"], &["aoide", &a]));
        let before = std::fs::read(projects_path()).unwrap();

        let out = project_remove(&invocation(&["project", "remove"], &["aoide", &b]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        assert_eq!(std::fs::read(projects_path()).unwrap(), before);

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn project_edit_replaces_the_root_list_exactly() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("edit-replaces-roots");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let (a, b, x, y) = (
            stage.join("a"),
            stage.join("b"),
            stage.join("x"),
            stage.join("y"),
        );
        for d in [&a, &b, &x, &y] {
            std::fs::create_dir_all(d).unwrap();
        }
        let (a, b, x, y) = (
            a.to_string_lossy().into_owned(),
            b.to_string_lossy().into_owned(),
            x.to_string_lossy().into_owned(),
            y.to_string_lossy().into_owned(),
        );
        project_add(&invocation(&["project", "add"], &["aoide", &a, &b]));

        let out = project_edit(&invocation(&["project", "edit"], &["aoide", &x, &y]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        let p = file.projects.iter().find(|p| p.name == "aoide").unwrap();
        assert_eq!(p.path, x);
        assert_eq!(p.roots, vec![y.clone()]);
        assert_eq!(p.roots(), vec![x.as_str(), y.as_str()]);
        assert!(!p.roots().contains(&a.as_str()) && !p.roots().contains(&b.as_str()));

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn project_edit_promotes_the_first_path_into_path_and_dedupes() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("edit-dedupes");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let (a, x, y) = (stage.join("a"), stage.join("x"), stage.join("y"));
        for d in [&a, &x, &y] {
            std::fs::create_dir_all(d).unwrap();
        }
        let (a, x, y) = (
            a.to_string_lossy().into_owned(),
            x.to_string_lossy().into_owned(),
            y.to_string_lossy().into_owned(),
        );
        project_add(&invocation(&["project", "add"], &["aoide", &a]));

        let out = project_edit(&invocation(&["project", "edit"], &["aoide", &x, &x, &y, &y]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        let p = file.projects.iter().find(|p| p.name == "aoide").unwrap();
        assert_eq!(p.path, x, "the FIRST path given becomes path");
        assert_eq!(p.roots(), vec![x.as_str(), y.as_str()], "duplicates collapse");

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn project_edit_refuses_an_unknown_name() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("edit-unknown-name");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let a = stage.join("a");
        std::fs::create_dir_all(&a).unwrap();
        let a = a.to_string_lossy().into_owned();

        let out = project_edit(&invocation(&["project", "edit"], &["ghost", &a]));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert_eq!(out.data.as_ref().unwrap()["reason"], "unknown");
        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        assert!(file.projects.is_empty());

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn project_edit_refuses_an_empty_path_list_as_a_usage_error() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("edit-empty-path-list");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let a = stage.join("a");
        std::fs::create_dir_all(&a).unwrap();
        let a = a.to_string_lossy().into_owned();
        project_add(&invocation(&["project", "add"], &["aoide", &a]));

        let out = project_edit(&invocation(&["project", "edit"], &["aoide"]));
        assert_eq!(out.status, aoide_protocol::output::Status::Usage);
        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        let p = file.projects.iter().find(|p| p.name == "aoide").unwrap();
        assert_eq!(p.path, a, "the refused call wrote nothing");

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn project_edit_leaves_auto_resume_alone() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("edit-leaves-auto-resume");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let (a, b) = (stage.join("a"), stage.join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let (a, b) = (a.to_string_lossy().into_owned(), b.to_string_lossy().into_owned());
        project_add(&project_invocation(
            &["project", "add"],
            &["aoide", &a],
            &[("auto-resume", "true")],
        ));

        let out = project_edit(&invocation(&["project", "edit"], &["aoide", &b]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        assert_eq!(out.data.as_ref().unwrap()["autoResume"], true);
        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        let p = file.projects.iter().find(|p| p.name == "aoide").unwrap();
        assert!(p.auto_resume, "`project edit` never touches autoResume");

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
}
