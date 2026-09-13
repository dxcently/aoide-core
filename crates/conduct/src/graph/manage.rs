//! The read/manage command handlers: `view`, `project add/edit/remove/list`,
//! `link`, `prune`. Every mutation re-stages `graph.json` via
//! [`super::doc::restage_graph`] so the read path never drifts.

use super::common::{load_inputs, require_args, stage_error};
use super::doc::{build_graph, prune_done, render, restage_graph, would_cycle};
use super::model::{
    hooks_path, load_stage, projects_path, sessions_path, sorted_projects,
    write_stage, HooksFile, Project, ProjectHost, ProjectsFile, SessionsFile, STAGE_GRAPH_VERSION,
};
use aoide_protocol::{Door, Invocation};
use aoide_protocol::output::Outcome;
use aoide_storage::fs::with_stage_lock;
use serde_json::json;
#[cfg(test)]
use serde_json::Value;

/// `project add/edit/remove` are DAEMON-OWNED atomic mutations, the same
/// shape `actions.rs`'s `assign_project`/`session_kill` set the precedent
/// for: a `Door::Cli` caller forwards through `aoided`'s dispatch socket and
/// errors if none answers; a `Door::Daemon` caller (already running INSIDE
/// `aoided`, because a remote request just landed there) takes the local
/// path directly — `daemon_dispatch` itself short-circuits to `None` on
/// `Door::Daemon` for exactly this reentrancy reason; every other door is
/// refused as local-only.
fn local_daemon(inv: &Invocation) -> Option<Outcome> {
    match inv.door {
        Door::Daemon => None,
        Door::Cli => Some(
            aoide_client::daemon::daemon_dispatch(inv).unwrap_or_else(|| {
                Outcome::error(inv.dotted(), "aoided must be running for project management")
            }),
        ),
        _ => Some(Outcome::error(inv.dotted(), "project management is local-only")),
    }
}

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

/// Validate a `--host <node>` value: a registered node, checked inside the
/// SAME `with_stage_lock` hold as the mutation it gates, so nothing can
/// deregister between the check and the write (P-14 M1 §2c rule 1). A
/// malformed name and an unregistered one refuse identically — the caller
/// gets one taught reason, `unknown-host`, and zero writes either way.
/// Shared by `project add|edit|remove --host`.
fn validate_host(cmd: &str, host: &str) -> Result<(), Outcome> {
    let registered = aoide_storage::node_store::valid_node_name(host)
        && aoide_storage::node_store::load_nodes()
            .iter()
            .any(|n| n.name == host);
    if !registered {
        return Err(Outcome::error(
            cmd,
            format!("no host named `{host}` is registered — register it with `aoide node add` first"),
        )
        .with_data(json!({ "reason": "unknown-host", "host": host })));
    }
    Ok(())
}

/// Validate one candidate HOST root (§2c rule 2) — absolute and
/// control-character-free, like [`validate_root`], but deliberately WITHOUT
/// its `is_dir` check or any canonicalization: a host root names a path on
/// a NODE this instance cannot see, so existence is that host's problem,
/// never checked here. `ProjectHost.roots` stores it verbatim.
fn validate_host_root(cmd: &str, host: &str, path: &str) -> Result<(), Outcome> {
    let p = std::path::Path::new(path);
    let ok = !path.is_empty() && p.is_absolute() && !path.chars().any(char::is_control);
    if !ok {
        let why = if path.is_empty() {
            "empty"
        } else if !p.is_absolute() {
            "not an absolute path"
        } else {
            "contains control characters"
        };
        return Err(Outcome::usage(
            cmd,
            format!(
                "invalid root `{path}` for host `{host}` ({why}) — a host root is an absolute \
                 path on that node, unchecked locally"
            ),
        )
        .with_data(json!({ "reason": "invalid-host-root", "host": host, "path": path })));
    }
    Ok(())
}

/// `project add <name> [<path>...]` — register a project, or grow an
/// existing one with more anchor roots. With no path, the current working
/// directory supplies exactly one root, so a bare `aoide project add <name>`
/// registers the dir you're in — and a session started there anchors to it
/// by cwd prefix. `--new` refuses a name that already exists instead of
/// adding to it. `--host <node>` (P-14 M1) re-scopes the same positional
/// path list from LOCAL to that host's own roots — a bare `--host <node>`
/// with no path is membership-only and NEVER falls back to the cwd default,
/// the one local-add convenience `--host` deliberately drops. DAEMON-OWNED
/// (`local_daemon`, above): a CLI caller forwards to `aoided`; only the door
/// check and arg parsing happen out here, the actual mutation is
/// [`add_roots`].
pub fn project_add(inv: &Invocation) -> Outcome {
    if let Some(out) = local_daemon(inv) {
        return out;
    }
    let args = match require_args(inv, &["name"]) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let name = args[0].clone();
    let host = inv.flags.get("host").cloned();
    let paths: Vec<String> = if inv.args.len() > 1 {
        inv.args[1..].to_vec()
    } else if host.is_some() {
        // Membership-only under `--host`: never the cwd default local `add`
        // uses, since a bare path here would silently register the CALLER's
        // local cwd as a REMOTE root on that host.
        Vec::new()
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
    // `--auto-resume` (P-D8, `docs/architecture/AOIDED.md`'s "L5"): opts this
    // project into the daemon's boot-time auto-resume sweep. Only ever sets
    // it true here — `project edit` never touches it (see this crate's own
    // `AGENTS.md`). Untouched by every `--host` path (§2c rule 5).
    add_roots(
        &name,
        &paths,
        inv.flag_present("new"),
        inv.flag_present("auto-resume"),
        host.as_deref(),
    )
}

/// The local mutation behind `project add`, run inside ONE [`with_stage_lock`]
/// hold end to end — the `--new` existence check, every path's validation,
/// and the write all happen under the SAME lock, so two threads racing
/// `--new` for the same name can never both see "unregistered" and both win
/// (only one lock holder observes the empty registry; the other sees the
/// first's write). `roots` is written as the FULL ordered root list, `path`
/// mirrored at `roots[0]` (ROOTS SERIALIZED COMPLETE) — never "just the new
/// ones appended to whatever was on disk." `host` re-scopes `paths` onto
/// that host's OWN root list (P-14 M1 §2b/§2c) instead of the local one —
/// see the dedicated branch below; local roots and `autoResume` are never
/// touched by a host call.
fn add_roots(name: &str, paths: &[String], new: bool, auto_resume: bool, host: Option<&str>) -> Outcome {
    with_stage_lock(|| {
        let mut file: ProjectsFile = match load_stage(&projects_path()) {
            Ok(f) => f,
            Err(e) => return stage_error("project.add", e),
        };

        // `--new` refuses a name that already exists BEFORE any path
        // validation or write — the invocation was well-formed, the world
        // disagreed. Applies identically under `--host`.
        if new && file.projects.iter().any(|p| p.name == name) {
            return Outcome::error(
                "project.add",
                format!(
                    "project `{name}` already exists — omit --new to add a root to it, or use `project edit` to replace its roots"
                ),
            )
            .with_data(json!({ "reason": "exists", "name": name }));
        }

        if let Some(host) = host {
            if let Err(e) = validate_host("project.add", host) {
                return e;
            }
            // Validate EVERY host root before mutating anything — same
            // all-or-nothing rule the local branch holds below.
            for path in paths {
                if let Err(e) = validate_host_root("project.add", host, path) {
                    return e;
                }
            }

            let mut changed: Vec<String> = Vec::new();
            if !file.projects.iter().any(|p| p.name == name) {
                // A project may be registered FIRST via host membership
                // alone — local presence is not a precondition.
                file.projects.push(Project { name: name.to_string(), ..Default::default() });
                changed.push(format!("registered project {name} (host-only)"));
            }
            let existing = file.projects.iter_mut().find(|p| p.name == name).unwrap();
            if !existing.hosts.iter().any(|h| h.name == host) {
                existing.hosts.push(ProjectHost { name: host.to_string(), roots: Vec::new() });
                changed.push(format!("project {name}: host {host} added"));
            }
            let hrec = existing.hosts.iter_mut().find(|h| h.name == host).unwrap();
            let mut added_roots: Vec<String> = Vec::new();
            for path in paths {
                if !hrec.roots.contains(path) {
                    hrec.roots.push(path.clone());
                    added_roots.push(path.clone());
                }
            }
            for r in &added_roots {
                changed.push(format!("project {name}: host {host} root → {r}"));
            }

            let message = if !added_roots.is_empty() {
                if added_roots.len() == 1 {
                    format!("added root {} to project `{name}` host `{host}`", added_roots[0])
                } else {
                    format!("added roots {} to project `{name}` host `{host}`", added_roots.join(", "))
                }
            } else if !changed.is_empty() {
                format!("project `{name}`: host `{host}` membership added")
            } else if paths.is_empty() {
                format!("project `{name}` already has host `{host}` (no change)")
            } else {
                format!(
                    "project `{name}` host `{host}` already has root {} (no change)",
                    paths.join(", ")
                )
            };

            if !changed.is_empty() {
                file.schema_version = STAGE_GRAPH_VERSION.to_string();
                file.projects.sort_by(|a, b| a.name.cmp(&b.name));
                if let Err(e) = write_stage(&projects_path(), &file) {
                    return stage_error("project.add", e);
                }
                match restage_graph() {
                    Ok(g) => changed.push(g.to_string_lossy().into_owned()),
                    Err(e) => return stage_error("project.add", e),
                }
            }

            let (final_path, final_roots, final_hosts, final_auto_resume) = file
                .projects
                .iter()
                .find(|p| p.name == name)
                .map(|p| {
                    (
                        p.path.clone(),
                        p.roots().into_iter().map(str::to_string).collect::<Vec<_>>(),
                        p.hosts.clone(),
                        p.auto_resume,
                    )
                })
                .unwrap_or_default();
            return Outcome::ok("project.add", message).changed(changed).with_data(json!({
                "name": name,
                "path": final_path,
                "roots": final_roots,
                "autoResume": final_auto_resume,
                "hosts": final_hosts,
                "file": projects_path().to_string_lossy(),
            }));
        }

        // Validate EVERY root before mutating anything — one bad path in the
        // list refuses the whole invocation and writes nothing.
        for path in paths {
            if let Err(e) = validate_root("project.add", name, path) {
                return e;
            }
        }

        let mut changed: Vec<String> = Vec::new();
        let mut added_roots: Vec<String> = Vec::new();
        let message;
        match file.projects.iter_mut().find(|p| p.name == name) {
            Some(existing) => {
                let mut current: Vec<String> =
                    existing.roots().into_iter().map(str::to_string).collect();
                let mut this_changed = false;
                for path in paths {
                    if !current.contains(path) {
                        if current.is_empty() {
                            changed.push(format!("project {name}: path → {path}"));
                        } else {
                            changed.push(format!("project {name}: added root {path}"));
                        }
                        current.push(path.clone());
                        added_roots.push(path.clone());
                        this_changed = true;
                    }
                }
                if auto_resume && !existing.auto_resume {
                    changed.push(format!("project {name}: autoResume → true"));
                    existing.auto_resume = true;
                    this_changed = true;
                }
                if this_changed {
                    existing.path = current[0].clone();
                    existing.roots = current;
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
                let mut full: Vec<String> = Vec::new();
                for path in paths {
                    if !full.contains(path) {
                        full.push(path.clone());
                    }
                }
                let first = full.first().cloned().unwrap_or_default();
                let rest_len = full.len().saturating_sub(1);
                file.projects.push(Project {
                    name: name.to_string(),
                    path: first.clone(),
                    roots: full,
                    auto_resume,
                    hosts: Vec::new(),
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
        let (final_path, final_roots, final_hosts): (String, Vec<String>, Vec<ProjectHost>) = file
            .projects
            .iter()
            .find(|p| p.name == name)
            .map(|p| {
                (
                    p.path.clone(),
                    p.roots().into_iter().map(str::to_string).collect(),
                    p.hosts.clone(),
                )
            })
            .unwrap_or_default();
        Outcome::ok("project.add", message).changed(changed).with_data(json!({
            "name": name,
            "path": final_path,
            "roots": final_roots,
            "autoResume": final_auto_resume,
            "hosts": final_hosts,
            "file": projects_path().to_string_lossy(),
        }))
    })
}

/// The onboarding-only bootstrap entry: `aoide onboard`'s `register_clone`
/// is its SOLE caller. Onboarding registers the clone as a project before
/// any daemon exists to answer a dispatch — the documented first-run path
/// is `git clone … && cd ~/Aoide && aoide onboard`, no daemon step — so
/// unlike `project_add`/`project_edit`/`project_remove` this never checks
/// `local_daemon` and never forwards; it goes straight to the same locked
/// mutation [`add_roots`] a live daemon runs once one exists, with the same
/// validation. Every other project mutation goes through `local_daemon`.
pub fn register_bootstrap_project(name: &str, path: &str, auto_resume: bool) -> Outcome {
    add_roots(name, &[path.to_string()], false, auto_resume, None)
}

/// `project remove <name> [<path>]` — unregister a whole project, or one of
/// its roots (dropping the project when that root was its last). No PATH is
/// today's behaviour byte-for-byte. Matching is exact string equality
/// against the stored root — no trailing-slash normalization, no
/// canonicalization, and no `is_dir` check: a root whose directory has
/// since been deleted must still be removable. `--host <node>` (P-14 M1)
/// re-scopes the same PATH slot to that host: bare `--host <node>` drops
/// the whole membership (roots included), `--host <node> <path>` drops just
/// that one host root and leaves the membership (even at zero roots).
/// DAEMON-OWNED (`local_daemon`, above): a CLI caller forwards to `aoided`;
/// the actual mutation is [`remove_roots`].
pub fn project_remove(inv: &Invocation) -> Outcome {
    if let Some(out) = local_daemon(inv) {
        return out;
    }
    let args = match require_args(inv, &["name"]) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let name = args[0].clone();
    let path = inv.args.get(1).cloned();
    let host = inv.flags.get("host").cloned();
    remove_roots(&name, path.as_deref(), host.as_deref())
}

/// The local mutation behind `project remove`, run inside ONE
/// [`with_stage_lock`] hold — the load, the root-membership check, and the
/// write all happen under the same lock. `roots` is rewritten as the FULL
/// remaining root list, `path` mirrored at `roots[0]` (ROOTS SERIALIZED
/// COMPLETE), same as [`add_roots`]/[`edit_roots`]. `host` diverts entirely
/// into the host-membership branch below; local roots are never touched by
/// a host call.
fn remove_roots(name: &str, path: Option<&str>, host: Option<&str>) -> Outcome {
    with_stage_lock(|| {
        let mut file: ProjectsFile = match load_stage(&projects_path()) {
            Ok(f) => f,
            Err(e) => return stage_error("project.remove", e),
        };

        if let Some(host) = host {
            if let Err(e) = validate_host("project.remove", host) {
                return e;
            }
        }

        let Some(existing) = file.projects.iter().find(|p| p.name == name) else {
            return Outcome::ok(
                "project.remove",
                format!("project `{name}` was not registered (no change)"),
            )
            .with_data(json!({ "name": name }));
        };

        if let Some(host) = host {
            if !existing.hosts.iter().any(|h| h.name == host) {
                return Outcome::ok(
                    "project.remove",
                    format!("project `{name}` has no host `{host}` (no change)"),
                )
                .with_data(json!({ "name": name, "host": host }));
            }
            return match path {
                None => {
                    // Bare `--host <node>`: drop the whole membership.
                    let existing = file.projects.iter_mut().find(|p| p.name == name).unwrap();
                    existing.hosts.retain(|h| h.name != host);
                    file.schema_version = STAGE_GRAPH_VERSION.to_string();
                    if let Err(e) = write_stage(&projects_path(), &file) {
                        return stage_error("project.remove", e);
                    }
                    let mut changed = vec![format!("project {name}: removed host {host}")];
                    match restage_graph() {
                        Ok(g) => changed.push(g.to_string_lossy().into_owned()),
                        Err(e) => return stage_error("project.remove", e),
                    }
                    let final_hosts = file
                        .projects
                        .iter()
                        .find(|p| p.name == name)
                        .map(|p| p.hosts.clone())
                        .unwrap_or_default();
                    Outcome::ok("project.remove", format!("removed host `{host}` from project `{name}`"))
                        .changed(changed)
                        .with_data(json!({
                            "name": name,
                            "hosts": final_hosts,
                            "file": projects_path().to_string_lossy(),
                        }))
                }
                Some(p) => {
                    let has_root = existing
                        .hosts
                        .iter()
                        .find(|h| h.name == host)
                        .is_some_and(|h| h.roots.iter().any(|r| r == p));
                    if !has_root {
                        return Outcome::ok(
                            "project.remove",
                            format!("project `{name}` host `{host}` has no root {p} (no change)"),
                        )
                        .with_data(json!({ "name": name, "host": host, "path": p }));
                    }
                    // Membership stays even at zero remaining roots — only a
                    // bare `--host <node>` (above) drops it.
                    let existing = file.projects.iter_mut().find(|pr| pr.name == name).unwrap();
                    let hrec = existing.hosts.iter_mut().find(|h| h.name == host).unwrap();
                    hrec.roots.retain(|r| r != p);
                    file.schema_version = STAGE_GRAPH_VERSION.to_string();
                    if let Err(e) = write_stage(&projects_path(), &file) {
                        return stage_error("project.remove", e);
                    }
                    let mut changed = vec![format!("project {name}: host {host} removed root {p}")];
                    match restage_graph() {
                        Ok(g) => changed.push(g.to_string_lossy().into_owned()),
                        Err(e) => return stage_error("project.remove", e),
                    }
                    let final_hosts = file
                        .projects
                        .iter()
                        .find(|pr| pr.name == name)
                        .map(|pr| pr.hosts.clone())
                        .unwrap_or_default();
                    Outcome::ok(
                        "project.remove",
                        format!("removed root {p} from project `{name}` host `{host}`"),
                    )
                    .changed(changed)
                    .with_data(json!({
                        "name": name,
                        "hosts": final_hosts,
                        "file": projects_path().to_string_lossy(),
                    }))
                }
            };
        }

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

        if !roots.iter().any(|r| r == path) {
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
        // untouched otherwise. `roots` stays the FULL remaining list, `path`
        // included at index 0.
        let existing = file.projects.iter_mut().find(|p| p.name == name).unwrap();
        let all: Vec<String> = existing.roots().iter().map(|s| s.to_string()).collect();
        let remaining: Vec<String> = all.into_iter().filter(|r| r != path).collect();
        existing.path = remaining[0].clone();
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
    })
}

/// `project edit <name> <path> [<path>…]` — replace a project's roots
/// outright. The first path becomes `path`, the rest follow it into
/// `roots`; duplicates collapse, order is the order given. The name is
/// immutable (`add`/`remove` are the only ways a project appears or
/// disappears) and `autoResume` is never touched. `--host <node>` (P-14 M1)
/// re-scopes the same path list onto that host's OWN roots — replaced
/// exactly, same as the local case, while local roots and every OTHER host
/// stay untouched. DAEMON-OWNED (`local_daemon`, above): a CLI caller
/// forwards to `aoided`; the actual mutation is [`edit_roots`].
pub fn project_edit(inv: &Invocation) -> Outcome {
    if let Some(out) = local_daemon(inv) {
        return out;
    }
    let args = match require_args(inv, &["name", "path"]) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let name = args[0].clone();
    let paths: Vec<String> = inv.args[1..].to_vec();
    let host = inv.flags.get("host").cloned();
    edit_roots(&name, &paths, host.as_deref())
}

/// The local mutation behind `project edit`, run inside ONE
/// [`with_stage_lock`] hold — the unknown-name check, every path's
/// validation, and the write all happen under the same lock. `roots` is
/// written as the FULL deduped list given, `path` mirrored at `roots[0]`
/// (ROOTS SERIALIZED COMPLETE), same as [`add_roots`]/[`remove_roots`].
/// `host` diverts into the host-root-replace branch below, upserting that
/// host's membership if it wasn't already one — local roots and every other
/// host are never touched by a host call.
fn edit_roots(name: &str, paths: &[String], host: Option<&str>) -> Outcome {
    with_stage_lock(|| {
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

        if let Some(host) = host {
            if let Err(e) = validate_host("project.edit", host) {
                return e;
            }
            for path in paths {
                if let Err(e) = validate_host_root("project.edit", host, path) {
                    return e;
                }
            }
            let mut deduped: Vec<String> = Vec::new();
            for path in paths {
                if !deduped.contains(path) {
                    deduped.push(path.clone());
                }
            }

            let existing = file.projects.iter().find(|p| p.name == name).unwrap();
            let current = existing.hosts.iter().find(|h| h.name == host).map(|h| h.roots.clone());
            if current.as_deref() == Some(deduped.as_slice()) {
                return Outcome::ok(
                    "project.edit",
                    format!("project `{name}` host `{host}` already has exactly those roots (no change)"),
                )
                .with_data(json!({ "name": name, "hosts": existing.hosts.clone() }));
            }

            let existing = file.projects.iter_mut().find(|p| p.name == name).unwrap();
            match existing.hosts.iter_mut().find(|h| h.name == host) {
                Some(hrec) => hrec.roots = deduped.clone(),
                None => existing.hosts.push(ProjectHost { name: host.to_string(), roots: deduped.clone() }),
            }

            file.schema_version = STAGE_GRAPH_VERSION.to_string();
            if let Err(e) = write_stage(&projects_path(), &file) {
                return stage_error("project.edit", e);
            }
            let mut changed: Vec<String> = deduped
                .iter()
                .map(|r| format!("project {name}: host {host} root {r}"))
                .collect();
            match restage_graph() {
                Ok(g) => changed.push(g.to_string_lossy().into_owned()),
                Err(e) => return stage_error("project.edit", e),
            }
            let final_hosts =
                file.projects.iter().find(|p| p.name == name).map(|p| p.hosts.clone()).unwrap_or_default();
            return Outcome::ok(
                "project.edit",
                format!(
                    "replaced the roots of project `{name}` host `{host}` → {}",
                    deduped.join(", ")
                ),
            )
            .changed(changed)
            .with_data(json!({
                "name": name,
                "hosts": final_hosts,
                "file": projects_path().to_string_lossy(),
            }));
        }

        // Validate EVERY path before any mutation — one bad path refuses the
        // whole edit.
        for path in paths {
            if let Err(e) = validate_root("project.edit", name, path) {
                return e;
            }
        }

        // Dedupe preserving first-seen order.
        let mut deduped: Vec<String> = Vec::new();
        for path in paths {
            if !deduped.contains(path) {
                deduped.push(path.clone());
            }
        }
        let desired: Vec<&str> = deduped.iter().map(String::as_str).collect();

        let existing = file.projects.iter().find(|p| p.name == name).unwrap();
        if existing.roots() == desired {
            return Outcome::ok(
                "project.edit",
                format!("project `{name}` already has exactly those roots (no change)"),
            )
            .with_data(json!({
                "name": name,
                "path": deduped[0],
                "roots": desired,
            }));
        }

        let existing = file.projects.iter_mut().find(|p| p.name == name).unwrap();
        existing.path = deduped[0].clone();
        existing.roots = deduped;

        file.schema_version = STAGE_GRAPH_VERSION.to_string();
        if let Err(e) = write_stage(&projects_path(), &file) {
            return stage_error("project.edit", e);
        }
        let (final_path, final_roots, final_auto_resume, final_hosts): (
            String,
            Vec<String>,
            bool,
            Vec<ProjectHost>,
        ) = file
            .projects
            .iter()
            .find(|p| p.name == name)
            .map(|p| {
                (
                    p.path.clone(),
                    p.roots().into_iter().map(str::to_string).collect(),
                    p.auto_resume,
                    p.hosts.clone(),
                )
            })
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
            "hosts": final_hosts,
            "file": projects_path().to_string_lossy(),
        }))
    })
}

/// `project list` — the registered anchor roots, plus every host membership
/// (P-14 M1): `data.projects[].hosts` is the `Project` record serialized
/// as-is (`skip_serializing_if`-empty), so this needs no separate mirroring
/// logic — it already reads back exactly what `project add|edit|remove
/// --host` wrote.
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
        for h in &p.hosts {
            message.push_str(&format!("\n     @{} {}", h.name, h.roots.join(", ")));
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
        let out = project_add(&daemon_invocation(
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

        let out = project_add(&daemon_invocation(&["project", "add"], &["aoide", "intergration"]));
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
        let out = project_add(&daemon_invocation(&["project", "add"], &["aoide", &bogus]));
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
        let out = project_add(&daemon_invocation(&["project", "add"], &["aoide"]));
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

    // `project add/edit/remove` are DAEMON-OWNED atomic mutations now
    // (`local_daemon`, above): a `Door::Cli` invocation forwards to `aoided`
    // instead of running locally, which a bare handler test has no daemon
    // to answer. Every direct in-process handler call below stamps
    // `Door::Daemon` instead — the exact door
    // `aoide_server::daemon::invocation_from_dispatch_request` stamps for a
    // request that already reached `aoided`, so this exercises the SAME
    // local path a live daemon runs, `local_daemon`'s `Door::Daemon => None`
    // arm taking it unconditionally with no connect attempt. The
    // `Door::Cli` forwarding path itself is covered separately (see
    // `project_add_forwards_through_a_live_daemon_and_refuses_without_one`,
    // below).
    fn project_invocation(cmd: &[&str], args: &[&str], flags: &[(&str, &str)]) -> Invocation {
        Invocation {
            path: cmd.iter().map(|s| s.to_string()).collect(),
            args: args.iter().map(|s| s.to_string()).collect(),
            flags: flags
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            door: aoide_protocol::Door::Daemon,
        }
    }
    fn daemon_invocation(path: &[&str], args: &[&str]) -> Invocation {
        project_invocation(path, args, &[])
    }
    /// A synthetic minimal registered node for `--host` tests — never a
    /// real host name, petname, pid, or path (test-fixture discipline).
    fn synthetic_node(name: &str) -> aoide_storage::node_store::Node {
        aoide_storage::node_store::Node {
            name: name.into(),
            url: format!("http://{name}.invalid:8710/"),
            autogate: false,
            token_file: None,
            bearer_secret: None,
            hub: false,
            pubkey: None,
            verified: false,
            allows: Vec::new(),
            via: None,
            added_at: "2026-01-01T00:00:00Z".into(),
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

        let out = project_add(&daemon_invocation(&["project", "add"], &["aoide", &a, &b, &c]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);

        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        let p = file.projects.iter().find(|p| p.name == "aoide").unwrap();
        assert_eq!(p.path, a);
        // ROOTS SERIALIZED COMPLETE: the raw field is the FULL list, `path`
        // mirrored at `roots[0]` — not "just the extras."
        assert_eq!(p.roots, vec![a.clone(), b.clone(), c.clone()]);
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
            project_add(&daemon_invocation(&["project", "add"], &["aoide", &a])).status,
            aoide_protocol::output::Status::Ok
        );
        let out = project_add(&daemon_invocation(&["project", "add"], &["aoide", &b]));
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

        project_add(&daemon_invocation(&["project", "add"], &["aoide", &a, &b]));
        let out = project_add(&daemon_invocation(&["project", "add"], &["aoide", &b, &c]));
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

        project_add(&daemon_invocation(&["project", "add"], &["aoide", &a]));
        let before = std::fs::read(projects_path()).unwrap();
        let out = project_add(&daemon_invocation(&["project", "add"], &["aoide", &a]));
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

        project_add(&daemon_invocation(&["project", "add"], &["aoide", &a]));
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

        let out = project_add(&daemon_invocation(
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

        let out = project_add(&daemon_invocation(&["project", "add"], &["aoide", &a, &b, &c]));
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
    fn register_bootstrap_project_writes_under_the_lock_with_cli_equivalent_validation() {
        // The onboarding-only entry point (`register_clone`'s sole caller):
        // never touches `local_daemon`, so it writes locally with no daemon
        // reachable at all -- and still refuses the same invalid root
        // `project_add`'s CLI path refuses, writing nothing.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("bootstrap-writes-and-validates");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let a = stage.join("a");
        std::fs::create_dir_all(&a).unwrap();
        let a = a.to_string_lossy().into_owned();

        let out = register_bootstrap_project("aoide", &a, false);
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        let p = file.projects.iter().find(|p| p.name == "aoide").unwrap();
        assert_eq!(p.path, a);
        assert_eq!(p.roots(), vec![a.as_str()]);

        // One bad root -- the CLI-equivalent validation `add_roots` already
        // applies -- refuses the whole call and writes nothing.
        let out = register_bootstrap_project("bogus", "not-absolute", false);
        assert_eq!(out.status, aoide_protocol::output::Status::Usage);
        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        assert!(
            !file.projects.iter().any(|p| p.name == "bogus"),
            "the bad root wrote nothing"
        );

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
        project_add(&daemon_invocation(&["project", "add"], &["aoide", &a, &b, &c]));

        let out = project_remove(&daemon_invocation(&["project", "remove"], &["aoide", &b]));
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
        project_add(&daemon_invocation(&["project", "add"], &["aoide", &a, &b, &c]));

        let out = project_remove(&daemon_invocation(&["project", "remove"], &["aoide", &a]));
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
        project_add(&daemon_invocation(&["project", "add"], &["aoide", &a]));

        let out = project_remove(&daemon_invocation(&["project", "remove"], &["aoide", &a]));
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
        project_add(&daemon_invocation(&["project", "add"], &["aoide", &a, &b]));

        let out = project_remove(&daemon_invocation(&["project", "remove"], &["aoide"]));
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
        project_add(&daemon_invocation(&["project", "add"], &["aoide", &a]));
        let before = std::fs::read(projects_path()).unwrap();

        let out = project_remove(&daemon_invocation(&["project", "remove"], &["aoide", &b]));
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
        project_add(&daemon_invocation(&["project", "add"], &["aoide", &a, &b]));

        let out = project_edit(&daemon_invocation(&["project", "edit"], &["aoide", &x, &y]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        let p = file.projects.iter().find(|p| p.name == "aoide").unwrap();
        assert_eq!(p.path, x);
        // ROOTS SERIALIZED COMPLETE: the raw field is the FULL replacement
        // list, `path` mirrored at `roots[0]`.
        assert_eq!(p.roots, vec![x.clone(), y.clone()]);
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
        project_add(&daemon_invocation(&["project", "add"], &["aoide", &a]));

        let out = project_edit(&daemon_invocation(&["project", "edit"], &["aoide", &x, &x, &y, &y]));
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

        let out = project_edit(&daemon_invocation(&["project", "edit"], &["ghost", &a]));
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
        project_add(&daemon_invocation(&["project", "add"], &["aoide", &a]));

        let out = project_edit(&daemon_invocation(&["project", "edit"], &["aoide"]));
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

        let out = project_edit(&daemon_invocation(&["project", "edit"], &["aoide", &b]));
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

    // ── P-14 M1: host membership (`--host <node>` on add/edit/remove) ──

    #[test]
    fn an_unregistered_host_is_refused_and_writes_nothing() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR"]);
        let stage = unique_stage("host-unknown-refused");
        let state = unique_stage("host-unknown-refused-state");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        // No node registered at all — `n1` is unknown by construction.

        let out = project_add(&project_invocation(
            &["project", "add"],
            &["proj"],
            &[("host", "n1")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert_eq!(out.data.as_ref().unwrap()["reason"], "unknown-host");
        assert_eq!(out.data.as_ref().unwrap()["host"], "n1");

        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        assert!(file.projects.is_empty(), "an unknown host writes nothing");

        let _ = std::fs::remove_dir_all(&stage);
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn a_host_root_is_never_inferred_from_the_local_cwd() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR"]);
        let saved_cwd = std::env::current_dir().ok();
        let stage = unique_stage("host-no-cwd-default");
        let state = unique_stage("host-no-cwd-default-state");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        aoide_storage::node_store::save_nodes(&[synthetic_node("n1")]).unwrap();
        // A real, existing cwd — if `--host` ever fell back to it (the local
        // `add` convenience), this would silently register the CALLER's
        // local directory as a remote root on `n1`.
        std::env::set_current_dir(&stage).unwrap();

        let out = project_add(&project_invocation(
            &["project", "add"],
            &["proj"],
            &[("host", "n1")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);

        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        let p = file.projects.iter().find(|p| p.name == "proj").unwrap();
        assert!(p.path.is_empty(), "no local root was ever set: {p:?}");
        assert!(p.roots.is_empty(), "no local root was ever set: {p:?}");
        assert_eq!(p.hosts, vec![ProjectHost { name: "n1".into(), roots: vec![] }]);

        if let Some(c) = saved_cwd {
            std::env::set_current_dir(c).unwrap();
        }
        let _ = std::fs::remove_dir_all(&stage);
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn a_host_root_needs_no_local_directory() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR"]);
        let stage = unique_stage("host-root-no-local-dir");
        let state = unique_stage("host-root-no-local-dir-state");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        aoide_storage::node_store::save_nodes(&[synthetic_node("n1")]).unwrap();

        // `/srv/n1/proj` exists on no filesystem this test runs on — a
        // host root is never `is_dir`-checked, never canonicalized.
        let out = project_add(&project_invocation(
            &["project", "add"],
            &["proj", "/srv/n1/proj"],
            &[("host", "n1")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");
        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        let p = file.projects.iter().find(|p| p.name == "proj").unwrap();
        assert_eq!(
            p.hosts,
            vec![ProjectHost { name: "n1".into(), roots: vec!["/srv/n1/proj".into()] }]
        );

        // A relative host root, by contrast, IS refused — absolute is still
        // required, just never checked against THIS machine's filesystem.
        let out = project_add(&project_invocation(
            &["project", "add"],
            &["proj", "relative/path"],
            &[("host", "n1")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Usage);
        assert_eq!(out.data.as_ref().unwrap()["reason"], "invalid-host-root");

        let _ = std::fs::remove_dir_all(&stage);
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn an_offline_selected_host_is_retained_across_a_local_root_edit() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR"]);
        let stage = unique_stage("host-retained-across-edit");
        let state = unique_stage("host-retained-across-edit-state");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        aoide_storage::node_store::save_nodes(&[synthetic_node("n1")]).unwrap();
        let (a, b) = (stage.join("a"), stage.join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let (a, b) = (a.to_string_lossy().into_owned(), b.to_string_lossy().into_owned());

        project_add(&project_invocation(&["project", "add"], &["proj", &a], &[]));
        project_add(&project_invocation(
            &["project", "add"],
            &["proj", "/srv/n1/proj"],
            &[("host", "n1")],
        ));

        // A plain local edit — `--host` absent — never even reads `hosts`,
        // let alone touches it, however unreachable that host currently is.
        let out = project_edit(&daemon_invocation(&["project", "edit"], &["proj", &b]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);

        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        let p = file.projects.iter().find(|p| p.name == "proj").unwrap();
        assert_eq!(p.path, b, "the local edit took effect");
        assert_eq!(
            p.hosts,
            vec![ProjectHost { name: "n1".into(), roots: vec!["/srv/n1/proj".into()] }],
            "host membership survives a local-only edit untouched"
        );

        let _ = std::fs::remove_dir_all(&stage);
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn multi_root_edit_preserves_session_assignments() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR"]);
        let stage = unique_stage("multi-root-edit-sessions");
        let state = unique_stage("multi-root-edit-sessions-state");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        aoide_storage::node_store::save_nodes(&[synthetic_node("n1")]).unwrap();
        let (a, b, c) = (stage.join("a"), stage.join("b"), stage.join("c"));
        for d in [&a, &b, &c] {
            std::fs::create_dir_all(d).unwrap();
        }
        let (a, b, c) = (
            a.to_string_lossy().into_owned(),
            b.to_string_lossy().into_owned(),
            c.to_string_lossy().into_owned(),
        );

        project_add(&project_invocation(&["project", "add"], &["proj", &a], &[]));
        project_add(&project_invocation(
            &["project", "add"],
            &["proj", "/srv/n1/proj"],
            &[("host", "n1")],
        ));
        // A session explicitly assigned to `proj` (`session project --id`'s
        // own field) — `edit_roots` never opens `sessions.json` at all.
        let mut rec = session("s1", &a, "working", "1", None);
        rec.project = Some("proj".into());
        write_stage(&sessions_path(), &SessionsFile { schema_version: "0".into(), sessions: vec![rec] })
            .unwrap();

        // Replace the LOCAL roots with a fresh multi-root list.
        let out = project_edit(&daemon_invocation(&["project", "edit"], &["proj", &b, &c]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);

        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        let p = file.projects.iter().find(|p| p.name == "proj").unwrap();
        assert_eq!(p.roots(), vec![b.as_str(), c.as_str()]);
        assert_eq!(
            p.hosts,
            vec![ProjectHost { name: "n1".into(), roots: vec!["/srv/n1/proj".into()] }],
            "host membership survives a multi-root local edit"
        );

        let sf: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(
            sf.sessions[0].project.as_deref(),
            Some("proj"),
            "the session's explicit project assignment survives a root edit untouched"
        );

        let _ = std::fs::remove_dir_all(&stage);
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn project_remove_host_drops_membership_but_leaves_local_roots() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR"]);
        let stage = unique_stage("remove-host-membership");
        let state = unique_stage("remove-host-membership-state");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        aoide_storage::node_store::save_nodes(&[synthetic_node("n1")]).unwrap();
        let a = stage.join("a");
        std::fs::create_dir_all(&a).unwrap();
        let a = a.to_string_lossy().into_owned();

        project_add(&project_invocation(&["project", "add"], &["proj", &a], &[]));
        project_add(&project_invocation(
            &["project", "add"],
            &["proj", "/srv/n1/proj"],
            &[("host", "n1")],
        ));

        let out = project_remove(&project_invocation(&["project", "remove"], &["proj"], &[("host", "n1")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);

        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        let p = file.projects.iter().find(|p| p.name == "proj").unwrap();
        assert_eq!(p.path, a, "local roots are untouched");
        assert!(p.hosts.is_empty(), "the whole host membership is dropped: {:?}", p.hosts);

        let _ = std::fs::remove_dir_all(&stage);
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn project_list_json_mirrors_hosts() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR"]);
        let stage = unique_stage("list-mirrors-hosts");
        let state = unique_stage("list-mirrors-hosts-state");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        aoide_storage::node_store::save_nodes(&[synthetic_node("n1")]).unwrap();
        let a = stage.join("a");
        std::fs::create_dir_all(&a).unwrap();
        let a = a.to_string_lossy().into_owned();

        project_add(&project_invocation(&["project", "add"], &["proj", &a], &[]));
        project_add(&project_invocation(
            &["project", "add"],
            &["proj", "/srv/n1/proj"],
            &[("host", "n1")],
        ));

        let out = project_list(&invocation(&["project", "list"], &[]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let rows = out.data.as_ref().unwrap()["projects"].as_array().unwrap();
        let row = rows.iter().find(|r| r["name"] == "proj").unwrap();
        assert_eq!(
            row["hosts"],
            json!([{"name": "n1", "roots": ["/srv/n1/proj"]}]),
            "`data.projects[].hosts` mirrors the stored record: {row}"
        );

        let _ = std::fs::remove_dir_all(&stage);
        let _ = std::fs::remove_dir_all(&state);
    }

    // ── DAEMON-OWNED ATOMIC MUTATIONS: the `with_stage_lock` hold really
    // serializes concurrent local mutators, and a `Door::Cli` caller with
    // no daemon listening really errors instead of silently going local ──

    #[test]
    fn add_roots_new_races_two_threads_for_one_name_exactly_one_wins() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("add-roots-new-race");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let (a, b) = (stage.join("a"), stage.join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let (a, b) = (a.to_string_lossy().into_owned(), b.to_string_lossy().into_owned());

        // Two threads race `add_roots(..., new: true)` for the SAME name
        // with DIFFERENT candidate paths. `add_roots` runs its whole
        // "unregistered?" check and its write inside ONE `with_stage_lock`
        // hold, so only one thread can ever observe the registry as still
        // missing the name — the other's `--new` refusal is a genuine "the
        // world disagreed", never a lost-update race where both threads
        // read empty and both win.
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let (b1, b2) = (barrier.clone(), barrier.clone());
        let t1 = std::thread::spawn(move || {
            b1.wait();
            add_roots("racer", &[a], true, false, None)
        });
        let t2 = std::thread::spawn(move || {
            b2.wait();
            add_roots("racer", &[b], true, false, None)
        });
        let (r1, r2) = (t1.join().unwrap(), t2.join().unwrap());

        let oks = [&r1, &r2]
            .iter()
            .filter(|o| o.status == aoide_protocol::output::Status::Ok)
            .count();
        assert_eq!(oks, 1, "exactly one racer wins `--new` for the same name");
        let errs = [&r1, &r2]
            .iter()
            .filter(|o| o.status == aoide_protocol::output::Status::Error)
            .count();
        assert_eq!(errs, 1, "the other sees a real `exists` refusal, not a silent clobber");

        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        assert_eq!(
            file.projects.iter().filter(|p| p.name == "racer").count(),
            1,
            "exactly one `racer` project ever lands in the registry"
        );

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn add_roots_two_concurrent_calls_add_distinct_roots_both_land() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("add-roots-concurrent-distinct");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let (base, x, y) = (stage.join("base"), stage.join("x"), stage.join("y"));
        for d in [&base, &x, &y] {
            std::fs::create_dir_all(d).unwrap();
        }
        let (base, x, y) = (
            base.to_string_lossy().into_owned(),
            x.to_string_lossy().into_owned(),
            y.to_string_lossy().into_owned(),
        );
        // Register the project up front so both racers hit the existing-
        // project append arm (not the create arm, exercised above).
        assert_eq!(
            add_roots("shared", std::slice::from_ref(&base), false, false, None).status,
            aoide_protocol::output::Status::Ok
        );

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let (b1, b2) = (barrier.clone(), barrier.clone());
        let (xc, yc) = (x.clone(), y.clone());
        let t1 = std::thread::spawn(move || {
            b1.wait();
            add_roots("shared", &[xc], false, false, None)
        });
        let t2 = std::thread::spawn(move || {
            b2.wait();
            add_roots("shared", &[yc], false, false, None)
        });
        let (r1, r2) = (t1.join().unwrap(), t2.join().unwrap());
        assert_eq!(r1.status, aoide_protocol::output::Status::Ok);
        assert_eq!(r2.status, aoide_protocol::output::Status::Ok);

        // `with_stage_lock` serializes the two read-modify-write cycles —
        // without it, whichever thread wrote second would clobber the
        // other's addition (a lost update). Both distinct roots survive.
        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        let p = file.projects.iter().find(|p| p.name == "shared").unwrap();
        assert!(p.roots().contains(&base.as_str()));
        assert!(p.roots().contains(&x.as_str()), "roots: {:?}", p.roots());
        assert!(p.roots().contains(&y.as_str()), "roots: {:?}", p.roots());

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn project_add_via_door_cli_with_no_daemon_errors_and_leaves_the_registry_untouched() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_socket = std::env::var("AOIDE_DAEMON_SOCKET").ok();
        let stage = unique_stage("add-door-cli-no-daemon");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        // A socket path with plainly nothing listening: `connect_bounded`
        // fails fast (100ms bound), `daemon_dispatch` returns `None`, and
        // `local_daemon` turns that into a real error — never a silent
        // fall-through to the local mutation.
        std::env::set_var("AOIDE_DAEMON_SOCKET", stage.join("no-such-daemon.sock"));
        let a = stage.join("a");
        std::fs::create_dir_all(&a).unwrap();
        let a = a.to_string_lossy().into_owned();

        // `invocation` (shared testutil helper) hardcodes `Door::Cli` — the
        // real shape a CLI process's own invocation carries.
        let out = project_add(&invocation(&["project", "add"], &["aoide", &a]));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert!(
            out.message.contains("aoided must be running"),
            "message: {}",
            out.message
        );
        assert!(
            !projects_path().exists(),
            "no daemon reachable: the registry file is never even created"
        );

        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        match saved_socket {
            Some(v) => std::env::set_var("AOIDE_DAEMON_SOCKET", v),
            None => std::env::remove_var("AOIDE_DAEMON_SOCKET"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn a_project_name_with_spaces_survives_add_edit_and_remove() {
        // No name validator beyond what `require_args` already enforces
        // (non-empty); a name with spaces is legal end to end.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("name-with-spaces");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let (a, b) = (stage.join("a"), stage.join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let (a, b) = (a.to_string_lossy().into_owned(), b.to_string_lossy().into_owned());
        let name = "My Project";

        let out = project_add(&daemon_invocation(&["project", "add"], &[name, &a]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        assert!(file.projects.iter().any(|p| p.name == name && p.path == a));

        let out = project_edit(&daemon_invocation(&["project", "edit"], &[name, &b]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        let p = file.projects.iter().find(|p| p.name == name).unwrap();
        assert_eq!(p.path, b);

        let out = project_remove(&daemon_invocation(&["project", "remove"], &[name]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let file: ProjectsFile = load_stage(&projects_path()).unwrap();
        assert!(!file.projects.iter().any(|p| p.name == name));

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
}
