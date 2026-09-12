//! Stage-file record shapes, stage I/O, and the pure DAG-shaping derivations
//! every other `graph` submodule builds on (CONTRACTS.md §4 shapes).
//!
//! The record shapes (`Project`, `SessionRecord`, `HookRecord`,
//! `ProjectsFile`, `SessionsFile`, `HooksFile`, `STAGE_GRAPH_VERSION`) and the
//! stage I/O (`load_stage`, `write_stage`, `projects_path`, `sessions_path`,
//! `hooks_path`, `graph_path`) moved to `aoide-storage` (Phase 3a restructure,
//! docs/architecture/PACKAGE-LAYOUT.md); re-exported below so every existing
//! `crate::graph::{Project, SessionRecord, load_stage, sessions_path, …}`
//! caller is untouched. The DAG-shaping derivations below (`cwd_under`,
//! `anchor_for`, `merged_sessions`, `sorted_projects`, `resolved_parent`) stay
//! here — they're conduct's charter and move in Phase 3b.

use std::collections::{BTreeMap, HashSet};

/// Record shapes — originally plain `pub struct`s/`pub const` here, so a glob
/// re-export preserves the exact original (fully public) visibility.
pub use aoide_storage::records::*;

/// Stage I/O — `projects_path`/`graph_path` were `pub(in crate::graph)` and
/// `sessions_path`/`hooks_path`/`load_stage`/`write_stage` were `pub(crate)`
/// here (root-crate-scoped, pre-Phase-3b); narrowed re-exports (rather than a
/// glob) preserve that exact split. `hooks_path` stays `pub(crate)` — only
/// this crate's own `reap.rs` reaches it. `load_stage`/`sessions_path`/
/// `write_stage` widen to `pub` (Phase 3b): they now cross the
/// aoide-conduct → aoide crate boundary too, since root's `a2a.rs` and
/// `commands/{a2a,usage}.rs` still call `crate::graph::{load_stage,
/// sessions_path, write_stage}` there — root's own shim re-narrows them back
/// to `pub(crate)` to match the original root-facing visibility.
pub(in crate::graph) use aoide_storage::stage::{graph_path, projects_path};
pub(crate) use aoide_storage::stage::hooks_path;
pub use aoide_storage::stage::{load_stage, sessions_path, write_stage};

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

/// Explicit membership takes precedence over automatic cwd anchoring.
pub fn project_for(session: &SessionRecord, projects: &[Project]) -> Option<usize> {
    session.project.as_ref().map_or_else(|| anchor_for(&session.cwd, projects), |name| projects.iter().position(|p| &p.name == name))
}

/// The project a session RENDERS under: own explicit project > owner's
/// effective project > own cwd anchor. Derived, never stored — see
/// `CONTRACTS.md`'s stored-vs-effective distinction.
/// An explicit `session.project` is never overridden — resolved or not
/// (unregistered stops the walk right here, exactly [`project_for`]'s own
/// behavior). Otherwise walks `parent_session_id` upward; the first
/// ancestor whose OWN [`project_for`] resolves (explicit name or its own
/// cwd anchor) wins — iterative, never a recursive re-entry into this
/// function. Walk shape copied from `doorbell.rs`'s `conducted_ancestor` /
/// `window.rs`'s `windowless_by_lineage_from_parent`: `HashSet` cycle guard,
/// a dangling or cyclic `parentSessionId` (or an exhausted chain) falls to
/// [`anchor_for`] on the SUBJECT's own cwd, bounded at 32 hops
/// (`actions.rs`'s `kill_target` walk).
pub fn effective_project_for(
    session: &SessionRecord,
    sessions: &[SessionRecord],
    projects: &[Project],
) -> Option<usize> {
    if session.project.is_some() {
        return project_for(session, projects);
    }
    let mut seen: HashSet<&str> = HashSet::new();
    seen.insert(session.session_id.as_str());
    let mut parent_id = session.parent_session_id.as_deref();
    for _ in 0..32 {
        let Some(pid) = parent_id else { break };
        if !seen.insert(pid) {
            break; // cycle guard
        }
        let Some(parent) = sessions.iter().find(|s| s.session_id == pid) else {
            break; // dangling parent link
        };
        if let Some(idx) = project_for(parent, projects) {
            return Some(idx);
        }
        parent_id = parent.parent_session_id.as_deref();
    }
    anchor_for(&session.cwd, projects)
}

/// The anchoring project for a cwd: the longest matching root wins across
/// EVERY root of EVERY project, so nested projects and a project's own
/// second root anchor correctly. Returns an index into `projects`.
pub fn anchor_for(cwd: &str, projects: &[Project]) -> Option<usize> {
    projects
        .iter()
        .enumerate()
        .filter_map(|(i, p)| {
            p.roots()
                .into_iter()
                .filter(|r| cwd_under(cwd, r))
                .map(|r| r.trim_end_matches('/').len())
                .max()
                .map(|len| (i, len))
        })
        .max_by_key(|(_, len)| *len)
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
    // Every producer's vocab is folded to the ONE canonical set the desktop
    // renders — so graph.json (conductor) and sessions.json (widgets) agree even for
    // an un-migrated legacy record.
    for s in &mut merged {
        s.state = canonical_state(&s.state).to_string();
    }
    // Deterministic ordering everywhere downstream: (startedAt, sessionId).
    merged.sort_by(|a, b| {
        (a.started_at.as_str(), a.session_id.as_str())
            .cmp(&(b.started_at.as_str(), b.session_id.as_str()))
    });
    merged
}

/// The canonical session-state vocabulary the desktop renders VERBATIM — no
/// widget-side regex derivation (that split-brain is what this replaces). Every
/// producer (hooks, `conduct`, the reaper) writes one of these onto
/// `sessions.json`; this shim also folds the legacy / hook-phase vocab
/// (`running`/`waiting`/`blocked`) onto it, so an old record is migrated the
/// first time any writer touches the file — no rollout dance.
///
///   working  — in a turn / running a tool (or a shell running a foreground cmd)
///   awaiting — needs the user (a permission prompt or the idle-input ping); the
///              dock peeks on this and only this (`needsInput ⇔ awaiting`)
///   stopped  — the turn ENDED and the agent is sitting at the prompt, RECENTLY.
///              Alive and warm: the natural face of a session you just finished
///              talking to. Ages out to `idle` after
///              [`crate::reap::STOPPED_IDLE_AFTER_SECS`] in the reaper pass.
///   idle     — at rest and COLD: stopped for more than an hour, or freshly
///              created / resumed and not yet active (a bare shell prompt too)
///   done     — the session ENDED (SessionEnd / a reap). Never `stopped`.
///
/// `stop`/`stopped` map to `stopped`, NOT `done`: the only producer that ever
/// writes either token is a Stop-hook adapter (`graph session phase --phase
/// stop`, the shape `entities/Agent-Hooking` documents for a foreign harness),
/// and the Stop hook means "the turn ended", not "the process exited". Real
/// termination arrives as `SessionEnd` (→ `do_session_end`, which writes `done`
/// directly and never routes through this shim) or as the explicit
/// `exit`/`finished`/`complete` vocabulary below.
///
/// Moved to `aoide-protocol` (Phase 2 restructure,
/// docs/architecture/PACKAGE-LAYOUT.md); re-exported here so `graph.rs`'s
/// existing `pub use self::model::{…canonical_state…}` keeps re-exporting it
/// onward untouched (`crate::graph::canonical_state` + all its callers).
pub use aoide_protocol::canonical_state;

pub(in crate::graph) fn sorted_projects(projects: &[Project]) -> Vec<Project> {
    let mut p = projects.to_vec();
    p.sort_by(|a, b| a.name.cmp(&b.name));
    p
}

/// Does the child's parent resolve to a registered session? (a dangling
/// `parentSessionId` falls back to project anchoring).
pub(in crate::graph) fn resolved_parent<'a>(
    s: &SessionRecord,
    ids: &HashSet<&'a str>,
) -> Option<String> {
    s.parent_session_id
        .as_deref()
        .filter(|p| ids.contains(p))
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::testutil::*;

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
    fn anchoring_spans_every_root_of_one_project() {
        let p = vec![Project {
            name: "aoide".into(),
            path: "/home/k/Aoide".into(),
            roots: vec!["/srv/docs".into()],
            ..Default::default()
        }];
        assert_eq!(
            anchor_for("/srv/docs/x", &p).map(|i| p[i].name.as_str()),
            Some("aoide"),
            "a session under the SECOND root anchors too"
        );
        assert_eq!(anchor_for("/srv/other", &p), None);
    }
    #[test]
    fn anchoring_longest_root_wins_across_projects() {
        let p = vec![
            Project {
                name: "outer".into(),
                path: "/home/k/Aoide".into(),
                roots: vec!["/srv/x".into()],
                ..Default::default()
            },
            Project {
                name: "inner".into(),
                path: "/srv/x/deep".into(),
                ..Default::default()
            },
        ];
        assert_eq!(
            anchor_for("/srv/x/deep/y", &p).map(|i| p[i].name.as_str()),
            Some("inner"),
            "the deeper root — even though it belongs to the second project — wins"
        );
        assert_eq!(
            anchor_for("/srv/x/other", &p).map(|i| p[i].name.as_str()),
            Some("outer")
        );
    }
    #[test]
    fn canonical_state_folds_every_producer_onto_the_five_state_vocabulary() {
        // The five canonical outputs, each reached by its own name.
        assert_eq!(canonical_state("working"), "working");
        assert_eq!(canonical_state("awaiting"), "awaiting");
        assert_eq!(canonical_state("stopped"), "stopped");
        assert_eq!(canonical_state("idle"), "idle");
        assert_eq!(canonical_state("done"), "done");

        // `stopped` is FIRST-CLASS, not an alias of `done`: the Stop hook ends a
        // TURN. Both spellings a Stop-hook adapter might write land there.
        assert_eq!(canonical_state("stopped"), "stopped");
        assert_eq!(canonical_state("stop"), "stopped");
        assert_eq!(canonical_state(" Stopped "), "stopped");
        assert_ne!(canonical_state("stopped"), "done");

        // Real termination keeps its own vocabulary.
        for ended in ["done", "exit", "finished", "complete"] {
            assert_eq!(canonical_state(ended), "done", "{ended}");
        }
        // Legacy vocab still migrates in passing.
        assert_eq!(canonical_state("running"), "working");
        assert_eq!(canonical_state("blocked"), "awaiting");
        assert_eq!(canonical_state("waiting"), "idle");
        // Empty/unknown never invents a signal — it rests, cold.
        assert_eq!(canonical_state(""), "idle");
        assert_eq!(canonical_state("mystery"), "idle");
    }

    // ── effective_project_for: rung 2 (owner walk) above rung 3 (own cwd) ──

    fn named_project(name: &str, path: &str) -> Project {
        Project { name: name.into(), path: path.into(), ..Default::default() }
    }

    #[test]
    fn effective_project_inherits_a_parent_project_from_outside_the_cwd_anchor() {
        let projects = vec![named_project("aoide", "/home/k/Aoide")];
        let root = SessionRecord { project: Some("aoide".into()), ..session("s-root", "/home/k/Aoide", "working", "1", None) };
        let child = session("s-child", "/tmp/elsewhere", "working", "2", Some("s-root"));
        let sessions = vec![root, child.clone()];
        assert_eq!(
            effective_project_for(&child, &sessions, &projects).map(|i| projects[i].name.as_str()),
            Some("aoide"),
            "the child's cwd anchors nowhere, but its owner's explicit project wins"
        );
    }

    #[test]
    fn effective_project_walks_nested_children_with_no_cwd_anchor() {
        let projects = vec![named_project("aoide", "/home/k/Aoide")];
        let root = SessionRecord { project: Some("aoide".into()), ..session("s-root", "/home/k/Aoide", "working", "1", None) };
        let mid = session("s-mid", "/tmp/elsewhere", "working", "2", Some("s-root"));
        let leaf = session("s-leaf", "/tmp/elsewhere-still", "working", "3", Some("s-mid"));
        let sessions = vec![root, mid, leaf.clone()];
        assert_eq!(
            effective_project_for(&leaf, &sessions, &projects).map(|i| projects[i].name.as_str()),
            Some("aoide"),
            "two hops up the chain, past a middle ancestor with no attribution of its own"
        );
    }

    #[test]
    fn an_explicit_child_project_beats_the_parents() {
        let projects = vec![named_project("aoide", "/home/k/Aoide"), named_project("other", "/home/k/Other")];
        let root = SessionRecord { project: Some("aoide".into()), ..session("s-root", "/home/k/Aoide", "working", "1", None) };
        let child = SessionRecord { project: Some("other".into()), ..session("s-child", "/tmp/elsewhere", "working", "2", Some("s-root")) };
        let sessions = vec![root, child.clone()];
        assert_eq!(
            effective_project_for(&child, &sessions, &projects).map(|i| projects[i].name.as_str()),
            Some("other"),
            "an explicit choice is never overridden by the owner"
        );
    }

    #[test]
    fn clearing_a_child_project_resumes_inheritance() {
        let projects = vec![named_project("aoide", "/home/k/Aoide"), named_project("other", "/home/k/Other")];
        let root = SessionRecord { project: Some("aoide".into()), ..session("s-root", "/home/k/Aoide", "working", "1", None) };
        let explicit_child = SessionRecord { project: Some("other".into()), ..session("s-child", "/tmp/elsewhere", "working", "2", Some("s-root")) };
        let cleared_child = SessionRecord { project: None, ..explicit_child.clone() };
        let sessions = vec![root, cleared_child.clone()];
        assert_eq!(
            effective_project_for(&explicit_child, &sessions, &projects).map(|i| projects[i].name.as_str()),
            Some("other"),
            "sanity: the explicit record still resolves to its own choice"
        );
        assert_eq!(
            effective_project_for(&cleared_child, &sessions, &projects).map(|i| projects[i].name.as_str()),
            Some("aoide"),
            "--clear drops the explicit name, resuming inheritance from the owner"
        );
    }

    #[test]
    fn reassigning_the_parent_moves_the_whole_subtree() {
        let projects = vec![named_project("aoide", "/home/k/Aoide"), named_project("other", "/home/k/Other")];
        let child = session("s-child", "/tmp/elsewhere", "working", "2", Some("s-root"));

        let root_aoide = SessionRecord { project: Some("aoide".into()), ..session("s-root", "/home/k/Aoide", "working", "1", None) };
        let sessions_aoide = vec![root_aoide, child.clone()];
        assert_eq!(
            effective_project_for(&child, &sessions_aoide, &projects).map(|i| projects[i].name.as_str()),
            Some("aoide")
        );

        let root_other = SessionRecord { project: Some("other".into()), ..session("s-root", "/home/k/Aoide", "working", "1", None) };
        let sessions_other = vec![root_other, child.clone()];
        assert_eq!(
            effective_project_for(&child, &sessions_other, &projects).map(|i| projects[i].name.as_str()),
            Some("other"),
            "reassigning the parent's project moves every descendant that inherits it"
        );
    }

    #[test]
    fn a_missing_parent_falls_back_to_the_cwd_anchor() {
        let projects = vec![named_project("aoide", "/home/k/Aoide")];
        let child = session("s-child", "/home/k/Aoide/sub", "working", "1", Some("s-ghost"));
        let sessions = vec![child.clone()]; // s-ghost is not registered anywhere
        assert_eq!(
            effective_project_for(&child, &sessions, &projects).map(|i| projects[i].name.as_str()),
            Some("aoide"),
            "a dangling parent link ends the walk; the subject's own cwd still anchors"
        );
    }

    #[test]
    fn a_parent_cycle_falls_back_to_the_cwd_anchor() {
        let projects = vec![named_project("aoide", "/home/k/Aoide")];
        let a = session("s-a", "/home/k/Aoide/sub", "working", "1", Some("s-b"));
        let b = session("s-b", "/tmp/elsewhere", "working", "2", Some("s-a"));
        let sessions = vec![a.clone(), b];
        assert_eq!(
            effective_project_for(&a, &sessions, &projects).map(|i| projects[i].name.as_str()),
            Some("aoide"),
            "a parent cycle is cut short by the seen-set guard, falling to the subject's own cwd"
        );
    }

    #[test]
    fn an_explicit_unregistered_project_resolves_to_no_group() {
        let projects = vec![named_project("aoide", "/home/k/Aoide")];
        let sess = SessionRecord { project: Some("ghost-project".into()), ..session("s-solo", "/home/k/Aoide/sub", "working", "1", None) };
        assert_eq!(
            effective_project_for(&sess, std::slice::from_ref(&sess), &projects),
            None,
            "an explicit but unregistered name stops the walk; it never falls through to the cwd anchor"
        );
    }
}
