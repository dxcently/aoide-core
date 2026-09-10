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
}
