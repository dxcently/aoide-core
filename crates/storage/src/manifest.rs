//! `.aoide/project.json` (v0) — a project's own SESSION SPECS
//! (command-defrag lane U1, 2026-08-27), so `resurrect` can bring up a
//! project's intended sessions on the host that conducts them (U2, a later
//! phase, is this module's first consumer) — self-sufficient, with no
//! `projects.json` registration required first.
//!
//! Distinct from [`crate::undying`] in every way that matters except one:
//! both are HOST-LOCAL, neither is committed. `undying` marks LIVE session
//! IDS durable on ONE host (`state/undying.json`, gitignored runtime state,
//! outside any project); this file lives INSIDE a project root (beside the
//! project, not under `state/`) and names the SHAPE of sessions a project
//! wants — never a session id, never a timestamp, nothing host-specific
//! except each spec's own `host` field — but it is JUST as host-local:
//! `.aoide/` self-ignores (below), so this file never leaves the host it
//! was written on by way of git. A project can hold both: an `undying`
//! mark and a `project.json` spec each name intent that only ever means
//! anything on the host that wrote it.
//!
//! `.aoide/` self-ignores on first write ([`ensure_self_gitignore`]) — the
//! manifest is a deliberately HOST-LOCAL decision (one focused host owns the
//! shape it wants for a project), not something meant to sync via git the
//! way the project's own source does.

use crate::fs::atomic_write;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// `.aoide/project.json` schema version (CONTRACTS.md, v0).
pub const MANIFEST_VERSION: u32 = 0;

/// One session a project wants brought up. `dir` is PROJECT-RELATIVE,
/// always — never an absolute path: this file is host-local (module doc),
/// but even on the ONE host it lives on, the project directory itself can
/// still move (a re-clone elsewhere, a rename) — a relative `dir` keeps
/// resolving correctly against whatever root `resurrect`'s own `walk_up`
/// finds it beside, where an absolute one would silently stop being
/// correct the moment the project moved even once. No session id, no
/// timestamp: those are exactly the two fields
/// [`crate::undying::UndyingSession`] carries and this type deliberately
/// does not — a spec names WHAT to bring up, not which past invocation it
/// was.
///
/// No `#[serde(deny_unknown_fields)]`, deliberately: a manifest persists on
/// disk indefinitely, host-local, never rewritten wholesale — it must stay
/// readable across an `aoide` upgrade or downgrade on that same host, not
/// only the exact build that wrote it. An unrecognized field is silently
/// preserved-by-omission on read (dropped, not round-tripped) rather than
/// refused — the same forward-tolerance every other additive stage/state
/// shape in this crate holds (`records::SessionRecord`'s own additive
/// fields, for one), applied at the whole-struct level instead of
/// field-by-field since this type has no reason to ever grow a
/// `#[serde(default)]` straggler of its own.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionSpec {
    pub host: String,
    pub dir: String,
    pub agent: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

/// The `.aoide/project.json` container.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    #[serde(default)]
    pub sessions: Vec<SessionSpec>,
}

impl Default for Manifest {
    fn default() -> Self {
        Manifest { version: MANIFEST_VERSION, sessions: Vec::new() }
    }
}

/// The manifest path for a given project root: `<project_root>/.aoide/project.json`.
pub fn manifest_path(project_root: &Path) -> PathBuf {
    project_root.join(".aoide").join("project.json")
}

/// Read `<project_root>/.aoide/project.json`. A MISSING file is `None`,
/// silently — the ordinary case for a project that has never declared
/// session specs. An UNREADABLE or malformed file (present but the read or
/// the parse fails) is narrated to stderr and THEN treated as `None` — the
/// caller still gets a clean "nothing declared" rather than a second error
/// type to handle, but the operator learns something is wrong rather than
/// silently losing their specs the way a routine "file doesn't exist yet"
/// should never announce itself.
pub fn load_manifest(project_root: &Path) -> Option<Manifest> {
    let path = manifest_path(project_root);
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            eprintln!("aoide: cannot read {} ({e}) — treating as no project manifest", path.display());
            return None;
        }
    };
    match serde_json::from_str::<Manifest>(&raw) {
        Ok(m) => Some(m),
        Err(e) => {
            eprintln!(
                "aoide: {} is not a valid project manifest ({e}) — treating as no project manifest",
                path.display()
            );
            None
        }
    }
}

/// Ensure `<dir>/.gitignore` exists containing `*\n` — `.aoide/` self-ignores
/// on first write into a project root, since the manifest is a host-local
/// decision, not something meant to sync via git the way the project's own
/// source does. NEVER overwrites an existing `.gitignore` there: an operator
/// who already customized it (or committed the directory on purpose,
/// overriding the default) keeps whatever they wrote.
fn ensure_self_gitignore(aoide_dir: &Path) -> Result<(), String> {
    let path = aoide_dir.join(".gitignore");
    if path.exists() {
        return Ok(());
    }
    atomic_write(&path, "*\n").map_err(|e| format!("{}: {e}", path.display()))
}

/// Atomic-write `manifest` to `<project_root>/.aoide/project.json`, creating
/// `.aoide/` (and its self-ignoring `.gitignore`, see
/// [`ensure_self_gitignore`]) on first use. Refuses BEFORE writing anything
/// if any [`SessionSpec::dir`] is absolute — this file is host-local (module
/// doc), but the project directory it sits beside can still move on that
/// same host (a re-clone elsewhere, a rename), and an absolute `dir` would
/// silently stop being correct the moment it did.
pub fn save_manifest(project_root: &Path, manifest: &Manifest) -> Result<(), String> {
    for spec in &manifest.sessions {
        if Path::new(&spec.dir).is_absolute() {
            return Err(format!(
                "session spec for host `{}` names an absolute dir (`{}`) — \
                 project.json's `dir` must be PROJECT-RELATIVE, never absolute",
                spec.host, spec.dir
            ));
        }
    }

    let aoide_dir = project_root.join(".aoide");
    std::fs::create_dir_all(&aoide_dir).map_err(|e| format!("{}: {e}", aoide_dir.display()))?;
    ensure_self_gitignore(&aoide_dir)?;

    let body = serde_json::to_string_pretty(manifest)
        .map_err(|e| format!("serialize project.json: {e}"))?
        + "\n";
    let path = manifest_path(project_root);
    atomic_write(&path, &body).map_err(|e| format!("{}: {e}", path.display()))
}

/// Walk from `start` up through every parent directory, git-style, looking
/// for the nearest `.aoide/project.json` — stops at the filesystem root.
/// Pure with respect to everything except the filesystem itself: no env var,
/// no `state_dir`/`stage_dir` indirection, just the path handed in (and
/// `$PWD` only when `start` is relative) — so a test points it straight at
/// a scratch tree with no ambient state to isolate.
///
/// The FIRST `.aoide/project.json` found (nearest wins, same as git finding
/// the nearest `.git`) is the one loaded — a directory further up is never
/// consulted even if the nearest one turns out to be unreadable
/// ([`load_manifest`] already narrates that case); this never silently
/// falls through to a grandparent's manifest instead.
///
/// LEXICAL, not realpath: each step is a bare `Path::parent()`, never a
/// `readlink`/`canonicalize` call. The per-level existence check
/// (`manifest_path(&dir).is_file()`) still follows a symlinked directory
/// component transparently (ordinary `stat` semantics), so a manifest
/// reachable through one is still found — what does NOT happen is
/// resuming the walk from a symlink's TARGET's own real ancestry once
/// past it; the walk continues from the path exactly as spelled, the same
/// way a shell's logical `..` does after `cd`-ing through a symlink.
pub fn walk_up(start: &Path) -> Option<(PathBuf, Manifest)> {
    let mut dir = if start.is_absolute() {
        start.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(start)
    };
    loop {
        if manifest_path(&dir).is_file() {
            return load_manifest(&dir).map(|m| (dir, m));
        }
        dir = dir.parent()?.to_path_buf();
    }
}

/// Join a spec's own `dir` onto `project_root` and normalize the result
/// LEXICALLY — no filesystem access, so this resolves correctly even before
/// the directory exists (a manifest names sessions to bring UP, which may
/// not have run yet). Refuses, rather than silently clamping, any `dir`
/// that would resolve outside `project_root` after normalization — a
/// `..`-laden spec must never escape the project root it was declared in,
/// whatever a bare lexical join might otherwise compute. `resurrect`'s
/// (U2, command-defrag lane U) spec-selection is this guard's first caller.
///
/// Tracks how many real (`Normal`) components have been pushed past
/// `project_root` so a `ParentDir` can only ever pop back down to the root,
/// never through it: a `..` while that count is already zero is refused
/// outright rather than popping `project_root` itself. `CurDir` (`.`) is a
/// no-op; an absolute `dir` (a `RootDir`/`Prefix` component) is refused the
/// same way [`save_manifest`] already refuses one at write time — this is
/// the read-time twin of that same invariant, needed because a manifest can
/// be hand-edited or written by a future version this build has never
/// validated.
///
/// **Lexical, not a filesystem guarantee (U2 review round 1).** This is a
/// STRING check on `dir` — it never touches disk, so it has no opinion
/// about what a clean-looking (no `..`) `dir` might resolve THROUGH at USE
/// time: a symlink somewhere inside the project pointing outside it still
/// escapes, undetected here, the moment a caller actually opens/execs the
/// returned path. Accepted, not a gap this function is meant to close —
/// the manifest's whole trust model is host-local and operator-authored,
/// so the operator who wrote the spec already controls what's on their own
/// disk, symlinks included.
pub fn resolve_spec_dir(project_root: &Path, dir: &str) -> Result<PathBuf, String> {
    use std::path::Component;

    let mut resolved = project_root.to_path_buf();
    let mut depth: usize = 0;
    for component in Path::new(dir).components() {
        match component {
            Component::CurDir => {}
            Component::Normal(seg) => {
                resolved.push(seg);
                depth += 1;
            }
            Component::ParentDir => {
                if depth == 0 {
                    return Err(format!(
                        "session spec dir `{dir}` escapes the project root `{}` — rejected",
                        project_root.display()
                    ));
                }
                resolved.pop();
                depth -= 1;
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "session spec dir `{dir}` is absolute — project.json's `dir` must be PROJECT-RELATIVE"
                ));
            }
        }
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("aoide-manifest-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn spec(host: &str, dir: &str, agent: &str) -> SessionSpec {
        SessionSpec { host: host.to_string(), dir: dir.to_string(), agent: agent.to_string(), command: None }
    }

    #[test]
    fn save_load_round_trip_through_a_temp_project_root() {
        let root = temp_dir("roundtrip");

        assert!(load_manifest(&root).is_none(), "a project with no manifest yet reads as None");

        let manifest = Manifest {
            version: MANIFEST_VERSION,
            sessions: vec![spec("yomi", ".", "claude"), spec("dxflake", "crates/aoide", "codex")],
        };
        save_manifest(&root, &manifest).unwrap();

        let loaded = load_manifest(&root).expect("a saved manifest must load back");
        assert_eq!(loaded, manifest);

        let raw = std::fs::read_to_string(manifest_path(&root)).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["version"], 0);
        assert_eq!(v["sessions"].as_array().unwrap().len(), 2);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_command_field_is_omitted_from_the_wire_when_none_and_present_when_some() {
        let root = temp_dir("skip-none");

        let manifest = Manifest {
            version: MANIFEST_VERSION,
            sessions: vec![
                spec("yomi", ".", "claude"),
                SessionSpec {
                    host: "yomi".to_string(),
                    dir: "tools".to_string(),
                    agent: "shell".to_string(),
                    command: Some("watch -n1 cargo check".to_string()),
                },
            ],
        };
        save_manifest(&root, &manifest).unwrap();

        let raw = std::fs::read_to_string(manifest_path(&root)).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert!(v["sessions"][0].get("command").is_none(), "a None command must be absent, not null: {v}");
        assert_eq!(v["sessions"][1]["command"], "watch -n1 cargo check");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn load_manifest_tolerates_a_corrupt_file_as_none() {
        let root = temp_dir("corrupt");
        std::fs::create_dir_all(root.join(".aoide")).unwrap();
        std::fs::write(manifest_path(&root), "{ not json at all").unwrap();

        assert!(load_manifest(&root).is_none());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn load_manifest_tolerates_the_wrong_shape_as_none() {
        let root = temp_dir("wrong-shape");
        std::fs::create_dir_all(root.join(".aoide")).unwrap();
        std::fs::write(manifest_path(&root), r#"{"version":0,"sessions":{}}"#).unwrap();

        assert!(load_manifest(&root).is_none());

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Unknown-field tolerance: a manifest written by a NEWER `aoide` with an
    /// extra top-level or per-spec field must still parse cleanly on this
    /// build — no `#[serde(deny_unknown_fields)]` anywhere in this module.
    #[test]
    fn an_unknown_field_at_either_level_is_tolerated_not_refused() {
        let root = temp_dir("unknown-field");
        std::fs::create_dir_all(root.join(".aoide")).unwrap();
        std::fs::write(
            manifest_path(&root),
            r#"{
                "version": 0,
                "futureTopLevelField": "ignored",
                "sessions": [
                    { "host": "yomi", "dir": ".", "agent": "claude", "futurePerSpecField": 42 }
                ]
            }"#,
        )
        .unwrap();

        let loaded = load_manifest(&root).expect("an unknown field must not refuse the whole file");
        assert_eq!(loaded.sessions.len(), 1);
        assert_eq!(loaded.sessions[0].host, "yomi");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The taught-error proof: an absolute `dir` in any spec refuses the
    /// WHOLE save, before anything touches disk — never a partial write.
    #[test]
    fn save_manifest_rejects_an_absolute_dir_with_a_taught_error_before_writing_anything() {
        let root = temp_dir("absolute-dir");

        let manifest = Manifest {
            version: MANIFEST_VERSION,
            sessions: vec![spec("yomi", "/etc/not/relative", "claude")],
        };
        let err = save_manifest(&root, &manifest).expect_err("an absolute dir must be refused");
        assert!(err.contains("yomi"), "error must name the offending host: {err}");
        assert!(err.contains("PROJECT-RELATIVE") || err.contains("absolute"), "error must teach: {err}");
        assert!(!manifest_path(&root).exists(), "a rejected save must not have written anything");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn first_save_creates_a_self_ignoring_gitignore_exactly_once() {
        let root = temp_dir("self-gitignore");

        save_manifest(&root, &Manifest::default()).unwrap();
        let gitignore = root.join(".aoide").join(".gitignore");
        assert_eq!(std::fs::read_to_string(&gitignore).unwrap(), "*\n");

        // An operator customization survives a second save untouched.
        std::fs::write(&gitignore, "*\n!keep-me.json\n").unwrap();
        save_manifest(
            &root,
            &Manifest { version: MANIFEST_VERSION, sessions: vec![spec("yomi", ".", "claude")] },
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(&gitignore).unwrap(),
            "*\n!keep-me.json\n",
            "an existing .gitignore must never be overwritten"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn walk_up_finds_the_manifest_from_a_deeply_nested_directory() {
        let root = temp_dir("walk-up");
        save_manifest(&root, &Manifest { version: MANIFEST_VERSION, sessions: vec![spec("yomi", ".", "claude")] })
            .unwrap();

        let nested = root.join("a").join("b").join("c");
        std::fs::create_dir_all(&nested).unwrap();

        let (found_root, manifest) = walk_up(&nested).expect("must find the manifest walking up");
        assert_eq!(found_root, root);
        assert_eq!(manifest.sessions[0].host, "yomi");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn walk_up_prefers_the_nearest_manifest_over_an_ancestors() {
        let root = temp_dir("walk-up-nearest");
        save_manifest(&root, &Manifest { version: MANIFEST_VERSION, sessions: vec![spec("far", ".", "claude")] })
            .unwrap();

        let nested = root.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        save_manifest(
            &nested,
            &Manifest { version: MANIFEST_VERSION, sessions: vec![spec("near", ".", "codex")] },
        )
        .unwrap();

        let deeper = nested.join("deeper");
        std::fs::create_dir_all(&deeper).unwrap();

        let (found_root, manifest) = walk_up(&deeper).unwrap();
        assert_eq!(found_root, nested, "the nearer manifest must win, not the ancestor's");
        assert_eq!(manifest.sessions[0].host, "near");

        let _ = std::fs::remove_dir_all(&root);
    }

    // ── `resolve_spec_dir`: the containment guard ────────────────────────

    #[test]
    fn resolve_spec_dir_joins_an_ordinary_relative_dir() {
        let root = PathBuf::from("/home/khoa/Aoide");
        assert_eq!(
            resolve_spec_dir(&root, "crates/aoide").unwrap(),
            root.join("crates/aoide")
        );
    }

    #[test]
    fn resolve_spec_dir_dot_resolves_to_the_root_itself() {
        let root = PathBuf::from("/home/khoa/Aoide");
        assert_eq!(resolve_spec_dir(&root, ".").unwrap(), root);
    }

    #[test]
    fn resolve_spec_dir_a_parent_segment_that_stays_inside_the_root_resolves() {
        let root = PathBuf::from("/home/khoa/Aoide");
        // a/../b nets out to <root>/b — never leaves the root at any point
        // a real filesystem walk would take, so the lexical guard allows it.
        assert_eq!(resolve_spec_dir(&root, "a/../b").unwrap(), root.join("b"));
    }

    #[test]
    fn resolve_spec_dir_rejects_a_leading_escape() {
        let root = PathBuf::from("/home/khoa/Aoide");
        let err = resolve_spec_dir(&root, "../escape").expect_err("a leading .. must escape and be refused");
        assert!(err.contains("escapes"), "error must teach: {err}");
    }

    #[test]
    fn resolve_spec_dir_rejects_an_escape_buried_past_a_deeper_prefix() {
        let root = PathBuf::from("/home/khoa/Aoide");
        // One real component pushed (a), then two `..` — the second pops
        // past the root, not just back to it.
        let err = resolve_spec_dir(&root, "a/../../escape")
            .expect_err("a dir that pops past the root after a deeper prefix must be refused");
        assert!(err.contains("escapes"), "error must teach: {err}");
    }

    #[test]
    fn resolve_spec_dir_rejects_an_absolute_dir() {
        let root = PathBuf::from("/home/khoa/Aoide");
        let err = resolve_spec_dir(&root, "/etc/passwd").expect_err("an absolute dir must be refused");
        assert!(err.contains("PROJECT-RELATIVE") || err.contains("absolute"), "error must teach: {err}");
    }

    /// The lexical-not-realpath note, proven: a manifest at `root/real`
    /// reached through a symlink `root/link -> root/real` is still found
    /// (the `is_file` check follows the symlink), and the returned root is
    /// the AS-WALKED `root/link`, never a `canonicalize`d `root/real` — the
    /// walk never resolves the symlink to keep climbing from its target.
    #[test]
    fn walk_up_finds_a_manifest_through_a_symlinked_directory_without_resolving_it() {
        let root = temp_dir("walk-up-symlink");
        let real = root.join("real");
        std::fs::create_dir_all(&real).unwrap();
        save_manifest(&real, &Manifest { version: MANIFEST_VERSION, sessions: vec![spec("yomi", ".", "claude")] })
            .unwrap();

        let link = root.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let nested = link.join("nested");
        std::fs::create_dir_all(&nested).unwrap();

        let (found_root, manifest) = walk_up(&nested).expect("must find the manifest through the symlink");
        assert_eq!(found_root, link, "the walk returns the AS-WALKED path, never a resolved realpath");
        assert_eq!(manifest.sessions[0].host, "yomi");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn walk_up_returns_none_when_no_manifest_exists_anywhere_above() {
        let root = temp_dir("walk-up-none");
        let nested = root.join("x").join("y");
        std::fs::create_dir_all(&nested).unwrap();

        // No manifest anywhere under `root` — walk_up must eventually give up
        // rather than loop forever or panic. (It will walk all the way to
        // the real filesystem root from here, which is fine — every real
        // ancestor of a fresh temp dir is guaranteed manifest-free.)
        assert!(walk_up(&nested).is_none());

        let _ = std::fs::remove_dir_all(&root);
    }
}
