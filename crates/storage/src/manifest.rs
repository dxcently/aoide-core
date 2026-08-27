//! `.aoide/project.json` (v0) — a project's own committed-adjacent SESSION
//! SPECS (command-defrag lane U1, 2026-08-27), so `resurrect` can bring up a
//! project's intended sessions from a bare clone that has never run `aoide`
//! before and so has no `state/undying.json` marks of its own (U2, a later
//! phase, is this module's first consumer).
//!
//! Distinct from [`crate::undying`] in every way that matters: `undying`
//! marks LIVE session IDS durable on ONE host (`state/undying.json`,
//! gitignored runtime state, outside any project); this file lives INSIDE a
//! project root, IS meant to be committed (it lives beside the project, not
//! under `state/`), and names the SHAPE of sessions a project wants — never
//! a session id, never a timestamp, nothing host-specific except each spec's
//! own `host` field. A project can hold both: an `undying` mark survives a
//! session's exit on the host that ran it; a `project.json` spec survives a
//! `git clone` onto a host that has never run anything.
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
/// always — never an absolute path (a manifest is meant to be portable
/// across clones/hosts; an absolute `dir` would only ever be correct on the
/// one host it was written on). No session id, no timestamp: those are
/// exactly the two fields [`crate::undying::UndyingSession`] carries and
/// this type deliberately does not — a spec names WHAT to bring up, not
/// which past invocation it was.
///
/// No `#[serde(deny_unknown_fields)]`, deliberately: a manifest is
/// committed, so it can be read by an older `aoide` build than the one that
/// wrote it. An unrecognized field is silently preserved-by-omission on
/// read (dropped, not round-tripped) rather than refused — the same
/// forward-tolerance every other additive stage/state shape in this crate
/// holds (`records::SessionRecord`'s own additive fields, for one), applied
/// at the whole-struct level instead of field-by-field since this type has
/// no reason to ever grow a `#[serde(default)]` straggler of its own.
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
/// if any [`SessionSpec::dir`] is absolute — a manifest is meant to be
/// portable across clones/hosts, and an absolute `dir` would silently stop
/// being correct the moment it is read on a different checkout.
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
