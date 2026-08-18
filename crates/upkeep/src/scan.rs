//! The three git/filesystem-sourced checks (C1–C3, soundcheck design doc
//! §3.2) — every one decides a boolean from a source that already exists;
//! none of them invents a canonical layout (the User's binding correction:
//! "truth in the place it is today is fine, it doesn't need to be hard
//! coded"). `checks.fmt`/`checks.lint`/`checks.discovery` (`lib/checks.nix`)
//! own the equivalent COMMITTED-tree checks; nix cannot see what these three
//! read (`.gitignore` collapses everything gitignored out of its git-filtered
//! source, full stop), so there is no overlap to reconcile.
//!
//! | id | class            | source of truth                                            |
//! |----|------------------|-------------------------------------------------------------|
//! | C1 | `unrecognized`   | `git status --porcelain`, root-scoped                        |
//! | C2 | `orphan-tracked` | `git ls-files --cached --ignored --exclude-standard`        |
//! | C3 | `clutter`        | the filesystem (`readlink`) — a root symlink into the store |
//!
//! `fmt`/`lint`/`tool-missing` (C4–C6) land in a later step; this module's
//! only job is the three classes above.

use serde::Serialize;
use std::path::Path;

/// One `soundcheck` finding. Five fields carry the whole contract (design
/// doc §4): `id` is stable across runs (never an ordinal — an agent can cite
/// it), `assertedAt` names WHERE the cited rule already lives so a reader can
/// go check it rather than trust this tool, and `action` is a concrete
/// command or one-sentence instruction — never a promise that `soundcheck`
/// will do it itself (report-only, forever).
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: String,
    pub check: &'static str,
    pub severity: Severity,
    pub path: String,
    pub rule: &'static str,
    #[serde(rename = "assertedAt")]
    pub asserted_at: String,
    pub detail: String,
    pub action: String,
}

/// `error` fails the run (`aoide soundcheck && …` breaks); `info` never
/// does — a build symlink must not break an agent's `&&` chain (design doc
/// §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Info,
}

/// Turn a repo-relative path into the id-safe slug stable ids are built
/// from: every `/` and `.` becomes `-`, nothing else changes — `lib/checks.nix`
/// slugs to `lib-checks-nix`; `result-1` (no separators to begin with) slugs
/// to itself unchanged. `<check>:<slug>` is collision-free for every check in
/// THIS module: C1/C2/C3 can each fire at most once per path (there is no
/// second tool that could double-report the same file the way `deadnix` and
/// `statix` both can — the stricter "one per (class, TOOL, file)" rule binds
/// `lint`'s ids later, design doc defect 4).
fn slug(path: &str) -> String {
    path.chars()
        .map(|c| if c == '/' || c == '.' { '-' } else { c })
        .collect()
}

/// Run `git -C <root> <args>`, returning its stdout on a clean exit and
/// `None` on ANY failure — git absent from `PATH`, `root` not a git repo (a
/// tarball checkout), a permissions error. Every caller in this module
/// degrades to "this check found nothing" rather than propagating the
/// failure, so a git-less environment never panics `aoide soundcheck` — it
/// just can't see C1/C2, which are git-sourced by construction. `commands`'s
/// tests cover this path explicitly.
fn run_git(root: &Path, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

// ── C1: unrecognized ─────────────────────────────────────────────────────

/// A repo-ROOT entry that is neither tracked by git nor matched by
/// `.gitignore`. Source: `git status --porcelain` — git's own answer; plain
/// `status` never lists an ignored entry at all, so every `??` line here is
/// already "untracked AND unignored" by construction.
///
/// Deliberately the DEFAULT `-unormal` mode, not `-uall` (verified live,
/// not assumed): `-unormal` shows an untracked file nested inside an
/// ALREADY-TRACKED directory by its own full path (`modules/brandnew.md`,
/// `modules/nucleus/untracked-new.nix`) but COLLAPSES a wholly-untracked
/// directory to one line (`newdir/`) rather than recursing into it —
/// exactly the split C1 needs, for free, with no directory-walking of our
/// own. `-uall` throws that collapse away and recurses into `newdir/` too,
/// which would make a brand-new root directory invisible to the
/// "no `/` in the path" filter below (an earlier draft of this check used
/// `-uall` and missed exactly that case).
///
/// Scoped to the root only — the User's own example was "agent creates
/// folder or file outside of where it's supposed to". Untracked-and-
/// unignored is NORMAL everywhere else in the tree (an agent mid-edit on
/// `pkgs/aoide/crates/storage/src/takes.rs` is doing its job, not making a
/// mess), so a line carrying a `/` after the collapse above is still nested
/// work and stays out of scope by design.
pub fn unrecognized_root_entries(root: &Path) -> Vec<Finding> {
    let Some(out) = run_git(root, &["status", "--porcelain"]) else {
        return Vec::new();
    };
    let mut findings: Vec<Finding> = out
        .lines()
        .filter_map(|line| line.strip_prefix("?? "))
        .map(|p| p.trim_end_matches('/'))
        .filter(|p| !p.is_empty() && !p.contains('/'))
        .map(unrecognized_finding)
        .collect();
    findings.sort_by(|a, b| a.path.cmp(&b.path));
    findings
}

fn unrecognized_finding(path: &str) -> Finding {
    Finding {
        id: format!("unrecognized:{}", slug(path)),
        check: "unrecognized",
        severity: Severity::Error,
        path: path.to_string(),
        rule: "the repo root is closed — every entry is either tracked or explicitly gitignored",
        asserted_at: "CONTRACTS.md §2 — the repo root is closed".to_string(),
        detail: format!(
            "{path} sits at the repo root, neither tracked by git nor matched by .gitignore"
        ),
        action: "move it into the tree at its designated place, or add it to .gitignore if it is runtime; the root is a contract change".to_string(),
    }
}

// ── C2: orphan-tracked ───────────────────────────────────────────────────

/// A file git TRACKS that `.gitignore` also matches: disposable state that
/// got force-added and can now never be cleanly reset by the ignore rule
/// meant to keep it out. Source: `git ls-files --cached --ignored
/// --exclude-standard` — one command, git's own answer. NOT root-scoped
/// (unlike C1): a force-added ignored file anywhere in the tree is the same
/// defect wherever it sits.
pub fn orphan_tracked(root: &Path) -> Vec<Finding> {
    let Some(out) = run_git(
        root,
        &["ls-files", "--cached", "--ignored", "--exclude-standard"],
    ) else {
        return Vec::new();
    };
    let mut findings: Vec<Finding> = out
        .lines()
        .filter(|l| !l.is_empty())
        .map(|path| orphan_tracked_finding(root, path))
        .collect();
    findings.sort_by(|a, b| a.path.cmp(&b.path));
    findings
}

fn orphan_tracked_finding(root: &Path, path: &str) -> Finding {
    let (asserted_at, pattern) =
        check_ignore_source(root, path).unwrap_or_else(|| (".gitignore".to_string(), String::new()));
    let detail = if pattern.is_empty() {
        format!("{path} is tracked but also matched by an ignore rule")
    } else {
        format!("{path} is tracked but also matched by `{pattern}` at {asserted_at}")
    };
    Finding {
        id: format!("orphan-tracked:{}", slug(path)),
        check: "orphan-tracked",
        severity: Severity::Error,
        path: path.to_string(),
        rule: "a tracked file must not also be gitignored — disposable state was force-added",
        asserted_at,
        detail,
        action: format!("git rm --cached {path}"),
    }
}

/// Resolve WHICH ignore pattern, and where it lives, catches `path` —
/// `git check-ignore -v` prints `<source>:<line>:<pattern>\t<path>`. This is
/// the ONE `assertedAt` that is a live line number rather than a file+phrase
/// anchor (design doc defect 2's stated exception): the pattern that catches
/// a given path can live in any `.gitignore` at any depth, computed fresh on
/// every run — never baked into Rust, so it can never go stale the way a
/// literal `flake.nix:173` would. `None` when the tool is unavailable or the
/// output doesn't parse; the caller falls back to a bare `.gitignore`
/// pointer rather than propagating the failure.
///
/// `--no-index` (verified live, not assumed): plain `check-ignore` special-
/// cases a path that's ALREADY IN THE INDEX and reports it as not-ignored —
/// exactly the case this function exists for, an orphan-tracked file that
/// force-add just put there. `--no-index` matches the pattern against the
/// path alone, ignoring the index entirely, so the answer we want (which
/// rule WOULD keep this out, were it not force-added) survives the file
/// already being tracked.
fn check_ignore_source(root: &Path, path: &str) -> Option<(String, String)> {
    let out = run_git(root, &["check-ignore", "-v", "--no-index", path])?;
    let first_line = out.lines().next()?;
    let left = first_line.split('\t').next()?;
    let mut parts = left.splitn(3, ':');
    let source = parts.next()?;
    let line = parts.next()?;
    let pattern = parts.next().unwrap_or("").to_string();
    Some((format!("{source}:{line}"), pattern))
}

// ── C3: clutter ──────────────────────────────────────────────────────────

/// A root symlink whose target resolves under `/nix/store`: a `nix build`
/// result link (`result`, `result-1`, `result-toplevel`, …). Source: the
/// filesystem itself (`read_link`), not git. `.gitignore` already declares
/// `result`/`result-*` expected (CONTRACTS.md §2), so by EXISTING truth
/// these are not rule violations — `severity: info`, the finding format's
/// own rule that a build symlink must never fail an agent's `soundcheck &&
/// …` chain.
pub fn clutter(root: &Path) -> Vec<Finding> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.file_type().is_symlink() {
            continue;
        }
        let Ok(target) = std::fs::read_link(&path) else {
            continue;
        };
        if target.to_string_lossy().starts_with("/nix/store") {
            let name = entry.file_name().to_string_lossy().into_owned();
            findings.push(clutter_finding(&name, &target.to_string_lossy()));
        }
    }
    findings.sort_by(|a, b| a.path.cmp(&b.path));
    findings
}

fn clutter_finding(name: &str, target: &str) -> Finding {
    Finding {
        id: format!("clutter:{}", slug(name)),
        check: "clutter",
        severity: Severity::Info,
        path: name.to_string(),
        rule: "a build-output symlink at root is expected clutter, not a rule violation",
        asserted_at: ".gitignore — result, result-*".to_string(),
        detail: format!("{name} -> {target}"),
        action: format!("rm {name} — a /nix/store symlink nix recreates on the next build"),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal real git repo: `git init`, a `.gitignore`, one committed
    /// file — the shared fixture every test below plants findings into.
    fn init_repo(root: &Path) {
        std::fs::create_dir_all(root).unwrap();
        run(root, &["init", "-q"]);
        run(root, &["config", "user.email", "test@example.invalid"]);
        run(root, &["config", "user.name", "test"]);
        std::fs::write(root.join(".gitignore"), "ignored-dir/\n*.ignored\n").unwrap();
        std::fs::write(root.join("README.md"), "committed\n").unwrap();
        run(root, &["add", ".gitignore", "README.md"]);
        run(root, &["commit", "-q", "-m", "init"]);
    }

    fn run(root: &Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .expect("git must be on PATH for this test");
        assert!(status.success(), "git {args:?} failed");
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        aoide_test_support::unique_tmp(&format!("upkeep-scan-{tag}"))
    }

    #[test]
    fn unrecognized_flags_only_root_level_untracked_entries() {
        let root = scratch("unrecognized");
        init_repo(&root);
        // Root-level, untracked, unignored — the target case.
        std::fs::write(root.join("stray.md"), "oops").unwrap();
        // Nested untracked file under an ALREADY-TRACKED directory — out of
        // scope (an agent's normal in-flight work). `modules` has to be
        // tracked first, or git status collapses IT to `modules/` too, same
        // as the wholly-new-directory case the next test covers.
        std::fs::create_dir_all(root.join("modules")).unwrap();
        std::fs::write(root.join("modules").join("tracked.nix"), "tracked").unwrap();
        run(&root, &["add", "modules/tracked.nix"]);
        run(&root, &["commit", "-q", "-m", "track modules/"]);
        std::fs::write(root.join("modules").join("also-stray.md"), "fine, deep work").unwrap();
        // Ignored — never appears in plain `git status` at all.
        std::fs::write(root.join("junk.ignored"), "ignored").unwrap();

        let findings = unrecognized_root_entries(&root);
        assert_eq!(findings.len(), 1, "{findings:?}");
        let f = &findings[0];
        assert_eq!(f.path, "stray.md");
        assert_eq!(f.id, "unrecognized:stray-md");
        assert_eq!(f.severity, Severity::Error);
        assert_eq!(f.asserted_at, "CONTRACTS.md §2 — the repo root is closed");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unrecognized_collapses_a_wholly_untracked_root_directory_into_one_finding() {
        let root = scratch("unrecognized-dir");
        init_repo(&root);
        std::fs::create_dir_all(root.join("newdir")).unwrap();
        std::fs::write(root.join("newdir").join("a.txt"), "x").unwrap();
        std::fs::write(root.join("newdir").join("b.txt"), "y").unwrap();

        let findings = unrecognized_root_entries(&root);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].path, "newdir");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn orphan_tracked_flags_a_force_added_ignored_file() {
        let root = scratch("orphan");
        init_repo(&root);
        std::fs::write(root.join("cache.ignored"), "force-added").unwrap();
        run(&root, &["add", "-f", "cache.ignored"]);
        run(&root, &["commit", "-q", "-m", "oops, force-added"]);

        let findings = orphan_tracked(&root);
        assert_eq!(findings.len(), 1, "{findings:?}");
        let f = &findings[0];
        assert_eq!(f.path, "cache.ignored");
        assert_eq!(f.id, "orphan-tracked:cache-ignored");
        assert_eq!(f.severity, Severity::Error);
        assert!(f.asserted_at.starts_with(".gitignore:"), "{}", f.asserted_at);
        assert_eq!(f.action, "git rm --cached cache.ignored");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn clutter_flags_a_nix_store_symlink_at_info_severity() {
        let root = scratch("clutter");
        init_repo(&root);
        std::os::unix::fs::symlink(
            "/nix/store/abc123-aoide-0.0.0",
            root.join("result-9"),
        )
        .unwrap();
        // A ordinary symlink NOT into the store must not fire.
        std::fs::write(root.join("elsewhere.txt"), "x").unwrap();
        std::os::unix::fs::symlink("elsewhere.txt", root.join("also-a-link")).unwrap();

        let findings = clutter(&root);
        assert_eq!(findings.len(), 1, "{findings:?}");
        let f = &findings[0];
        assert_eq!(f.path, "result-9");
        assert_eq!(f.id, "clutter:result-9");
        assert_eq!(f.severity, Severity::Info);
        assert!(f.detail.contains("/nix/store/abc123-aoide-0.0.0"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_clean_tree_yields_no_findings_from_any_check() {
        let root = scratch("clean");
        init_repo(&root);
        assert!(unrecognized_root_entries(&root).is_empty());
        assert!(orphan_tracked(&root).is_empty());
        assert!(clutter(&root).is_empty());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn git_sourced_checks_degrade_to_empty_rather_than_panic_when_root_is_not_a_repo() {
        // A tarball checkout / any directory git doesn't recognize: no crash,
        // no findings from the git-sourced checks — `clutter` is filesystem-
        // only so it still works.
        let root = scratch("not-a-repo");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("whatever.txt"), "x").unwrap();

        assert!(unrecognized_root_entries(&root).is_empty());
        assert!(orphan_tracked(&root).is_empty());
        assert!(clutter(&root).is_empty(), "no symlinks planted here");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn slug_replaces_slashes_and_dots_only() {
        assert_eq!(slug("lib/checks.nix"), "lib-checks-nix");
        assert_eq!(slug("result-1"), "result-1");
        assert_eq!(slug("a/b/c.d.e"), "a-b-c-d-e");
    }
}
