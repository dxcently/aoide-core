//! `aoide soundcheck` — report-only, forever (the User's binding
//! correction: "repairing should mainly just point out what's not supposed
//! to be there"). This command never mutates, never repairs, never moves or
//! deletes anything; it names findings precisely enough that a human or an
//! agent can go fix them. `--json` is free on every command (`cmd!`'s
//! `JSON_FLAG`) — there is no `--only` (cut: speculative, `--json | jq`
//! covers it — soundcheck design doc, binding amendments §5) and no
//! mutating flag of any kind, so no typo, no half-parsed argv, and no
//! MCP/A2A caller can turn an inspection into a change.
//!
//! **Envelope** (`--json`, riding `Outcome.data`): `{ "findings": [...],
//! "summary": { <class>: n } }`. `findings` present with at least one
//! `error`-severity entry → `Outcome::error` at exit 1 (the `rice lint`
//! precedent, `crates/song/src/commands/rice.rs`'s `handle_rice_lint`), so
//! `aoide soundcheck && git commit` works as a gate. `info`-severity
//! findings (today: `clutter` alone) never fail the run on their own — a
//! `result` symlink must not break an agent's `&&` chain.
//!
//! **Rendering.** Bare-on-a-tty gets [`aoide_protocol::output::Outcome`]'s
//! own default human line (`[status] soundcheck: <message>`) — plain text,
//! no picker (there is nothing to select: the command reports, it doesn't
//! branch). A grouped per-finding report is a later step's job, not this
//! one's.
//!
//! **Checks landed here:** C1 `unrecognized`, C2 `orphan-tracked`, C3
//! `clutter` (`scan`'s module doc). C4–C6 (`fmt`/`lint`/`tool-missing`, the
//! three external-tool shell-outs) land in a later step.

use aoide_protocol::Invocation;
use aoide_protocol::output::Outcome;
use aoide_protocol::registry::{cmd, Registry};
use crate::scan::{self, Finding, Severity};
use serde_json::json;

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["soundcheck"],
        summary: "Report-only mechanical-integrity sweep of the WORKING tree: repo-root slop, orphaned tracked/ignored files, build clutter. Never mutates, never repairs — `nix flake check` (fmt/lint/discovery) owns the COMMITTED-tree half.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_soundcheck,
    ));
}

/// The check classes this step runs, in report order.
const CLASSES: [&str; 3] = ["unrecognized", "orphan-tracked", "clutter"];

fn handle_soundcheck(_inv: &Invocation) -> Outcome {
    let root = aoide_storage::fs::flake_root();

    let mut findings = Vec::new();
    findings.extend(scan::unrecognized_root_entries(&root));
    findings.extend(scan::orphan_tracked(&root));
    findings.extend(scan::clutter(&root));

    let mut summary = serde_json::Map::new();
    for class in CLASSES {
        let n = findings.iter().filter(|f| f.check == class).count();
        summary.insert(class.to_string(), json!(n));
    }

    let body = json!({
        "findings": findings,
        "summary": summary,
    });
    let message = summary_message(&findings);

    // Error-severity findings fail the run; info-only ones (clutter, today)
    // never do — `soundcheck && …` must stay usable with a `result` symlink
    // sitting at root.
    if findings.iter().any(|f| f.severity == Severity::Error) {
        Outcome::error("soundcheck", message).with_data(body)
    } else {
        Outcome::ok("soundcheck", message).with_data(body)
    }
}

fn summary_message(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "clean — no findings".to_string();
    }
    let errors = findings.iter().filter(|f| f.severity == Severity::Error).count();
    let infos = findings.len() - errors;
    format!(
        "{} finding{} ({errors} error, {infos} info) — see --json for detail",
        findings.len(),
        if findings.len() == 1 { "" } else { "s" },
    )
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use aoide_protocol::output::Status;
    use aoide_test_support::{inv, unique_tmp, EnvSaver};
    use crate::env_lock;

    fn run_git(root: &std::path::Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .expect("git must be on PATH for this test");
        assert!(status.success(), "git {args:?} failed");
    }

    /// A fixture repo carrying one planted finding from EACH of C1/C2/C3, and
    /// point `AOIDE_FLAKE_ROOT` (hence `flake_root()`, soundcheck's checkout
    /// seam since L-C2) at it. Returns the root so callers can inspect the
    /// tree further.
    fn plant_fixture() -> std::path::PathBuf {
        let root = unique_tmp("upkeep-cmd-fixture");
        run_git(&root, &["init", "-q"]);
        run_git(&root, &["config", "user.email", "test@example.invalid"]);
        run_git(&root, &["config", "user.name", "test"]);
        // `result*` mirrors the real repo's own `.gitignore` — a `result`
        // symlink there is EXPECTED (clutter, not unrecognized); without this
        // line the fixture would double-fire C1 on the same path C3 already
        // covers, which is not what a real checkout ever does.
        std::fs::write(root.join(".gitignore"), "*.ignored\nresult\nresult-*\n").unwrap();
        std::fs::write(root.join("README.md"), "committed\n").unwrap();
        run_git(&root, &["add", ".gitignore", "README.md"]);
        run_git(&root, &["commit", "-q", "-m", "init"]);

        // C1 unrecognized: a root-level untracked, unignored file.
        std::fs::write(root.join("stray.md"), "oops").unwrap();
        // C2 orphan-tracked: a force-added ignored file.
        std::fs::write(root.join("cache.ignored"), "force-added").unwrap();
        run_git(&root, &["add", "-f", "cache.ignored"]);
        run_git(&root, &["commit", "-q", "-m", "oops, force-added"]);
        // C3 clutter: a root symlink into /nix/store.
        std::os::unix::fs::symlink("/nix/store/abc123-aoide-0.0.0", root.join("result")).unwrap();

        std::env::set_var("AOIDE_FLAKE_ROOT", &root);
        root
    }

    #[test]
    fn a_fixture_with_one_finding_per_class_reports_all_three_and_fails_on_the_errors() {
        let _g = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _s = EnvSaver::capture(&["AOIDE_FLAKE_ROOT"]);
        let root = plant_fixture();

        let out = handle_soundcheck(&inv(&["soundcheck"], &[]));
        assert_eq!(out.status, Status::Error, "unrecognized/orphan-tracked are error-severity");

        let data = out.data.unwrap();
        let findings = data["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 3, "{findings:#?}");

        let by_id = |id: &str| {
            findings
                .iter()
                .find(|f| f["id"] == id)
                .unwrap_or_else(|| panic!("missing finding {id} in {findings:#?}"))
        };

        let unrecognized = by_id("unrecognized:stray-md");
        assert_eq!(unrecognized["check"], "unrecognized");
        assert_eq!(unrecognized["severity"], "error");
        assert_eq!(unrecognized["path"], "stray.md");
        assert_eq!(unrecognized["assertedAt"], "CONTRACTS.md §2 — the repo root is closed");
        assert_eq!(unrecognized["action"].as_str().unwrap().is_empty(), false);

        let orphan = by_id("orphan-tracked:cache-ignored");
        assert_eq!(orphan["check"], "orphan-tracked");
        assert_eq!(orphan["severity"], "error");
        assert_eq!(orphan["action"], "git rm --cached cache.ignored");
        assert!(orphan["assertedAt"].as_str().unwrap().starts_with(".gitignore:"));

        let clutter = by_id("clutter:result");
        assert_eq!(clutter["check"], "clutter");
        assert_eq!(clutter["severity"], "info");

        assert_eq!(data["summary"]["unrecognized"], 1);
        assert_eq!(data["summary"]["orphan-tracked"], 1);
        assert_eq!(data["summary"]["clutter"], 1);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_clean_tree_exits_ok_with_zero_findings() {
        let _g = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _s = EnvSaver::capture(&["AOIDE_FLAKE_ROOT"]);
        let root = unique_tmp("upkeep-cmd-clean");
        run_git(&root, &["init", "-q"]);
        run_git(&root, &["config", "user.email", "test@example.invalid"]);
        run_git(&root, &["config", "user.name", "test"]);
        std::fs::write(root.join("README.md"), "committed\n").unwrap();
        run_git(&root, &["add", "README.md"]);
        run_git(&root, &["commit", "-q", "-m", "init"]);
        std::env::set_var("AOIDE_FLAKE_ROOT", &root);

        let out = handle_soundcheck(&inv(&["soundcheck"], &[]));
        assert_eq!(out.status, Status::Ok);
        assert_eq!(out.message, "clean — no findings");
        let data = out.data.unwrap();
        assert!(data["findings"].as_array().unwrap().is_empty());
        assert_eq!(data["summary"]["unrecognized"], 0);
        assert_eq!(data["summary"]["orphan-tracked"], 0);
        assert_eq!(data["summary"]["clutter"], 0);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_non_repo_root_never_panics_and_still_reports_ok() {
        // A tarball checkout: no `.git` at all. The git-sourced checks (C1/C2)
        // degrade to no findings (`scan`'s own graceful-degrade contract);
        // the filesystem-only check (C3) still runs.
        let _g = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _s = EnvSaver::capture(&["AOIDE_FLAKE_ROOT"]);
        let root = unique_tmp("upkeep-cmd-not-a-repo");
        std::env::set_var("AOIDE_FLAKE_ROOT", &root);

        let out = handle_soundcheck(&inv(&["soundcheck"], &[]));
        assert_eq!(out.status, Status::Ok);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stable_ids_never_collide_across_findings_in_the_same_run() {
        let _g = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _s = EnvSaver::capture(&["AOIDE_FLAKE_ROOT"]);
        let root = plant_fixture();
        // A second clutter symlink, so this run carries >1 finding of the
        // SAME class too — the collision surface the id rule exists for.
        std::os::unix::fs::symlink("/nix/store/def456-aoide-notes-0.0.0", root.join("result-1"))
            .unwrap();

        let out = handle_soundcheck(&inv(&["soundcheck"], &[]));
        let data = out.data.unwrap();
        let findings = data["findings"].as_array().unwrap();
        let ids: Vec<&str> = findings.iter().map(|f| f["id"].as_str().unwrap()).collect();
        let mut unique = ids.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "duplicate id in {ids:?}");

        let _ = std::fs::remove_dir_all(&root);
    }
}
