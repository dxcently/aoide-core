//! The git seam (project-snapshot/per-session-revert plan, §2): five thin
//! `git` subprocess operations that let [`crate::edits`]'s journal name a
//! pre-image by git blob sha instead of carrying full file bytes itself.
//!
//! **Why blobs-plus-refs, not a second content store (plan §2.1).** Git's
//! object database already IS a content-addressed blob store, sitting right
//! there in every project that has one; duplicating that machinery under
//! `~/Aoide/state/` would be a second store answering a question git already
//! answers, and it would need its own gc story from scratch. This module
//! shells out to the project's OWN `git` (`hash-object -w` to write a
//! pre-image, `cat-file blob` to read one back) and anchors each write with
//! `update-ref refs/aoide/preimage/<sha>` so the object survives that
//! project's own `git gc` — a bare unreferenced blob is exactly what `git gc
//! --prune`'s ~2-week expiry exists to reclaim, and a safety feature whose
//! pre-images silently vanish after two weeks is disqualified (verdict §2,
//! resolution 3). One ref per blob, named by the blob's own sha: no registry
//! file to keep in sync, no ref to accidentally reuse, and `git gc` honors
//! every ref it finds regardless of how aggressively a project's gc config
//! is tuned (verdict, "attacks that held").
//!
//! **The whole-module invariant, load-bearing:** this module never stages
//! anything (no `git add`), never commits, never moves `HEAD`, and writes
//! only under `refs/aoide/`. Every operation below is one of exactly five:
//! `rev-parse --show-toplevel` (is this a repo / where), `hash-object -w`
//! (store a pre-image), `hash-object` (fingerprint the current file),
//! `cat-file blob` (read a pre-image back), `update-ref` under `refs/aoide/`
//! (anchor). Nothing here can touch the User's branch, index, stash, or
//! history — a revert built on this module is a working-tree restore, never
//! a git-history operation.
//!
//! **R2 scope only.** No CLI (`Outcome`/`Invocation` are a later layer, same
//! boundary [`crate::edits`] draws for R1), no domain validation, no
//! decision about WHICH files to capture or WHEN (that is R3). Every
//! function here takes a caller-supplied path/repo/sha and does exactly the
//! one git operation its name says.
//!
//! **Tool-missing shape mirrors `aoide_screen::ocr`'s tesseract
//! handling** (the house precedent this plan cites for the tenth/eleventh
//! external binary, plan §1.4): a spawn failure (`git` not on `PATH`) and a
//! nonzero exit (git ran and refused) are DISTINCT failure shapes, both
//! folded into this module's `Result<_, String>` return type via
//! [`run_git`] rather than a dedicated error enum — every caller here wants
//! a `String` already, so a typed `GitError` with only this module's own
//! immediate `.map_err` as its consumer would be machinery nothing needs.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Run `git [-C <cwd>] <args>`, returning raw stdout bytes on success.
/// Mirrors `screen/ocr.rs::run_tesseract_tsv`'s split of "couldn't even
/// spawn" (`git` missing from `PATH`) versus "ran but exited nonzero" (git
/// itself refused) — collapsed into one `Result<_, String>` message, since
/// every function in this module hands its caller a `String`, not a typed
/// backend error the way `OcrError` serves `screen::ocr`'s own callers.
///
/// Stdout is returned as raw `Vec<u8>`, never lossily decoded here — this is
/// the one place that would silently corrupt a binary pre-image if it
/// guessed UTF-8, so every caller that wants text (`toplevel`,
/// `hash_object_write`, `hash_object`) does its own trimmed
/// `from_utf8_lossy` on the (ASCII-only, hex-or-path) output it expects,
/// while [`cat_file_blob`] returns these bytes completely untouched.
fn run_git(cwd: Option<&Path>, args: &[&str]) -> Result<Vec<u8>, String> {
    let mut cmd = Command::new("git");
    if let Some(dir) = cwd {
        cmd.arg("-C").arg(dir);
    }
    cmd.args(args);
    match cmd.output() {
        Err(e) => Err(format!("git-unavailable: could not run \"git {}\": {e}", args.join(" "))),
        Ok(out) if out.status.success() => Ok(out.stdout),
        Ok(out) => {
            let said = String::from_utf8_lossy(&out.stderr);
            let said = said.trim();
            Err(format!(
                "git-failed: \"git {}\" exited {:?}: {}",
                args.join(" "),
                out.status.code(),
                if said.is_empty() { "no message" } else { said }
            ))
        }
    }
}

/// The directory to run git in for a file-scoped operation
/// ([`hash_object_write`]/[`hash_object`]): the file's own parent, so git's
/// ordinary repo-discovery walk (upward from cwd to the nearest `.git`)
/// finds the enclosing project regardless of where the CALLING process's own
/// cwd happens to be. The file argument itself is always passed as the
/// caller gave it (typically already absolute), so this only decides where
/// `git` looks for a `.git` — never how the path argument resolves.
fn file_scoped_dir(file: &Path) -> &Path {
    file.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."))
}

/// `git rev-parse --show-toplevel` — is `dir` inside a git working tree, and
/// if so, its root. `Err` names `dir` whether the failure was git being
/// absent from `PATH` or `dir` genuinely not being inside a repo (git's own
/// `fatal: not a git repository (or any of the parent directories)`), so a
/// caller never has to re-derive which directory it was even asking about.
pub fn toplevel(dir: &Path) -> Result<PathBuf, String> {
    let out = run_git(Some(dir), &["rev-parse", "--show-toplevel"])
        .map_err(|e| format!("{e} (looking for a git repo at {})", dir.display()))?;
    let text = String::from_utf8_lossy(&out);
    let text = text.trim();
    if text.is_empty() {
        return Err(format!(
            "git rev-parse --show-toplevel returned nothing for {}",
            dir.display()
        ));
    }
    Ok(PathBuf::from(text))
}

/// `git hash-object -w --` — write `file`'s CURRENT content into its
/// enclosing repo's object store as a blob and return its sha. This is the
/// pre-image capture primitive: the caller (R3) invokes this BEFORE an edit
/// tool overwrites the file, so the blob this returns is what the file
/// looked like a moment ago.
///
/// Repo discovery is implicit ([`file_scoped_dir`]) — this function takes no
/// separate `repo` argument because the file already names, via its own
/// location, which repo it belongs to; git's own upward `.git` search
/// resolves the rest, exactly as it would for a `git hash-object -w` typed
/// by hand from that file's directory.
pub fn hash_object_write(file: &Path) -> Result<String, String> {
    let file_arg = file.to_string_lossy().into_owned();
    let out = run_git(Some(file_scoped_dir(file)), &["hash-object", "-w", "--", &file_arg])
        .map_err(|e| format!("{e} (writing a blob for {})", file.display()))?;
    let text = String::from_utf8_lossy(&out);
    let sha = text.trim();
    if sha.is_empty() {
        return Err(format!("git hash-object -w returned no hash for {}", file.display()));
    }
    Ok(sha.to_string())
}

/// `git hash-object --` (no `-w`) — fingerprint `file`'s CURRENT content
/// without writing anything to the object store. `Ok(None)` when `file` does
/// not exist, checked BEFORE shelling out (never inferred from git's stderr,
/// which would conflate "no such file" with any other failure git might
/// report for the same exit code).
///
/// This absent-means-`None` shape is deliberate and load-bearing, not an
/// omission (verdict, binding settlement): a later step maps (file absent,
/// journal still names a recorded post-sha) to a "deleted" classification,
/// and that mapping only works if absence is a normal `Ok` value here, never
/// an `Err` a caller has to special-case out of its error path.
///
/// `file.exists()` follows a symlink to its target (std's ordinary
/// behavior), matching git's own content-follows-the-link semantics for an
/// ordinary tracked symlink target — the same posture the plan's D8
/// amendment documents for symlinked paths generally.
pub fn hash_object(file: &Path) -> Result<Option<String>, String> {
    if !file.exists() {
        return Ok(None);
    }
    let file_arg = file.to_string_lossy().into_owned();
    let out = run_git(Some(file_scoped_dir(file)), &["hash-object", "--", &file_arg])
        .map_err(|e| format!("{e} (hashing {})", file.display()))?;
    let text = String::from_utf8_lossy(&out);
    let sha = text.trim();
    if sha.is_empty() {
        return Err(format!("git hash-object returned no hash for {}", file.display()));
    }
    Ok(Some(sha.to_string()))
}

/// `git cat-file blob <sha>` — read a blob's content back out of `repo`'s
/// object store, verbatim bytes. Takes `repo` explicitly (unlike
/// [`hash_object_write`]/[`hash_object`]): a blob sha carries no location of
/// its own, so the caller must say which project's object store to read it
/// from — normally the SAME repo [`toplevel`] resolved for that project.
///
/// Returns raw `Vec<u8>` straight from `run_git`'s stdout, with no UTF-8
/// decoding anywhere on this path — the whole point (plan/verdict: "the
/// whole path is bytes") is that a pre-image round-trips exactly, binary
/// content and embedded NUL bytes included, never lossily reinterpreted as
/// text.
pub fn cat_file_blob(repo: &Path, sha: &str) -> Result<Vec<u8>, String> {
    run_git(Some(repo), &["cat-file", "blob", sha])
        .map_err(|e| format!("{e} (reading blob {sha} from {})", repo.display()))
}

/// `git update-ref refs/aoide/preimage/<sha> <sha>` — anchor a blob so it
/// survives `repo`'s own `git gc`. THE reason this module exists at all
/// (module doc, verdict resolution 3): `hash-object -w` alone writes a loose
/// object with nothing pointing at it, and an unreferenced loose object is
/// exactly what `git gc --prune`'s ~2-week expiry window exists to reclaim —
/// silently, with no warning, on a repo the User already runs ordinary git
/// commands in. One ref per blob, named BY the blob's own sha: two captures
/// of identical content collide onto the same ref harmlessly (updating a ref
/// to the sha it already names is a no-op), and nothing needs a separate
/// registry to know which refs exist — `refs/aoide/preimage/*` enumerates
/// itself.
pub fn anchor(repo: &Path, sha: &str) -> Result<(), String> {
    let ref_name = format!("refs/aoide/preimage/{sha}");
    run_git(Some(repo), &["update-ref", &ref_name, sha])
        .map(|_| ())
        .map_err(|e| format!("{e} (anchoring {sha} in {})", repo.display()))
}

// ── Tests ─────────────────────────────────────────────────────────────────
//
// Every test drives a REAL temp git repo (`unique_tmp` + `git init`), never a
// mock — the whole point of this module is what a real `git` subprocess
// does, and `git gc --prune=now` in particular has no meaningful fake.

#[cfg(test)]
mod tests {
    use super::*;
    use aoide_test_support::unique_tmp;

    /// `git [-C dir] <args>`, asserting success — the test-side counterpart
    /// of [`run_git`], used to set up/inspect fixtures rather than to
    /// exercise this module's own functions.
    fn git_ok(dir: &Path, args: &[&str]) -> Vec<u8> {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .expect("git must be on PATH for this test");
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    }

    /// A fresh repo, `git init -q`'d, with a name/email set (some git builds
    /// warn or refuse to commit without one — this module never commits, but
    /// `git gc` itself is silent on that point either way; set for hygiene).
    fn init_repo(tag: &str) -> PathBuf {
        let dir = unique_tmp(tag);
        git_ok(&dir, &["init", "-q"]);
        git_ok(&dir, &["config", "user.email", "test@example.invalid"]);
        git_ok(&dir, &["config", "user.name", "test"]);
        dir
    }

    // ── hash_object_write / cat_file_blob: the basic round trip ────────────

    #[test]
    fn a_blob_round_trips_through_hash_object_write_and_cat_file_blob() {
        let repo = init_repo("git-roundtrip");
        let file = repo.join("pre-image.txt");
        std::fs::write(&file, "hello, pre-image\n").unwrap();

        let sha = hash_object_write(&file).unwrap();
        assert_eq!(sha.len(), 40, "a sha-1 hex digest: {sha}");

        let back = cat_file_blob(&repo, &sha).unwrap();
        assert_eq!(back, b"hello, pre-image\n");
    }

    #[test]
    fn binary_content_with_embedded_nul_and_invalid_utf8_round_trips_exactly() {
        // The whole path is bytes: `cat_file_blob -> Vec<u8>` must never
        // lossily reinterpret content as text, embedded NUL and invalid
        // UTF-8 included (plan/verdict, "attacks that held": binary files).
        let repo = init_repo("git-binary-roundtrip");
        let file = repo.join("binary.bin");
        let bytes: Vec<u8> = vec![0x00, 0xff, 0xfe, 0x00, 0x9f, 0x00, b'x', 0x00, 0xc0, 0x80];
        std::fs::write(&file, &bytes).unwrap();
        assert!(
            std::str::from_utf8(&bytes).is_err(),
            "fixture must genuinely be invalid UTF-8"
        );

        let sha = hash_object_write(&file).unwrap();
        let back = cat_file_blob(&repo, &sha).unwrap();
        assert_eq!(back, bytes, "binary content, embedded NUL included, round-trips byte-for-byte");
    }

    // ── hash_object: absent file is None, not an error ──────────────────────

    #[test]
    fn hash_object_of_an_absent_file_is_none() {
        let repo = init_repo("git-hash-absent");
        let missing = repo.join("never-written.txt");
        assert_eq!(hash_object(&missing).unwrap(), None);
    }

    #[test]
    fn hash_object_of_a_present_file_matches_hash_object_write_without_storing_it() {
        let repo = init_repo("git-hash-present");
        let file = repo.join("f.txt");
        std::fs::write(&file, "content").unwrap();

        let fingerprint = hash_object(&file).unwrap();
        assert!(fingerprint.is_some());
        // Confirm it agrees with the writing variant's own sha for the same
        // bytes — same hashing rule, only one of the two actually persists.
        let written_sha = hash_object_write(&file).unwrap();
        assert_eq!(fingerprint.unwrap(), written_sha);
    }

    // ── toplevel: subdirectory resolves the root; a non-repo names the path ─

    #[test]
    fn toplevel_from_a_subdirectory_returns_the_repo_root() {
        let repo = init_repo("git-toplevel-subdir");
        let sub = repo.join("a").join("b").join("c");
        std::fs::create_dir_all(&sub).unwrap();

        let found = toplevel(&sub).unwrap();
        // Compare canonicalized: on some systems the temp root itself sits
        // behind a symlink (e.g. /tmp -> /private/tmp), and git's own
        // `--show-toplevel` output is the resolved path either way.
        assert_eq!(found.canonicalize().unwrap(), repo.canonicalize().unwrap());
    }

    #[test]
    fn toplevel_from_a_non_repo_directory_errors_naming_the_path() {
        let dir = unique_tmp("git-toplevel-non-repo");
        // Deliberately no `git init` — this directory is not inside any repo
        // (a fresh unique_tmp scratch dir, never itself checked into git).

        let err = toplevel(&dir).unwrap_err();
        assert!(
            err.contains(&dir.display().to_string()),
            "error must name the path that was not a repo: {err}"
        );
    }

    // ── anchor: THE load-bearing test — a blob survives `git gc --prune=now` ─

    #[test]
    fn anchor_makes_the_blob_survive_git_gc_prune_now() {
        let repo = init_repo("git-anchor-survives-gc");
        let file = repo.join("pre-image.txt");
        std::fs::write(&file, "anchored content\n").unwrap();

        // Write the blob but NEVER `git add`/commit it — nothing but the ref
        // this test is about to create will point at it. Confirm that up
        // front: `cat-file -e` on a truly dangling object still succeeds
        // (the object exists in the store) but nothing in `for-each-ref` or
        // any commit names it, which is what makes it gc-eligible at all.
        let sha = hash_object_write(&file).unwrap();
        let refs_before = git_ok(&repo, &["for-each-ref"]);
        assert!(
            !String::from_utf8_lossy(&refs_before).contains(&sha),
            "the blob must be unreachable — no ref names it yet"
        );

        anchor(&repo, &sha).unwrap();

        // The anchor ref exists and names exactly this sha — confirms
        // `anchor` is what made the object reachable, not some other write.
        let anchor_ref = git_ok(&repo, &["rev-parse", &format!("refs/aoide/preimage/{sha}")]);
        assert_eq!(String::from_utf8_lossy(&anchor_ref).trim(), sha);

        git_ok(&repo, &["gc", "--prune=now"]);

        let back = cat_file_blob(&repo, &sha).unwrap();
        assert_eq!(back, b"anchored content\n", "the anchored blob survives an aggressive gc");
    }

    #[test]
    fn an_unanchored_blob_does_not_survive_git_gc_prune_now() {
        // The control for the test above: without `anchor`, the SAME
        // sequence loses the blob to gc — proving the anchor ref, not some
        // gc no-op or a fixture accident, is what keeps the anchored one
        // alive.
        let repo = init_repo("git-unanchored-lost-to-gc");
        let file = repo.join("pre-image.txt");
        std::fs::write(&file, "unanchored content\n").unwrap();
        let sha = hash_object_write(&file).unwrap();

        git_ok(&repo, &["gc", "--prune=now"]);

        assert!(
            cat_file_blob(&repo, &sha).is_err(),
            "an unanchored, unreferenced blob must be reclaimed by an aggressive gc"
        );
    }
}
