//! Locating the `drachma` binary (the note engine, pkgs/drachma).
//!
//! `rice lint` shells out to `drachma lint`. We locate the binary via
//! `$AOIDE_DRACHMA_BIN` first, then a PATH lookup, and tolerate its absence
//! with a structured error rather than a panic (walking-skeleton contract).

use std::path::PathBuf;
use std::process::Command;

/// Resolve the `drachma` binary path, or `None` if unavailable.
///
/// Order: explicit `$AOIDE_DRACHMA_BIN` → PATH lookup for `drachma`.
pub fn locate() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("AOIDE_DRACHMA_BIN") {
        if !explicit.is_empty() {
            let p = PathBuf::from(&explicit);
            if p.exists() {
                return Some(p);
            }
        }
    }
    path_lookup("drachma")
}

/// Minimal PATH lookup (no external which dependency).
fn path_lookup(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Result of a lint delegation.
pub struct LintRun {
    pub located: Option<PathBuf>,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// Shell out to `drachma lint [args...]`. Returns a structured result;
/// `located: None` signals the tolerated "note engine absent" case.
pub fn run_lint(extra_args: &[String]) -> LintRun {
    let Some(bin) = locate() else {
        return LintRun {
            located: None,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
        };
    };

    let mut cmd = Command::new(&bin);
    cmd.arg("lint");
    cmd.args(extra_args);

    match cmd.output() {
        Ok(out) => LintRun {
            located: Some(bin),
            exit_code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        },
        Err(e) => LintRun {
            located: Some(bin),
            exit_code: None,
            stdout: String::new(),
            stderr: format!("failed to execute drachma: {e}"),
        },
    }
}
