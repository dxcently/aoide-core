//! The note-engine seam — `rice lint`'s validator.
//!
//! A thin wrapper over the native `livery::lint` validator, so `rice lint`
//! validates in-process: no binary to locate, no Node on PATH. The
//! `run_lint` shape (`file` → structured result) is kept so its caller's
//! call site reads unchanged.

use std::path::PathBuf;

/// Result of a lint run.
pub struct LintRun {
    pub file: PathBuf,
    pub ok: bool,
    pub errors: Vec<String>,
}

/// Run the native `livery lint` over the note file at `path`.
///
/// A read failure or JSON parse failure surfaces as a lint failure carrying
/// the Node engine's exact message shape (`cannot read {file}: {e}` /
/// `invalid JSON in {file}: {e}`) — a missing file is a lint failure, never
/// a panic (the walking-skeleton contract).
pub fn run_lint(path: &PathBuf) -> LintRun {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            return LintRun {
                file: path.clone(),
                ok: false,
                errors: vec![format!("cannot read {}: {e}", path.display())],
            }
        }
    };
    let parsed: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            return LintRun {
                file: path.clone(),
                ok: false,
                errors: vec![format!("invalid JSON in {}: {e}", path.display())],
            }
        }
    };
    let v = crate::livery::lint(&parsed);
    LintRun {
        file: path.clone(),
        ok: v.ok,
        errors: v.errors,
    }
}
