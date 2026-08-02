//! Shared verb/arg/error glue used by every handler-bearing `graph` submodule:
//! positional/flag arg validation, the stage-error envelope, and the
//! three-registry loader.

use super::model::{
    hooks_path, load_stage, projects_path, sessions_path, HooksFile, ProjectsFile, SessionsFile,
};
use aoide_protocol::Invocation;
use aoide_protocol::output::Outcome;
use serde_json::json;

/// Positional-arg check → structured usage error (exit 2) on a miss.
pub(in crate::graph) fn require_args(
    inv: &Invocation,
    names: &[&str],
) -> Result<Vec<String>, Outcome> {
    if inv.args.len() < names.len() {
        return Err(Outcome::usage(
            inv.dotted(),
            format!(
                "usage: aoide {} {} [--json]",
                inv.path.join(" "),
                names
                    .iter()
                    .map(|n| format!("<{n}>"))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
        ));
    }
    Ok(inv.args[..names.len()].to_vec())
}

pub(crate) fn stage_error(cmd: &str, msg: String) -> Outcome {
    Outcome::error(cmd, msg).with_data(json!({ "reason": "stage-file-unreadable-or-unwritable" }))
}

/// Load all three graph inputs, tolerating missing files.
pub(in crate::graph) fn load_inputs(
    cmd: &str,
) -> Result<(ProjectsFile, SessionsFile, HooksFile), Outcome> {
    let p: ProjectsFile = load_stage(&projects_path()).map_err(|e| stage_error(cmd, e))?;
    let s: SessionsFile = load_stage(&sessions_path()).map_err(|e| stage_error(cmd, e))?;
    let h: HooksFile = load_stage(&hooks_path()).map_err(|e| stage_error(cmd, e))?;
    Ok((p, s, h))
}

/// A required `--flag` → structured usage error (exit 2) when absent/empty.
pub(in crate::graph) fn require_flag(inv: &Invocation, name: &str) -> Result<String, Outcome> {
    match inv.flags.get(name).filter(|v| !v.is_empty()) {
        Some(v) => Ok(v.clone()),
        None => Err(Outcome::usage(
            inv.dotted(),
            format!(
                "usage: aoide {} --{name} <value> [--json]",
                inv.path.join(" ")
            ),
        )),
    }
}
