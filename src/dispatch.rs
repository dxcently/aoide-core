//! The single command dispatcher.
//!
//! Both the CLI door (`bin/aoide.rs`) and the MCP door (`mcp.rs`) call
//! [`dispatch`] with a command path + parsed args/flags. There is ONE
//! implementation of every command; the two doors cannot drift because both
//! land here (concepts/Agent-Interface: "two doors, one schema").

use crate::daemon::{self, Door};
use crate::guide::GUIDE;
use crate::notes;
use crate::output::Outcome;
use crate::schema;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Parsed invocation handed to the dispatcher.
pub struct Invocation {
    /// Command path, e.g. `["rice", "gen"]`.
    pub path: Vec<String>,
    /// Positional args in order.
    pub args: Vec<String>,
    /// Named flags (`--foo bar`, or `--foo` → `"true"`).
    pub flags: BTreeMap<String, String>,
    /// Which door this came through (for the audit log).
    pub door: Door,
}

impl Invocation {
    pub fn flag_present(&self, name: &str) -> bool {
        self.flags.contains_key(name)
    }
    pub fn dotted(&self) -> String {
        self.path.join(".")
    }
}

/// Look up the schema entry for a command path.
fn schema_for(path: &[String]) -> Option<schema::Command> {
    schema::commands()
        .into_iter()
        .find(|c| c.path.len() == path.len() && c.path.iter().zip(path).all(|(a, b)| *a == b))
}

/// The audit-log path in effect (flag override → `aoide.auditLog` default).
fn audit_log_path(inv: &Invocation) -> std::path::PathBuf {
    if let Some(p) = inv.flags.get("audit-log") {
        return std::path::PathBuf::from(p);
    }
    daemon::default_audit_log()
}

/// Dispatch one invocation to its handler and return the structured outcome.
/// Every path here also appends to the single audit log — both doors inherit
/// the same policy surface (concepts/Governance).
pub fn dispatch(inv: &Invocation) -> Outcome {
    let cmd = inv.dotted();
    let meta = schema_for(&inv.path);

    let outcome = match inv
        .path
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["guide"] => Outcome::ok("guide", "printed the four-tier onboarding")
            .with_data(json!({ "text": GUIDE })),

        ["schema"] => {
            let doc = schema::schema();
            let val = serde_json::to_value(&doc).unwrap_or(Value::Null);
            Outcome::ok("schema", "emitted the v0 command + state-file schema").with_data(val)
        }

        ["rice", "lint"] => handle_rice_lint(inv),

        ["mcp", "serve"] => Outcome::ok(
            "mcp.serve",
            "MCP stdio server is spawned via the binary entrypoint; \
             its tool list is generated from `schema --json`",
        )
        .with_data(json!({
            "hint": "run `aoide mcp serve --stdio` to serve; tools derive from the schema",
            "toolCount": schema::commands().len(),
        })),

        ["daemon"] => {
            let log = audit_log_path(inv);
            let status = daemon::run(log);
            Outcome::ok("daemon", "aoided skeleton self-check complete").with_data(status)
        }

        // ── graph: project/session DAG viewer + manager (graph.rs) ──────────
        ["graph", "view"] => crate::graph::view(inv),
        ["graph", "project", "add"] => crate::graph::project_add(inv),
        ["graph", "project", "remove"] => crate::graph::project_remove(inv),
        ["graph", "project", "list"] => crate::graph::project_list(inv),
        ["graph", "link"] => crate::graph::link(inv),
        ["graph", "focus"] => crate::graph::focus(inv),
        ["graph", "prune"] => crate::graph::prune(inv),
        ["graph", "emit"] => crate::graph::emit(inv),

        ["shellbridge"] => {
            let status = crate::shellbridge::run();
            Outcome::ok("shellbridge", "shellbridge skeleton self-check complete").with_data(status)
        }

        // `baton` is interactive: like `mcp serve --stdio`, the loop itself is
        // resolved at the entry point (lib.rs) — everything below stays
        // frontend-agnostic. This arm only RECORDS the launch (so the audit log
        // carries the door-open the baton then tails) and, for a non-interactive
        // door (MCP/daemon), returns the "run it from a terminal" outcome. The
        // CLI door short-circuits in run_cli AFTER dispatching here, so on the
        // Cli path this is the audit record, not a stub.
        ["baton"] => match inv.door {
            Door::Cli => Outcome::ok("baton", "raising the baton over the agent sessions")
                .with_data(json!({
                    "interactive": true,
                    "stageDir": crate::shellbridge::stage_dir().to_string_lossy(),
                })),
            _ => Outcome::ok(
                "baton",
                "baton is interactive; run `aoide baton` from a terminal (not over this door)",
            )
            .with_data(json!({ "interactive": true, "door": "non-cli" })),
        },

        ["adapter", "melete"] => {
            let status = crate::adapter::run_melete();
            Outcome::ok(
                "adapter.melete",
                "melete-adapter skeleton self-check complete",
            )
            .with_data(status)
        }

        // ── Structured "not-implemented" stubs (walking skeleton) ───────────
        _ => match &meta {
            Some(m) => Outcome::not_implemented(cmd.clone(), m.gated).with_data(json!({
                "path": m.path,
                "args": inv.args,
                "flags": inv.flags,
            })),
            None => Outcome::usage(
                cmd.clone(),
                format!("unknown command: `{}`", cmd.replace('.', " ")),
            ),
        },
    };

    // Wire the audit-log append as a real code path for every dispatch.
    let log = audit_log_path(inv);
    let _ = daemon::audit(
        &log,
        inv.door,
        daemon::EventClass::Audit,
        &cmd,
        match outcome.status {
            crate::output::Status::Ok => "ok",
            crate::output::Status::Error => "error",
            crate::output::Status::Usage => "usage",
            crate::output::Status::NotImplemented => "not-implemented",
        },
        &outcome.message,
    );

    // Mark gated commands so both doors surface the gate uniformly.
    match meta {
        Some(m) if m.gated => outcome.gated(true),
        _ => outcome,
    }
}

/// `rice lint` — real: delegates to `drachma lint`, tolerates absence.
fn handle_rice_lint(inv: &Invocation) -> Outcome {
    let run = notes::run_lint(&inv.args);
    match run.located {
        None => Outcome::error(
            "rice.lint",
            "drachma not found; set $AOIDE_DRACHMA_BIN or put it on PATH",
        )
        .with_data(json!({
            "reason": "notes-binary-unavailable",
            "searched": ["$AOIDE_DRACHMA_BIN", "PATH"],
        })),
        Some(bin) => {
            let ok = run.exit_code == Some(0);
            let mut out = if ok {
                Outcome::ok("rice.lint", "note schema validation passed")
            } else {
                Outcome::error("rice.lint", "note schema validation reported problems")
            };
            out = out.with_data(json!({
                "delegate": bin.to_string_lossy(),
                "exitCode": run.exit_code,
                "stdout": run.stdout,
                "stderr": run.stderr,
            }));
            out
        }
    }
}
