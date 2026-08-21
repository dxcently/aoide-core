//! The single command dispatcher.
//!
//! Both the CLI door (`bin/aoide.rs`) and the MCP door (`mcp.rs`) call
//! [`dispatch`] with a command path + parsed args/flags. There is ONE
//! implementation of every command; the two doors cannot drift (concepts/Agent-Interface: "two doors, one schema" — now three
//! doors onto that one schema: A2A (`a2a.rs`, CONTRACTS.md §6) reuses these
//! same command handlers directly rather than dispatching every JSON-RPC
//! method through here).
//!
//! `dispatch()` itself is thin: it looks up the [`crate::registry::Registry`]
//! (built once via [`registry`]) and either calls the matched command's
//! handler, returns the not-implemented envelope, or returns an
//! unknown-command usage error — then appends to the single audit log and
//! applies the gate tail uniformly. Every command's actual behavior lives in
//! its DOMAIN crate's `commands` module (`aoide_conduct::commands`,
//! `aoide_storage::commands`, … — Phase 9 restructure,
//! docs/architecture/PACKAGE-LAYOUT.md), assembled here by
//! `commands/mod.rs::all()`. (`aoide_song::commands`/`aoide_screen::commands`
//! are the same pattern one door over — they assemble into `lyra`'s
//! registry, not this crate's, since P-A5.)
//!
//! `Invocation` moved to `aoide-protocol` (Phase 2 restructure,
//! docs/architecture/PACKAGE-LAYOUT.md) — it's the type that broke the cycle
//! (`Command.handler` is `fn(&Invocation) -> Outcome`) and is re-exported here
//! so every existing `crate::dispatch::Invocation` caller is untouched.

pub use aoide_protocol::Invocation;

use crate::daemon;
use crate::output::Outcome;
use crate::registry::Registry;
use std::sync::OnceLock;

/// The process-wide command registry, built once from every command group's
/// `register()`. `cli.rs`, `mcp.rs`, and `dispatch()` all read through this
/// single instance.
pub fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(crate::commands::all)
}

/// The audit-log path in effect (flag override → `aoide.auditLog` default).
/// The function itself moved to `aoide-protocol` (Phase 9 restructure) — both
/// its inputs are protocol types; re-exported here so every existing
/// `crate::dispatch::audit_log_path` caller is untouched.
pub(crate) use aoide_protocol::audit_log_path;

/// Dispatch one invocation to its handler and return the structured outcome.
/// Every path here also appends to the single audit log — both doors inherit
/// the same policy surface (concepts/Governance).
pub fn dispatch(inv: &Invocation) -> Outcome {
    let cmd = inv.dotted();
    let meta = registry().get(&inv.path);

    let outcome = match meta {
        Some(m) if m.implemented => (m.handler)(inv),
        Some(m) => Outcome::not_implemented(cmd.clone(), m.gated).with_data(serde_json::json!({
            "path": m.path,
            "args": inv.args,
            "flags": inv.flags,
        })),
        None => Outcome::usage(
            cmd.clone(),
            format!("unknown command: `{}`", cmd.replace('.', " ")),
        ),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::Door;
    use crate::output::Status;
    use std::collections::BTreeMap;

    fn inv(path: &[&str], args: &[&str]) -> Invocation {
        Invocation {
            path: path.iter().map(|s| s.to_string()).collect(),
            args: args.iter().map(|s| s.to_string()).collect(),
            flags: BTreeMap::new(),
            door: Door::Cli,
        }
    }

    #[test]
    fn unknown_command_is_usage_exit_2() {
        let out = dispatch(&inv(&["nope", "nope"], &[]));
        assert_eq!(out.status, Status::Usage);
        assert_eq!(out.render(false).1, crate::output::exit::USAGE);
        assert!(out.message.contains("unknown command"));
    }

    #[test]
    fn not_implemented_command_carries_the_stub_envelope_and_gate() {
        // `rice declare` (the gated+not-implemented example this test used to
        // exercise) moved to lyra at P-A5. `content approve` is core's own
        // gated + not-implemented stub — same shape, still here.
        let out = dispatch(&inv(&["content", "approve"], &["/tmp/dusk"]));
        assert_eq!(out.status, Status::NotImplemented);
        assert_eq!(out.render(false).1, crate::output::exit::NOT_IMPLEMENTED);
        assert!(out.gated, "content.approve is a gated command");
        assert_eq!(out.data.unwrap()["args"][0], "/tmp/dusk");
    }

    #[test]
    fn implemented_command_dispatches_to_its_handler() {
        let out = dispatch(&inv(&["guide"], &[]));
        assert_eq!(out.status, Status::Ok);
        assert!(out.data.unwrap()["text"].as_str().unwrap().contains("aoide"));
    }
}
