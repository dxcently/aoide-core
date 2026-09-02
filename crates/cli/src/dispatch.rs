//! The single command dispatcher.
//!
//! Both the CLI door (`bin/aoide.rs`) and the MCP door (`mcp.rs`) call
//! [`dispatch`] with a command path + parsed args/flags. There is ONE
//! implementation of every command; the doors cannot drift ("three doors,
//! one schema", concepts/Agent-Interface). A2A (`a2a.rs`, CONTRACTS.md §6)
//! reuses these same command handlers directly rather than dispatching
//! every JSON-RPC method through here.
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

    /// Task #138's design record §5 reviewer checklist item 3, the dangerous
    /// one: the external-command probe (`aoide_protocol::door::run`) must
    /// stay OUT of `dispatch()`'s own `None =>` arm above — that
    /// "simplification" would leave the golden green while silently
    /// granting `PATH` execution to MCP, A2A, and the aoided socket, since
    /// `dispatch()` (unlike `run`) is the one door-agnostic point every
    /// non-CLI door reaches directly. This is the tripwire: even with a
    /// real `aoide-foo` executable sitting on `PATH`, dispatching an
    /// unregistered path on any non-CLI door must still be a plain
    /// unknown-command usage error, because `dispatch()` has no PATH-probing
    /// logic of its own — shaped on `require_cli_tty_refuses_every_non_cli_
    /// door` (`crates/conduct/src/graph/grant.rs`), which loops the same
    /// three doors.
    #[test]
    fn an_unregistered_path_on_a_non_cli_door_is_still_unknown_command() {
        let _guard = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var_os("PATH");
        let dir = std::env::temp_dir().join(format!("aoide_cli_dispatch_non_cli_door_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let plugin = dir.join("aoide-foo");
        std::fs::write(&plugin, "#!/bin/sh\nexit 0\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&plugin).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&plugin, perms).unwrap();
        }
        std::env::set_var("PATH", &dir);

        for door in [Door::Mcp, Door::Daemon, Door::A2a] {
            let out = dispatch(&Invocation {
                path: vec!["foo".to_string()],
                args: vec![],
                flags: BTreeMap::new(),
                door,
            });
            assert_eq!(out.status, Status::Usage, "door {door:?}: {}", out.message);
            assert!(out.message.contains("unknown command"), "door {door:?}: {}", out.message);
        }

        match saved {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
