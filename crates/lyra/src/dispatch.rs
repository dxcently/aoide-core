//! The single command dispatcher — lyra's own, mirroring `aoide-cli`'s
//! `dispatch.rs` exactly (registry-lookup, audit append, gate tail) against
//! lyra's OWN [`crate::commands::all`] assembly. There is still ONE
//! implementation of every command underneath (the domain crates' handlers
//! are shared with core); this is a second composition root over the same
//! handler code, not a second implementation of it.

pub use aoide_protocol::Invocation;

use crate::daemon;
use crate::output::Outcome;
use crate::registry::Registry;
use std::sync::OnceLock;

/// The process-wide command registry, built once from lyra's own
/// `commands::all()`.
pub fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(crate::commands::all)
}

pub(crate) use aoide_protocol::audit_log_path;

/// Dispatch one invocation to its handler and return the structured outcome.
/// Every path here also appends to the single audit log — lyra inherits the
/// same policy surface as the core door (concepts/Governance).
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
    fn not_implemented_command_carries_the_stub_envelope() {
        // `rice transpose` is still a walking-skeleton stub, registered via
        // lyra's own `stubs::register_rice_late` — `rice declare`'s sibling
        // graduated to a real handler at L-C2 (task #107), see
        // `commands/stubs.rs`'s own module doc.
        let out = dispatch(&inv(&["rice", "transpose"], &["dusk", "midnight"]));
        assert_eq!(out.status, Status::NotImplemented);
        assert_eq!(out.render(false).1, crate::output::exit::NOT_IMPLEMENTED);
        assert!(!out.gated, "rice.transpose is not a gated command");
        assert_eq!(out.data.unwrap()["args"][0], "dusk");
    }

    #[test]
    fn implemented_command_dispatches_to_its_handler() {
        let out = dispatch(&inv(&["guide"], &[]));
        assert_eq!(out.status, Status::Ok);
        assert!(out.data.unwrap()["text"].as_str().unwrap().contains("Lyra"));
    }

    /// Task #138's design record §5 reviewer checklist item 3, mirroring
    /// `aoide-cli`'s own `dispatch.rs` twin test: the external-command probe
    /// (`aoide_protocol::door::run`) must stay OUT of `dispatch()`'s own
    /// `None =>` arm above — that "simplification" would leave the golden
    /// green while silently granting `PATH` execution to MCP, A2A, and the
    /// aoided socket, since `dispatch()` (unlike `run`) is the one
    /// door-agnostic point every non-CLI door reaches directly. This is the
    /// tripwire: even with a real `lyra-foo` executable sitting on `PATH`,
    /// dispatching an unregistered path on any non-CLI door must still be a
    /// plain unknown-command usage error.
    #[test]
    fn an_unregistered_path_on_a_non_cli_door_is_still_unknown_command() {
        let _guard = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var_os("PATH");
        let dir = std::env::temp_dir().join(format!("aoide_lyra_dispatch_non_cli_door_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let plugin = dir.join("lyra-foo");
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
