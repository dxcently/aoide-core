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
    fn not_implemented_command_carries_the_stub_envelope_and_gate() {
        // `rice declare` is gated + not implemented — same walking-skeleton
        // stub core carries, registered via lyra's own `stubs::register_rice_late`.
        let out = dispatch(&inv(&["rice", "declare"], &["dusk"]));
        assert_eq!(out.status, Status::NotImplemented);
        assert_eq!(out.render(false).1, crate::output::exit::NOT_IMPLEMENTED);
        assert!(out.gated, "rice.declare is a gated command");
        assert_eq!(out.data.unwrap()["args"][0], "dusk");
    }

    #[test]
    fn implemented_command_dispatches_to_its_handler() {
        let out = dispatch(&inv(&["guide"], &[]));
        assert_eq!(out.status, Status::Ok);
        assert!(out.data.unwrap()["text"].as_str().unwrap().contains("Lyra"));
    }
}
