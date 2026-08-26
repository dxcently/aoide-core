//! The server domain's CLI commands: `a2a serve`'s door-hint handler and
//! `daemon` (the aoided skeleton).
//!
//! Moved from the root package's `src/commands/a2a.rs` + the server half of
//! `src/commands/infra.rs` (Phase 9 restructure,
//! docs/architecture/PACKAGE-LAYOUT.md): a domain's CLI commands live with the
//! domain. The root package's `commands::all()` calls [`register_infra`]
//! directly after its own root-coupled `mcp serve` registration and
//! [`register_a2a_serve`] directly before
//! `aoide_client::commands::register_agents`, so `schema --json` order never
//! shifts.
//!
//! `shellbridge` moved out at P-A2 of the binary-split workstream
//! (docs/architecture/PACKAGE-LAYOUT.md): it belongs with the graphical
//! binary (`lyra`), not core, so its registration now lives in
//! `aoide_conduct::commands::shellbridge` — `commands::all()` calls it
//! directly after [`register_infra`] so the assembled order is unchanged.
//!
//! `a2a serve` itself is a long-running blocking server, so the root
//! package's `run_cli` special-cases its launch exactly like
//! `mcp serve --stdio`/`conductor`; the `serve` handler below only covers the
//! non-Cli-door / metadata path. (`mcp serve`'s handler stays in the ROOT
//! package — it reads the assembled registry's tool count, the one coupling
//! the DI seam cannot sever.)

use aoide_protocol::output::Outcome;
use aoide_protocol::registry::{cmd, flag, Registry};
use aoide_protocol::{Door, Invocation};
use serde_json::json;

/// `events tail`'s launch-record handler (P-D3, `docs/architecture/
/// AOIDED.md`'s "L1" section, "Terminal reachability" paragraph) — the
/// SAME shape `handle_a2a_serve`/`aoide_secrets::commands::
/// handle_secrets_watch` already hold for a foreground/blocking command:
/// this only gates the door and reports where the actual tail loop lives;
/// the blocking loop itself (`crate::events::tail`) runs from `cli`'s
/// `special` hook, dispatched to AFTER this handler records the launch
/// attempt through the single audit log. CLI-only — a follow-style command
/// that blocks a connection until Ctrl-C makes no sense over MCP/A2A,
/// exactly the reasoning `secrets watch` already established for the same
/// shape of command.
fn handle_events_tail(inv: &Invocation) -> Outcome {
    match inv.door {
        Door::Cli => Outcome::ok("events.tail", "following aoided's own events feed").with_data(json!({
            "eventsPath": crate::daemon::events_path(&crate::daemon::socket_path()).to_string_lossy(),
        })),
        _ => Outcome::usage(
            "events.tail",
            "events tail is a foreground follow that blocks until Ctrl-C; run it from a terminal (not over this door)",
        ),
    }
}

/// `a2a serve`'s handler. On the Cli door this is only ever reached via
/// `run_cli`'s special-case (dispatch first, to record the launch, THEN
/// block in the accept loop); on any other door (e.g. an MCP `tools/call`
/// for `a2a.serve`) it never blocks that door, it just reports how to
/// actually raise the server.
fn handle_a2a_serve(inv: &Invocation) -> Outcome {
    let (bind, port) = crate::a2a::resolve_bind_port(inv);
    match inv.door {
        Door::Cli => Outcome::ok(
            "a2a.serve",
            format!("raising the A2A server on http://{bind}:{port}/"),
        )
        .with_data(json!({ "interactive": true, "bind": bind, "port": port })),
        _ => Outcome::ok(
            "a2a.serve",
            "a2a serve is a long-running server; run `aoide a2a serve` from a terminal \
             or the aoide-a2a systemd unit (not over this door)",
        )
        .with_data(json!({ "interactive": true, "door": "non-cli" })),
    }
}

fn handle_daemon(inv: &Invocation) -> Outcome {
    let log = aoide_protocol::audit_log_path(inv);
    let status = crate::daemon::run(log);
    Outcome::ok("daemon", "aoided skeleton self-check complete").with_data(status)
}

/// `daemon`, registered directly after the root package's own `mcp serve`
/// entry (the historical pre-`graph` order; `shellbridge` used to register
/// here too — see the module doc for where it moved).
pub fn register_infra(r: &mut Registry) {
    r.insert(cmd!(
        path: ["daemon"],
        summary: "Run the aoided daemon skeleton (policy, lint, gate, single audit log).",
        args: [],
        flags: [flag!("audit-log", "string", "Override the audit log path (default aoide.auditLog).")],
        gated: false,
        implemented: true,
        handler: handle_daemon,
    ));
}

/// `events tail`, appended newest (P-D3) — see [`handle_events_tail`]'s doc
/// for the door-policy reasoning. `--class` is a comma-separated filter
/// (the same convention `secrets add --consumers` already uses for a
/// multi-value flag over this registry's flat `BTreeMap<String,String>`
/// flag model — there is no repeatable-flag primitive to reach for
/// instead); omitted or empty means every class.
pub fn register_events(r: &mut Registry) {
    r.insert(cmd!(
        path: ["events", "tail"],
        summary: "Foreground, line-mode follow of aoided's own events feed (the secrets-mirror's name-only lines, the #69 hand-edit watcher, and any future producer). Blocks until Ctrl-C. CLI-only — a follow-style command makes no sense over MCP/A2A.",
        args: [],
        flags: [flag!("class", "string", "Only print events whose `class` matches (comma-separated; default: every class).")],
        gated: false,
        implemented: true,
        handler: handle_events_tail,
        examples: ["events tail", "events tail --class secret", "events tail --class secret,audit --json"],
    ));
}

/// `a2a serve`, registered directly before `aoide-client`'s four `agent`
/// commands (the historical `a2a` group order).
pub fn register_a2a_serve(r: &mut Registry) {
    r.insert(cmd!(
        path: ["a2a", "serve"],
        summary: "Run the A2A (Agent2Agent) server: expose aoide-orchestrated sessions as a discoverable A2A agent (AgentCard + message/send + tasks/get). Localhost, user-only, off by default.",
        args: [],
        flags: [
            flag!("port", "int", "Override the A2A HTTP port (default aoide.a2a.port)."),
            flag!("bind", "string", "Override the A2A HTTP bind address (default aoide.a2a.bindAddress)."),
            flag!("spawn-agent", "string", "Override the command message/send's spawn path conducts (default aoide.a2a.spawnAgent; empty = spawning disabled)."),
            flag!("peer-name", "string", "Override this instance's aoide/graphSummary instance name (default: the OS hostname)."),
            flag!("token-file", "string", "Path to a file holding the shared secret an inbound message/send must present (Authorization: Bearer <token>) (default aoide.a2a.tokenFile; empty = no token required, loopback keeps today's automatic trust)."),
            flag!("bearer-secret", "string", "Name of a secret, resolved fresh on every request through the local secrets broker, this door expects as its inbound Authorization: Bearer token (default AOIDE_A2A_BEARER_SECRET; empty = not configured). Takes precedence over --token-file when set; a broker resolve failure fails closed."),
            flag!("discovery-advertise", "bool", "Advertise this instance's own discovery beacon (name/fingerprint/url) on the fixed LAN multicast group+port, ~30s jittered cadence, for aoide peer discover/invite to hear (default aoide.a2a.discoveryAdvertise / AOIDE_DISCOVERY_ADVERTISE; off by default — discovery grants nothing, docs/architecture/PAIRING.md)."),
        ],
        gated: false,
        implemented: true,
        handler: handle_a2a_serve,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use aoide_protocol::output::Status;
    use std::collections::BTreeMap;

    fn inv(door: Door, flags: &[(&str, &str)]) -> Invocation {
        Invocation {
            path: vec!["events".into(), "tail".into()],
            args: vec![],
            flags: flags.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<BTreeMap<_, _>>(),
            door,
        }
    }

    #[test]
    fn events_tail_is_cli_only() {
        assert_eq!(handle_events_tail(&inv(Door::Cli, &[])).status, Status::Ok);
        assert_eq!(handle_events_tail(&inv(Door::Mcp, &[])).status, Status::Usage);
        assert_eq!(handle_events_tail(&inv(Door::A2a, &[])).status, Status::Usage);
    }

    #[test]
    fn events_tail_ok_reports_the_resolved_events_path() {
        let out = handle_events_tail(&inv(Door::Cli, &[]));
        assert!(out.data.as_ref().and_then(|d| d.get("eventsPath")).is_some(), "{out:?}");
    }

    #[test]
    fn events_tail_registers_at_the_expected_path() {
        let mut r = Registry::new();
        register_events(&mut r);
        let cmd = r.get(&["events".to_string(), "tail".to_string()]).expect("events tail must be registered");
        assert_eq!(cmd.dotted(), "events.tail");
        assert!(cmd.flags.iter().any(|f| f.name == "class"), "{:?}", cmd.flags);
    }
}
