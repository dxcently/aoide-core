//! Lyra — the graphical/rice binary. A second composition root over the
//! same domain-crate handler code `aoide-cli` assembles (P-A4 of the
//! binary-split workstream, docs/architecture/PACKAGE-LAYOUT.md): the
//! self-ricing loop, screen, herald, shellbridge, and quickshell — never
//! conducting, the graph, A2A, peers, or the daemon (core `aoide` identity).
//! One binary (`lyra`), one schema, same "three doors, one schema" contract
//! (concepts/Agent-Interface) — the MCP door reuses these exact command
//! handlers, same as core's.

pub mod commands;
pub mod daemon;
pub mod dispatch;
pub mod guide;
pub mod output;
pub mod registry;

use daemon::Door;

/// Run the `lyra` CLI trunk. Returns the process exit code.
///
/// `argv` excludes the program name. The parse/dispatch/render skeleton is
/// `aoide_protocol::door::run` (P-A3) — the same loop `aoide-cli`'s
/// `run_cli` drives, against lyra's OWN registry/dispatcher and its OWN
/// smaller `special` hook: `mcp serve --stdio` starts the stdio server,
/// `guide`/`schema`/`livery` bypass the generic `Outcome` envelope exactly
/// like core does for the same three. Deliberately absent: `a2a serve` and
/// `conductor` — those are core identity, never lyra's (plan P-A4: "NO a2a
/// serve, NO conductor").
pub fn run_lyra(argv: &[String]) -> i32 {
    aoide_protocol::door::run(argv, Door::Cli, "lyra", dispatch::registry(), dispatch::dispatch, |inv, json| {
        // `mcp serve --stdio` is a long-running server, not a one-shot
        // dispatch. The registry + dispatcher are injected here (the DI
        // seam `aoide-server`'s module doc comment explains) — LYRA's own
        // assembled registry, not core's, so the tool list matches lyra's
        // 42-path bundle.
        if inv.path == ["mcp", "serve"] && inv.flag_present("stdio") {
            return Some(match aoide_server::mcp::serve_stdio(dispatch::registry(), dispatch::dispatch) {
                Ok(()) => output::exit::OK,
                Err(e) => {
                    eprintln!("lyra mcp serve: {e}");
                    output::exit::ERROR
                }
            });
        }

        // `guide` in text mode prints the full onboarding rather than a summary.
        if inv.path == ["guide"] && !json {
            print!("{}", guide::render(dispatch::registry()));
            return Some(output::exit::OK);
        }

        // `schema --json` emits the raw contract document at top level
        // (CONTRACTS §3), NOT wrapped in the generic outcome envelope — same
        // posture as core's `schema`.
        if inv.path == ["schema"] {
            // Still record the read through the single audit log for parity.
            let _ = daemon::audit(
                &daemon::default_audit_log(),
                Door::Cli,
                daemon::EventClass::Audit,
                "schema",
                "ok",
                "emitted schema",
            );
            let doc = dispatch::registry().schema();
            let body = serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into());
            println!("{body}");
            return Some(output::exit::OK);
        }

        // `livery emit` / `livery resolve` / `livery lint` print the
        // engine's raw byte output in text mode, NOT the outcome envelope —
        // same posture as `schema` above. `--json` keeps the structured
        // envelope.
        if inv.path.len() == 2 && inv.path[0] == "livery" && !json {
            let outcome = dispatch::dispatch(inv);
            if outcome.status == output::Status::Ok {
                if let Some(stdout) = outcome
                    .data
                    .as_ref()
                    .and_then(|d| d.get("stdout"))
                    .and_then(|s| s.as_str())
                {
                    print!("{stdout}");
                    return Some(output::exit::OK);
                }
            }
            let (body, code) = outcome.render(false);
            if code == output::exit::OK {
                println!("{body}");
            } else {
                eprintln!("{body}");
            }
            return Some(code);
        }

        None
    })
}
