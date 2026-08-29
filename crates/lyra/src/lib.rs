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

        // `secrets ask` (P3) speaks zenity's own output contract, not the
        // generic `Outcome` envelope — `crates/lyra/src/commands/secrets.rs`'s
        // module doc: `aoide_secrets::watch::spawn_lyra_entry` reads this
        // process's stdout expecting EXACTLY the typed code (exit 0), the
        // literal string `Dismiss ask` (exit 1), or a bare cancel (exit 1,
        // nothing on stdout) — never a JSON envelope, `--json` included,
        // since the caller spawning this process is never passing that flag
        // and a human running it by hand gets the identical zenity-shaped
        // output either way. `"failed"` (live-incident fix, this commit) is
        // the ONE addition on top of that contract: `commands::secrets::
        // EXIT_INFRA_FAILURE`'s own doc has the full incident (a killed
        // dialog silently treated as a user Cancel) this distinct exit code
        // and this `eprintln!` both exist to close — `stdout stays EMPTY on
        // this path (the code/`Dismiss ask` contract is unaffected), the
        // failure reason goes to STDERR, which `aoide_secrets::watch`'s own
        // `spawn_lyra_entry` now inherits straight through to the journal
        // (that crate's own doc on why).
        if inv.path == ["secrets", "ask"] {
            let outcome = dispatch::dispatch(inv);
            let result = outcome.data.as_ref().and_then(|d| d.get("result")).and_then(|r| r.as_str());
            return Some(match result {
                Some("approved") => {
                    let code = outcome.data.as_ref().and_then(|d| d.get("code")).and_then(|c| c.as_str()).unwrap_or("");
                    println!("{code}");
                    output::exit::OK
                }
                Some("dismissed") => {
                    println!("Dismiss ask");
                    output::exit::ERROR
                }
                Some("cancelled") => output::exit::ERROR,
                Some("failed") => {
                    eprintln!("aoide lyra secrets ask: {}", outcome.message);
                    commands::secrets::EXIT_INFRA_FAILURE
                }
                _ => {
                    // A usage error (bad/missing flags) — the ONLY case left
                    // that reaches this arm now that `"failed"` has its own
                    // (`handle_secrets_ask` tags every domain-error path
                    // `"failed"` explicitly) — reported on stderr, same
                    // posture every other CLI usage path holds.
                    eprintln!("{}", outcome.message);
                    output::exit::USAGE
                }
            });
        }

        // `pair ask` (P-PV3, task #132) speaks the SAME zenity-shaped output
        // contract as `secrets ask` above, one marker/label swapped:
        // `crates/lyra/src/commands/pair.rs`'s module doc has the full
        // rundown. `aoide_client::pair_watch::run_entry_dialog` reads this
        // process's stdout expecting the typed code (exit 0), the literal
        // string `Reject request` (exit 1), or a bare cancel (exit 1,
        // nothing on stdout) — never a JSON envelope.
        if inv.path == ["pair", "ask"] {
            let outcome = dispatch::dispatch(inv);
            let result = outcome.data.as_ref().and_then(|d| d.get("result")).and_then(|r| r.as_str());
            return Some(match result {
                Some("approved") => {
                    let code = outcome.data.as_ref().and_then(|d| d.get("code")).and_then(|c| c.as_str()).unwrap_or("");
                    println!("{code}");
                    output::exit::OK
                }
                Some("dismissed") => {
                    println!("Reject request");
                    output::exit::ERROR
                }
                Some("cancelled") => output::exit::ERROR,
                Some("failed") => {
                    eprintln!("aoide lyra pair ask: {}", outcome.message);
                    commands::pair::EXIT_INFRA_FAILURE
                }
                _ => {
                    eprintln!("{}", outcome.message);
                    output::exit::USAGE
                }
            });
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
