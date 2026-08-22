//! Aoide — the CLI trunk, the MCP façade, and the aoided daemon skeleton.
//!
//! One crate, two binaries (`aoide`, `aoided`), one schema. Everything the CLI
//! door and the MCP door can do is described once in [`schema`] and executed
//! once in [`dispatch`]; the two doors cannot drift (concepts/Agent-Interface).
//! A2A (`a2a.rs`, CONTRACTS.md §6) is a third door onto the same schema — its
//! AgentCard derives from it too, and `message/send` reuses these same
//! command handlers rather than dispatching every JSON-RPC method through
//! here.

pub mod a2a;
pub mod commands;
pub mod cli;
pub mod daemon;
pub mod dispatch;
pub mod graph;
pub mod guide;
pub mod mcp;
pub mod output;
pub mod registry;

pub use aoide_client as client;
pub use aoide_conduct as conduct;
pub use aoide_conductor as conductor;
pub use aoide_protocol as protocol;
pub use aoide_server as server;
pub use aoide_storage as storage;
pub use aoide_vault as vault;

use daemon::Door;

/// Run the `aoide` CLI trunk. Returns the process exit code.
///
/// `argv` excludes the program name. The parse/dispatch/render skeleton lives
/// in `aoide_protocol::door::run` (Phase 3 restructure,
/// docs/architecture/PACKAGE-LAYOUT.md) so a second binary (lyra, P-A4) can
/// drive the same loop against its own registry without duplicating it; this
/// crate supplies its own special-cased verbs via the `special` hook —
/// `mcp serve --stdio`, `a2a serve`, and `vault serve` start servers,
/// `vault exec` resolves a secret and execs a command with it injected as an
/// env var (`Stdio::inherit` throughout — the value can never cross the
/// generic `Outcome` envelope, Workstream VAULT P-V2), `vault enroll` prints
/// a fresh TOTP secret's `otpauth://` URI + base32 form directly to stdout
/// for the same reason (Workstream VAULT P-V3), `conductor` hands off
/// to the interactive terminal loop, `guide`/`schema` bypass the generic
/// `Outcome` envelope — everything else routes through the single dispatcher
/// (so the audit log + gate apply uniformly). `livery` was an earlier special
/// case; it moved to lyra with the rest of the graphical bundle at P-A5 —
/// core no longer parses `livery.*` at all.
pub fn run_cli(argv: &[String]) -> i32 {
    protocol::door::run(argv, Door::Cli, "aoide", dispatch::registry(), dispatch::dispatch, |inv, json| {
        // `mcp serve --stdio` is a long-running server, not a one-shot dispatch.
        // The registry + dispatcher are injected here (the DI seam
        // `aoide-server`'s module doc comment explains — `aoide-server` cannot
        // reach the crate-global, fully-assembled `dispatch::registry()` itself).
        if inv.path == ["mcp", "serve"] && inv.flag_present("stdio") {
            return Some(match mcp::serve_stdio(dispatch::registry(), dispatch::dispatch) {
                Ok(()) => output::exit::OK,
                Err(e) => {
                    eprintln!("aoide mcp serve: {e}");
                    output::exit::ERROR
                }
            });
        }

        // `a2a serve` is a long-running server, launched at the entry point
        // exactly like `mcp serve --stdio` and `conductor`: dispatch FIRST (so
        // the single audit log records the launch, and a non-Cli door — e.g. an
        // MCP `tools/call` for `a2a.serve` — gets the "run this from a terminal"
        // outcome via `handle_a2a_serve` instead of blocking that door), then
        // block in the accept loop.
        if inv.path == ["a2a", "serve"] {
            let launch = dispatch::dispatch(inv);
            if launch.status != output::Status::Ok {
                let (body, code) = launch.render(json);
                eprintln!("{body}");
                return Some(code);
            }
            let (bind, port) = a2a::resolve_bind_port(inv);
            let spawn_agent = a2a::resolve_spawn_agent(inv);
            let peer_name = a2a::resolve_peer_name(inv);
            let token_file = a2a::resolve_token_file(inv);
            let expected_token = a2a::read_expected_token(&token_file).unwrap_or_default();
            let audit_log = dispatch::audit_log_path(inv);
            // The registry is injected here too (same DI seam as `mcp serve
            // --stdio` above) — `a2a::serve` needs it to build the AgentCard.
            return Some(match a2a::serve(&bind, port, &audit_log, &spawn_agent, &peer_name, &expected_token, dispatch::registry()) {
                Ok(()) => output::exit::OK,
                Err(e) => {
                    eprintln!("aoide a2a serve: {e}");
                    output::exit::ERROR
                }
            });
        }

        // `conductor` is an interactive loop, resolved at the entry point exactly
        // like `mcp serve --stdio` — mode resolution happens here; everything
        // below the door is frontend-agnostic. We dispatch FIRST (so the single
        // audit log records the launch — the very record the LOG panel then
        // tails), then hand control to the terminal loop. The loop installs a
        // panic hook + a Drop guard that restore the terminal (leave the
        // alternate screen, disable raw mode) on ANY exit path, so a panic can
        // never leave a wedged tty.
        if inv.path == ["conductor"] {
            let launch = dispatch::dispatch(inv);
            if launch.status != output::Status::Ok {
                let (body, code) = launch.render(json);
                eprintln!("{body}");
                return Some(code);
            }
            return Some(match conductor::run(dispatch::dispatch) {
                Ok(()) => output::exit::OK,
                Err(e) => {
                    eprintln!("aoide conductor: {e}");
                    output::exit::ERROR
                }
            });
        }

        // `vault serve` is a long-running broker, launched at the entry point
        // exactly like `a2a serve`/`conductor`/`mcp serve --stdio`: dispatch
        // FIRST (records the launch through the single audit log, and gives a
        // non-Cli door — e.g. an MCP `tools/call` for `vault.serve` — the
        // "run this from a terminal" outcome via `handle_vault_serve` instead
        // of blocking that door), then block in the broker's accept loop
        // (`aoide_vault::broker::serve`).
        if inv.path == ["vault", "serve"] {
            let launch = dispatch::dispatch(inv);
            if launch.status != output::Status::Ok {
                let (body, code) = launch.render(json);
                eprintln!("{body}");
                return Some(code);
            }
            return Some(
                match vault::broker::serve(&vault::home::vault_home(), &vault::socket::socket_path()) {
                    Ok(()) => output::exit::OK,
                    Err(e) => {
                        eprintln!("aoide vault serve: {e}");
                        output::exit::ERROR
                    }
                },
            );
        }

        // `vault exec` is CLI-only, special-cased the same way: dispatch
        // FIRST (audits the launch attempt and gives every non-Cli door a
        // clean "run this from a terminal" outcome via `handle_vault_exec`),
        // then hand off to `aoide_vault::client::run_exec` — the resolved
        // value is injected as an env var and the wrapped command is exec'd
        // with `Stdio::inherit()` throughout, so its exit code (not any of
        // aoide's own exit-code vocabulary) is what this returns. The value
        // itself never touches this function, this crate, or any Outcome —
        // see `aoide_vault::client`'s module doc.
        if inv.path == ["vault", "exec"] {
            let launch = dispatch::dispatch(inv);
            if launch.status != output::Status::Ok {
                let (body, code) = launch.render(json);
                eprintln!("{body}");
                return Some(code);
            }
            return Some(vault::client::run_exec(inv, &vault::socket::socket_path()));
        }

        // `vault enroll` (P-V3) is special-cased the SAME way as `vault
        // exec`, for the same reason: the printed `otpauth://` URI + base32
        // secret must never ride the generic `Outcome` envelope (this
        // crate's `AGENTS.md`). Dispatch first (audits the launch attempt
        // and gives every non-Cli door the clean "run it from a terminal"
        // outcome via `handle_vault_enroll`, touching no vault-home file),
        // then hand off to `aoide_vault::enroll::run`, which does the real
        // work — generate/persist/print — and prints the secret directly
        // to stdout.
        if inv.path == ["vault", "enroll"] {
            let launch = dispatch::dispatch(inv);
            if launch.status != output::Status::Ok {
                let (body, code) = launch.render(json);
                eprintln!("{body}");
                return Some(code);
            }
            let force = inv.flag_present("force");
            return Some(match vault::enroll::run(&vault::home::vault_home(), force) {
                Ok(()) => output::exit::OK,
                Err(e) => {
                    eprintln!("aoide vault enroll: {e}");
                    output::exit::ERROR
                }
            });
        }

        // `guide` in text mode prints the full onboarding rather than a summary.
        if inv.path == ["guide"] && !json {
            print!("{}", guide::GUIDE);
            return Some(output::exit::OK);
        }

        // `schema --json` emits the raw contract document at top level (CONTRACTS
        // §3), NOT wrapped in the generic outcome envelope — it is the source of
        // truth the MCP tool list and external tooling parse directly.
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

        None
    })
}
