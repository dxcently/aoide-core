//! Aoide — the CLI trunk, the MCP façade, and the aoided daemon skeleton.
//!
//! One crate, two binaries (`aoide`, `aoided`), one schema. Everything the CLI
//! door and the MCP door can do is described once in [`schema`] and executed
//! once in [`dispatch`]; the two doors cannot drift (concepts/Agent-Interface).

pub mod adapter;
pub mod conductor;
pub mod cli;
pub mod daemon;
pub mod dispatch;
pub mod graph;
pub mod reap;
pub mod guide;
pub mod hypr;
pub mod mcp;
pub mod notes;
pub mod output;
pub mod schema;
pub mod shellbridge;

use daemon::Door;

/// Run the `aoide` CLI trunk. Returns the process exit code.
///
/// `argv` excludes the program name. Special-cases: `mcp serve --stdio` starts
/// the MCP server; `guide` prints the onboarding text; everything else routes
/// through the single dispatcher (so the audit log + gate apply uniformly).
pub fn run_cli(argv: &[String]) -> i32 {
    // Determine `--json` up front for uniform rendering of parse errors too.
    let (inv, json) = match cli::parse(argv, Door::Cli) {
        Ok(v) => v,
        Err(o) => {
            let json = wants_json(argv);
            let (body, code) = o.render(json);
            if code == output::exit::OK {
                // Informational (a `--help`/`-h` usage block): to stdout, exit 0.
                // Text mode prints the raw usage; `--json` still emits the
                // envelope so a tool reading `--help --json` gets structure.
                if json {
                    println!("{body}");
                } else {
                    println!("{}", o.message);
                }
            } else {
                eprintln!("{body}");
            }
            return code;
        }
    };

    // `mcp serve --stdio` is a long-running server, not a one-shot dispatch.
    if inv.path == ["mcp", "serve"] && inv.flag_present("stdio") {
        return match mcp::serve_stdio() {
            Ok(()) => output::exit::OK,
            Err(e) => {
                eprintln!("aoide mcp serve: {e}");
                output::exit::ERROR
            }
        };
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
        let launch = dispatch::dispatch(&inv);
        if launch.status != output::Status::Ok {
            let (body, code) = launch.render(json);
            eprintln!("{body}");
            return code;
        }
        return match conductor::run() {
            Ok(()) => output::exit::OK,
            Err(e) => {
                eprintln!("aoide conductor: {e}");
                output::exit::ERROR
            }
        };
    }

    // `guide` in text mode prints the full onboarding rather than a summary.
    if inv.path == ["guide"] && !json {
        print!("{}", guide::GUIDE);
        return output::exit::OK;
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
        let doc = schema::schema();
        let body = serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into());
        println!("{body}");
        return output::exit::OK;
    }

    let outcome = dispatch::dispatch(&inv);
    let (body, code) = outcome.render(json);
    if code == output::exit::OK {
        println!("{body}");
    } else {
        eprintln!("{body}");
    }
    code
}

/// Did argv contain `--json` anywhere? (used before full parse for errors).
fn wants_json(argv: &[String]) -> bool {
    argv.iter().any(|a| a == "--json" || a == "--json=true")
}

/// A crate-wide lock serialising every test that mutates process-global env
/// (`AOIDE_STAGE_DIR`, `PATH`, `AOIDE_DRACHMA_BIN`, …). `std::env::set_var` is
/// process-global, so env-touching tests across modules must share ONE mutex or
/// they race each other under the multithreaded test harness.
#[cfg(test)]
pub(crate) fn env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    &LOCK
}
