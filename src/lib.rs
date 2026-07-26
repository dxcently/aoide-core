//! Aoide — the CLI trunk, the MCP façade, and the aoided daemon skeleton.
//!
//! One crate, two binaries (`aoide`, `aoided`), one schema. Everything the CLI
//! door and the MCP door can do is described once in [`schema`] and executed
//! once in [`dispatch`]; the two doors cannot drift (concepts/Agent-Interface).

pub mod adapter;
pub mod cli;
pub mod daemon;
pub mod dispatch;
pub mod guide;
pub mod mcp;
pub mod output;
pub mod schema;
pub mod shellbridge;
pub mod tokens;

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
        Err(usage) => {
            let (body, code) = usage.render(wants_json(argv));
            eprintln!("{body}");
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
