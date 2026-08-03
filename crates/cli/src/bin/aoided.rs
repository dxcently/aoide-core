//! The `aoided` binary — the orchestrator daemon skeleton.
//!
//! Owns the single policy surface: audit log, user rebuild gate, neutral event
//! stream with default-deny-per-class subscriptions (entities/aoided). This is
//! the same code path reachable via `aoide daemon`; the standalone binary is
//! what a systemd unit would launch.

use aoide::daemon;

fn main() {
    // Allow `aoided --audit-log <path>`; else use the aoide.auditLog default.
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let log = argv
        .iter()
        .position(|a| a == "--audit-log")
        .and_then(|i| argv.get(i + 1))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(daemon::default_audit_log);

    let status = daemon::run(log);
    match serde_json::to_string_pretty(&status) {
        Ok(s) => println!("{s}"),
        Err(e) => {
            eprintln!("aoided: {e}");
            std::process::exit(1);
        }
    }
}
