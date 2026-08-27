//! The `aoided` binary — the resident orchestrator daemon (P-D2/P-D4,
//! `docs/architecture/AOIDED.md`).
//!
//! Owns the single policy surface: audit log, user rebuild gate, neutral event
//! stream with default-deny-per-class subscriptions (entities/aoided). Binds
//! its own control socket (`ping`/`subscribe`/`dispatch` — the fourth door
//! onto this binary's own registry) and runs
//! forever — this is what the systemd unit execs (`modules/nucleus/
//! aoided.nix`, `Type=simple` + `Restart=on-failure` as of this phase).
//! `dispatch::registry()`/`dispatch::dispatch` are injected here — the SAME
//! DI seam `mcp serve --stdio`/`a2a serve` close at their own launch sites
//! (`lib.rs`'s `run_cli`) — because `aoide-server` sits BELOW this crate and
//! cannot reach the fully-assembled registry itself
//! (`aoide_server::daemon`'s own module doc).

use aoide::daemon;
use aoide::dispatch;

fn main() {
    // One-shot, idempotent `~/Aoide` → `$AOIDE_ROOT` migration (L-C2, task
    // #107) — see `aoide_storage::fs::root`'s own doc for why this runs
    // here, explicitly, rather than hanging off a path getter.
    aoide_storage::fs::migrate_root_once();

    // Allow `aoided --audit-log <path>`; else use the aoide.auditLog default.
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let log = argv
        .iter()
        .position(|a| a == "--audit-log")
        .and_then(|i| argv.get(i + 1))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(daemon::default_audit_log);

    let socket = daemon::socket_path();
    let events = daemon::events_path(&socket);

    if let Err(e) = daemon::run_loop(socket, events, log, dispatch::registry(), dispatch::dispatch) {
        eprintln!("aoided: {e}");
        std::process::exit(1);
    }
}
