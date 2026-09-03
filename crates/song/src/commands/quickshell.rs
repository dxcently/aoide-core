//! `quickshell healthcheck` — the placeholder-screen lockup watchdog.
//!
//! `quickshell reload` DIED into the top-level `reload` command
//! (`commands/reload.rs`, `lyra reload` design settled 2026-08-31): the
//! declarative arm of that command's mode-aware dispatch IS this file's old
//! `handle_quickshell_reload` byte-for-byte — hard cutover, no alias, the
//! `peer invite` precedent. `healthcheck` is a watchdog, not an iteration
//! step, so it stays here, untouched, its own command.
//!
//! Named `quickshell`, not `shell` (the User, 2026-08-15): a top-level command
//! whose first path segment is `shell` collides with `--agent shell`, the
//! value `graph conduct`/`aoide-shell`'s kitty wrapper have used for a long
//! time — `is_command_token` (now `protocol/src/door.rs`, position-blind at
//! the time) treated any bare token matching a REGISTERED command's first
//! segment as the start of a new subcommand
//! rather than a flag's value, so `--agent shell` silently stopped being
//! consumed as a flag once `shell` became a real command, and the actual
//! program to conduct (the login shell) got pushed out of `inv.args[0]` —
//! confirmed live: every terminal opened via kitty closed immediately,
//! `conduct: failed to conduct \`shell\`: No such file or directory`.
//! `quickshell` doesn't collide with any known `--agent` value.

use aoide_protocol::Invocation;
use aoide_protocol::output::Outcome;
use aoide_protocol::registry::{cmd, Registry};
use serde_json::json;

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["quickshell", "healthcheck"],
        summary: "Detect and recover the placeholder-screen lockup: aoide-quickshell.service alive but rendered onto Qt's internal placeholder screen after a transient output blip, painting no layer-shell surfaces anywhere. Restarts the service to reattach, spacing repeated attempts along a retry ladder (immediate, then 15s/60s/5m, settling at 15m) that slows down but never stops. A desktop painting nothing for some other reason reports 'blank' and is left alone — named, not restarted, since the placeholder screen is the only mechanism this watchdog knows how to undo. Meant to run off a systemd timer, not interactively.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_quickshell_healthcheck,
    ));
}

/// `quickshell healthcheck` — best-effort, always `Outcome::ok`: whether
/// nothing was wrong, the desktop is blank for a reason this watchdog
/// cannot undo, a restart was fired, or a restart was withheld under
/// backoff are all reported facts, not command failures (same posture as
/// `reload`'s declarative arm, `commands/reload.rs`).
fn handle_quickshell_healthcheck(_inv: &Invocation) -> Outcome {
    let outcome = crate::health::run_healthcheck();
    Outcome::ok("quickshell.healthcheck", outcome.message())
        .with_data(json!({ "status": outcome.tag() }))
}
