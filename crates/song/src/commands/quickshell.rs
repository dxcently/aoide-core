//! `quickshell reload` — trigger Quickshell's in-process reload via IPC.
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
        path: ["quickshell", "reload"],
        summary: "Trigger Quickshell's in-process reload via IPC — rebuilds the whole scene from shell.qml, picking up dynamically-loaded widget/facet QML the file watcher can't track. No systemd restart. No-ops gracefully if quickshell isn't running.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_quickshell_reload,
    ));
    r.insert(cmd!(
        path: ["quickshell", "healthcheck"],
        summary: "Detect and recover the placeholder-screen lockup: aoide-quickshell.service alive but rendered onto Qt's internal placeholder screen after a transient output blip, painting no layer-shell surfaces anywhere. Restarts the service to reattach, spacing repeated attempts along a retry ladder (immediate, then 15s/60s/5m, settling at 15m) that slows down but never stops. Meant to run off a systemd timer, not interactively.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_quickshell_healthcheck,
    ));
}

/// `quickshell reload` — best-effort, always `Outcome::ok` regardless of
/// whether the underlying IPC call actually reached a live instance: not
/// running, or the call itself failing, are reported facts, not command
/// failures (same posture as `rice stage`'s own `hyprctl`/reload folding).
fn handle_quickshell_reload(_inv: &Invocation) -> Outcome {
    let status = crate::ipc::quickshell_ipc_reload();
    Outcome::ok("quickshell.reload", status.message())
        .with_data(json!({ "status": status.tag() }))
}

/// `quickshell healthcheck` — best-effort, always `Outcome::ok`: whether
/// nothing was wrong, a restart was fired, or a restart was withheld under
/// backoff are all reported facts, not command failures (same posture as
/// `handle_quickshell_reload` above).
fn handle_quickshell_healthcheck(_inv: &Invocation) -> Outcome {
    let outcome = crate::health::run_healthcheck();
    Outcome::ok("quickshell.healthcheck", outcome.message())
        .with_data(json!({ "status": outcome.tag() }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aoide_protocol::output::Status;

    /// Always `Ok`, whatever the live reload attempt actually resolved to —
    /// `not-running`/`failed`/`reloaded` are reported facts in `data.status`,
    /// never a command failure (best-effort tier, `ipc.rs`'s own doc
    /// comment). Deliberately doesn't assert WHICH tag: that depends on
    /// whether `aoide-quickshell.service` happens to be live on the machine
    /// running this test.
    #[test]
    fn quickshell_reload_is_always_ok_and_carries_a_status_tag() {
        let out = handle_quickshell_reload(&aoide_test_support::inv(&["quickshell", "reload"], &[]));
        assert_eq!(out.status, Status::Ok);
        assert_eq!(out.command, "quickshell.reload");
        let data = out.data.unwrap();
        assert!(data["status"].is_string(), "{data:?}");
    }
}
