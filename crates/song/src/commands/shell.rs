//! `shell reload` — trigger Quickshell's in-process reload via IPC.

use aoide_protocol::Invocation;
use aoide_protocol::output::Outcome;
use aoide_protocol::registry::{cmd, Registry};
use serde_json::json;

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["shell", "reload"],
        summary: "Trigger Quickshell's in-process reload via IPC — rebuilds the whole scene from shell.qml, picking up dynamically-loaded widget/facet QML the file watcher can't track. No systemd restart. No-ops gracefully if quickshell isn't running.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_shell_reload,
    ));
}

/// `shell reload` — best-effort, always `Outcome::ok` regardless of whether
/// the underlying IPC call actually reached a live instance: not running,
/// or the call itself failing, are reported facts, not command failures
/// (same posture as `rice stage`'s own `hyprctl`/reload folding).
fn handle_shell_reload(_inv: &Invocation) -> Outcome {
    let status = crate::ipc::quickshell_ipc_reload();
    Outcome::ok("shell.reload", status.message())
        .with_data(json!({ "status": status.tag() }))
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
    fn shell_reload_is_always_ok_and_carries_a_status_tag() {
        let out = handle_shell_reload(&aoide_test_support::inv(&["shell", "reload"], &[]));
        assert_eq!(out.status, Status::Ok);
        assert_eq!(out.command, "shell.reload");
        let data = out.data.unwrap();
        assert!(data["status"].is_string(), "{data:?}");
    }
}
