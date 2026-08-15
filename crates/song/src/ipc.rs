//! Quickshell IPC hot-reload trigger — the running-process half of `rice
//! stage`'s hot-sync story.
//!
//! `rice stage` (and widget-body sync, `widgets.rs`) already write bytes
//! onto disk that Quickshell's own file watcher can pick up for STATICALLY
//! `import`ed QML — but every song widget loads dynamically via
//! `Qt.createComponent`, and facet-owned QML (`shell.qml`,
//! `ShellBridge.qml`, `StagingEngine.qml`, `WidgetSlot.qml`,
//! `SurfaceSlot.qml`) isn't watched at all. `Quickshell.reload(hard: bool)`
//! (`AoideIpc.qml`, exposed via `Quickshell.Io.IpcHandler`) tears down and
//! rebuilds the WHOLE scene fresh from `shell.qml` — closer to an
//! in-process restart than a selective reload — which is exactly what
//! picks those up without a `systemctl --user restart
//! aoide-quickshell.service`.
//!
//! `quickshell ipc call <target> <function>` does NOT auto-discover a
//! running instance by itself (confirmed live: it looks for a "default"
//! config directory and fails otherwise) — the instance here was launched
//! with `-p <run_qml_dir>/shell.qml` (`modules/facets/quickshell/default.nix`),
//! so the same `-p` has to prefix the `ipc call` invocation to target it.

/// The result of one `quickshell ipc call shell reload` attempt.
pub enum ReloadStatus {
    /// The IPC call was dispatched and `quickshell` exited 0.
    Reloaded,
    /// `aoide-quickshell.service` isn't running — nothing to reload, and no
    /// IPC call was even attempted.
    NotRunning,
    /// Quickshell is running, but the IPC call itself failed (nonzero exit,
    /// or the `quickshell` binary couldn't be spawned at all).
    Failed(String),
}

impl ReloadStatus {
    /// JSON-safe tag for `Outcome::with_data` payloads.
    pub fn tag(&self) -> &'static str {
        match self {
            ReloadStatus::Reloaded => "reloaded",
            ReloadStatus::NotRunning => "not-running",
            ReloadStatus::Failed(_) => "failed",
        }
    }

    /// Human-readable summary, folding the failure detail (if any) in —
    /// same idiom as `live::apply_live`'s status strings: describe what
    /// happened, never propagate as a hard error.
    pub fn message(&self) -> String {
        match self {
            ReloadStatus::Reloaded => "quickshell reloaded live via IPC".to_string(),
            ReloadStatus::NotRunning => {
                "quickshell isn't running; nothing to reload".to_string()
            }
            ReloadStatus::Failed(e) => format!("quickshell ipc reload failed: {e}"),
        }
    }
}

/// Trigger `Quickshell.reload(false)` in the live instance via `quickshell
/// ipc call shell reload`. Best-effort throughout — never panics, never
/// returns a hard error type; callers fold [`ReloadStatus`] into their own
/// `Outcome` without ever failing the surrounding command on its account
/// (mirrors `live::apply_live`'s guarded, non-fatal posture).
///
/// No-ops to [`ReloadStatus::NotRunning`] when
/// `aoide-quickshell.service` isn't up (`reap::quickshell_service_main_pid`
/// returns `None`) — the common case in this sandboxed environment, and any
/// time a rebuild/rice change lands with no live shell to show it in.
pub fn quickshell_ipc_reload() -> ReloadStatus {
    if crate::reap::quickshell_service_main_pid().is_none() {
        return ReloadStatus::NotRunning;
    }
    let shell_qml = aoide_storage::fs::run_qml_dir().join("shell.qml");
    match std::process::Command::new("quickshell")
        .arg("-p")
        .arg(shell_qml)
        .args(["ipc", "call", "shell", "reload"])
        .output()
    {
        Ok(out) if out.status.success() => ReloadStatus::Reloaded,
        Ok(out) => ReloadStatus::Failed(String::from_utf8_lossy(&out.stderr).trim().into()),
        Err(e) => ReloadStatus::Failed(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reloaded_tag_and_message() {
        assert_eq!(ReloadStatus::Reloaded.tag(), "reloaded");
        assert_eq!(ReloadStatus::Reloaded.message(), "quickshell reloaded live via IPC");
    }

    #[test]
    fn not_running_tag_and_message() {
        assert_eq!(ReloadStatus::NotRunning.tag(), "not-running");
        assert!(ReloadStatus::NotRunning.message().contains("isn't running"));
    }

    #[test]
    fn failed_tag_and_message_folds_in_the_detail() {
        let s = ReloadStatus::Failed("boom".to_string());
        assert_eq!(s.tag(), "failed");
        assert!(s.message().contains("boom"), "{}", s.message());
    }

    // `quickshell_ipc_reload()` itself isn't unit-tested here: it reads the
    // REAL `aoide-quickshell.service` state via `systemctl --user`, which is
    // environment-dependent (absent in this sandbox, but legitimately live
    // on a real desktop) — same reason `reap.rs`'s tests only exercise its
    // pure `classify()`, never the real `quickshell_service_main_pid()`.
}
