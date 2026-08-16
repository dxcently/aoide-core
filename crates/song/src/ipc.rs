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
//!
//! ── Why success is judged on OUTPUT, not the exit code (khoa, 2026-08-15) ──
//! `quickshell ipc call` exits 0 whether or not the call actually reached a
//! handler. Measured against the live instance, all four cases:
//!
//! | invocation          | exit | stdout                                  |
//! |---------------------|------|-----------------------------------------|
//! | real `shell reload` |   0  | *(empty)*                               |
//! | unknown function    |   0  | `Not ready to accept queries yet.`      |
//! | unknown target      |   0  | `Not ready to accept queries yet.`      |
//! | bad `-p` path       | 255  | `Could not open config file at "..."`   |
//!
//! So the first cut of this module — `out.status.success() => Reloaded` —
//! reported `"reloaded"` for a call that never ran, and would have kept
//! reporting it if `AoideIpc.qml` were deleted outright. It also read
//! `out.stderr` for the failure detail, but quickshell writes ALL of this to
//! stdout, so the `Failed` arm carried an empty reason.
//!
//! The discriminator is that `reload()` is declared `: void` in
//! `AoideIpc.qml` — a void IPC call that reaches its handler prints NOTHING,
//! and `ipc call` prints a returning function's value. So for THIS call, any
//! output at all means it did not land. That invariant is why the check is
//! narrow: it holds because the function is void, and a future non-void IPC
//! verb would need its own success test rather than this one.
//!
//! This matters more than it looks: quickshell's own file watcher only scans
//! the TOP LEVEL of `run/qml/`, never `run/qml/songs/`, so a `rice stage`
//! can never trigger a reload on its own — it depends entirely on this call.
//! A silently-unearned "reloaded" therefore reads as "your edit is live"
//! while nothing on screen has changed.

/// The result of one `quickshell ipc call shell reload` attempt.
pub enum ReloadStatus {
    /// The IPC call reached its handler: `quickshell` exited 0 AND printed
    /// nothing (see the module header — a void call that lands is silent).
    Reloaded,
    /// `aoide-quickshell.service` isn't running — nothing to reload, and no
    /// IPC call was even attempted.
    NotRunning,
    /// Quickshell is running, but the IPC call itself failed — nonzero exit,
    /// output where a landed void call prints none (unknown target/function),
    /// or the `quickshell` binary couldn't be spawned at all.
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
        Ok(out) => classify_call(
            out.status.success(),
            &String::from_utf8_lossy(&out.stdout),
            &String::from_utf8_lossy(&out.stderr),
        ),
        Err(e) => ReloadStatus::Failed(e.to_string()),
    }
}

/// Judge one finished `quickshell ipc call` from its exit status and output,
/// per the matrix in the module header. Split out as a pure function so that
/// matrix is actually unit-tested — [`quickshell_ipc_reload`] itself can't be,
/// since it reads the real `aoide-quickshell.service` (the same reason
/// `reap.rs` only tests its pure `classify()`).
///
/// Reads stdout FIRST because that is where quickshell puts every one of
/// these messages, with stderr as a fallback so a future version that moves
/// them doesn't silently regress this back to a blank reason.
fn classify_call(exited_ok: bool, stdout: &str, stderr: &str) -> ReloadStatus {
    let said = {
        let o = stdout.trim();
        if o.is_empty() { stderr.trim() } else { o }
    };
    if !exited_ok {
        return ReloadStatus::Failed(if said.is_empty() {
            "quickshell exited nonzero with no message".to_string()
        } else {
            said.to_string()
        });
    }
    // Exit 0 is NOT sufficient (header matrix): a void call that reached its
    // handler is silent, so anything spoken here means it didn't.
    if said.is_empty() {
        ReloadStatus::Reloaded
    } else {
        ReloadStatus::Failed(said.to_string())
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

    // ── The measured matrix from the module header, as tests ──────────────
    // Each case below was captured from the live instance on 2026-08-15;
    // the first two are the ones the original `status.success()` check got
    // WRONG (it called them "reloaded").

    #[test]
    fn a_silent_exit_zero_is_the_only_real_success() {
        assert_eq!(classify_call(true, "", "").tag(), "reloaded");
        // trailing newline from the process is not "output"
        assert_eq!(classify_call(true, "\n", "").tag(), "reloaded");
    }

    #[test]
    fn exit_zero_that_speaks_is_a_failure_not_a_reload() {
        let s = classify_call(true, "Not ready to accept queries yet.\n", "");
        assert_eq!(s.tag(), "failed", "unknown target/function exits 0 — see header");
        assert!(s.message().contains("Not ready"), "{}", s.message());
    }

    #[test]
    fn the_reason_is_read_from_stdout_where_quickshell_actually_writes_it() {
        let s = classify_call(false, "Could not open config file at \"/nope\"", "");
        assert_eq!(s.tag(), "failed");
        assert!(s.message().contains("Could not open config file"), "{}", s.message());
    }

    #[test]
    fn stderr_is_the_fallback_so_a_future_move_cannot_blank_the_reason() {
        let s = classify_call(false, "", "moved to stderr");
        assert!(s.message().contains("moved to stderr"), "{}", s.message());
    }

    #[test]
    fn a_mute_nonzero_exit_still_explains_itself() {
        let s = classify_call(false, "", "");
        assert_eq!(s.tag(), "failed");
        assert!(s.message().contains("nonzero"), "{}", s.message());
    }

    // `quickshell_ipc_reload()` itself isn't unit-tested here: it reads the
    // REAL `aoide-quickshell.service` state via `systemctl --user`, which is
    // environment-dependent (absent in this sandbox, but legitimately live
    // on a real desktop) — same reason `reap.rs`'s tests only exercise its
    // pure `classify()`, never the real `quickshell_service_main_pid()`.
}
