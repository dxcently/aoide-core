//! The code-entry dialog substrate: the generic run-a-dialog-child loop
//! ([`run_entry_dialog`]) and its outcome type ([`DialogResult`]), the
//! screen-lock probes a `--popup` gate consults before ever opening one
//! ([`locked_state`], [`is_locked`], and their two real I/O probes), the
//! spawn-retry backoff a failing dialog binary backs off on
//! ([`next_spawn_backoff`]), and the one pure string-trim
//! ([`strip_one_trailing_newline`]) every dialog child's stdout is read
//! through.
//!
//! **This is a pure extraction — every item here moved VERBATIM from
//! `aoide_secrets::watch`/`aoide_secrets::client`, generalized away from
//! secrets-specific naming and doc references only, never its mechanics**
//! (the same `aoide_protocol::feed::Follower` precedent, P-D1, this
//! module's own sibling holds — see `feed.rs`'s module doc). `aoide-secrets`
//! consumes every item back at its OLD path via a `pub use`/`use` shim
//! (`pkgs/aoide/crates/AGENTS.md`'s "no cross-crate copying" — a moved
//! symbol is re-exported, never duplicated); every external spelling
//! (`watch::ZenityResult`, `watch::locked_state`, `client::
//! strip_one_trailing_newline`, …) stays byte-identical, including which
//! ones were already fully `pub` (a `pub use` shim) versus crate-private
//! (a bare `use` shim, preserving the exact same restricted visibility).
//! The one rename is [`DialogResult`] itself (`ZenityResult` in the old
//! crate) — this substrate now backs more than one dialog binary
//! (`aoide-secrets`' `zenity`/`lyra` entry dialogs AND P-P5's own pairing
//! confirm dialog), so the type name drops the single-binary implication;
//! the shim re-exports it under the old name at the old path.
//!
//! `aoide-protocol` is the DAG leaf every domain crate already depends on
//! (`feed.rs`'s own module doc restates this crate's own dependency
//! posture: `std` and its existing dependencies only, nothing new), so it
//! is the only crate that can host a shared primitive here without adding
//! a new dependency edge; `aoide-client`'s own P-P5 popup arm (a SECOND
//! consumer, alongside `aoide-secrets`) is what actually forces the
//! extraction rather than a second copy.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

// ── screen-lock probes (`--popup`'s own gate) ────────────────────────────

/// The locker process name a `--popup`-shaped gate scans `/proc` for —
/// `AOIDE_SECRETS_LOCKER`, default `hyprlock` (`aoide-secrets`' own
/// `--popup` module doc; this resolver stayed generic on the move since
/// nothing about it is secrets-specific).
pub fn locker_process_name() -> String {
    std::env::var("AOIDE_SECRETS_LOCKER").unwrap_or_else(|_| "hyprlock".to_string())
}

/// `loginctl show-session <id> -p LockedHint --value`, gated on
/// `$XDG_SESSION_ID` being set at all — `None` on any failure (no session
/// id, `loginctl` missing, a non-zero exit, unparseable output), never an
/// error: this is one OR term of [`locked_state`], and an unanswerable
/// probe must read as "doesn't say locked," not "locked."
pub fn probe_loginctl_locked() -> Option<bool> {
    let session = std::env::var("XDG_SESSION_ID").ok()?;
    let output = Command::new("loginctl")
        .args(["show-session", &session, "-p", "LockedHint", "--value"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim() == "yes")
}

/// Is a process named `process_name` (its `/proc/<pid>/comm`, exact match
/// after trimming) currently running? Best-effort: an unreadable `/proc`
/// entry (a process that exited mid-scan, a permission gap) is skipped, not
/// fatal — same "a probe that can't answer reads as false, never crashes
/// the watcher" posture [`probe_loginctl_locked`] holds.
pub fn probe_locker_running(process_name: &str) -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else { return false };
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let comm_path = entry.path().join("comm");
        if let Ok(comm) = std::fs::read_to_string(&comm_path) {
            if comm.trim() == process_name {
                return true;
            }
        }
    }
    false
}

/// The locked-state OR: `loginctl`'s own `LockedHint` (`None` when it can't
/// answer — treated as "doesn't say locked", never as "locked") OR'd with a
/// named locker process's own liveness (some lockers, e.g. hyprlock 0.9.6,
/// carry no `SetLockedHint` symbol, so this half can be load-bearing on its
/// own). Pure — the two real probes ([`probe_loginctl_locked`]/
/// [`probe_locker_running`]) are thin I/O wrappers this function never
/// calls itself, the same clock-as-parameter split this substrate's own
/// callers hold for their own real-time reads.
pub fn locked_state(loginctl_locked: Option<bool>, locker_running: bool) -> bool {
    loginctl_locked.unwrap_or(false) || locker_running
}

/// The real locked-state read — wires the two probes above into
/// [`locked_state`]. The only place either probe is meant to be called
/// from a `--popup`-shaped loop.
pub fn is_locked(locker_process: &str) -> bool {
    locked_state(probe_loginctl_locked(), probe_locker_running(locker_process))
}

// ── spawn-retry backoff ──────────────────────────────────────────────────

/// A dialog loop's spawn-retry backoff floor: a failing dialog spawn (the
/// binary went missing, the display died mid-session — anything short of
/// an up-front availability check, which already refuses to even enter
/// popup mode) must not busy-loop a fresh `Command::spawn` every poll tick
/// forever. [`next_spawn_backoff`] doubles from this floor up to
/// [`SPAWN_BACKOFF_MAX`] on each consecutive failure; a SUCCESSFUL spawn
/// (any [`DialogResult`] other than `SpawnError`) resets it straight back
/// here. Deliberately not wired through any tolerant-env-override shape —
/// this is an internal retry cadence, not a user-facing knob.
pub const SPAWN_BACKOFF_INITIAL: Duration = Duration::from_secs(1);

/// Ceiling [`next_spawn_backoff`] never exceeds — see
/// [`SPAWN_BACKOFF_INITIAL`]'s own doc for the full policy.
pub const SPAWN_BACKOFF_MAX: Duration = Duration::from_secs(60);

/// The doubling step itself, pure — `1s, 2s, 4s, 8s, 16s, 32s, 60s, 60s,
/// ...`, capped at [`SPAWN_BACKOFF_MAX`] rather than overflowing or
/// wrapping past it.
pub fn next_spawn_backoff(current: Duration) -> Duration {
    current.saturating_mul(2).min(SPAWN_BACKOFF_MAX)
}

// ── the dialog-child run loop ─────────────────────────────────────────────

/// The `--extra-button` label a dialog-reading loop recognizes as an
/// explicit dismiss (as opposed to a bare Cancel/Escape/window-close) — a
/// dialog's own contract: pressing an extra button exits non-zero (the
/// SAME status a bare Cancel produces) but prints the button's own label
/// to stdout instead of the entry's typed value, which is the one thing
/// that tells the two apart. `aoide-secrets`' own `--popup` dialogs use
/// this exact label; P-P5's pairing confirm dialog uses its own distinct
/// `"Reject request"` label instead (F6) rather than reusing this one —
/// two different ceremonies, two different labels, one shared reader.
pub const DISMISS_LABEL: &str = "Dismiss ask";

/// The exit code that means "the dialog infrastructure itself failed" —
/// NEVER a user action, never collapsed into [`DialogResult::Cancelled`].
/// Mirrors `aoide_lyra::commands::secrets::EXIT_INFRA_FAILURE` byte for
/// byte; there is no shared Rust type to enforce that agreement (no crate
/// in this workspace may depend on `aoide-lyra` — root `AGENTS.md`'s
/// core/paint boundary), so both constants carry this SAME comment
/// pointing at the other file. A dialog's OWN real exit codes are
/// `0`/`1`/a `--timeout`-only range, none of which collide with this one
/// in practice, so checking for it unconditionally in [`run_entry_dialog`]
/// — regardless of which binary answered — is safe.
pub const LYRA_INFRA_FAILURE_EXIT: i32 = 3;

/// Outcome of one code-entry dialog round trip — never a bare `Result`,
/// since "the user closed it," "a wrong code," "spawning it failed," and
/// "the dialog infrastructure itself broke" are four different things the
/// caller must react to differently. `ZenityResult` in `aoide-secrets`
/// before P-P5 — renamed on the move to `aoide-protocol` since this
/// substrate now backs more than one dialog binary and more than one
/// ceremony; `aoide-secrets`' own shim re-exports it under the old name.
#[derive(Debug)]
pub enum DialogResult {
    /// Exit 0 — the value the user typed, trimmed of exactly the one
    /// trailing newline a dialog's own stdout carries
    /// ([`strip_one_trailing_newline`], reused verbatim — never a blanket
    /// `.trim()`).
    Approved(String),
    /// Non-zero exit, stdout was the [`DISMISS_LABEL`] extra button.
    Dismissed,
    /// Non-zero exit, anything else — Cancel, Escape, or the window closed.
    Cancelled,
    /// The underlying request stopped being relevant (resolved elsewhere)
    /// WHILE the dialog sat open; the child was killed by its exact pid
    /// before this returned.
    CancelledExternally,
    /// The dialog process could not be spawned or waited on at all (an
    /// `io::Error` from `Command::spawn`/`Child::try_wait`).
    SpawnError(String),
    /// The dialog process spawned and ran, but exited signaling
    /// [`LYRA_INFRA_FAILURE_EXIT`] — a genuine infrastructure failure,
    /// never a user action. The `String` names the exit status only (a
    /// `lyra`-shaped caller inherits that child's stderr straight through
    /// to its own, so the actual failure detail already reached the
    /// journal directly and does not need to be re-captured here).
    DialogFailure(String),
}

/// Run one code-entry dialog CHILD to completion, polling every 200ms
/// between the dialog's own exit and `should_cancel()` — the mechanism
/// behind [`DialogResult::CancelledExternally`]: `should_cancel` is the
/// caller's own "is this request still live?" check, so a request that
/// resolves elsewhere while this dialog sits open gets its EXACT child
/// killed via the `Child` handle this function already holds (never a
/// re-derived pid, never a name match) rather than left orphaned on
/// screen for a request that no longer exists. Generic over HOW the child
/// was spawned (`spawn` is called exactly once, inside here, so a failed
/// spawn is still reported as [`DialogResult::SpawnError`]) — this is the
/// ONE place any dialog binary's exit status/stdout is parsed, so every
/// dialog binary sharing this loop must share its output CONTRACT (exit
/// 0 = typed value on stdout, exit 1 + `dismiss_label` on stdout =
/// dismissed, exit 1 + anything else on stdout (including empty) =
/// cancelled, [`LYRA_INFRA_FAILURE_EXIT`] = infrastructure failure).
///
/// `dismiss_label` is a PARAMETER, not [`DISMISS_LABEL`] read internally —
/// two different ceremonies share this loop with two different extra-
/// button labels (`aoide-secrets`' own dialogs pass [`DISMISS_LABEL`]
/// itself; P-P5's pairing confirm dialog passes its own distinct
/// `"Reject request"` label) and the loop must compare against whichever
/// one the caller's own dialog was actually built with.
pub fn run_entry_dialog(
    spawn: impl FnOnce() -> std::io::Result<Child>,
    dismiss_label: &str,
    mut should_cancel: impl FnMut() -> bool,
) -> DialogResult {
    let mut child = match spawn() {
        Ok(c) => c,
        Err(e) => return DialogResult::SpawnError(e.to_string()),
    };

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut raw = String::new();
                if let Some(mut out) = child.stdout.take() {
                    let _ = out.read_to_string(&mut raw);
                }
                let out = strip_one_trailing_newline(raw);
                return if status.success() {
                    DialogResult::Approved(out)
                } else if out == dismiss_label {
                    DialogResult::Dismissed
                } else if status.code() == Some(LYRA_INFRA_FAILURE_EXIT) {
                    // Checked BEFORE falling through to `Cancelled` — the
                    // ONE branch point this whole distinction exists for
                    // ([`DialogResult::DialogFailure`]'s own doc).
                    DialogResult::DialogFailure(format!("dialog child exited with status {status}"))
                } else {
                    DialogResult::Cancelled
                };
            }
            Ok(None) => {
                if should_cancel() {
                    let _ = child.kill();
                    let _ = child.wait();
                    return DialogResult::CancelledExternally;
                }
                thread::sleep(Duration::from_millis(200));
            }
            Err(e) => return DialogResult::SpawnError(e.to_string()),
        }
    }
}

/// Feature-detect a dialog binary at startup — spawn failure IS the
/// detection, never a separate "is it on PATH" probe.
pub fn zenity_available(zenity_cmd: &str) -> bool {
    Command::new(zenity_cmd).arg("--version").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok()
}

// ── the one pure trim ─────────────────────────────────────────────────────

/// Strip exactly ONE trailing `\n`, never a blanket `.trim_end()` — a
/// subprocess's own stdout line carries the newline its own `echo`/
/// `printf` produced; this removes that one character and nothing else a
/// typed/pasted value might legitimately end with. Pure and total, so it
/// stays independently unit tested with no tty involved.
pub fn strip_one_trailing_newline(mut s: String) -> String {
    if s.ends_with('\n') {
        s.pop();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    // ── locked_state (the OR logic, injected probes) ─────────────────

    #[test]
    fn locked_state_true_when_loginctl_says_locked() {
        assert!(locked_state(Some(true), false));
    }

    #[test]
    fn locked_state_true_when_the_locker_process_is_running_even_if_loginctl_disagrees() {
        assert!(locked_state(Some(false), true));
    }

    #[test]
    fn locked_state_true_when_loginctl_cant_answer_but_the_locker_process_is_running() {
        assert!(locked_state(None, true));
    }

    #[test]
    fn locked_state_false_when_neither_signal_says_locked() {
        assert!(!locked_state(Some(false), false));
        assert!(!locked_state(None, false));
    }

    // ── next_spawn_backoff (spawn-retry doubling, pure) ────────────────

    #[test]
    fn next_spawn_backoff_doubles_from_the_floor() {
        assert_eq!(next_spawn_backoff(SPAWN_BACKOFF_INITIAL), Duration::from_secs(2));
        assert_eq!(next_spawn_backoff(Duration::from_secs(2)), Duration::from_secs(4));
        assert_eq!(next_spawn_backoff(Duration::from_secs(4)), Duration::from_secs(8));
    }

    #[test]
    fn next_spawn_backoff_caps_at_the_ceiling_and_never_exceeds_it() {
        assert_eq!(next_spawn_backoff(Duration::from_secs(32)), SPAWN_BACKOFF_MAX);
        assert_eq!(next_spawn_backoff(SPAWN_BACKOFF_MAX), SPAWN_BACKOFF_MAX);
        assert_eq!(next_spawn_backoff(Duration::from_secs(1000)), SPAWN_BACKOFF_MAX);
    }

    // ── strip_one_trailing_newline (pure) ──────────────────────────────

    #[test]
    fn strip_one_trailing_newline_removes_exactly_one() {
        assert_eq!(strip_one_trailing_newline("hunter2\n".to_string()), "hunter2");
        assert_eq!(strip_one_trailing_newline("hunter2\n\n".to_string()), "hunter2\n");
        assert_eq!(strip_one_trailing_newline("hunter2".to_string()), "hunter2");
        assert_eq!(strip_one_trailing_newline(String::new()), "");
        // Trailing spaces in a pasted value are NOT eaten — only the one
        // newline the Enter key produced, never a blanket `.trim_end()`.
        assert_eq!(strip_one_trailing_newline("hunter2  \n".to_string()), "hunter2  ");
    }

    // ── zenity_available (feature-detect, real spawn) ──────────────────

    /// Serializes this module's own write-a-shim-then-exec-it tests
    /// against each other — the same genuine `execve()`/`close()` TOCTOU
    /// `aoide_secrets::watch`'s own `shim_lock` documents at length
    /// (`crates/secrets/src/watch.rs`, the "Text file busy" flake found
    /// under heavy parallel contention). This module carries only one such
    /// test today, so the lock is a cheap defensive precedent rather than
    /// a proven-necessary fix here — kept anyway so a second shim test
    /// added later doesn't have to rediscover the race.
    fn shim_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A `bash` script named explicitly (never a bare `sh`, never a `PATH`
    /// mutation) — sandbox-safe under a nix build's restricted `PATH`.
    fn write_shim(tag: &str, script: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aoide-protocol-dialog-shim-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let shim = dir.join("dialog-shim");
        std::fs::write(&shim, script).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        thread::sleep(Duration::from_millis(5));
        shim
    }

    fn remove_shim(shim: &Path) {
        if let Some(dir) = shim.parent() {
            std::fs::remove_dir_all(dir).ok();
        }
    }

    #[test]
    fn zenity_available_is_false_for_a_binary_name_that_does_not_exist() {
        assert!(!zenity_available("aoide-protocol-dialog-test-definitely-not-a-real-binary"));
    }

    #[test]
    fn zenity_available_is_true_when_the_shim_spawns_and_exits_zero() {
        let _guard = shim_lock();
        let shim = write_shim("version", "#!/usr/bin/env bash\necho zenity 3.99.0\nexit 0\n");
        assert!(zenity_available(shim.to_str().unwrap()));
        remove_shim(&shim);
    }
}
