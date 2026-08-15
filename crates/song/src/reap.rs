//! Stray-process sweep for `rice mode stage` (`commands/mode.rs`). Entering
//! staging mode is meant to always leave a KNOWN-clean process slate behind
//! it — not just a marker flip — so this runs once on every unlock and kills
//! three specific patterns a prior hot-load/preview session can strand:
//!
//!   - a `quickshell`/`qs -p <file>` PREVIEW harness, where `<file>`'s
//!     basename ends `Preview.qml` — the standalone screenshot-rig
//!     convention (`CalendarPreview.qml`, `ExodosPreview.qml`, …) an agent
//!     iterating live can forget to tear down.
//!   - a SECOND live `quickshell -p .../shell.qml` process that is not the
//!     one `aoide-quickshell.service` is tracking — two shells would fight
//!     over the same layer-shell namespaces.
//!   - any `hyprlock` process at all. If this code can run interactively,
//!     the box is not actually locked, so a live `hyprlock` here is always
//!     stale (leftover from powermenu/lock testing), never a real session.
//!
//! Best-effort throughout: an unreadable `/proc` entry, a process that races
//! away mid-sweep, or a `kill` that fails is skipped, never propagated —
//! this is hygiene, not a precondition for staging to succeed.

use std::fs;
use std::path::Path;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ReapedProcess {
    pub pid: u32,
    pub reason: &'static str,
    pub cmdline: String,
}

/// Pure classification: does this argv belong to a stray process the sweep
/// should kill, and why? `None` leaves it alone. Split out from the effectful
/// sweep so the matching rules are unit-testable without touching real
/// `/proc` or spawning `kill`.
pub(crate) fn classify(argv: &[String], spared_pid: Option<u32>, pid: u32) -> Option<&'static str> {
    let bin = argv.first().map(|a| basename(a)).unwrap_or("");
    match bin {
        "hyprlock" => Some("stray-hyprlock"),
        "quickshell" | "qs" => {
            let target = argv.iter().position(|a| a == "-p").and_then(|i| argv.get(i + 1))?;
            match basename(target) {
                b if b.ends_with("Preview.qml") => Some("preview-harness"),
                "shell.qml" if spared_pid != Some(pid) => Some("duplicate-shell"),
                _ => None,
            }
        }
        _ => None,
    }
}

fn basename(path: &str) -> &str {
    Path::new(path).file_name().and_then(|n| n.to_str()).unwrap_or(path)
}

/// `/proc/<pid>/cmdline` as its argv vector (NUL-separated on disk) — kept as
/// a `Vec`, not joined, so an argument containing a space never corrupts the
/// `-p <file>` boundary [`classify`] depends on. `None` on any read failure.
fn read_argv(pid: u32) -> Option<Vec<String>> {
    let raw = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    if raw.is_empty() {
        return None;
    }
    let argv: Vec<String> = raw
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    if argv.is_empty() { None } else { Some(argv) }
}

/// Every live pid on the box right now — best-effort, an unreadable `/proc`
/// (permissions, or absent entirely off Linux) just yields nothing.
fn all_pids() -> Vec<u32> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .collect()
}

/// The pid `aoide-quickshell.service` is currently tracking, if active —
/// spared even when its argv matches the `shell.qml` pattern below. `None`
/// off Hyprland/systemd, or when the unit isn't running: nothing is spared,
/// but nothing fails either (the sweep just proceeds without a systemd
/// opinion, matching the rest of this codebase's guarded-optional posture
/// toward system services it doesn't own).
pub(crate) fn quickshell_service_main_pid() -> Option<u32> {
    let out = std::process::Command::new("systemctl")
        .args(["--user", "show", "aoide-quickshell.service", "--property=MainPID", "--value"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|&p| p != 0)
}

fn kill(pid: u32) -> bool {
    std::process::Command::new("kill")
        .arg(pid.to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Run the sweep for real: enumerate every pid, classify its argv, `kill`
/// whatever matches. Returns what it actually reaped (for the caller's
/// outcome/audit reporting) — never errors, since a failed sweep is not a
/// reason to refuse the `rice mode stage` unlock it runs inside.
pub fn reap_stray_processes() -> Vec<ReapedProcess> {
    let spared_pid = quickshell_service_main_pid();
    let mut reaped = Vec::new();
    for pid in all_pids() {
        let Some(argv) = read_argv(pid) else { continue };
        if let Some(reason) = classify(&argv, spared_pid, pid) {
            if kill(pid) {
                reaped.push(ReapedProcess { pid, reason, cmdline: argv.join(" ") });
            }
        }
    }
    reaped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn hyprlock_is_always_stray() {
        assert_eq!(classify(&argv(&["/run/current-system/sw/bin/hyprlock"]), None, 42), Some("stray-hyprlock"));
    }

    #[test]
    fn preview_harness_matches_any_star_preview_qml() {
        assert_eq!(
            classify(&argv(&["qs", "-p", "/home/khoa/Aoide/run/qml/ExodosPreview.qml"]), None, 42),
            Some("preview-harness")
        );
        assert_eq!(
            classify(&argv(&["/nix/store/xyz/bin/quickshell", "-p", "run/qml/CalendarPreview.qml"]), None, 42),
            Some("preview-harness")
        );
    }

    #[test]
    fn duplicate_shell_qml_is_stray_unless_it_is_the_spared_pid() {
        let a = argv(&["quickshell", "-p", "/home/khoa/Aoide/run/qml/shell.qml"]);
        assert_eq!(classify(&a, None, 99), Some("duplicate-shell"));
        assert_eq!(classify(&a, Some(1234), 99), Some("duplicate-shell"));
        assert_eq!(classify(&a, Some(99), 99), None, "the systemd-tracked pid itself is spared");
    }

    #[test]
    fn quickshell_with_no_dash_p_flag_is_left_alone() {
        assert_eq!(classify(&argv(&["quickshell"]), None, 42), None);
    }

    #[test]
    fn quickshell_loading_a_non_preview_non_shell_file_is_left_alone() {
        // Conservative: only the two known patterns get touched, nothing else.
        assert_eq!(
            classify(&argv(&["quickshell", "-p", "run/qml/AoideLauncher.qml"]), None, 42),
            None
        );
    }

    #[test]
    fn unrelated_processes_are_never_touched() {
        assert_eq!(classify(&argv(&["bash", "-c", "cargo test"]), None, 42), None);
        assert_eq!(classify(&argv(&[]), None, 42), None);
    }
}
