//! Live watchdog for the quickshell placeholder-screen lockup.
//!
//! `aoide-quickshell.service`'s `Restart=on-failure` (`modules/facets/
//! quickshell/default.nix`) is useless against one specific failure mode:
//! after a transient output blip on the real monitor, Qt's wayland QPA
//! backend sometimes falls onto an internal placeholder screen and never
//! reattaches even once the real output returns — the process stays
//! `active` (no crash, no exit), so systemd has nothing to restart on.
//! Confirmed live 2026-08-28 and twice more 2026-08-29: the desktop (bar/
//! dock/wallpaper/herald) goes bare for hours until someone notices and runs
//! `systemctl --user restart aoide-quickshell.service` by hand. A rebuild-
//! time mitigation already exists (`home.activation.aoideRestartRice`), but
//! it only fires on a nix switch, not live mid-session — this closes that
//! gap with a periodic check (`aoide-quickshell-healthcheck.timer`).
//!
//! Detection combines two signals because neither is reliable alone:
//! Quickshell's own journal line (`There are no outputs - creating
//! placeholder screen`, emitted by Qt's QPA layer at the exact moment of the
//! failure) confirms the EVENT happened, but not whether it's still true —
//! a blip that self-healed before this runs would still show the line.
//! `hyprctl layers` showing zero `aoide-*` surfaces anywhere confirms the
//! CURRENT state, but is also true for the first second or two after any
//! normal start/reload, which is not a lockup. Requiring both, scoped to the
//! journal since the unit's own `ActiveEnterTimestamp` (so an old, already-
//! recovered-from occurrence can never re-trigger after a restart moves that
//! timestamp forward), rules out the reload-window false positive.
//!
//! The second signal counts the shell's OWN surfaces system-wide rather than
//! checking any one monitor: none of `modules/facets/quickshell/qml/`'s
//! `PanelWindow`s are per-screen (no `Variants`, no `Quickshell.screens`, no
//! `screen:` binding anywhere in that tree — each is declared once,
//! unconditionally), so this shell always paints exactly one output. On a
//! multi-monitor host every other enabled monitor legitimately and
//! permanently carries zero layers forever, by design — a per-monitor "is
//! any enabled monitor empty" test would read that as stuck and restart a
//! healthy desktop. Summing `aoide-`-namespaced surfaces across every
//! monitor and every level instead makes the signal monitor-count-agnostic:
//! zero total means the shell is painting nothing anywhere, which is the
//! actual failure; nonzero means it is painting something, somewhere, on
//! whichever single output it owns.
//!
//! No QML-side fix exists for this: `Quickshell.screens` is populated below
//! QML by `QGuiApplication`'s wayland platform plugin, so no in-process
//! `Quickshell.reload()`/`onScreensChanged` handler can reach or reset the
//! stuck QPA state — only a full process re-exec does, which is exactly
//! what [`run_healthcheck`]'s restart provides.

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// A 3rd trigger inside this many seconds withholds the restart instead of
/// looping forever against a genuinely flapping output (suspected hub/GPU
/// power-state issue, not yet confirmed) — see [`backoff_engaged`].
const BACKOFF_WINDOW_SECS: i64 = 300;
const BACKOFF_CAP: usize = 3;

/// The result of one `aoide quickshell healthcheck` run.
pub enum HealthOutcome {
    /// No lockup detected (including: the service isn't running at all —
    /// nothing to watch).
    Healthy,
    /// Confirmed stuck; the service was restarted.
    Restarted,
    /// Confirmed stuck again, but [`backoff_engaged`] withheld the restart —
    /// a herald notification was fired instead.
    BackoffWithheld,
}

impl HealthOutcome {
    pub fn tag(&self) -> &'static str {
        match self {
            HealthOutcome::Healthy => "healthy",
            HealthOutcome::Restarted => "restarted",
            HealthOutcome::BackoffWithheld => "backoff-withheld",
        }
    }

    pub fn message(&self) -> String {
        match self {
            HealthOutcome::Healthy => "quickshell is healthy".to_string(),
            HealthOutcome::Restarted => {
                "quickshell was stuck on a placeholder screen; restarted".to_string()
            }
            HealthOutcome::BackoffWithheld => {
                "quickshell is stuck again but the restart backoff engaged; notified instead"
                    .to_string()
            }
        }
    }
}

/// Pure: does this journal tail contain the exact line Qt's QPA wayland
/// backend emits when it falls onto its internal placeholder screen? Split
/// from the journal read itself so the string match is unit-tested without
/// a real `journalctl`.
pub(crate) fn journal_shows_placeholder(journal_tail: &str) -> bool {
    journal_tail.contains("no outputs") && journal_tail.contains("creating placeholder screen")
}

/// Pure: total `aoide-`-namespaced layer-shell surfaces `hyprctl layers -j`
/// reports, summed across every monitor and every level. This is the
/// shell's own footprint, not any one output's — see the module header for
/// why a per-monitor count is the wrong shape on a multi-monitor host.
pub(crate) fn total_aoide_layers(layers: &Value) -> usize {
    let Some(monitors) = layers.as_object() else {
        return 0;
    };
    monitors
        .values()
        .filter_map(|m| m.get("levels"))
        .filter_map(Value::as_object)
        .flat_map(|levels| levels.values())
        .filter_map(Value::as_array)
        .flatten()
        .filter(|surface| {
            surface.get("namespace").and_then(Value::as_str).is_some_and(|ns| ns.starts_with("aoide-"))
        })
        .count()
}

/// Pure: is the shell painting nothing anywhere? `true` is the stuck signal
/// — zero `aoide-*` surfaces across the whole `hyprctl layers -j` map, which
/// is also true for the first second or two after any normal start/reload
/// (not a lockup on its own; the journal-line signal in [`run_healthcheck`]
/// is what rules that window out). Requires `layers` to actually be the
/// object `hyprctl -j layers` returns — a failed/malformed call comes back
/// as [`Value::Null`] from `hyprctl_json` and must read as "unconfirmed",
/// never as the stuck signal itself, matching [`run_healthcheck`]'s
/// guarded-optional posture toward system calls it doesn't own.
pub(crate) fn shell_has_zero_layers(layers: &Value) -> bool {
    layers.is_object() && total_aoide_layers(layers) == 0
}

/// Pure: restart timestamps (unix epoch seconds) from a marker file's
/// contents that still fall inside `window_secs` of `now` — everything
/// older is treated as expired and dropped, so the window is a sliding one,
/// never a cumulative lifetime count.
pub(crate) fn recent_restarts_within(marker_contents: &str, now: i64, window_secs: i64) -> Vec<i64> {
    marker_contents
        .lines()
        .filter_map(|l| l.trim().parse::<i64>().ok())
        .filter(|&t| now - t < window_secs)
        .collect()
}

/// Pure: has this already restarted `cap` times inside the window? `true`
/// means withhold — a hardware-level flap that keeps re-triggering must not
/// turn into an infinite restart loop.
pub(crate) fn backoff_engaged(recent: &[i64], cap: usize) -> bool {
    recent.len() >= cap
}

/// Pure: the marker's sentinel line for "a backoff notification already
/// fired at this epoch", if present. Written as `notified:<epoch>` rather
/// than a bare number so it lives in the same marker file as the restart
/// timestamps without [`recent_restarts_within`] mistaking it for one — that
/// function only accepts lines that parse as a bare `i64`, so this sentinel
/// is invisible to it by construction.
pub(crate) fn last_notified_at(marker_contents: &str) -> Option<i64> {
    marker_contents.lines().find_map(|l| l.trim().strip_prefix("notified:")?.parse::<i64>().ok())
}

/// Pure: should this tick stay silent because a backoff notification already
/// fired for the episode still in progress? Reuses the same sliding-window
/// shape as [`recent_restarts_within`] rather than a separate expiry rule —
/// a continuously-engaged episode never lasts as long as `window_secs`
/// (it ends once enough restart timestamps age out of that same window), so
/// comparing the last notification against it is enough to fire exactly once
/// per episode while still allowing a genuinely new, later episode to notify
/// again.
pub(crate) fn already_notified_this_episode(last_notified: Option<i64>, now: i64, window_secs: i64) -> bool {
    last_notified.is_some_and(|t| now - t < window_secs)
}

fn marker_path() -> PathBuf {
    aoide_storage::fs::state_dir().join("quickshell-healthcheck-restarts")
}

fn now_epoch() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// `systemctl --user show aoide-quickshell.service --property=ActiveEnterTimestamp
/// --value` — a systemd timestamp string, passed straight through to
/// `journalctl --since` rather than parsed to an epoch here: journalctl
/// already understands systemd's own timestamp format, so there is nothing
/// to convert. `None` when the unit isn't running or has never been active
/// (both `journal_shows_placeholder` and the `hyprctl` cross-check are
/// skipped in that case — an absent service is [`HealthOutcome::Healthy`],
/// nothing to watch).
fn active_enter_timestamp() -> Option<String> {
    let out = Command::new("systemctl")
        .args(["--user", "show", "aoide-quickshell.service", "--property=ActiveEnterTimestamp", "--value"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn journal_tail_since(since: &str) -> String {
    Command::new("journalctl")
        .args(["--user", "-u", "aoide-quickshell.service", "--no-pager", "--since"])
        .arg(since)
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
        .unwrap_or_default()
}

fn hyprctl_json(subcommand: &str) -> Value {
    Command::new("hyprctl")
        .args(["-j", subcommand])
        .output()
        .ok()
        .and_then(|out| serde_json::from_slice(&out.stdout).ok())
        .unwrap_or(Value::Null)
}

fn restart_service() {
    let _ = Command::new("systemctl").args(["--user", "restart", "aoide-quickshell.service"]).status();
}

/// Raise a toast through the stock freedesktop client, detached — same
/// idiom as `aoide-conduct`'s `announce_reap`/`dispatch_rice_mode_toggle`: a
/// slow/missing `notify-send` must never delay or fail the healthcheck
/// itself (it is a `oneshot` on a 15s timer).
fn notify_backoff_engaged() {
    match Command::new("notify-send").args(["--app-name=aoide", "quickshell watchdog"]).arg(
        "quickshell keeps landing on a placeholder screen — restart withheld after repeated triggers; investigate the output/monitor connection",
    ).spawn() {
        Ok(mut child) => {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
        Err(e) => eprintln!("[aoide/quickshell-health] notify-send failed: {e}"),
    }
}

/// Run one check. Best-effort and side-effecting throughout (see the module
/// header for why two signals are required); never panics, never returns an
/// error type — a failed `systemctl`/`journalctl`/`hyprctl` call just reads
/// as [`HealthOutcome::Healthy`] (nothing confirmed stuck), the same
/// guarded-optional posture the rest of this crate takes toward system
/// services it doesn't own.
pub fn run_healthcheck() -> HealthOutcome {
    if crate::reap::quickshell_service_main_pid().is_none() {
        return HealthOutcome::Healthy;
    }
    let Some(since) = active_enter_timestamp() else {
        return HealthOutcome::Healthy;
    };
    if !journal_shows_placeholder(&journal_tail_since(&since)) {
        return HealthOutcome::Healthy;
    }
    let layers = hyprctl_json("layers");
    if !shell_has_zero_layers(&layers) {
        return HealthOutcome::Healthy;
    }

    let now = now_epoch();
    let marker = marker_path();
    let prior = std::fs::read_to_string(&marker).unwrap_or_default();
    let recent = recent_restarts_within(&prior, now, BACKOFF_WINDOW_SECS);
    if backoff_engaged(&recent, BACKOFF_CAP) {
        if !already_notified_this_episode(last_notified_at(&prior), now, BACKOFF_WINDOW_SECS) {
            notify_backoff_engaged();
            let mut lines: Vec<String> = recent.iter().map(i64::to_string).collect();
            lines.push(format!("notified:{now}"));
            let _ = std::fs::write(&marker, lines.join("\n"));
        }
        return HealthOutcome::BackoffWithheld;
    }

    let mut updated = recent;
    updated.push(now);
    let body: String = updated.iter().map(i64::to_string).collect::<Vec<_>>().join("\n");
    let _ = std::fs::write(&marker, body);
    restart_service();
    HealthOutcome::Restarted
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn placeholder_line_matches_the_exact_qt_qpa_wording() {
        assert!(journal_shows_placeholder(
            "INFO qt.qpa.wayland: There are no outputs - creating placeholder screen"
        ));
    }

    #[test]
    fn unrelated_journal_lines_never_match() {
        assert!(!journal_shows_placeholder(""));
        assert!(!journal_shows_placeholder("WARN quickshell.dbus: Could not launch service org.freedesktop.UPower"));
        assert!(!journal_shows_placeholder("INFO: Configuration Loaded"));
    }

    // Real shape from `hyprctl -j layers`, verified live on this box: one
    // top-level key per monitor, each holding a `levels` object keyed
    // `"0"`..`"3"`, each an array of surface objects carrying `namespace`.
    fn two_monitor_one_painted() -> Value {
        json!({
            "DP-1": {
                "levels": {
                    "0": [{"namespace": "aoide-wallpaper"}],
                    "1": [],
                    "2": [{"namespace": "aoide-bar"}, {"namespace": "aoide-dock"}],
                    "3": [{"namespace": "aoide-herald"}]
                }
            },
            "HDMI-A-1": {
                "levels": { "0": [], "1": [], "2": [], "3": [] }
            }
        })
    }

    #[test]
    fn total_aoide_layers_sums_across_every_monitor_and_level() {
        assert_eq!(total_aoide_layers(&two_monitor_one_painted()), 4);
    }

    #[test]
    fn non_aoide_namespaced_surfaces_never_count() {
        let layers = json!({ "DP-1": { "levels": { "0": [{"namespace": "waybar"}], "1": [], "2": [], "3": [] } } });
        assert_eq!(total_aoide_layers(&layers), 0);
        assert!(shell_has_zero_layers(&layers));
    }

    // Regression for the multi-monitor false positive: none of
    // `modules/facets/quickshell/qml`'s `PanelWindow`s bind to a screen (no
    // `Variants`, no `Quickshell.screens`, no `screen:` anywhere in that
    // tree), so this shell always paints exactly one output. A second
    // enabled, connected monitor that legitimately and permanently carries
    // zero layers must read HEALTHY, not stuck — the old per-monitor
    // predicate flagged this host as stuck forever.
    #[test]
    fn two_monitor_host_with_one_painted_and_one_legitimately_empty_is_healthy() {
        assert!(!shell_has_zero_layers(&two_monitor_one_painted()));
    }

    #[test]
    fn every_monitor_empty_is_the_stuck_signal() {
        let layers = json!({
            "DP-1": { "levels": { "0": [], "1": [], "2": [], "3": [] } },
            "HDMI-A-1": { "levels": { "0": [], "1": [], "2": [], "3": [] } }
        });
        assert!(shell_has_zero_layers(&layers));
    }

    #[test]
    fn malformed_hyprctl_output_reads_as_not_stuck_never_panics() {
        // `hyprctl_json` falls back to `Value::Null` on a failed/unparsable
        // call — that must read as "unconfirmed", the same guarded-optional
        // posture the rest of `run_healthcheck` takes, never as the stuck
        // signal itself.
        assert!(!shell_has_zero_layers(&Value::Null));
        assert_eq!(total_aoide_layers(&Value::Null), 0);
    }

    #[test]
    fn recent_restarts_drops_entries_older_than_the_window() {
        let marker = "1000\n1100\n1200\n";
        assert_eq!(recent_restarts_within(marker, 1250, 300), vec![1000, 1100, 1200]);
        assert_eq!(recent_restarts_within(marker, 1450, 300), vec![1200]);
    }

    #[test]
    fn recent_restarts_ignores_garbage_lines() {
        assert_eq!(recent_restarts_within("not-a-number\n\n42\n", 100, 300), vec![42]);
    }

    #[test]
    fn backoff_engages_at_the_cap_not_one_past_it() {
        assert!(!backoff_engaged(&[1, 2], 3));
        assert!(backoff_engaged(&[1, 2, 3], 3));
        assert!(backoff_engaged(&[1, 2, 3, 4], 3));
    }

    #[test]
    fn recent_restarts_never_mistakes_the_notified_sentinel_for_a_restart() {
        let marker = "1000\n1100\nnotified:1150\n1200\n";
        assert_eq!(recent_restarts_within(marker, 1250, 300), vec![1000, 1100, 1200]);
    }

    #[test]
    fn last_notified_at_finds_the_sentinel_line_among_restart_timestamps() {
        assert_eq!(last_notified_at("1000\n1100\nnotified:1150\n1200\n"), Some(1150));
    }

    #[test]
    fn last_notified_at_is_none_without_a_sentinel_line() {
        assert_eq!(last_notified_at("1000\n1100\n1200\n"), None);
        assert_eq!(last_notified_at(""), None);
    }

    #[test]
    fn no_notification_yet_never_suppresses() {
        assert!(!already_notified_this_episode(None, 1000, 300));
    }

    #[test]
    fn a_notification_inside_the_window_suppresses_the_next_one() {
        // This is the fix for the spam defect: with a 15s timer, every tick
        // inside one still-engaged episode must stay silent after the first.
        assert!(already_notified_this_episode(Some(1000), 1015, 300));
        assert!(already_notified_this_episode(Some(1000), 1299, 300));
    }

    #[test]
    fn a_notification_outside_the_window_allows_a_fresh_one() {
        // A later, genuinely new backoff episode (old timestamps long aged
        // out) must still get its own toast, not stay silent forever.
        assert!(!already_notified_this_episode(Some(1000), 1300, 300));
    }

    #[test]
    fn outcome_tags_and_messages() {
        assert_eq!(HealthOutcome::Healthy.tag(), "healthy");
        assert_eq!(HealthOutcome::Restarted.tag(), "restarted");
        assert_eq!(HealthOutcome::BackoffWithheld.tag(), "backoff-withheld");
        assert!(HealthOutcome::Restarted.message().contains("restarted"));
    }

    // `run_healthcheck()` itself isn't unit-tested here: it reads the REAL
    // `aoide-quickshell.service` state via `systemctl`/`journalctl`/
    // `hyprctl`, environment-dependent the same way `reap.rs`'s
    // `quickshell_service_main_pid()` and `ipc.rs`'s `quickshell_ipc_reload()`
    // are — only their pure halves get unit tests, for the same reason.
}
