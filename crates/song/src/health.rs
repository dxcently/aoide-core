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
//! Two signals, asked in the order below, because they answer different
//! questions. `hyprctl layers` showing zero `aoide-*` surfaces anywhere is
//! the CURRENT state, and it is the user-visible failure itself: the desktop
//! is blank. Quickshell's own journal line (`There are no outputs - creating
//! placeholder screen`, emitted by Qt's QPA layer at the exact moment of the
//! failure) names a MECHANISM, and only one — it confirms the event happened
//! but not whether it is still true, so a blip that self-healed before this
//! runs would still show the line.
//!
//! So the surface count decides health on its own, and the journal line
//! decides only whether this watchdog may act: zero surfaces with the line
//! present is the placeholder lockup, restartable on the ladder below; zero
//! surfaces without it is [`HealthOutcome::Blank`], reported and left alone.
//! Asking the journal first instead would let one unrecognized mechanism
//! report a blank desktop as healthy — incident #40, a pre-QML deadlock in
//! the `QApplication` constructor that emits no QPA line, went unseen for 22
//! minutes on two hosts that way.
//!
//! The journal read is scoped to the unit's own `ActiveEnterTimestamp`, so
//! an old, already-recovered-from occurrence can never re-trigger after a
//! restart moves that timestamp forward. That same timestamp is what keeps
//! the surface count honest across a reload: zero surfaces is also true for
//! the first second or two after any normal start, and a restart resets the
//! window the journal is read over.
//!
//! That count sums the shell's OWN surfaces system-wide rather than
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

/// How long a run of restarts stays in view before it's forgotten, and the
/// same window the once-per-episode notification is gated against (see
/// [`already_notified_this_episode`]): a continuously-engaged episode never
/// outlives this window, since it ends once enough restart timestamps age
/// out of it, so comparing the last notification against the same window is
/// enough to fire the toast exactly once per episode while still letting a
/// later, genuinely new episode notify again. An hour of quiet resets the
/// ladder below to its bottom rung.
const HISTORY_WINDOW_SECS: i64 = 3600;

/// Exponential retry ladder: the minimum gap, in seconds, required since the
/// last restart before another is allowed, indexed by how many restarts
/// already sit in [`HISTORY_WINDOW_SECS`] — 0/1/2/3/4-or-more restarts so far
/// map to 0s/15s/60s/300s/900s. The last rung is a floor, never a ceiling
/// that gives up: once the ladder bottoms out it keeps trying forever at the
/// 900s (15-minute) cadence instead of stopping — see
/// [`ladder_permits_restart`] and the module header for why "eventually
/// refuse" is exactly the failure mode a suspected flapping output cannot be
/// allowed to reproduce.
const RETRY_LADDER_SECS: [i64; 5] = [0, 15, 60, 300, 900];

/// The result of one `aoide quickshell healthcheck` run.
pub enum HealthOutcome {
    /// No lockup detected (including: the service isn't running at all —
    /// nothing to watch).
    Healthy,
    /// Painting nothing, and this watchdog cannot say why: zero `aoide-*`
    /// layer surfaces anywhere, but no placeholder-screen line in the
    /// journal since the unit went active. The desktop is blank — the same
    /// user-visible failure [`Restarted`](HealthOutcome::Restarted) exists
    /// for — but the one mechanism this watchdog knows how to attribute is
    /// absent, so it reports and does not act. Incident #40 was exactly this
    /// shape: a pre-QML deadlock in the `QApplication` constructor, which
    /// emits no QPA line at all, and it sat unreported for 22 minutes on two
    /// hosts. Naming that state is this variant's whole job — a blank
    /// desktop with no recognized mechanism must never collapse into
    /// [`Healthy`](HealthOutcome::Healthy).
    Blank,
    /// Confirmed stuck; the service was restarted.
    Restarted,
    /// Confirmed stuck again, but [`ladder_permits_restart`] says the retry
    /// ladder's gap since the last restart hasn't elapsed yet. Withheld for
    /// THIS TICK only, silently — the next tick (~15s later, off the timer)
    /// re-evaluates and restarts as soon as the gap has passed. Never a
    /// terminal state: see the module header and [`RETRY_LADDER_SECS`] for
    /// why this design never stops trying.
    Deferred { next_attempt_in_secs: i64, recent_restarts: usize },
}

impl HealthOutcome {
    pub fn tag(&self) -> &'static str {
        match self {
            HealthOutcome::Healthy => "healthy",
            HealthOutcome::Blank => "blank",
            HealthOutcome::Restarted => "restarted",
            HealthOutcome::Deferred { .. } => "deferred",
        }
    }

    pub fn message(&self) -> String {
        match self {
            HealthOutcome::Healthy => "quickshell is healthy".to_string(),
            HealthOutcome::Blank => {
                "quickshell is painting nothing, and no placeholder-screen line explains it; \
                 not restarting"
                    .to_string()
            }
            HealthOutcome::Restarted => {
                "quickshell was stuck on a placeholder screen; restarted".to_string()
            }
            HealthOutcome::Deferred { next_attempt_in_secs, recent_restarts } => {
                let plural = if *recent_restarts == 1 { "" } else { "s" };
                format!(
                    "quickshell is stuck; next restart attempt in {next_attempt_in_secs}s \
                     ({recent_restarts} restart{plural} in the last hour)"
                )
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

/// Pure: is the shell painting nothing anywhere? `true` is the blank
/// desktop — zero `aoide-*` surfaces across the whole `hyprctl layers -j`
/// map. It is also true for the first second or two after any normal
/// start/reload, which is why it decides [`HealthOutcome::Healthy`] but
/// never a restart on its own: the journal line in [`run_healthcheck`]
/// separates the placeholder lockup, which is restartable, from
/// [`HealthOutcome::Blank`], which is only reported.
///
/// Requires `layers` to actually be the object `hyprctl -j layers` returns
/// — a failed/malformed call comes back as [`Value::Null`] from
/// `hyprctl_json` and must read as "unconfirmed", never as a blank desktop,
/// matching [`run_healthcheck`]'s guarded-optional posture toward system
/// calls it doesn't own. That guard is load-bearing because this signal is
/// asked first: without it a missing `hyprctl` would report every tick as
/// [`HealthOutcome::Blank`].
pub(crate) fn shell_has_zero_layers(layers: &Value) -> bool {
    layers.is_object() && total_aoide_layers(layers) == 0
}

/// Pure: restart timestamps (unix epoch seconds) from a marker file's
/// contents that still fall inside `window_secs` of `now` — everything
/// older is treated as expired and dropped, so the window is a sliding one,
/// never a cumulative lifetime count. Bounded on BOTH sides (`t <= now` as
/// well as `now - t < window_secs`): a line ahead of `now` — an NTP step, a
/// clock skew correction, a corrupted or hand-edited marker — must never
/// count as "recent" via a negative age, because [`ladder_permits_restart`]
/// would then measure `now - last` as deeply negative and never reach
/// [`required_gap_secs`], turning [`next_attempt_in_secs`] into an
/// effectively permanent refusal instead of the bounded delay this design
/// promises (see the module header and [`RETRY_LADDER_SECS`]).
pub(crate) fn recent_restarts_within(marker_contents: &str, now: i64, window_secs: i64) -> Vec<i64> {
    marker_contents
        .lines()
        .filter_map(|l| l.trim().parse::<i64>().ok())
        .filter(|&t| t <= now && now - t < window_secs)
        .collect()
}

/// Pure: the minimum number of seconds required since the last restart
/// before another is allowed, given how many restarts already sit in the
/// window. The index floors at the ladder's final rung (900s) rather than
/// panicking or growing past it — this is what makes [`RETRY_LADDER_SECS`] a
/// floor and never a "stop" state: every count of prior restarts, however
/// large, still maps to a finite, reachable gap.
pub(crate) fn required_gap_secs(restarts_in_window: usize) -> i64 {
    let rung = restarts_in_window.min(RETRY_LADDER_SECS.len() - 1);
    RETRY_LADDER_SECS[rung]
}

/// Pure: does the retry ladder permit a restart right now? `recent` is
/// already pruned to the sliding window by [`recent_restarts_within`]. No
/// prior restart in the window always permits (the ladder's 0s rung).
/// Otherwise the gap is measured against the MOST RECENT restart, not the
/// oldest — each restart resets the clock for the next rung — and must have
/// reached [`required_gap_secs`] for how many restarts already sit in the
/// window. This is a delay, never a denial: there is no `recent`/`now` pair
/// this returns `false` for forever, because the ladder floors at 900s
/// instead of an unreachable cap.
pub(crate) fn ladder_permits_restart(recent: &[i64], now: i64) -> bool {
    match recent.iter().copied().max() {
        None => true,
        Some(last) => now - last >= required_gap_secs(recent.len()),
    }
}

/// Pure: seconds remaining until [`ladder_permits_restart`] would allow a
/// restart, for the deferral message — never negative, so the message never
/// reads as overdue when it's actually already due.
pub(crate) fn next_attempt_in_secs(recent: &[i64], now: i64) -> i64 {
    match recent.iter().copied().max() {
        None => 0,
        Some(last) => (required_gap_secs(recent.len()) - (now - last)).max(0),
    }
}

/// Pure: has the ladder bottomed out at its 900s floor? True from the 4th
/// restart in the window onward. This is the point the once-per-episode
/// notification in [`run_healthcheck`] fires — by then the pattern is
/// clearly not a one-off blip, unlike an early rung that could still be a
/// single transient blip self-correcting on its own.
pub(crate) fn ladder_at_cap(restarts_in_window: usize) -> bool {
    restarts_in_window >= RETRY_LADDER_SECS.len() - 1
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

/// Pure: compose the marker file's full body from a set of restart
/// timestamps (already pruned to the sliding window, the same shape
/// [`recent_restarts_within`] returns) and a `notified:` sentinel to carry
/// forward, if any. The one place [`run_healthcheck`]'s two marker writes
/// (defer-with-notify and restart) both build their contents from, so the
/// sentinel can never again be dropped by one write path while the other
/// keeps it — that asymmetry was the spam defect: the restart-path write
/// used to compose its body from timestamps alone, unconditionally losing
/// whatever `notified:` line [`last_notified_at`] would have found in the
/// prior contents, so every restart at the ladder's 900s cap cleared the
/// sentinel and the very next deferred tick read that absence as "never
/// notified" and fired again — once per restart instead of once per
/// episode. `notified: None` composes a body with no sentinel line at all
/// (not a placeholder) — the shape a fresh marker, or a prior with no
/// sentinel to carry, collapses to.
pub(crate) fn marker_body(timestamps: &[i64], notified: Option<i64>) -> String {
    let mut lines: Vec<String> = timestamps.iter().map(i64::to_string).collect();
    if let Some(t) = notified {
        lines.push(format!("notified:{t}"));
    }
    lines.join("\n")
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
/// itself (it is a `oneshot` on a 15s timer). Fired once per episode, only
/// once the ladder has bottomed out at its 900s floor (see
/// [`ladder_at_cap`]) — by then the pattern is clearly not a one-off blip.
/// Best-effort, not this healthcheck's fallback: dunst's `skip_display`
/// (`modules/dendrites/dunst.nix`) means it never draws, only forwards to
/// the herald ledger inside the very shell this reports on, so the toast
/// only becomes visible once the shell recovers — the restart the caller
/// already fired is what actually does the work.
fn notify_still_flapping() {
    match Command::new("notify-send").args(["--app-name=aoide", "quickshell watchdog"]).arg(
        "quickshell keeps landing on a placeholder screen and is being restarted repeatedly — the output/monitor connection looks suspect",
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
    // Current state first, cause second. The surface count is the only
    // signal that speaks to NOW (module header), so it decides `Healthy` on
    // its own; the journal line only chooses between acting and reporting
    // once the desktop is already known to be blank. Reading them the other
    // way round is what made incident #40 invisible, and it spends a full
    // `journalctl` read on every healthy tick; this order pays that only
    // when something is actually wrong.
    let layers = hyprctl_json("layers");
    if !shell_has_zero_layers(&layers) {
        return HealthOutcome::Healthy;
    }
    if !journal_shows_placeholder(&journal_tail_since(&since)) {
        return HealthOutcome::Blank;
    }

    let now = now_epoch();
    let marker = marker_path();
    if let Some(parent) = marker.parent() {
        // Best-effort, same guarded posture as every write below: `state/`
        // is normally seeded by the nix module's systemd-tmpfiles rule
        // (`modules/nucleus/aoided.nix`), but nothing in this crate creates
        // it, and an absent directory would otherwise make BOTH writes below
        // silently fail — `recent` would then never accumulate, the ladder
        // would permanently take its "no prior restart" branch, and the
        // shell would get restarted every ~15s forever, the exact inverse of
        // the future-timestamp defect above and just as bad. A failure here
        // must not panic or change the outcome, so it's swallowed exactly
        // like the writes are.
        let _ = std::fs::create_dir_all(parent);
    }
    let prior = std::fs::read_to_string(&marker).unwrap_or_default();
    let recent = recent_restarts_within(&prior, now, HISTORY_WINDOW_SECS);
    if !ladder_permits_restart(&recent, now) {
        if ladder_at_cap(recent.len())
            && !already_notified_this_episode(last_notified_at(&prior), now, HISTORY_WINDOW_SECS)
        {
            notify_still_flapping();
            let _ = std::fs::write(&marker, marker_body(&recent, Some(now)));
        }
        return HealthOutcome::Deferred {
            next_attempt_in_secs: next_attempt_in_secs(&recent, now),
            recent_restarts: recent.len(),
        };
    }

    // Carry the prior `notified:` sentinel (if any) forward — see
    // `marker_body`'s doc for why composing this body from `updated` alone
    // was the spam defect: it silently dropped whatever notification state
    // `prior` was carrying every time a restart landed.
    let mut updated = recent;
    updated.push(now);
    let _ = std::fs::write(&marker, marker_body(&updated, last_notified_at(&prior)));
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
        // Also what keeps a missing `hyprctl` from reporting every tick as
        // `HealthOutcome::Blank`, since this signal is asked first.
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
    fn required_gap_secs_follows_the_ladder_and_floors_at_the_cap() {
        assert_eq!(required_gap_secs(0), 0);
        assert_eq!(required_gap_secs(1), 15);
        assert_eq!(required_gap_secs(2), 60);
        assert_eq!(required_gap_secs(3), 300);
        assert_eq!(required_gap_secs(4), 900);
        // 5-or-more never becomes "never" — the floor holds indefinitely.
        assert_eq!(required_gap_secs(5), 900);
        assert_eq!(required_gap_secs(100), 900);
    }

    #[test]
    fn ladder_withholds_before_the_required_gap_has_elapsed() {
        // One restart already in the window (rung 1: 15s required); only
        // 10s have passed since it.
        assert!(!ladder_permits_restart(&[1000], 1010));
    }

    #[test]
    fn ladder_permits_once_the_required_gap_has_elapsed() {
        assert!(ladder_permits_restart(&[1000], 1015));
        assert!(ladder_permits_restart(&[1000], 1020));
    }

    #[test]
    fn ladder_always_permits_with_no_prior_restart_in_the_window() {
        assert!(ladder_permits_restart(&[], 1000));
    }

    #[test]
    fn ladder_gates_on_the_most_recent_restart_not_the_oldest() {
        // Three restarts already in the window; the 4th must wait out the
        // 3-restart rung (300s) measured from the LAST of the three, not
        // the first.
        let recent = [1000, 1015, 1075];
        assert!(!ladder_permits_restart(&recent, 1075 + 299));
        assert!(ladder_permits_restart(&recent, 1075 + 300));
    }

    #[test]
    fn an_hour_of_quiet_prunes_the_window_and_resets_the_ladder_to_the_bottom_rung() {
        let marker = "1000\n1015\n1075\n1375\n";
        let long_after = 1375 + HISTORY_WINDOW_SECS;
        let recent = recent_restarts_within(marker, long_after, HISTORY_WINDOW_SECS);
        assert!(recent.is_empty());
        assert_eq!(required_gap_secs(recent.len()), 0);
        assert!(ladder_permits_restart(&recent, long_after));
    }

    #[test]
    fn ladder_reaches_cap_at_four_restarts_in_the_window_not_before() {
        assert!(!ladder_at_cap(3));
        assert!(ladder_at_cap(4));
        assert!(ladder_at_cap(5));
    }

    #[test]
    fn next_attempt_in_secs_counts_down_and_never_goes_negative() {
        assert_eq!(next_attempt_in_secs(&[1000], 1000), 15);
        assert_eq!(next_attempt_in_secs(&[1000], 1010), 5);
        assert_eq!(next_attempt_in_secs(&[1000], 1015), 0);
        assert_eq!(next_attempt_in_secs(&[1000], 1020), 0);
    }

    #[test]
    fn next_attempt_in_secs_is_zero_without_a_prior_restart() {
        assert_eq!(next_attempt_in_secs(&[], 1000), 0);
    }

    // Regression: this design must never permanently withhold. For any
    // restart history, waiting the ladder's own longest possible gap (the
    // 900s cap rung) since the last restart always reaches a moment the
    // ladder permits — there is no `recent` for which it refuses forever.
    // Deliberately one-sided: `now` is always `last + 900` here, i.e.
    // `now >= last` in every case, so this covers only the "wait long
    // enough" axis. The OPPOSITE, adversarial axis — a marker timestamp
    // AHEAD of `now` — is covered separately below, since a naive filter
    // that only checks `now - t < window_secs` (no lower bound on `t`)
    // would pass a future `t` through as a negative age and this loop would
    // never catch that: `last` here is always taken from the same clock as
    // `now`, never manufactured ahead of it.
    #[test]
    fn no_restart_history_ever_permanently_refuses_a_future_restart() {
        for count in 0..=50usize {
            let recent: Vec<i64> = (0..count).map(|i| i as i64 * 10).collect();
            let last = recent.iter().copied().max().unwrap_or(0);
            assert!(ladder_permits_restart(&recent, last + 900));
        }
    }

    // Regression for the defect the loop above is structurally blind to: a
    // marker line AHEAD of `now` (an NTP step, a clock skew correction, a
    // corrupted or hand-edited marker) must never be counted as "recent" —
    // `recent_restarts_within` used to filter on `now - t < window_secs`
    // alone, with no `t <= now` lower bound, so a future `t` produced a
    // negative age that passed the filter. Downstream, `ladder_permits_restart`
    // then measured `now - last` as deeply negative (never reaching
    // `required_gap_secs`), and `next_attempt_in_secs` reported a wait of
    // `required_gap + |now - last|` — a marker dated 2100 against a real
    // `now` of 2027 produced a reported wait of roughly 73 years, a de-facto
    // permanent refusal despite [`RETRY_LADDER_SECS`] never being a "stop"
    // state on paper.
    #[test]
    fn a_future_marker_timestamp_is_dropped_not_counted_as_recent() {
        let now = 1_800_000_000_i64; // a real "now"
        let wildly_future = now + 60 * 60 * 24 * 365 * 70; // ~2100 against a ~2027 `now`

        let recent = recent_restarts_within(&format!("{wildly_future}\n"), now, HISTORY_WINDOW_SECS);
        assert!(recent.is_empty(), "a future timestamp must never count as a recent restart");
        assert!(ladder_permits_restart(&recent, now), "no valid recent restart means the ladder permits immediately");
        assert_eq!(next_attempt_in_secs(&recent, now), 0);
    }

    #[test]
    fn recent_restarts_within_keeps_now_itself_but_drops_anything_past_it() {
        // `t <= now` is inclusive at the boundary (t == now is not "future"),
        // but t == now + 1 already is.
        assert_eq!(recent_restarts_within("1000\n", 1000, 300), vec![1000]);
        assert!(recent_restarts_within("1001\n", 1000, 300).is_empty());
    }

    #[test]
    fn a_future_marker_line_never_poisons_the_gate_alongside_a_real_recent_restart() {
        // A marker holding one genuine recent restart AND one wildly future
        // (corrupted) entry: the future line must be dropped, and the ladder
        // must gate ONLY on the real restart — a bounded, sane wait, never
        // the multi-year refusal a negative age would have produced.
        let now = 1_800_000_000_i64;
        let wildly_future = now + 60 * 60 * 24 * 365 * 70;
        let marker = format!("{now}\n{wildly_future}\n");

        let recent = recent_restarts_within(&marker, now, HISTORY_WINDOW_SECS);
        assert_eq!(recent, vec![now]);
        assert!(!ladder_permits_restart(&recent, now), "rung 1 (15s) hasn't elapsed yet");
        let wait = next_attempt_in_secs(&recent, now);
        assert_eq!(wait, 15);
        assert!(wait <= *RETRY_LADDER_SECS.last().unwrap(), "must stay within the ladder's own bound, not blow up");
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
        // A later, genuinely new flapping episode (old timestamps long aged
        // out) must still get its own toast, not stay silent forever.
        assert!(!already_notified_this_episode(Some(1000), 1300, 300));
    }

    #[test]
    fn marker_body_with_no_timestamps_and_no_sentinel_is_an_empty_string() {
        assert_eq!(marker_body(&[], None), "");
    }

    #[test]
    fn marker_body_renders_bare_timestamps_one_per_line() {
        assert_eq!(marker_body(&[1000, 1015, 1075], None), "1000\n1015\n1075");
    }

    // Regression for the spam defect: composing the RESTART-path body from
    // `updated` (fresh timestamps) must still carry a sentinel found in
    // `prior` forward rather than losing it, the way the old inline
    // `updated.iter()...join("\n")` composition unconditionally did.
    #[test]
    fn marker_body_carries_the_notified_sentinel_through_a_restart_path_write() {
        let prior = "700\nnotified:650\n";
        let recent = recent_restarts_within(prior, 900, HISTORY_WINDOW_SECS);
        let mut updated = recent;
        updated.push(900);
        let body = marker_body(&updated, last_notified_at(prior));
        assert_eq!(body, "700\n900\nnotified:650");
        // And the composed body round-trips: a subsequent read finds the
        // SAME sentinel, unlike the old code where it vanished after one
        // restart-path write.
        assert_eq!(last_notified_at(&body), Some(650));
    }

    // Complement: an episode boundary — no sentinel to carry (a fresh
    // marker, or a prior that never reached the ladder's cap) — must clear
    // to no `notified:` line at all, not some leftover or placeholder value,
    // so the next tick's `already_notified_this_episode` sees a clean
    // `None` and is free to notify on a genuinely new episode.
    #[test]
    fn marker_body_with_no_sentinel_to_carry_clears_it_at_an_episode_boundary() {
        let body = marker_body(&[900], None);
        assert_eq!(body, "900");
        assert_eq!(last_notified_at(&body), None);
        assert!(!already_notified_this_episode(last_notified_at(&body), 900, HISTORY_WINDOW_SECS));
    }

    #[test]
    fn outcome_tags_and_messages() {
        assert_eq!(HealthOutcome::Healthy.tag(), "healthy");
        assert_eq!(HealthOutcome::Restarted.tag(), "restarted");
        assert!(HealthOutcome::Restarted.message().contains("restarted"));

        // A blank desktop must never render as the healthy one — that
        // collapse is what left incident #40 unreported for 22 minutes.
        assert_eq!(HealthOutcome::Blank.tag(), "blank");
        let blank = HealthOutcome::Blank.message();
        assert!(blank.contains("painting nothing"), "{blank}");
        assert!(blank.contains("not restarting"), "{blank}");

        let deferred = HealthOutcome::Deferred { next_attempt_in_secs: 847, recent_restarts: 4 };
        assert_eq!(deferred.tag(), "deferred");
        let msg = deferred.message();
        assert!(msg.contains("847"), "{msg}");
        assert!(msg.contains("4 restarts"), "{msg}");

        let singular = HealthOutcome::Deferred { next_attempt_in_secs: 10, recent_restarts: 1 };
        assert!(singular.message().contains("1 restart "), "{}", singular.message());
    }

    // `run_healthcheck()` itself isn't unit-tested here: it reads the REAL
    // `aoide-quickshell.service` state via `systemctl`/`journalctl`/
    // `hyprctl`, environment-dependent the same way `reap.rs`'s
    // `quickshell_service_main_pid()` and `ipc.rs`'s `quickshell_ipc_reload()`
    // are — only their pure halves get unit tests, for the same reason.
}
