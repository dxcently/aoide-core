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
//! questions. `hyprctl layers` missing the surfaces the shell is supposed to
//! have mapped is the CURRENT state, and it is the user-visible failure
//! itself: the desktop is blank — or half-blank, which is the case that
//! matters here. Quickshell's own journal line (`There are no outputs -
//! creating placeholder screen`, emitted by Qt's QPA layer at the exact
//! moment of the failure) names a MECHANISM, and only one — it confirms the
//! event happened but not whether it is still true, so a blip that self-healed
//! before this runs would still show the line.
//!
//! So the mapped-surface predicate decides health on its own, and the journal
//! line decides only whether this watchdog may act: surfaces missing with the
//! line present is the placeholder lockup, restartable on the ladder below;
//! surfaces missing without it is [`HealthOutcome::Blank`], reported and left
//! alone. Asking the journal first instead would let one unrecognized
//! mechanism report a blank desktop as healthy — incident #40, a pre-QML
//! deadlock in the `QApplication` constructor that emits no QPA line, went
//! unseen for 22 minutes on two hosts that way.
//!
//! The journal read is scoped to the unit's own `ActiveEnterTimestamp`, so
//! an old, already-recovered-from occurrence can never re-trigger after a
//! restart moves that timestamp forward. That same timestamp is what keeps
//! the predicate honest across a reload: "nothing painted yet" is also true
//! for the first second or two after any normal start, and a restart resets
//! the window the journal is read over.
//!
//! That predicate used to be a bare total: any `aoide-*` surface, anywhere,
//! on any monitor, at any layer. It cannot see a PARTIAL loss, and a partial
//! loss is exactly what happens. When one output blips, the surfaces that
//! recover and the surfaces that do not are decided per-surface — a
//! `Variants { model: Quickshell.screens }` delegate is rebuilt against the
//! new screen list and re-homes itself, while a singleton bound to one now
//! dead output stays bound to it forever. Verified live on osaka: the
//! per-screen wallpaper recovered and the bar and dock did not, so the total
//! count stayed nonzero and this watchdog called that desktop healthy for
//! hours. A count can only ever answer "is anything painted", and the
//! question that matters is "is what SHOULD be painted, painted".
//!
//! Answering that question needs a set to compare against, and the set
//! cannot be hardcoded here: on a host where waybar owns the bar, expecting
//! `aoide-bar` would restart a healthy desktop every fifteen minutes
//! forever. So it is DECLARED by the active song
//! (`aoide.arrangement.surfaces`) and published to
//! `run/qml/songs/surfaces.json` by the quickshell facet's build
//! (CONTRACTS.md §5). When that file is present this checks the declared
//! namespaces against what is actually mapped, per monitor where the
//! declaration says per-monitor; when it is absent or unreadable, no
//! expectation is declared and the old total count decides, unchanged. A
//! host that declares nothing pays for nothing.
//!
//! The per-monitor comparison is why `hyprctl monitors` is read at all — a
//! `perMonitor` namespace must be mapped once on EVERY real output, and
//! counting surfaces instead of distinct monitors would let two copies on
//! one head satisfy a two-head expectation. Hyprland synthesizes a
//! `FALLBACK` output while every real head is off, which is excluded from
//! both sides: with no real output there is nothing to paint on, restarting
//! reproduces the placeholder state, and the shell is expected to come back
//! on its own when a head returns.
//!
//! No QML-side fix exists for the placeholder lockup itself:
//! `Quickshell.screens` is populated below QML by `QGuiApplication`'s
//! wayland platform plugin, so no in-process `Quickshell.reload()`/
//! `onScreensChanged` handler can reach or reset the stuck QPA state — only
//! a full process re-exec does, which is exactly what
//! [`run_healthcheck`]'s restart provides. This is separate from the
//! per-surface recovery above: a `Variants` delegate re-homes across a blip,
//! but nothing in QML recovers a QPA backend that has already fallen onto
//! the placeholder screen.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
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
    /// The shell isn't painting the desktop it should be, and this watchdog
    /// cannot say why: either the declared surface set falls short of what
    /// `run/qml/songs/surfaces.json` says should be mapped, or — with no
    /// expectation published — zero `aoide-*` layer surfaces anywhere exist,
    /// and in both cases there is no placeholder-screen line in the journal
    /// since the unit went active. Either way the user sees a desktop that is
    /// missing something it declared — blank, or half-painted with a bar or
    /// dock gone — which is the same user-visible failure
    /// [`Restarted`](HealthOutcome::Restarted) exists for, but the one
    /// mechanism this watchdog knows how to attribute is absent, so it
    /// reports and does not act. Incident #40 was exactly this shape: a
    /// pre-QML deadlock in the `QApplication` constructor, which emits no QPA
    /// line at all, and it sat unreported for 22 minutes on two hosts. Naming
    /// that state is this variant's whole job — a desktop that is not what it
    /// declared must never collapse into [`Healthy`](HealthOutcome::Healthy).
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
                "quickshell is not painting what it should be, and no placeholder-screen line \
                 explains it; not restarting"
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
/// reports, summed across every monitor and every level. Only the
/// no-expectation fallback in [`run_healthcheck`] uses this — see the module
/// header for why a total count cannot see the partial loss that
/// [`surfaces_fall_short`] exists to catch, and for why summing across every
/// monitor is the right shape for the fallback specifically.
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
/// This is the NO-EXPECTATION fallback: [`run_healthcheck`] asks it only
/// when nothing published `run/qml/songs/surfaces.json`, so a host that
/// declares no surfaces keeps exactly the behaviour it had before that file
/// existed. When an expectation IS declared, [`surfaces_fall_short`] decides
/// instead — and on a multi-monitor host the two differ deliberately: this
/// reads healthy as soon as ONE surface exists anywhere, which is precisely
/// the blind spot it is kept for the no-expectation case only (module
/// header).
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

/// Pure: the published expectation's namespaces, each mapped to its
/// `perMonitor` flag — `None` when `v` is not the object
/// [`published_surfaces`] would have handed over, i.e. not an object
/// carrying a `surfaces` object. Read straight off the generated
/// `run/qml/songs/surfaces.json` (CONTRACTS.md §5), whose keys are already
/// the RESOLVED layer-shell namespaces (`aoide-<slot>`) precisely so this
/// function derives nothing of its own and compares them directly against
/// the compositor's own layer list.
///
/// An EMPTY `surfaces` object is `Some(empty)`, never `None`, and the two are
/// not the same thing: `None` means "nothing was published, fall back to the
/// old count", while an empty map means "this song declared nothing and
/// therefore expects nothing" — which [`surfaces_fall_short`] must read as
/// healthy. Collapsing them would make a song with an empty declaration
/// restart forever, since no namespace could ever satisfy it.
///
/// A missing `perMonitor` on one entry reads as `false` — "exactly one,
/// wherever it lands" — matching the nix option's own default, so a
/// hand-written or forward-compatible file that omits the flag is treated as
/// the weaker demand rather than as malformed.
pub(crate) fn parse_expectation(v: &Value) -> Option<BTreeMap<String, bool>> {
    let surfaces = v.get("surfaces")?.as_object()?;
    Some(
        surfaces
            .iter()
            .map(|(ns, entry)| (ns.clone(), entry.get("perMonitor").and_then(Value::as_bool).unwrap_or(false)))
            .collect(),
    )
}

/// Pure: how many REAL outputs are worth demanding a surface on, from
/// `hyprctl monitors -j`. Entries that are `"disabled": true` are off, and
/// one named `FALLBACK` is the placeholder Hyprland synthesizes while every
/// real head is off — neither is somewhere a surface could be painted, so
/// neither is counted. (Hyprland's own output list carries the literal name
/// `FALLBACK` for that synthetic monitor.)
///
/// `None` when `monitors` is not an array — a malformed or failed `hyprctl`
/// (which comes back as [`Value::Null`] from `hyprctl_json`) means the real
/// output count is UNCONFIRMED, and unconfirmed must never be mistaken for
/// zero. The two differ in what they demand: zero real outputs is a reason to
/// stand down entirely (see [`surfaces_fall_short`]), while `None` is a
/// reason not to judge at all, so this returns the distinction rather than
/// flattening both to a number.
pub(crate) fn real_monitor_count(monitors: &Value) -> Option<usize> {
    let entries = monitors.as_array()?;
    Some(entries.iter().filter(|m| is_real_monitor(m)).count())
}

/// `hyprctl monitors -j` gives each output as an object; an entry that is not
/// an object at all (malformed, or a shape a future hyprctl changes) is not
/// evidence of a real head, so it is skipped rather than demanded on —
/// counting it would push the demand above what actually exists, which is the
/// direction that restarts a healthy desktop. The two exclusions proper are
/// `"disabled": true` and the literal name `FALLBACK`; both checks are exact,
/// so an output that merely lacks a `name` counts, since nothing says it is
/// the synthesized one.
fn is_real_monitor(m: &Value) -> bool {
    if !m.is_object() {
        return false;
    }
    if m.get("disabled").and_then(Value::as_bool).unwrap_or(false) {
        return false;
    }
    m.get("name").and_then(Value::as_str) != Some("FALLBACK")
}

/// Pure: for each `aoide-*` namespace present in `hyprctl layers -j`, the
/// number of DISTINCT real monitors it is mapped on. Skipping `FALLBACK`
/// here as well as in [`real_monitor_count`] is what keeps the two sides of
/// the comparison measuring the same thing: a surface drawn onto the
/// synthesized placeholder output is not painted on a real head, so counting
/// it would satisfy a demand that nothing actually meets. Counting them in
/// one place and not the other is an off-by-one that fires on every blackout.
///
/// Distinct monitors, not total surfaces: a namespace with two surfaces on a
/// SINGLE head covers one head, and must not satisfy a two-head `perMonitor`
/// expectation. Each monitor contributes its namespace once, via the set
/// collected per monitor before the tally.
pub(crate) fn namespace_coverage(layers: &Value) -> BTreeMap<String, usize> {
    let Some(monitors) = layers.as_object() else {
        return BTreeMap::new();
    };
    let mut coverage: BTreeMap<String, usize> = BTreeMap::new();
    for (monitor_name, monitor) in monitors {
        if monitor_name == "FALLBACK" {
            continue;
        }
        // One monitor's own set first, so duplicate surfaces of the same
        // namespace on this one output collapse to a single head's worth of
        // coverage before anything is tallied.
        let namespaces: BTreeSet<&str> = monitor
            .get("levels")
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(|levels| levels.values())
            .filter_map(Value::as_array)
            .flatten()
            .filter_map(|surface| surface.get("namespace").and_then(Value::as_str))
            .filter(|ns| ns.starts_with("aoide-"))
            .collect();
        for ns in namespaces {
            *coverage.entry(ns.to_string()).or_insert(0) += 1;
        }
    }
    coverage
}

/// Pure: does the desktop fall short of the published expectation? `true` is
/// the NEW bad-state predicate — the shell is not painting what it declared —
/// and it is what [`run_healthcheck`] asks when
/// `run/qml/songs/surfaces.json` exists.
///
/// A declared namespace is "genuinely missing" when its [`namespace_coverage`]
/// is below what the declaration demands: `perMonitor` demands coverage equal
/// to [`real_monitor_count`] (one mapped surface on every real output),
/// anything else demands coverage of at least one (exactly one, wherever it
/// lands — this asks only that it exists, since a single surface legitimately
/// lives on whichever output it was placed on).
///
/// Standing down, never restarting, is the answer in every case where the
/// comparison cannot be made in good faith:
///
/// - an EMPTY expectation declares nothing, so nothing can fall short — a
///   song that says nothing is never unhealthy;
/// - `layers` not being an object, or `monitors` not being an array, is a
///   failed/unconfirmed system call (both come back as [`Value::Null`] from
///   `hyprctl_json`), and this watchdog never acts on a reading it does not
///   have;
/// - [`real_monitor_count`] of 0 is the single most important guard here.
///   With no real output there is nowhere to paint, so a restart would
///   reproduce the placeholder state and could loop against a blackout —
///   which is exactly the harm this whole watchdog exists to avoid causing.
///   The shell is expected to come back on its own when a head returns.
///
/// The `perMonitor`-with-zero-monitors case is folded into that last guard
/// deliberately, rather than demanding coverage equal to zero for every
/// namespace (which would be vacuously satisfied): a host in blackout must
/// read the same for both kinds of declaration, and that reading is "stand
/// down".
pub(crate) fn surfaces_fall_short(
    exp: &BTreeMap<String, bool>,
    layers: &Value,
    monitors: &Value,
) -> bool {
    if exp.is_empty() {
        return false;
    }
    if !layers.is_object() {
        return false;
    }
    let Some(real_monitors) = real_monitor_count(monitors) else {
        return false;
    };
    if real_monitors == 0 {
        return false;
    }
    let coverage = namespace_coverage(layers);
    exp.iter().any(|(ns, per_monitor)| {
        let covered = coverage.get(ns).copied().unwrap_or(0);
        if *per_monitor { covered < real_monitors } else { covered == 0 }
    })
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

/// The published expected-paint declaration, read from the live deployed
/// tree: `run/qml/songs/surfaces.json` beside `manifest.json` and
/// `registry.json` (CONTRACTS.md §5). The path resolves through
/// [`aoide_storage::fs::run_qml_dir`] like every other reader of that tree
/// (`crate::ipc`'s `shell.qml` lookup is the sibling case) rather than
/// spelling `$AOIDE_ROOT` or `~/.aoide` here — the runtime root is one
/// relocatable seam, and a second spelling would be the one that drifts.
///
/// EVERY failure mode is `None`: absent (a host whose facet predates this
/// file, or one that never deployed it), unreadable, or not valid JSON. `None`
/// means "no expectation declared", which sends [`run_healthcheck`] down the
/// total-count fallback — the same behaviour this watchdog had before the
/// declaration existed. That is the whole reason failures are swallowed
/// rather than surfaced: this is a build-time statement of intent, not stage
/// state, and a host that never published one must keep working, never report
/// unhealthy for the absence of a file nothing in this crate writes.
///
/// The one impure function here — it reads the filesystem — and deliberately
/// the only one: everything it hands to [`parse_expectation`] and
/// [`surfaces_fall_short`] is a plain [`Value`] so the judgement itself stays
/// unit-testable against literal fixtures.
fn published_surfaces() -> Option<Value> {
    let path = aoide_storage::fs::run_qml_dir().join("songs").join("surfaces.json");
    let bytes = std::fs::read(&path).ok()?;
    serde_json::from_slice(&bytes).ok()
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
///
/// The bad-state predicate: [`surfaces_fall_short`] against the published
/// expectation when there is one, [`shell_has_zero_layers`] when there is
/// not. Everything downstream of that decision — the journal gate, the
/// marker, the retry ladder, the flapping notification — is identical for
/// both, which is deliberate: which surfaces should be mapped is a
/// declaration, but what to DO about a desktop that lost them is not.
pub fn run_healthcheck() -> HealthOutcome {
    if crate::reap::quickshell_service_main_pid().is_none() {
        return HealthOutcome::Healthy;
    }
    let Some(since) = active_enter_timestamp() else {
        return HealthOutcome::Healthy;
    };
    // Current state first, cause second. The mapped-surface predicate is the
    // only signal that speaks to NOW (module header), so it decides `Healthy`
    // on its own; the journal line only chooses between acting and reporting
    // once the desktop is already known to fall short. Reading them the other
    // way round is what made incident #40 invisible, and it spends a full
    // `journalctl` read on every healthy tick; this order pays that only
    // when something is actually wrong.
    //
    // Which predicate, though, depends on whether anything was declared. With
    // a published expectation the declared set decides, and `hyprctl monitors`
    // is read because a `perMonitor` namespace is judged against the real
    // output count. With none, the old total count decides and the monitors
    // call is never made at all — a host that declares nothing pays nothing
    // for a mechanism it opted out of.
    let layers = hyprctl_json("layers");
    let published = published_surfaces();
    let expectation = published.as_ref().and_then(parse_expectation);
    let bad = match expectation {
        Some(exp) => surfaces_fall_short(&exp, &layers, &hyprctl_json("monitors")),
        None => shell_has_zero_layers(&layers),
    };
    if !bad {
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

    // The NO-EXPECTATION fallback's own regression, from before a
    // declaration existed: this predicates sums surfaces across every
    // monitor, so a second enabled output that legitimately and permanently
    // carries zero layers must not read as stuck. It stays correct for what
    // it now is — the fallback a host that publishes no expectation keeps —
    // and the per-monitor demand that WOULD flag this host lives in
    // `surfaces_fall_short`, asked only when a song declares one.
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

    // ── The declared-expectation predicate ────────────────────────────────
    //
    // The published shape, verbatim from the quickshell facet's own output
    // (`modules/facets/quickshell/default.nix`'s `surfacesJsonFile`,
    // CONTRACTS.md §5): one object, NOT keyed by song, whose keys are the
    // already-RESOLVED layer-shell namespaces. That resolution is why nothing
    // here derives `aoide-<slot>` itself.
    fn sonata_expectation() -> Value {
        json!({
            "song": "sonata",
            "surfaces": {
                "aoide-bar": { "perMonitor": true },
                "aoide-wallpaper": { "perMonitor": true },
                "aoide-dock": { "perMonitor": false }
            }
        })
    }

    fn two_real_monitors() -> Value {
        json!([
            { "name": "DP-1", "disabled": false },
            { "name": "HDMI-A-1", "disabled": false }
        ])
    }

    #[test]
    fn parse_expectation_reads_namespaces_to_their_per_monitor_flag() {
        let exp = parse_expectation(&sonata_expectation()).unwrap();
        assert_eq!(exp.get("aoide-bar"), Some(&true));
        assert_eq!(exp.get("aoide-wallpaper"), Some(&true));
        assert_eq!(exp.get("aoide-dock"), Some(&false));
        assert_eq!(exp.len(), 3);
    }

    #[test]
    fn parse_expectation_is_none_without_a_surfaces_object() {
        assert_eq!(parse_expectation(&Value::Null), None);
        assert_eq!(parse_expectation(&json!("aoide-bar")), None);
        assert_eq!(parse_expectation(&json!([1, 2])), None);
        // An object, but not this file's shape — a bare namespace map under
        // some other key is not a declaration this reads.
        assert_eq!(parse_expectation(&json!({ "song": "sonata" })), None);
        assert_eq!(parse_expectation(&json!({ "surfaces": "aoide-bar" })), None);
    }

    // An empty declaration is `Some`, NOT `None`, and the difference is
    // load-bearing: `None` means "nothing published, keep the old count",
    // while an empty map means "this song declared nothing and expects
    // nothing". Collapsing them would make a song with an empty declaration
    // un-satisfiable and restart forever.
    #[test]
    fn parse_expectation_keeps_an_empty_declaration_distinct_from_no_declaration() {
        let empty = parse_expectation(&json!({ "song": "nocturne", "surfaces": {} })).unwrap();
        assert!(empty.is_empty());
    }

    // A hand-written or forward-compatible entry omitting the flag reads as
    // the WEAKER demand, matching the nix option's own `perMonitor = false`
    // default, rather than as malformed.
    #[test]
    fn parse_expectation_defaults_a_missing_per_monitor_to_false() {
        let exp = parse_expectation(&json!({ "surfaces": { "aoide-dock": {} } })).unwrap();
        assert_eq!(exp.get("aoide-dock"), Some(&false));
    }

    #[test]
    fn real_monitor_count_excludes_disabled_outputs() {
        let monitors = json!([
            { "name": "DP-1", "disabled": false },
            { "name": "HDMI-A-1", "disabled": true },
            { "name": "DP-2", "disabled": false }
        ]);
        assert_eq!(real_monitor_count(&monitors), Some(2));
    }

    // Hyprland synthesizes an output literally named `FALLBACK` while every
    // real head is off. Counting it would demand a surface on a monitor that
    // does not exist, so the count is zero — the stand-down case.
    #[test]
    fn real_monitor_count_excludes_the_synthesized_fallback_output() {
        let monitors = json!([{ "name": "FALLBACK", "disabled": false }]);
        assert_eq!(real_monitor_count(&monitors), Some(0));
        assert_eq!(real_monitor_count(&json!([])), Some(0));
    }

    // `None`, not `Some(0)`: a failed `hyprctl` is UNCONFIRMED, and
    // unconfirmed must never be flattened into the "no real output, stand
    // down" reading — they mean different things to the caller.
    #[test]
    fn real_monitor_count_is_none_when_hyprctl_did_not_answer() {
        assert_eq!(real_monitor_count(&Value::Null), None);
        assert_eq!(real_monitor_count(&json!({ "DP-1": {} })), None);
        assert_eq!(real_monitor_count(&json!("DP-1")), None);
    }

    // A non-object entry is not evidence of a head. Counting it would push
    // the demand above what exists, which is the direction that restarts a
    // healthy desktop — so it is skipped, and an output merely lacking a
    // `name` (nothing says it is the synthesized one) still counts.
    #[test]
    fn real_monitor_count_skips_non_object_entries_but_not_nameless_ones() {
        let monitors = json!([1, "DP-1", { "disabled": false }, { "name": "DP-1" }]);
        assert_eq!(real_monitor_count(&monitors), Some(2));
    }

    #[test]
    fn namespace_coverage_counts_one_per_monitor_with_that_namespace() {
        let layers = json!({
            "DP-1": {
                "levels": {
                    "0": [{"namespace": "aoide-wallpaper"}],
                    "2": [{"namespace": "aoide-bar"}, {"namespace": "aoide-dock"}]
                }
            },
            "HDMI-A-1": {
                "levels": { "0": [{"namespace": "aoide-wallpaper"}], "2": [] }
            }
        });
        let coverage = namespace_coverage(&layers);
        assert_eq!(coverage.get("aoide-wallpaper"), Some(&2));
        assert_eq!(coverage.get("aoide-bar"), Some(&1));
        assert_eq!(coverage.get("aoide-dock"), Some(&1));
    }

    // Distinct monitors, not total surfaces. The dock's own column can hold
    // the same namespace at two levels on one head; that is still one head
    // covered, and it must not satisfy a two-head `perMonitor` demand.
    #[test]
    fn namespace_coverage_collapses_duplicate_surfaces_on_one_head() {
        let layers = json!({
            "DP-1": {
                "levels": {
                    "0": [{"namespace": "aoide-wallpaper"}],
                    "2": [{"namespace": "aoide-wallpaper"}]
                }
            }
        });
        assert_eq!(namespace_coverage(&layers).get("aoide-wallpaper"), Some(&1));
    }

    // Same exclusion as `real_monitor_count`: a surface drawn onto the
    // synthesized placeholder output is not painted on a real head. Counting
    // it on one side and not the other is an off-by-one that fires the
    // watchdog on every blackout.
    #[test]
    fn namespace_coverage_skips_the_synthesized_fallback_output() {
        let layers = json!({
            "FALLBACK": { "levels": { "0": [{"namespace": "aoide-wallpaper"}] } },
            "DP-1": { "levels": { "0": [{"namespace": "aoide-bar"}] } }
        });
        let coverage = namespace_coverage(&layers);
        assert_eq!(coverage.get("aoide-wallpaper"), None);
        assert_eq!(coverage.get("aoide-bar"), Some(&1));
    }

    #[test]
    fn namespace_coverage_ignores_non_aoide_namespaces_and_malformed_layers() {
        let layers = json!({
            "DP-1": { "levels": { "0": [{"namespace": "waybar"}, {"namespace": "aoide-bar"}] } }
        });
        let coverage = namespace_coverage(&layers);
        assert_eq!(coverage.get("aoide-bar"), Some(&1));
        assert_eq!(coverage.get("waybar"), None);
        // A failed `hyprctl layers` is an empty map, never a panic.
        assert!(namespace_coverage(&Value::Null).is_empty());
    }

    // The actual incident: two real heads, the per-screen wallpaper recovered
    // on both, the bar stayed mapped on only one. The bar and the dock
    // survived the blip bound to the dead output, and the old TOTAL count saw
    // three surviving `aoide-*` surfaces and called this desktop healthy for
    // hours. Against the declaration, `aoide-bar` covers one head where two
    // are demanded — genuinely missing.
    #[test]
    fn the_incident_a_per_monitor_namespace_mapped_on_only_one_of_two_heads_falls_short() {
        let layers = json!({
            "DP-1": {
                "levels": {
                    "0": [{"namespace": "aoide-wallpaper"}],
                    "2": [{"namespace": "aoide-bar"}]
                }
            },
            "HDMI-A-1": {
                "levels": { "0": [{"namespace": "aoide-wallpaper"}], "2": [] }
            }
        });
        // Precondition: the OLD predicate reads this desktop as healthy,
        // which is the whole defect — the new one must not.
        assert!(!shell_has_zero_layers(&layers));
        let exp = parse_expectation(&sonata_expectation()).unwrap();
        assert!(surfaces_fall_short(&exp, &layers, &two_real_monitors()));
    }

    #[test]
    fn a_declared_non_per_monitor_namespace_mapped_nowhere_falls_short() {
        let layers = json!({
            "DP-1": {
                "levels": {
                    "0": [{"namespace": "aoide-wallpaper"}],
                    "2": [{"namespace": "aoide-bar"}]
                }
            },
            "HDMI-A-1": {
                "levels": { "0": [{"namespace": "aoide-wallpaper"}], "2": [{"namespace": "aoide-bar"}] }
            }
        });
        // Everything per-monitor is satisfied on both heads; only the dock —
        // declared `perMonitor = false`, demanding exactly one, wherever it
        // lands — is absent, and its absence alone is the verdict.
        let exp = parse_expectation(&sonata_expectation()).unwrap();
        assert!(surfaces_fall_short(&exp, &layers, &two_real_monitors()));
    }

    #[test]
    fn a_fully_satisfied_declaration_does_not_fall_short() {
        let layers = json!({
            "DP-1": {
                "levels": {
                    "0": [{"namespace": "aoide-wallpaper"}],
                    "2": [{"namespace": "aoide-bar"}, {"namespace": "aoide-dock"}]
                }
            },
            "HDMI-A-1": {
                "levels": {
                    "0": [{"namespace": "aoide-wallpaper"}],
                    "2": [{"namespace": "aoide-bar"}]
                }
            }
        });
        let exp = parse_expectation(&sonata_expectation()).unwrap();
        assert!(!surfaces_fall_short(&exp, &layers, &two_real_monitors()));
    }

    // One real head plus the synthesized `FALLBACK` output, everything mapped
    // on the real one. The fallback must be excluded from BOTH the demand
    // (the count) and the coverage: a perMonitor namespace mapped once on the
    // one real head satisfies a one-head expectation, and a namespace drawn
    // on the phantom does not count.
    #[test]
    fn one_real_head_plus_fallback_is_satisfied_when_the_real_head_is_covered() {
        let layers = json!({
            "HDMI-A-1": {
                "levels": {
                    "0": [{"namespace": "aoide-wallpaper"}],
                    "2": [{"namespace": "aoide-bar"}, {"namespace": "aoide-dock"}]
                }
            },
            "FALLBACK": { "levels": { "0": [], "1": [], "2": [], "3": [] } }
        });
        let monitors = json!([
            { "name": "HDMI-A-1", "disabled": false },
            { "name": "FALLBACK", "disabled": false }
        ]);
        let exp = parse_expectation(&sonata_expectation()).unwrap();
        assert!(!surfaces_fall_short(&exp, &layers, &monitors));
    }

    // ── Standing down: every case where the predicate must NOT be true ────
    //
    // A song that declares nothing is never unhealthy — nothing can fall
    // short of an empty demand.
    #[test]
    fn an_empty_expectation_never_falls_short() {
        let layers = json!({
            "DP-1": { "levels": { "0": [], "1": [], "2": [], "3": [] } },
            "HDMI-A-1": { "levels": { "0": [], "1": [], "2": [], "3": [] } }
        });
        assert!(!surfaces_fall_short(&BTreeMap::new(), &layers, &two_real_monitors()));
    }

    #[test]
    fn an_unreadable_layers_reading_never_falls_short() {
        let exp = parse_expectation(&sonata_expectation()).unwrap();
        assert!(!surfaces_fall_short(&exp, &Value::Null, &two_real_monitors()));
        assert!(!surfaces_fall_short(&exp, &json!([1, 2]), &two_real_monitors()));
        assert!(!surfaces_fall_short(&exp, &json!("DP-1"), &two_real_monitors()));
    }

    #[test]
    fn an_unreadable_monitors_reading_never_falls_short() {
        let exp = parse_expectation(&sonata_expectation()).unwrap();
        assert!(!surfaces_fall_short(&exp, &json!({}), &Value::Null));
        assert!(!surfaces_fall_short(&exp, &json!({}), &json!({ "DP-1": {} })));
    }

    // THE single most important guard in this predicate. With no real output
    // enabled there is nothing to paint on: restarting reproduces the
    // placeholder state and could loop straight through a blackout — the
    // exact harm this watchdog exists to avoid causing. Standing down is
    // correct because the shell is expected to reattach on its own when a
    // head returns.
    #[test]
    fn zero_real_monitors_never_falls_short_even_with_nothing_mapped() {
        let exp = parse_expectation(&sonata_expectation()).unwrap();
        // Every declared namespace absent from `hyprctl layers`.
        let blank_layers = json!({});
        // No monitors at all: a display that has gone to sleep, a laptop lid
        // shut, a dock unplugged.
        assert!(!surfaces_fall_short(&exp, &blank_layers, &json!([])));
        // Every real head disabled.
        let all_disabled = json!([
            { "name": "DP-1", "disabled": true },
            { "name": "HDMI-A-1", "disabled": true }
        ]);
        assert!(!surfaces_fall_short(&exp, &blank_layers, &all_disabled));
        // Only Hyprland's synthesized placeholder output remains — the exact
        // state a blip leaves behind, and the one a restart cannot fix.
        let fallback_only = json!([{ "name": "FALLBACK", "disabled": false }]);
        assert!(!surfaces_fall_short(&exp, &blank_layers, &fallback_only));
    }

    // The empty expectation and the zero-monitor guard must compose: a song
    // declaring nothing on a host in blackout is the most stand-down case
    // there is.
    #[test]
    fn an_empty_expectation_on_a_blacked_out_host_never_falls_short() {
        assert!(!surfaces_fall_short(&BTreeMap::new(), &Value::Null, &json!([])));
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

        // A desktop that is not what it declared must never render as the
        // healthy one — that collapse is what left incident #40 unreported
        // for 22 minutes, and separately what let a half-painted desktop read
        // healthy for hours. The wording must not assert a blank desktop
        // either: this variant now also covers a shell painting SOMETHING,
        // just not the declared set.
        assert_eq!(HealthOutcome::Blank.tag(), "blank");
        let blank = HealthOutcome::Blank.message();
        assert!(blank.contains("not painting what it should be"), "{blank}");
        assert!(blank.contains("not restarting"), "{blank}");
        assert!(!blank.contains("painting nothing"), "{blank}");

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
