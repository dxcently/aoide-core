//! `aoide screen point <verb>` — pointer synthesis, ported from
//! `tools/pointer.sh` (Phase 2 of the `screen` verb family; the script is
//! the BEHAVIORAL spec, read but not reused as code — a bash prototype, not
//! a library, same relationship `capture.rs`/`hypr.rs` already have to it).
//!
//! ── Why real motion, not a warp (measured; see `tools/pointer.sh`'s own
//! header + `song/songbook/sonata/design/hazards.md` §6) ──────────────────
//! `hyprctl dispatch movecursor` WARPS the cursor: it does not generate a
//! `wl_pointer.motion` event inside a surface the pointer is already in, so
//! hover states never change and no agent could ever verify one. The three
//! motion-synthesizing verbs here (`move`/`click`/`scroll`) instead drive
//! `zwlr_virtual_pointer_manager_v1` via `wlrctl`, entering Hyprland's
//! normal input pipeline and producing genuine events. `restore` is the one
//! deliberate exception — see [`super::hypr::dispatch_movecursor`]'s doc.
//!
//! ── The pointer-synthesis boundary (khoa, 2026-08-16) — mirrors
//! `capture.rs`'s pixel-acquisition boundary exactly ───────────────────────
//! [`run_wlrctl_pointer`] is the ONLY place `wlrctl` is named anywhere in
//! this crate. Every verb above it decides WHAT pointer action to
//! synthesize (delta math, button choice, scroll notches) and hands down
//! already-assembled argv; this function decides HOW. [`PointerError`]'s
//! reason codes stay backend-agnostic (`pointer-*`, never `wlrctl-*`) — the
//! same discipline `capture.rs`'s `capture_image`/`CaptureError` boundary
//! already established for grim (khoa's Phase 1 review, D2): a caller must
//! never learn which tool did the work from the reason code, only (when it
//! wants to) from the free-text detail string.
//!
//! ── NOT live-proven this phase (khoa's Phase 2 brief, explicit + HARD RULE
//! 5) ────────────────────────────────────────────────────────────────────
//! A human may be at this desk with the pointer physically "leased" to
//! another agent while this phase is built. `move`/`click`/`scroll` all
//! shell out to [`run_wlrctl_pointer`], and `restore` warps via
//! [`super::hypr::dispatch_movecursor`] — none of the four are executed
//! live this phase, only unit-tested up to (never across) that boundary.
//! `idle`/`save` are pure reads (never touch wlrctl, never move anything)
//! and ARE live-proven — see the executor's report. The usage-error paths
//! of every verb (missing/malformed args) return before touching hyprctl OR
//! wlrctl at all, so those are live-proven too, for all six verbs.

use super::hypr;
use aoide_protocol::output::Outcome;
use aoide_protocol::Invocation;
use serde_json::json;

// ── Absolute→relative delta (wlrctl's `pointer move` is relative-only) ────

/// The relative delta `wlrctl pointer move` needs to land the cursor on
/// `target`, computed from wherever it is `current`ly. Saturating: a target
/// or current position near the i64 extremes (malformed `--x`/`--y` input,
/// or a pathological hyprctl reading) must never overflow/panic computing
/// the delta — mirrors `capture::clamp_region`'s saturating discipline
/// exactly (khoa's Phase 1 review, D3; the same class of bug, ported ahead
/// of it recurring here).
pub fn move_delta(current: hypr::Point, target: hypr::Point) -> (i64, i64) {
    (
        target.x.saturating_sub(current.x),
        target.y.saturating_sub(current.y),
    )
}

// ── The drift decision: did the move land? ─────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MoveResult {
    Landed,
    Drifted { got: hypr::Point },
}

/// Exact-equality landing check — mirrors `tools/pointer.sh`'s own
/// `[ "$got" = "$x,$y" ]` string comparison exactly (no tolerance/fuzz
/// band: a real wlrctl move either lands exactly or something interfered —
/// a human bump, or an off-screen/clamped target). A drift must halt a
/// scripted loop rather than let it sail on to a blind click on the wrong
/// spot (khoa's brief, `move`'s spec).
pub fn classify_landing(target: hypr::Point, got: hypr::Point) -> MoveResult {
    if got == target {
        MoveResult::Landed
    } else {
        MoveResult::Drifted { got }
    }
}

// ── The guarded-click predicate ─────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ClickRefusal {
    pub at: hypr::Point,
    pub expected: hypr::Point,
}

/// `None` (no `X Y` given) always passes — no guard was asked for. `Some`
/// requires an EXACT match; any mismatch, however small, refuses. The one
/// irreversible action (a real button press) gets the one pre-flight guard
/// — a human bump between `move` and `click` becomes a loud refusal, never
/// a blind press (khoa's brief, `click`'s spec; mirrors `tools/pointer.sh`'s
/// `[ "$now" = "$want" ] || refuse`).
pub fn guard_click(
    expected: Option<hypr::Point>,
    actual: hypr::Point,
) -> Result<(), ClickRefusal> {
    match expected {
        None => Ok(()),
        Some(e) if e == actual => Ok(()),
        Some(e) => Err(ClickRefusal { at: actual, expected: e }),
    }
}

// ── Button vocabulary ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Button {
    Left,
    Right,
    Middle,
}

impl Button {
    /// Case-sensitive lowercase spellings only — mirrors `tools/pointer.sh`'s
    /// own bash `case` match exactly (`left|right|middle`, no `nocasematch`).
    pub fn parse(s: &str) -> Option<Button> {
        match s {
            "left" => Some(Button::Left),
            "right" => Some(Button::Right),
            "middle" => Some(Button::Middle),
            _ => None,
        }
    }
    /// wlrctl's own button vocabulary — identical spellings, so this doubles
    /// as the wlrctl argv token.
    pub fn as_str(self) -> &'static str {
        match self {
            Button::Left => "left",
            Button::Right => "right",
            Button::Middle => "middle",
        }
    }
}

/// Parse `click`'s flexible positional shape: `[button] [x y]`. The button
/// word, if present, is consumed first; whatever remains must be exactly
/// zero or two tokens (a guard needs both coordinates or neither).
///
/// **Deliberate divergence from `tools/pointer.sh`** (khoa's brief: state
/// divergences plainly). Bash's `case "${1:-}" in left|right|middle) …;;
/// esac` only shifts $1 when it MATCHES a button word — if it doesn't (e.g.
/// a stray `click 500`, one bare number with no pair), the non-matching
/// token is left in place, `$#` stays 1, the `[ $# -ge 2 ]` guard check
/// fails, and `cmd_click` silently proceeds with the default button,
/// **dropping the stray argument with no error at all**. That silent drop
/// is exactly the kind of "a caller would then act on a lie" failure this
/// codebase's own review comments repeatedly flag elsewhere (e.g.
/// `capture.rs`'s clamp-announcement discipline) — so this port makes it a
/// usage error instead: any leftover token count other than 0 or 2 refuses
/// up front, before anything is read or pressed.
pub fn parse_click_args(args: &[String]) -> Result<(Button, Option<(i64, i64)>), String> {
    let (button, rest): (Button, &[String]) =
        match args.first().and_then(|s| Button::parse(s)) {
            Some(b) => (b, &args[1..]),
            None => (Button::Left, args),
        };
    match rest.len() {
        0 => Ok((button, None)),
        2 => {
            let x: i64 = rest[0]
                .parse()
                .map_err(|_| format!("<x> must be an integer, got `{}`", rest[0]))?;
            let y: i64 = rest[1]
                .parse()
                .map_err(|_| format!("<y> must be an integer, got `{}`", rest[1]))?;
            Ok((button, Some((x, y))))
        }
        n => Err(format!(
            "click takes [left|right|middle] [x y] — {n} trailing arg(s) don't fit that shape"
        )),
    }
}

// ── Scroll notch math ────────────────────────────────────────────────────

/// One notch == wlrctl value 5 (measured, `tools/pointer.sh`: `v=$(( n * 5
/// ))`). Saturating: an extreme `N` must not overflow computing the wlrctl
/// value.
pub fn scroll_notches(n: i64) -> i64 {
    n.saturating_mul(5)
}

// ── wlrctl argv assembly — pure, one function per verb, unit-tested
// directly. These are the only functions besides run_wlrctl_pointer that
// know wlrctl's own subcommand vocabulary. ────────────────────────────────

pub fn move_argv(dx: i64, dy: i64) -> Vec<String> {
    vec!["pointer".into(), "move".into(), dx.to_string(), dy.to_string()]
}

pub fn click_argv(button: Button) -> Vec<String> {
    vec!["pointer".into(), "click".into(), button.as_str().into()]
}

/// `pointer scroll <v> 0` — positive `N` (down) matches a physical wheel
/// pulled toward the user, per `tools/pointer.sh`.
pub fn scroll_argv(n: i64) -> Vec<String> {
    vec![
        "pointer".into(),
        "scroll".into(),
        scroll_notches(n).to_string(),
        "0".into(),
    ]
}

// ── Idle-streak tracking ─────────────────────────────────────────────────

/// One incremental step: given the running (last-sample, streak-length)
/// state and a NEW sample, returns the updated state. A changed sample
/// resets the streak to 1 (this new sample is itself the first of a
/// possible new streak); a repeat extends it.
///
/// **Deliberate divergence from `tools/pointer.sh`** (state plainly, per
/// the brief). Bash: `if [ "$p" = "$last" ]; then n=$((n+1)); else n=0;
/// last=$p; fi` — on a CHANGE it sets `n=0`, not `1`, so the sample that
/// just became the new `last` isn't itself counted; reaching `n -ge
/// need_n` therefore takes `need_n + 1` raw samples in bash, off by one
/// from its own doc comment's claim of "N consecutive identical samples".
/// This version counts a streak's first sample as 1, so `need_n` raw
/// samples suffice — matching the STATED intent exactly rather than
/// reproducing the off-by-one. Functionally near-identical at the 250ms
/// poll cadence (one extra ~0.25s in the bash version); not ported as a
/// bug-for-bug port on purpose.
pub fn idle_step(
    state: (Option<hypr::Point>, u32),
    sample: hypr::Point,
) -> (Option<hypr::Point>, u32) {
    match state.0 {
        Some(last) if last == sample => (Some(sample), state.1 + 1),
        _ => (Some(sample), 1),
    }
}

/// Fold a whole synthetic sample sequence through [`idle_step`], returning
/// the sample at the point the streak FIRST reaches `need_n` — `None` if it
/// never does. Pure, so a test can feed a fixed `&[Point]` standing in for
/// "what the poller sampled over time" (the brief's own phrasing) without
/// any real sleeping or hyprctl spawn. [`wait_idle`] (not unit-tested —
/// env/timing-dependent) folds this exact same step function over REAL
/// samples one at a time, live.
pub fn track_idle(samples: &[hypr::Point], need_n: u32) -> Option<hypr::Point> {
    let mut state: (Option<hypr::Point>, u32) = (None, 0);
    for &s in samples {
        state = idle_step(state, s);
        if state.1 >= need_n {
            return Some(s);
        }
    }
    None
}

// ── THE POINTER-SYNTHESIS BOUNDARY ──────────────────────────────────────

/// One `wlrctl` shell-out's failure, split the same way `CaptureError`/
/// `HyprError` already split theirs (spawn-failed vs ran-but-refused).
#[derive(Debug, Clone, PartialEq)]
pub enum PointerError {
    /// `wlrctl` couldn't even be spawned (missing / no exec bit).
    Unavailable(String),
    /// It ran but exited nonzero.
    Failed(String),
}

impl PointerError {
    /// Backend-agnostic reason code — `pointer-*`, NEVER `wlrctl-*` (khoa's
    /// Phase 1 review, D2, applied preemptively here per the Phase 2 brief:
    /// a caller must never learn which tool did the work from this code).
    pub fn reason(&self) -> &'static str {
        match self {
            PointerError::Unavailable(_) => "pointer-unavailable",
            PointerError::Failed(_) => "pointer-failed",
        }
    }
    /// The actual backend detail (wlrctl's stderr, or the OS spawn error) —
    /// genuinely useful troubleshooting text; unlike `reason()`, allowed to
    /// say whatever wlrctl actually said.
    pub fn detail(&self) -> &str {
        match self {
            PointerError::Unavailable(s) | PointerError::Failed(s) => s,
        }
    }
}

/// THE POINTER-SYNTHESIS BOUNDARY (khoa, 2026-08-16, Phase 2). Everything
/// above this function in the call chain decides WHAT pointer action to
/// synthesize; this decides HOW. Today: one `wlrctl` shell-out — the ONLY
/// place `wlrctl` is named anywhere in this codebase. Judged the ordinary
/// way (like `capture_image`, unlike `song::ipc`'s quirky void-IPC case):
/// wlrctl prints its error to stderr and exits nonzero on failure, exit 0
/// means the action was synthesized; no output-vs-exit-code mismatch to
/// guard against. NOT unit-tested itself (spawns a real process, and per
/// HARD RULE 5 this phase never invokes it live either — see the module
/// header); every pure argv-assembly function that feeds it IS unit-tested.
pub fn run_wlrctl_pointer(argv: &[String]) -> Result<(), PointerError> {
    match std::process::Command::new("wlrctl").args(argv).output() {
        Err(e) => Err(PointerError::Unavailable(e.to_string())),
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => {
            let said = String::from_utf8_lossy(&out.stderr);
            let said = said.trim();
            Err(PointerError::Failed(if said.is_empty() {
                format!("wlrctl exited {:?} with no message", out.status.code())
            } else {
                said.to_string()
            }))
        }
    }
}

/// A [`PointerError`] folded into the command's structured error `Outcome`
/// — mirrors `hypr::hypr_error_outcome` exactly.
fn pointer_error_outcome(cmd: &str, e: &PointerError) -> Outcome {
    Outcome::error(cmd, format!("{}: {}", e.reason(), e.detail()))
        .with_data(json!({ "reason": e.reason() }))
}

// ── The live idle poller (NOT unit-tested — real sleeps + a real hyprctl
// spawn loop; env/timing-dependent, same reason hypr::run_hyprctl_json
// itself isn't). Read-only: never touches wlrctl, so — unlike every other
// live action this phase — this IS exercised live; see the executor's
// report. ───────────────────────────────────────────────────────────────

pub enum IdleResult {
    Idle(hypr::Point),
    Timeout,
}

/// Poll `hyprctl cursorpos` every 250ms until [`track_idle`]'s streak
/// condition is met, or `timeout_s` elapses — `tools/pointer.sh`'s own
/// `cmd_idle` polling cadence, ported directly (`max_tries =
/// timeout_s.saturating_mul(4)`; saturating because an adversarial
/// `--timeout` must not overflow the trip count, though nothing this small
/// realistically would).
///
/// **Divergence from `tools/pointer.sh`**: a genuine `hyprctl` failure
/// mid-poll propagates immediately as `Err(HyprError)` rather than (bash's
/// behavior) silently looping on whatever `cursorpos` printed on failure
/// (empty/garbage, never checked). `hypr::cursor()` already gives typed
/// failure detection for free; swallowing it here would be strictly worse,
/// not a deliberate simplification.
fn wait_idle(need_n: u32, timeout_s: u64) -> Result<IdleResult, hypr::HyprError> {
    let max_tries = timeout_s.saturating_mul(4);
    let mut state: (Option<hypr::Point>, u32) = (None, 0);
    for _ in 0..max_tries {
        let p = hypr::cursor()?;
        state = idle_step(state, p);
        if state.1 >= need_n {
            return Ok(IdleResult::Idle(p));
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    Ok(IdleResult::Timeout)
}

// ── `aoide screen point <verb>` handlers ────────────────────────────────

/// `aoide screen point move <x> <y>` — absolute move via real wlrctl
/// motion, verified on landing. See the module header for the full
/// move/verify/drift story; NOT executed live this phase (HARD RULE 5) past
/// the usage-error paths (missing/malformed `<x>`/`<y>`, which return
/// before touching hyprctl or wlrctl at all).
pub fn point_move(inv: &Invocation) -> Outcome {
    let cmd = "screen.point.move";
    if inv.args.len() < 2 {
        return Outcome::usage(cmd, format!("usage: aoide {} <x> <y> [--json]", inv.path.join(" ")));
    }
    let x: i64 = match inv.args[0].parse() {
        Ok(v) => v,
        Err(_) => return Outcome::usage(cmd, format!("<x> must be an integer, got `{}`", inv.args[0])),
    };
    let y: i64 = match inv.args[1].parse() {
        Ok(v) => v,
        Err(_) => return Outcome::usage(cmd, format!("<y> must be an integer, got `{}`", inv.args[1])),
    };
    let target = hypr::Point { x, y };

    let current = match hypr::cursor() {
        Ok(p) => p,
        Err(e) => return hypr::hypr_error_outcome(cmd, &e),
    };
    let (dx, dy) = move_delta(current, target);
    if let Err(e) = run_wlrctl_pointer(&move_argv(dx, dy)) {
        return pointer_error_outcome(cmd, &e);
    }
    let got = match hypr::cursor() {
        Ok(p) => p,
        Err(e) => return hypr::hypr_error_outcome(cmd, &e),
    };
    match classify_landing(target, got) {
        MoveResult::Landed => Outcome::ok(cmd, format!("moved to {},{}", got.x, got.y))
            .with_data(json!({ "x": got.x, "y": got.y })),
        MoveResult::Drifted { got } => Outcome::error(
            cmd,
            format!(
                "drift — pointer at {},{}, wanted {},{}: a human moved the mouse, or the target is off-screen",
                got.x, got.y, target.x, target.y
            ),
        )
        .with_data(json!({
            "reason": "pointer-drift",
            "x": got.x, "y": got.y,
            "wanted": { "x": target.x, "y": target.y },
        })),
    }
}

/// `aoide screen point click [left|right|middle] [x y]` — see the module
/// header on the guard. NOT executed live this phase (HARD RULE 5) past the
/// usage-error paths.
pub fn point_click(inv: &Invocation) -> Outcome {
    let cmd = "screen.point.click";
    let (button, guard) = match parse_click_args(&inv.args) {
        Ok(v) => v,
        Err(msg) => return Outcome::usage(cmd, msg),
    };
    if let Some((x, y)) = guard {
        let actual = match hypr::cursor() {
            Ok(p) => p,
            Err(e) => return hypr::hypr_error_outcome(cmd, &e),
        };
        if let Err(refusal) = guard_click(Some(hypr::Point { x, y }), actual) {
            return Outcome::error(
                cmd,
                format!(
                    "pointer at {},{}, expected {},{} — not pressing blind",
                    refusal.at.x, refusal.at.y, refusal.expected.x, refusal.expected.y
                ),
            )
            .with_data(json!({ "reason": "pointer-refused" }));
        }
    }
    if let Err(e) = run_wlrctl_pointer(&click_argv(button)) {
        return pointer_error_outcome(cmd, &e);
    }
    Outcome::ok(cmd, format!("click {}", button.as_str()))
        .with_data(json!({ "button": button.as_str() }))
}

/// `aoide screen point scroll <n>` — positive down, negative up. NOT
/// executed live this phase (HARD RULE 5) past the usage-error path
/// (missing/malformed `<n>`).
pub fn point_scroll(inv: &Invocation) -> Outcome {
    let cmd = "screen.point.scroll";
    let n: i64 = match inv.args.first() {
        Some(s) => match s.parse() {
            Ok(v) => v,
            Err(_) => return Outcome::usage(cmd, format!("<n> must be an integer, got `{s}`")),
        },
        None => return Outcome::usage(cmd, format!("usage: aoide {} <n> [--json]", inv.path.join(" "))),
    };
    if let Err(e) = run_wlrctl_pointer(&scroll_argv(n)) {
        return pointer_error_outcome(cmd, &e);
    }
    let dir = match n.cmp(&0) {
        std::cmp::Ordering::Greater => "down",
        std::cmp::Ordering::Less => "up",
        std::cmp::Ordering::Equal => "none",
    };
    Outcome::ok(cmd, format!("scroll {n} notch(es) {dir}"))
        .with_data(json!({ "n": n, "direction": dir }))
}

/// `aoide screen point idle [samples] [timeout]` — read-only; SAFE and
/// live-proven this phase (see the module header).
pub fn point_idle(inv: &Invocation) -> Outcome {
    let cmd = "screen.point.idle";
    let need_n: u32 = match inv.args.first() {
        None => 10,
        Some(s) => match s.parse::<u32>() {
            Ok(v) if v >= 1 => v,
            _ => return Outcome::usage(cmd, format!("<samples> must be a positive integer, got `{s}`")),
        },
    };
    let timeout_s: u64 = match inv.args.get(1) {
        None => 60,
        Some(s) => match s.parse::<u64>() {
            Ok(v) if v >= 1 => v,
            _ => return Outcome::usage(cmd, format!("<timeout> must be a positive integer of seconds, got `{s}`")),
        },
    };
    match wait_idle(need_n, timeout_s) {
        Err(e) => hypr::hypr_error_outcome(cmd, &e),
        Ok(IdleResult::Idle(p)) => Outcome::ok(cmd, format!("idle at {},{}", p.x, p.y))
            .with_data(json!({ "x": p.x, "y": p.y, "samples": need_n })),
        Ok(IdleResult::Timeout) => Outcome::error(
            cmd,
            format!("not idle after {timeout_s}s — a human appears to be using this mouse"),
        )
        .with_data(json!({ "reason": "pointer-not-idle" })),
    }
}

/// `aoide screen point save` — persist the current cursor position.
/// Read-only cursor sample + a local file write; SAFE and live-proven this
/// phase.
pub fn point_save(_inv: &Invocation) -> Outcome {
    let cmd = "screen.point.save";
    let p = match hypr::cursor() {
        Ok(p) => p,
        Err(e) => return hypr::hypr_error_outcome(cmd, &e),
    };
    let path = aoide_storage::fs::pointer_state_file();
    let text = serde_json::to_string(&p).unwrap_or_default();
    if let Err(e) = aoide_storage::fs::atomic_write(&path, &text) {
        return Outcome::error(cmd, format!("read cursor but failed to persist it: {e}"))
            .with_data(json!({ "reason": "pointer-save-failed" }));
    }
    Outcome::ok(cmd, format!("saved {},{} to {}", p.x, p.y, path.display()))
        .changed(vec![path.to_string_lossy().into_owned()])
        .with_data(json!({ "x": p.x, "y": p.y, "path": path.to_string_lossy() }))
}

/// `aoide screen point restore` — warp back to the last `save`d position
/// (see [`hypr::dispatch_movecursor`]'s doc on why a warp is the right tool
/// here). MOVES the pointer — NOT executed live this phase (HARD RULE 5).
pub fn point_restore(_inv: &Invocation) -> Outcome {
    let cmd = "screen.point.restore";
    let path = aoide_storage::fs::pointer_state_file();
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => {
            return Outcome::error(
                cmd,
                format!(
                    "nothing saved — {} does not exist (run `screen point save` first)",
                    path.display()
                ),
            )
            .with_data(json!({ "reason": "pointer-nothing-saved" }))
        }
    };
    let target: hypr::Point = match serde_json::from_str(&text) {
        Ok(p) => p,
        Err(e) => {
            return Outcome::error(cmd, format!("saved pointer state is corrupt: {e}"))
                .with_data(json!({ "reason": "pointer-state-corrupt" }))
        }
    };
    if let Err(e) = hypr::dispatch_movecursor(target.x, target.y) {
        return hypr::hypr_error_outcome(cmd, &e);
    }
    let got = hypr::cursor().unwrap_or(target);
    Outcome::ok(cmd, format!("restored to {},{} (wanted {},{})", got.x, got.y, target.x, target.y))
        .with_data(json!({
            "x": got.x, "y": got.y,
            "wanted": { "x": target.x, "y": target.y },
        }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pt(x: i64, y: i64) -> hypr::Point {
        hypr::Point { x, y }
    }

    // ── move_delta ──────────────────────────────────────────────────────

    #[test]
    fn move_delta_ordinary_positive_and_negative() {
        assert_eq!(move_delta(pt(100, 100), pt(150, 80)), (50, -20));
        assert_eq!(move_delta(pt(0, 0), pt(-50, -50)), (-50, -50));
    }

    #[test]
    fn move_delta_zero_when_already_there() {
        assert_eq!(move_delta(pt(42, 42), pt(42, 42)), (0, 0));
    }

    #[test]
    fn move_delta_saturates_instead_of_overflowing_at_i64_extremes() {
        assert_eq!(move_delta(pt(i64::MIN, 0), pt(0, 0)), (i64::MAX, 0));
        assert_eq!(move_delta(pt(i64::MAX, 0), pt(i64::MIN, 0)), (i64::MIN, 0));
        assert_eq!(move_delta(pt(0, i64::MIN), pt(0, i64::MAX)), (0, i64::MAX));
    }

    // ── classify_landing ────────────────────────────────────────────────

    #[test]
    fn classify_landing_exact_match_is_landed() {
        assert_eq!(classify_landing(pt(10, 20), pt(10, 20)), MoveResult::Landed);
    }

    #[test]
    fn classify_landing_any_axis_mismatch_is_drifted() {
        assert_eq!(classify_landing(pt(10, 20), pt(11, 20)), MoveResult::Drifted { got: pt(11, 20) });
        assert_eq!(classify_landing(pt(10, 20), pt(10, 21)), MoveResult::Drifted { got: pt(10, 21) });
        assert_eq!(classify_landing(pt(10, 20), pt(0, 0)), MoveResult::Drifted { got: pt(0, 0) });
    }

    // ── guard_click ─────────────────────────────────────────────────────

    #[test]
    fn guard_click_no_guard_always_passes() {
        assert_eq!(guard_click(None, pt(1, 2)), Ok(()));
        assert_eq!(guard_click(None, pt(-999, 999)), Ok(()));
    }

    #[test]
    fn guard_click_matching_guard_passes() {
        assert_eq!(guard_click(Some(pt(5, 5)), pt(5, 5)), Ok(()));
    }

    #[test]
    fn guard_click_mismatched_guard_refuses_with_both_points() {
        assert_eq!(
            guard_click(Some(pt(5, 5)), pt(6, 5)),
            Err(ClickRefusal { at: pt(6, 5), expected: pt(5, 5) })
        );
    }

    // ── Button ──────────────────────────────────────────────────────────

    #[test]
    fn button_parses_known_spellings_case_sensitively() {
        assert_eq!(Button::parse("left"), Some(Button::Left));
        assert_eq!(Button::parse("right"), Some(Button::Right));
        assert_eq!(Button::parse("middle"), Some(Button::Middle));
        assert_eq!(Button::parse("Left"), None, "case-sensitive, mirrors pointer.sh's bash case");
        assert_eq!(Button::parse("LEFT"), None);
        assert_eq!(Button::parse("top"), None);
        assert_eq!(Button::parse(""), None);
    }

    #[test]
    fn button_as_str_round_trips_through_parse() {
        for b in [Button::Left, Button::Right, Button::Middle] {
            assert_eq!(Button::parse(b.as_str()), Some(b));
        }
    }

    // ── parse_click_args ────────────────────────────────────────────────

    #[test]
    fn click_args_empty_defaults_to_left_no_guard() {
        assert_eq!(parse_click_args(&[]), Ok((Button::Left, None)));
    }

    #[test]
    fn click_args_button_word_alone_sets_button_no_guard() {
        assert_eq!(parse_click_args(&["right".into()]), Ok((Button::Right, None)));
        assert_eq!(parse_click_args(&["middle".into()]), Ok((Button::Middle, None)));
    }

    #[test]
    fn click_args_two_numbers_alone_is_a_guard_with_default_button() {
        assert_eq!(
            parse_click_args(&["500".into(), "300".into()]),
            Ok((Button::Left, Some((500, 300))))
        );
    }

    #[test]
    fn click_args_button_plus_guard() {
        assert_eq!(
            parse_click_args(&["right".into(), "-10".into(), "-20".into()]),
            Ok((Button::Right, Some((-10, -20)))),
            "negative coordinates must parse (multi-monitor origins can be negative)"
        );
    }

    #[test]
    fn click_args_one_dangling_token_is_a_usage_error_not_a_silent_drop() {
        // The deliberate divergence from pointer.sh's bash: a stray single
        // token (no pair) refuses instead of being silently ignored.
        assert!(parse_click_args(&["500".into()]).is_err());
        assert!(parse_click_args(&["right".into(), "500".into()]).is_err());
    }

    #[test]
    fn click_args_too_many_tokens_is_a_usage_error() {
        assert!(parse_click_args(&["1".into(), "2".into(), "3".into()]).is_err());
    }

    #[test]
    fn click_args_non_numeric_guard_coordinate_is_a_usage_error() {
        assert!(parse_click_args(&["abc".into(), "5".into()]).is_err());
        assert!(parse_click_args(&["5".into(), "abc".into()]).is_err());
    }

    // ── scroll_notches ──────────────────────────────────────────────────

    #[test]
    fn scroll_notches_multiplies_by_five_each_direction() {
        assert_eq!(scroll_notches(1), 5);
        assert_eq!(scroll_notches(3), 15);
        assert_eq!(scroll_notches(-2), -10);
        assert_eq!(scroll_notches(0), 0);
    }

    #[test]
    fn scroll_notches_saturates_at_i64_extremes() {
        assert_eq!(scroll_notches(i64::MAX), i64::MAX);
        assert_eq!(scroll_notches(i64::MIN), i64::MIN);
    }

    // ── wlrctl argv assembly ────────────────────────────────────────────

    #[test]
    fn move_argv_shape() {
        assert_eq!(move_argv(12, -7), vec!["pointer", "move", "12", "-7"]);
        assert_eq!(move_argv(0, 0), vec!["pointer", "move", "0", "0"]);
    }

    #[test]
    fn click_argv_shape_for_each_button() {
        assert_eq!(click_argv(Button::Left), vec!["pointer", "click", "left"]);
        assert_eq!(click_argv(Button::Right), vec!["pointer", "click", "right"]);
        assert_eq!(click_argv(Button::Middle), vec!["pointer", "click", "middle"]);
    }

    #[test]
    fn scroll_argv_shape_uses_the_notch_math() {
        assert_eq!(scroll_argv(1), vec!["pointer", "scroll", "5", "0"]);
        assert_eq!(scroll_argv(-2), vec!["pointer", "scroll", "-10", "0"]);
    }

    // ── idle_step / track_idle ──────────────────────────────────────────

    #[test]
    fn idle_step_first_sample_starts_a_streak_of_one() {
        assert_eq!(idle_step((None, 0), pt(1, 1)), (Some(pt(1, 1)), 1));
    }

    #[test]
    fn idle_step_repeat_extends_change_resets() {
        let s0 = (None, 0);
        let s1 = idle_step(s0, pt(1, 1));
        assert_eq!(s1, (Some(pt(1, 1)), 1));
        let s2 = idle_step(s1, pt(1, 1));
        assert_eq!(s2, (Some(pt(1, 1)), 2));
        let s3 = idle_step(s2, pt(2, 2)); // moved — resets
        assert_eq!(s3, (Some(pt(2, 2)), 1));
    }

    #[test]
    fn track_idle_reaches_streak_needing_exactly_need_n_samples() {
        // Deliberately need_n raw samples suffice here (see idle_step's own
        // doc on the off-by-one divergence from pointer.sh).
        let samples = [pt(5, 5), pt(5, 5), pt(5, 5)];
        assert_eq!(track_idle(&samples, 3), Some(pt(5, 5)));
        assert_eq!(track_idle(&samples, 4), None, "one short of the streak — never idle");
    }

    #[test]
    fn track_idle_need_n_one_is_idle_on_the_first_sample() {
        assert_eq!(track_idle(&[pt(9, 9)], 1), Some(pt(9, 9)));
    }

    #[test]
    fn track_idle_a_reset_mid_sequence_still_finds_a_later_streak() {
        let samples = [pt(1, 1), pt(2, 2), pt(2, 2), pt(2, 2), pt(3, 3)];
        assert_eq!(track_idle(&samples, 3), Some(pt(2, 2)));
    }

    #[test]
    fn track_idle_never_reaching_the_streak_is_none() {
        let samples = [pt(1, 1), pt(2, 2), pt(3, 3), pt(4, 4)];
        assert_eq!(track_idle(&samples, 2), None);
    }

    // ── PointerError ────────────────────────────────────────────────────

    #[test]
    fn pointer_error_reasons_never_name_wlrctl() {
        let u = PointerError::Unavailable("no such file or directory".to_string());
        let f = PointerError::Failed("some wlrctl stderr text".to_string());
        assert_eq!(u.reason(), "pointer-unavailable");
        assert_eq!(f.reason(), "pointer-failed");
        assert!(!u.reason().contains("wlrctl"));
        assert!(!f.reason().contains("wlrctl"));
        // The DETAIL string is allowed to say whatever the backend said.
        assert_eq!(f.detail(), "some wlrctl stderr text");
    }
}
