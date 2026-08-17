//! `aoide screen point <verb>` — pointer synthesis, ported from
//! `tools/pointer.sh` (Phase 2 of the `screen` verb family; the script is
//! the BEHAVIORAL spec, read but not reused as code — a bash prototype, not
//! a library, same relationship `capture.rs`/`hypr.rs` already have to it).
//! Phase A of the pointer-emulation workstream (khoa, 2026-08-17) then
//! swapped the transport behind [`synthesize`] from a `wlrctl` shell-out to
//! a native `zwlr_virtual_pointer_v1` client (`screen::synth`) — every verb
//! below behaves identically; only how the boundary is crossed changed.
//!
//! ── Why real motion, not a warp (measured; see `tools/pointer.sh`'s own
//! header + `song/songbook/sonata/design/hazards.md` §6) ──────────────────
//! `hyprctl dispatch movecursor` WARPS the cursor: it does not generate a
//! `wl_pointer.motion` event inside a surface the pointer is already in, so
//! hover states never change and no agent could ever verify one. The five
//! motion-synthesizing verbs here (`move`/`click`/`drag`/`hover`/`scroll`)
//! instead drive `zwlr_virtual_pointer_manager_v1`, entering Hyprland's
//! normal input pipeline and producing genuine events. `restore` is the one
//! deliberate exception — see [`super::hypr::dispatch_movecursor`]'s doc.
//!
//! ── The pointer-synthesis boundary (khoa, 2026-08-16; transport moved
//! 2026-08-17) — mirrors `capture.rs`'s pixel-acquisition boundary exactly
//! ────────────────────────────────────────────────────────────────────────
//! [`synth::synthesize`](super::synth::synthesize) is the ONLY place a
//! Wayland client type is named anywhere in this crate (see that module's
//! own header). Every verb in this file decides WHAT pointer action to
//! synthesize (delta math, button choice, scroll notches) and hands down an
//! already-assembled [`synth::Seq`](super::synth::Seq); `synthesize`
//! decides HOW. [`PointerError`]'s reason codes stay backend-agnostic
//! (`pointer-*`, never naming the backend) — the same discipline
//! `capture.rs`'s `capture_image`/`CaptureError` boundary already
//! established for grim (khoa's Phase 1 review, D2): a caller must never
//! learn which tool did the work from the reason code, only (when it wants
//! to) from the free-text detail string.
//!
//! ── NOT live-proven this phase (khoa's Phase 2 brief, explicit + HARD RULE
//! 5; still true under Phase A's transport swap and Phase B's new verbs) ──
//! A human may be at this desk with the pointer physically "leased" to
//! another agent while this phase is built. `move`/`click`/`drag`/`hover`/
//! `scroll` all call [`synth::synthesize`](super::synth::synthesize), and
//! `restore` warps via [`super::hypr::dispatch_movecursor`] — none of those
//! six are executed live this phase, only unit-tested up to (never across)
//! that boundary. `idle`/`save` are pure reads (never touch the
//! pointer-synthesis boundary, never move anything) and ARE live-proven —
//! see the executor's report. The usage-error paths of every verb
//! (missing/malformed args) return before touching hyprctl or the synthesis
//! boundary at all, so those are live-proven too, for all eight verbs.
//!
//! ── Phase B of the pointer-emulation workstream (khoa, 2026-08-17) ───────
//! Two new verbs, [`point_drag`]/[`point_hover`], plus `click --count` and a
//! second `scroll` axis (`dx`). Same HARD RULE 5 as Phase A: neither new
//! verb is executed live this phase either — `drag` and `hover` both cross
//! the pointer-synthesis boundary, so they're unit-tested only up to it,
//! same split as `move`/`click`/`scroll`. `drag` is the one verb in this
//! file that synthesizes a press AND a release in a SINGLE
//! [`synth::synthesize`] call — see [`drag_seq`]'s doc on why that's not
//! optional (the stuck-button safety contract this workstream's Phase A
//! built [`synth::synthesize`]'s whole cleanup-on-every-exit-path invariant
//! around).

use super::capture;
use super::hypr;
use super::synth::{self, Axis, Seq, Step};
pub use super::synth::PointerError;
use aoide_protocol::output::Outcome;
use aoide_protocol::Invocation;
use serde_json::json;

// ── Absolute→relative delta (virtual-pointer motion is relative-only) ────

/// The relative delta a [`Step::Motion`] needs to land the cursor on
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
/// band: a real synthesized move either lands exactly or something interfered —
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

// ── The reachability pre-flight: is a point even on the layout? ─────────

/// Half-open containment: `p.x` in `[bounds.x, bounds.x + bounds.w)`, same
/// for `y` — the same edge convention `capture::clamp_region` already uses
/// measuring a capture rectangle against `hypr::layout_bounds` (khoa,
/// 2026-08-17, Opus's Phase B review, F2). `point_drag`'s handler is the one
/// caller today (refusing an unreachable endpoint BEFORE pressing anything —
/// see that function's doc), but nothing here is drag-specific: it's just
/// "is this point on some monitor," pure and reusable. `bounds.w`/`bounds.h`
/// added via `saturating_add` so a pathological `hyprctl` reading can't
/// overflow the upper-edge check.
pub fn point_in_bounds(p: hypr::Point, bounds: hypr::Region) -> bool {
    p.x >= bounds.x
        && p.x < bounds.x.saturating_add(bounds.w)
        && p.y >= bounds.y
        && p.y < bounds.y.saturating_add(bounds.h)
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
    /// This verb's own canonical spelling — echoed back in `click`'s
    /// `Outcome` message/data (`{"button": ...}`), not fed to any backend
    /// (that's [`button_code`] now).
    pub fn as_str(self) -> &'static str {
        match self {
            Button::Left => "left",
            Button::Right => "right",
            Button::Middle => "middle",
        }
    }
}

/// Linux input-event-codes constants (`linux/input-event-codes.h`), NOT
/// Wayland types — plain `u32`s, so defined here rather than in `synth.rs`
/// (that module's naming restriction is about Wayland/wlr protocol types
/// specifically; these are the same button-code numbers `wl_pointer` and
/// every other Linux input consumer already use). `BTN_LEFT` = `0x110` =
/// `272`, and `BTN_RIGHT`/`BTN_MIDDLE` follow it consecutively.
pub fn button_code(b: Button) -> u32 {
    match b {
        Button::Left => 272,
        Button::Right => 273,
        Button::Middle => 274,
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

/// The `click --count N` bound (khoa, 2026-08-17, Phase B): 1..=10 clicks
/// per invocation. **Refuses** out of range rather than clamping — unlike
/// [`clamp_notches`], where "the caller meant 100000000, give them the max"
/// is a plausible silent-degrade reading for a wheel notch count, "click 11
/// times" has no such reading: an out-of-range `--count` is a usage
/// mistake, not a request to saturate.
pub const MAX_CLICK_COUNT: u32 = 10;

/// `None` (no `--count` given) defaults to 1 — today's only behavior before
/// this flag existed, unchanged. `Some` must parse as an integer in
/// `1..=MAX_CLICK_COUNT`.
pub fn parse_count_flag(raw: Option<&String>) -> Result<u32, String> {
    match raw {
        None => Ok(1),
        Some(s) => match s.parse::<u32>() {
            Ok(n) if (1..=MAX_CLICK_COUNT).contains(&n) => Ok(n),
            Ok(n) => Err(format!("--count must be 1-{MAX_CLICK_COUNT}, got {n}")),
            Err(_) => Err(format!("--count must be an integer, got `{s}`")),
        },
    }
}

/// Parse `drag`'s positional shape: `<x1> <y1> <x2> <y2>` — exactly four
/// integers, start point then end point (khoa, 2026-08-17, Phase B).
/// Negative values are valid (multi-monitor origins can be negative, same
/// discipline `parse_click_args`'s guard coordinates already follow).
pub fn parse_drag_args(args: &[String]) -> Result<(i64, i64, i64, i64), String> {
    if args.len() != 4 {
        return Err(format!("drag takes <x1> <y1> <x2> <y2> — got {} arg(s)", args.len()));
    }
    let names = ["x1", "y1", "x2", "y2"];
    let mut v = [0i64; 4];
    for (i, name) in names.iter().enumerate() {
        v[i] = args[i]
            .parse()
            .map_err(|_| format!("<{name}> must be an integer, got `{}`", args[i]))?;
    }
    Ok((v[0], v[1], v[2], v[3]))
}

/// Parse `scroll`'s positional shape: `<dy> [dx]` (khoa, 2026-08-17, Phase
/// B — extends the Phase A single-axis `<n>`). `dy` is required; `dx`
/// defaults to 0 when absent, matching Phase A's own single-axis behavior
/// exactly. Mirrors `parse_click_args`'s divergence discipline: any token
/// count outside 1..=2, or a non-numeric token, refuses up front rather
/// than silently defaulting or dropping the extra.
pub fn parse_scroll_args(args: &[String]) -> Result<(i64, i64), String> {
    match args.len() {
        0 => Err("scroll takes <dy> [dx] — <dy> is required".to_string()),
        1 | 2 => {
            let dy: i64 = args[0]
                .parse()
                .map_err(|_| format!("<dy> must be an integer, got `{}`", args[0]))?;
            let dx: i64 = match args.get(1) {
                Some(s) => s.parse().map_err(|_| format!("<dx> must be an integer, got `{s}`"))?,
                None => 0,
            };
            Ok((dy, dx))
        }
        n => Err(format!(
            "scroll takes <dy> [dx] — {} trailing arg(s) don't fit that shape",
            n - 2
        )),
    }
}

// ── Seq assembly — pure, one builder per verb, unit-tested directly. These
// (plus button_code above) are the only functions that know the shape of a
// synth::Seq; synth::synthesize itself only ever walks whatever Seq it's
// handed. ───────────────────────────────────────────────────────────────

/// One [`Step::Motion`] — `(0, 0)` (already at target) yields an empty
/// [`Seq`] rather than a motion event that would move nothing;
/// `synth::synthesize` short-circuits an empty `Seq` before it even opens a
/// connection (see that module's header), so a no-op `move` touches the
/// pointer-synthesis boundary not at all.
pub fn move_seq(dx: i64, dy: i64) -> Seq {
    if dx == 0 && dy == 0 {
        return Seq(vec![]);
    }
    Seq(vec![Step::Motion { dx, dy }])
}

/// `count` clicks of `button`, each a press immediately followed by a
/// release; a 60ms [`Step::Pause`] between clicks (not after the last one)
/// so a compositor sees `count` distinct clicks rather than one long press
/// with a chattering button code. `count` is plumbed through now — Phase A
/// scope is one click (`count = 1`, today's only caller); the CLI's
/// `--count` flag wiring is Phase B.
pub fn click_seq(button: Button, count: u32) -> Seq {
    let code = button_code(button);
    let mut steps = Vec::new();
    for i in 0..count {
        if i > 0 {
            steps.push(Step::Pause { ms: 60 });
        }
        steps.push(Step::Button { code, pressed: true });
        steps.push(Step::Button { code, pressed: false });
    }
    Seq(steps)
}

/// Drag's default/bounds for `--steps` (khoa, 2026-08-17, Phase B) — how
/// many [`Step::Motion`] events [`interpolate`] breaks the start→end travel
/// into. 20 is a reasonable default granularity for a desktop-scale drag
/// (a few hundred px); 1..=200 bounds it the same way `--count`/`--settle-ms`
/// bound their own CLI-reachable numbers, refusing (not clamping) outside
/// range — `point_drag`'s handler enforces this, [`interpolate`] itself
/// accepts any `u32` (a pure fn has no CLI-input opinion of its own).
pub const DRAG_DEFAULT_STEPS: u32 = 20;
pub const DRAG_MIN_STEPS: u32 = 1;
pub const DRAG_MAX_STEPS: u32 = 200;

/// Break the straight-line travel from `start` to `end` into `steps`
/// RELATIVE deltas (khoa, 2026-08-17, Phase B) — virtual-pointer motion is
/// relative-only (see [`move_delta`]'s own doc), and a drag wants to arrive
/// smoothly rather than in one jump, so each element here becomes one
/// [`Step::Motion`] in [`drag_seq`].
///
/// The property that matters (the whole point of this function, not an
/// incidental nice-to-have): the returned deltas ALWAYS sum to exactly the
/// total `(end - start)` delta, for any `steps` — even when the distance
/// doesn't divide evenly by the step count, or is smaller than it (e.g. a
/// 3px drag over 7 steps). Computed via a running "where should we be by
/// step i" target (`total * i / steps`, exact at `i == steps` since
/// `steps` divides its own multiple exactly) rather than a fixed
/// per-step increment — the increment approach's rounding error would
/// otherwise accumulate and the drag would land short of (or past) `end`
/// after the interpolated motions, defeating the whole point of a verified
/// landing check afterward. Uses `i128` for the intermediate product so a
/// large `total * steps` never overflows `i64` before the division brings
/// it back down.
///
/// `start == end` (zero total distance) returns an empty `Vec` regardless
/// of `steps` — nothing to interpolate. `point_drag`'s handler never calls
/// this in that case anyway (it refuses before pressing — see that
/// function's doc), but the pure function is unconditionally correct on its
/// own terms too.
///
/// `total_dx`/`total_dy` are computed via `saturating_sub`, not plain `-`
/// (Opus's Phase B review, F1 — a blocking defect: a `drag`'s `<x2>`/`<y2>`
/// are agent-controlled `i64`s reaching all the way down to here, and an
/// extreme pair like `500 -> i64::MIN` would panic this in a debug build or,
/// worse, silently WRAP in release — `i64::MIN - 500` wrapping to roughly
/// `i64::MAX` would interpolate a drag in the exact opposite direction,
/// button held, across the whole layout). Mirrors [`move_delta`]'s own
/// saturating discipline exactly (this file's D3 pattern: an `i64` fresh off
/// agent input must never overflow plain arithmetic). `point_drag`'s handler
/// also pre-flights both endpoints against the layout bounds before this is
/// ever called (see that function's doc, F2) — this saturating fix is
/// defense-in-depth on top of that, not a substitute for it: the pure
/// function must be correct on its own terms regardless of what any caller
/// already checked.
pub fn interpolate(start: (i64, i64), end: (i64, i64), steps: u32) -> Vec<(i64, i64)> {
    let total_dx = end.0.saturating_sub(start.0);
    let total_dy = end.1.saturating_sub(start.1);
    if steps == 0 || (total_dx == 0 && total_dy == 0) {
        return Vec::new();
    }
    let steps_i = steps as i128;
    let mut deltas = Vec::with_capacity(steps as usize);
    let (mut prev_x, mut prev_y) = (0i64, 0i64);
    for i in 1..=(steps as i64) {
        let cur_x = ((total_dx as i128) * (i as i128) / steps_i) as i64;
        let cur_y = ((total_dy as i128) * (i as i128) / steps_i) as i64;
        deltas.push((cur_x - prev_x, cur_y - prev_y));
        prev_x = cur_x;
        prev_y = cur_y;
    }
    deltas
}

/// The atomic drag [`Seq`] (khoa, 2026-08-17, Phase B) — press, a 40ms
/// settle pause, every interpolated relative motion each followed by an 8ms
/// pause, a final 40ms settle pause, then release. Press and release live in
/// this ONE `Seq`, meaning `point_drag`'s handler hands it to
/// [`synth::synthesize`] in a SINGLE call — never split across two
/// invocations. That's not a style choice: `synthesize`'s stuck-button
/// invariant (see that module's header) only protects a button for the
/// duration of ONE `synthesize` call — release-tracking state lives on that
/// call's stack and is gone the moment it returns. Two separate `move`+
/// `click`-shaped calls (press in one, release in another) would leave a
/// window between them where a crash, a `?`-propagated error, or simply this
/// process getting killed leaves the button held with nothing left watching
/// it — building one `Seq` here closes that window entirely.
///
/// `deltas` empty still produces a syntactically valid press/pause/pause/
/// release `Seq` (this function has no opinion on whether a caller SHOULD
/// pass an empty slice) — but `point_drag`'s handler never does: a
/// zero-distance drag is refused as a usage error before anything is
/// pressed (see that function's doc), so this degenerate shape is exercised
/// only by this file's own tests, never a real caller.
///
/// A `(0, 0)` element is skipped entirely — no `Step::Motion`/`Step::Pause`
/// pair for it (Opus's Phase B review nit). [`interpolate`]'s own integer
/// division legitimately produces these for a short drag over many steps
/// (e.g. a 1px travel over 3 steps rounds two of the three to no movement at
/// all); emitting them anyway would be a real zero-motion wire event and an
/// 8ms pause bought for literally nothing.
pub fn drag_seq(button: Button, deltas: &[(i64, i64)]) -> Seq {
    let code = button_code(button);
    let mut steps = Vec::with_capacity(deltas.len() * 2 + 4);
    steps.push(Step::Button { code, pressed: true });
    steps.push(Step::Pause { ms: 40 });
    for &(dx, dy) in deltas {
        if dx == 0 && dy == 0 {
            continue;
        }
        steps.push(Step::Motion { dx, dy });
        steps.push(Step::Pause { ms: 8 });
    }
    steps.push(Step::Pause { ms: 40 });
    steps.push(Step::Button { code, pressed: false });
    Seq(steps)
}

/// Scroll notches clamp to `±MAX_SCROLL_NOTCHES` per axis, per call
/// (Opus's Phase A review, B2 — a blocking defect: an unclamped `<n>` was
/// CLI-reachable all the way down to `walk`'s per-notch loop in `synth.rs`,
/// so a `screen point scroll 100000000` would have queued 100 million
/// request pairs, and `i64::MIN` would never even finish — `unsigned_abs()`
/// on it is `2^63`). Mirrors the old wlrctl-era `scroll_notches`' own
/// saturating discipline, which this replaces (that function scaled by 5
/// and saturated the *product*, not the notch count itself — this bounds
/// the count directly, which is the number that actually drives a request
/// loop now).
///
/// DEFINED as (not merely equal to) `synth::MAX_WHEEL_NOTCHES_PER_STEP` —
/// see that constant's own doc on why the sharing runs this direction
/// (`synth.rs` must not import from `point.rs`). Also mirrored in prose in
/// `commands/screen.rs`'s `screen point scroll` summary string ("+/-100
/// notches") — update both if this bound ever changes (Phase A review nit
/// 2, folded in Phase B: the summary can't embed the const directly, its
/// type is `&'static str`, so a cross-reference comment is the next best
/// thing).
pub const MAX_SCROLL_NOTCHES: i64 = synth::MAX_WHEEL_NOTCHES_PER_STEP;

/// Clamp one axis's requested notch count to `±MAX_SCROLL_NOTCHES` — pure,
/// so `scroll_seq` (which applies it) and `point_scroll`'s handler (which
/// calls it again to detect whether clamping fired, to announce it in the
/// `Outcome` — `capture.rs`'s clamp-announcement discipline) share one
/// definition rather than two copies of the same bound drifting apart.
pub fn clamp_notches(n: i64) -> i64 {
    n.clamp(-MAX_SCROLL_NOTCHES, MAX_SCROLL_NOTCHES)
}

/// Vertical (`dy_notches`) and horizontal (`dx_notches`) wheel steps —
/// positive `dy` (down) matches a physical wheel pulled toward the user,
/// per `tools/pointer.sh`'s original convention. Both axes are clamped via
/// [`clamp_notches`] before a [`Step::Wheel`] is built. Either axis at zero
/// (after clamping) omits that `Step::Wheel` entirely; both zero yields an
/// empty [`Seq`]. Today's CLI only ever passes `dx_notches = 0`
/// (`point_scroll`'s handler) — the dx wiring is Phase B, same as
/// `click_seq`'s `count`. The wlrctl-era `n * 5` notch scaling is GONE:
/// beyond the clamp, this function passes notches straight through
/// unscaled, and the wheel's physical magnitude now lives entirely in
/// `synth::WHEEL_VALUE` (see that constant's doc for the divergence).
pub fn scroll_seq(dy_notches: i64, dx_notches: i64) -> Seq {
    let dy_notches = clamp_notches(dy_notches);
    let dx_notches = clamp_notches(dx_notches);
    let mut steps = Vec::new();
    if dy_notches != 0 {
        steps.push(Step::Wheel { axis: Axis::Vertical, notches: dy_notches });
    }
    if dx_notches != 0 {
        steps.push(Step::Wheel { axis: Axis::Horizontal, notches: dx_notches });
    }
    Seq(steps)
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
//
// [`PointerError`] and the boundary function itself
// ([`synth::synthesize`](super::synth::synthesize)) now live in
// `synth.rs` (Phase A, 2026-08-17) — `pub use`d back in above so every
// call site and `pointer_error_outcome` below stay unchanged. See that
// module's header for the full boundary story; this file keeps only the
// WHAT half (delta math, button choice, scroll notches → a `synth::Seq`).

/// A [`PointerError`] folded into the command's structured error `Outcome`
/// — mirrors `hypr::hypr_error_outcome` exactly. `pub(crate)` (khoa,
/// 2026-08-17, Phase F): `screen::text`'s live click path reuses this
/// directly rather than growing a second copy of the same fold.
pub(crate) fn pointer_error_outcome(cmd: &str, e: &PointerError) -> Outcome {
    Outcome::error(cmd, format!("{}: {}", e.reason(), e.detail()))
        .with_data(json!({ "reason": e.reason() }))
}

// ── `--from-shot <capture>`: image-space coordinates on any coordinate-
// taking `screen point` verb (khoa, 2026-08-17, Phase D of the pointer-
// emulation workstream) ─────────────────────────────────────────────────
//
// Closes the model-space↔screen-space loop `screen shot --fit`/`--cursor`
// opened: an agent that read a coordinate off a (possibly downscaled) shot
// hands it straight to `move`/`click`/`drag`/`hover` as IMAGE pixels, and
// this converts it to screen space via that capture's own sidecar BEFORE
// any existing verb logic runs — the same "convert once, up front" shape
// `Sidecar::image_point_to_screen` itself follows (bounds-check, then
// scale-check, then transform).

/// Read `<capture>.json` for a `--from-shot <capture>` flag value, already
/// folded into the command's `Outcome` on failure (missing/corrupt) —
/// `capture::read_sidecar`'s two reason codes (`sidecar-missing`/
/// `sidecar-corrupt`) turned into the exact same error shape
/// `pointer_error_outcome`/`hypr::hypr_error_outcome` already use, so every
/// failure path in this file looks the same regardless of which boundary it
/// came from. `pub(crate)` (khoa, 2026-08-17, Phase F): `screen::text` reads
/// a sidecar off the very same `--from-shot <capture>` flag spelling — see
/// that module's header on why its SEMANTICS differ (an OCR source, never a
/// coordinate space) even though the loader is identical.
pub(crate) fn from_shot_sidecar(cmd: &str, capture_path: &str) -> Result<capture::Sidecar, Outcome> {
    capture::read_sidecar(std::path::Path::new(capture_path)).map_err(|(reason, detail)| {
        Outcome::error(cmd, format!("--from-shot: {detail}")).with_data(json!({ "reason": reason }))
    })
}

/// A [`capture::FromShotError`] folded into the command's `Outcome` — mirrors
/// [`pointer_error_outcome`] exactly, one variant each for
/// `from-shot-out-of-bounds`/`from-shot-bad-scale`. Reports BOTH spaces it
/// knows about in `data` (the requested image point plus the bound it
/// violated) — there's no screen-space value to report on this path since
/// the conversion itself is what failed.
fn from_shot_error_outcome(cmd: &str, e: &capture::FromShotError) -> Outcome {
    match e {
        capture::FromShotError::OutOfBounds { x, y, image_w, image_h } => Outcome::error(
            cmd,
            format!(
                "--from-shot: image point {x},{y} is outside the capture's recorded image size {image_w}x{image_h}"
            ),
        )
        .with_data(json!({
            "reason": "from-shot-out-of-bounds",
            "image": { "x": x, "y": y },
            "imageSize": { "w": image_w, "h": image_h },
        })),
        capture::FromShotError::BadScale { scale } => Outcome::error(
            cmd,
            format!("--from-shot: sidecar has an invalid scale ({scale}) — must be positive and finite"),
        )
        .with_data(json!({ "reason": "from-shot-bad-scale", "scale": scale })),
    }
}

/// Convert ONE `(x, y)` through `--from-shot <capture>`, if present — the
/// shared seam `move`/`click`/`hover`'s single-point handlers all call.
/// `None` flag value: passes `(x, y)` through unchanged, `image: None` (no
/// conversion happened, nothing to report). `Some`: reads the sidecar,
/// converts, and returns the SCREEN point plus the original image point (for
/// the success `Outcome`'s `data.image`) — or an already-built `Outcome` on
/// either failure, for the call site to return directly.
fn resolve_from_shot_point(
    cmd: &str,
    inv: &Invocation,
    x: i64,
    y: i64,
) -> Result<(hypr::Point, Option<(i64, i64)>), Outcome> {
    match inv.flags.get("from-shot") {
        None => Ok((hypr::Point { x, y }, None)),
        Some(capture_path) => {
            let sidecar = from_shot_sidecar(cmd, capture_path)?;
            match sidecar.image_point_to_screen(x, y) {
                Ok(p) => Ok((p, Some((x, y)))),
                Err(e) => Err(from_shot_error_outcome(cmd, &e)),
            }
        }
    }
}

// ── The live idle poller (NOT unit-tested — real sleeps + a real hyprctl
// spawn loop; env/timing-dependent, same reason hypr::run_hyprctl_json
// itself isn't). Read-only: never touches the pointer-synthesis boundary, so — unlike every other
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

/// `aoide screen point move <x> <y>` — absolute move via real synthesized
/// motion, verified on landing. See the module header for the full
/// move/verify/drift story; NOT executed live this phase (HARD RULE 5) past
/// the usage-error paths (missing/malformed `<x>`/`<y>`, which return
/// before touching hyprctl or the pointer-synthesis boundary at all).
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
    let (target, image) = match resolve_from_shot_point(cmd, inv, x, y) {
        Ok(v) => v,
        Err(outcome) => return outcome,
    };

    let current = match hypr::cursor() {
        Ok(p) => p,
        Err(e) => return hypr::hypr_error_outcome(cmd, &e),
    };
    let (dx, dy) = move_delta(current, target);
    if let Err(e) = synth::synthesize(&move_seq(dx, dy)) {
        return pointer_error_outcome(cmd, &e);
    }
    let got = match hypr::cursor() {
        Ok(p) => p,
        Err(e) => return hypr::hypr_error_outcome(cmd, &e),
    };
    match classify_landing(target, got) {
        MoveResult::Landed => {
            let mut data = json!({ "x": got.x, "y": got.y });
            if let Some((ix, iy)) = image {
                data["image"] = json!({ "x": ix, "y": iy });
            }
            Outcome::ok(cmd, format!("moved to {},{}", got.x, got.y)).with_data(data)
        }
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

/// `aoide screen point click [left|right|middle] [x y] [--count N]` — see
/// the module header on the guard. `--count` (1..=10, default 1, khoa
/// 2026-08-17 Phase B) repeats the click via [`click_seq`]'s existing
/// multi-click plumbing (Phase A built `count` in, unused until now). The
/// positional `[x y]` guard is untouched — it still fires exactly once,
/// before ANY of the `count` clicks, not once per click (a human bump mid-
/// burst would be exactly as bad caught after click 1 as before it, and
/// re-reading the cursor between clicks would fight the very click cadence
/// `click_seq`'s 60ms inter-click pause exists to protect). NOT executed
/// live this phase (HARD RULE 5) past the usage-error paths.
pub fn point_click(inv: &Invocation) -> Outcome {
    let cmd = "screen.point.click";
    let (button, guard) = match parse_click_args(&inv.args) {
        Ok(v) => v,
        Err(msg) => return Outcome::usage(cmd, msg),
    };
    let count = match parse_count_flag(inv.flags.get("count")) {
        Ok(n) => n,
        Err(msg) => return Outcome::usage(cmd, msg),
    };
    // `--from-shot` with no guard x/y is a usage error, not a silent no-op
    // (khoa's Phase D review nit — this file's own `never-silently-drop`
    // stance, `parse_click_args`'s doc on the exact same discipline for a
    // stray trailing token): there is nothing for the flag to convert
    // without a guard, and an agent that typed `--from-shot` clearly meant
    // for it to do something.
    if inv.flags.contains_key("from-shot") && guard.is_none() {
        return Outcome::usage(
            cmd,
            "--from-shot has nothing to convert without a guard x/y — pass [left|right|middle] <x> <y> --from-shot <capture>",
        );
    }
    // `--from-shot` only has anything to convert when a guard was given —
    // no positional coordinates means no image-space value to translate.
    let (guard, image) = match guard {
        Some((x, y)) => match resolve_from_shot_point(cmd, inv, x, y) {
            Ok((p, image)) => (Some((p.x, p.y)), image),
            Err(outcome) => return outcome,
        },
        None => (None, None),
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
    if let Err(e) = synth::synthesize(&click_seq(button, count)) {
        return pointer_error_outcome(cmd, &e);
    }
    let message = if count == 1 {
        format!("click {}", button.as_str())
    } else {
        format!("click {} x{count}", button.as_str())
    };
    let mut data = json!({ "button": button.as_str(), "count": count });
    if let Some((ix, iy)) = image {
        data["image"] = json!({ "x": ix, "y": iy });
    }
    Outcome::ok(cmd, message).with_data(data)
}

/// `aoide screen point drag <x1> <y1> <x2> <y2> [--button left|right|middle]
/// [--steps N]` — the flagship of Phase B (khoa, 2026-08-17). Three steps:
///
/// 1. Move to `(x1,y1)` through the EXISTING move+verify path — read the
///    cursor, synthesize the delta as a plain [`move_seq`], re-read, and
///    [`classify_landing`] it. Drift here REFUSES WITHOUT PRESSING (error,
///    `reason: "pointer-drift"`, `got`/`wanted` — the same drift shape
///    `point_move` itself reports): a human bump before the press is
///    exactly the case `move`'s own drift guard already exists to catch,
///    and a drag inherits it unchanged rather than reimplementing it.
/// 2. Build ONE atomic [`drag_seq`] (press, [`interpolate`]d motion,
///    release — see that function's own doc on why press and release must
///    share a single [`synth::synthesize`] call, never two) and synthesize
///    it.
/// 3. Re-read the cursor and [`classify_landing`] against `(x2,y2)`. Drift
///    HERE is still an error, but its message says the button was ALREADY
///    RELEASED — by this point `drag_seq`'s own release step already ran
///    inside `synthesize`, so whatever caused the drift (a human bump
///    mid-drag, a compositor clamping the drop point) happened to an
///    already-idle button, not one left stuck.
///
/// A zero-distance drag (`(x1,y1) == (x2,y2)`) is refused as a usage error
/// BEFORE step 1 even reads the cursor — see [`drag_seq`]'s own doc on why
/// that decision lives at this level, not inside the builder. `--button`
/// defaults to left; `--steps` defaults to [`DRAG_DEFAULT_STEPS`], bounds
/// [`DRAG_MIN_STEPS`]..=[`DRAG_MAX_STEPS`]. NOT executed live this phase
/// (HARD RULE 5) past the usage-error paths.
///
/// **Pre-flight, before step 1** (Opus's Phase B review, F2 — a blocking
/// defect: an unreachable `(x2,y2)` used to press, drag the full travel to
/// the screen edge, release, and only THEN error on the landing check).
/// Both `(x1,y1)` and `(x2,y2)` are checked against
/// [`hypr::layout_bounds`]/[`point_in_bounds`] before anything else touches
/// the pointer — `(x2,y2)` because an unreachable end point has no business
/// being dragged to at all, and `(x1,y1)` for symmetry (the move+verify in
/// step 1 would already catch a bad start, but catching it before ANY
/// hyprctl-visible motion is strictly better). This REFUSES rather than
/// clamps — unlike `capture.rs`'s region math, a drag endpoint is not a
/// capture rectangle with a reasonable "nearest valid" reading; a point
/// outside the layout means the caller's own model of the screen is wrong,
/// and clamping would silently act on that lie instead of surfacing it.
pub fn point_drag(inv: &Invocation) -> Outcome {
    let cmd = "screen.point.drag";
    let (x1, y1, x2, y2) = match parse_drag_args(&inv.args) {
        Ok(v) => v,
        Err(msg) => return Outcome::usage(cmd, msg),
    };
    let button = match inv.flags.get("button") {
        None => Button::Left,
        Some(s) => match Button::parse(s) {
            Some(b) => b,
            None => {
                return Outcome::usage(cmd, format!("--button must be left|right|middle, got `{s}`"))
            }
        },
    };
    let steps: u32 = match inv.flags.get("steps") {
        None => DRAG_DEFAULT_STEPS,
        Some(s) => match s.parse::<u32>() {
            Ok(n) if (DRAG_MIN_STEPS..=DRAG_MAX_STEPS).contains(&n) => n,
            Ok(n) => {
                return Outcome::usage(
                    cmd,
                    format!("--steps must be {DRAG_MIN_STEPS}-{DRAG_MAX_STEPS}, got {n}"),
                )
            }
            Err(_) => return Outcome::usage(cmd, format!("--steps must be an integer, got `{s}`")),
        },
    };

    // `--from-shot` converts BOTH endpoints off the SAME sidecar — read once,
    // convert twice; either failure returns before touching hyprctl at all.
    let (start, end, image) = match inv.flags.get("from-shot") {
        None => (hypr::Point { x: x1, y: y1 }, hypr::Point { x: x2, y: y2 }, None),
        Some(capture_path) => {
            let sidecar = match from_shot_sidecar(cmd, capture_path) {
                Ok(s) => s,
                Err(outcome) => return outcome,
            };
            let start = match sidecar.image_point_to_screen(x1, y1) {
                Ok(p) => p,
                Err(e) => return from_shot_error_outcome(cmd, &e),
            };
            let end = match sidecar.image_point_to_screen(x2, y2) {
                Ok(p) => p,
                Err(e) => return from_shot_error_outcome(cmd, &e),
            };
            (start, end, Some(((x1, y1), (x2, y2))))
        }
    };
    if start == end {
        // Phase D review nit: at scale > 1, two DISTINCT image points can
        // land on the same screen pixel after --from-shot's rounding
        // division (`transform_point`'s own `scale_div_round`) — a caller
        // staring at two different pixels it picked off the image deserves
        // to know THAT's why the refusal fired, not just "same point" as if
        // it had typed identical coordinates itself.
        let msg = match image {
            Some(((ix1, iy1), (ix2, iy2))) if (ix1, iy1) != (ix2, iy2) => format!(
                "drag start and end are the same point ({},{}) — image points ({ix1},{iy1}) and \
                 ({ix2},{iy2}) differ but collapse at this capture's scale",
                start.x, start.y
            ),
            _ => "drag start and end are the same point".to_string(),
        };
        return Outcome::usage(cmd, msg);
    }

    // ── 0. Pre-flight both endpoints against the layout — before ANY motion
    // (F2). See this function's doc on why this refuses rather than clamps.
    let monitors = match hypr::monitors() {
        Ok(m) => m,
        Err(e) => return hypr::hypr_error_outcome(cmd, &e),
    };
    let Some(bounds) = hypr::layout_bounds(&monitors) else {
        return Outcome::error(cmd, "no monitors reported by hyprctl")
            .with_data(json!({ "reason": "no-monitors" }));
    };
    for (label, p) in [("start", start), ("end", end)] {
        if !point_in_bounds(p, bounds) {
            return Outcome::error(
                cmd,
                format!(
                    "{label} {},{} is outside the layout ({},{} {}x{}) — refusing before pressing",
                    p.x, p.y, bounds.x, bounds.y, bounds.w, bounds.h
                ),
            )
            .with_data(json!({
                "reason": "pointer-out-of-bounds",
                "wanted": { "x": p.x, "y": p.y },
                "bounds": { "x": bounds.x, "y": bounds.y, "w": bounds.w, "h": bounds.h },
            }));
        }
    }

    // ── 1. Move to start, verified — refuse without pressing on drift. ────
    let current = match hypr::cursor() {
        Ok(p) => p,
        Err(e) => return hypr::hypr_error_outcome(cmd, &e),
    };
    let (dx0, dy0) = move_delta(current, start);
    if let Err(e) = synth::synthesize(&move_seq(dx0, dy0)) {
        return pointer_error_outcome(cmd, &e);
    }
    let landed = match hypr::cursor() {
        Ok(p) => p,
        Err(e) => return hypr::hypr_error_outcome(cmd, &e),
    };
    if let MoveResult::Drifted { got } = classify_landing(start, landed) {
        return Outcome::error(
            cmd,
            format!(
                "drift before pressing — pointer at {},{}, wanted start {},{}: a human moved \
                 the mouse, or the start point is off-screen; refusing to drag (button never \
                 pressed)",
                got.x, got.y, start.x, start.y
            ),
        )
        .with_data(json!({
            "reason": "pointer-drift",
            "x": got.x, "y": got.y,
            "wanted": { "x": start.x, "y": start.y },
        }));
    }

    // ── 2. The atomic press-move-release Seq, one synthesize() call. ──────
    let deltas = interpolate((start.x, start.y), (end.x, end.y), steps);
    if let Err(e) = synth::synthesize(&drag_seq(button, &deltas)) {
        // The one synthesize() call in this handler that presses a button —
        // if it fails partway through, this is the one path where a reader
        // would rightly fear a stuck button, so say plainly that it isn't:
        // synthesize()'s own cleanup-on-every-exit-path invariant (see
        // synth.rs's module header) already released whatever it still had
        // tracked as held before returning this error (Opus's Phase B
        // review nit).
        return Outcome::error(
            cmd,
            format!(
                "{}: {} (the backend attempts to release any button it still had tracked \
                 as held before returning this error — not stuck)",
                e.reason(),
                e.detail()
            ),
        )
        .with_data(json!({ "reason": e.reason() }));
    }

    // ── 3. Verify the release landed on target. ────────────────────────────
    let got = match hypr::cursor() {
        Ok(p) => p,
        Err(e) => return hypr::hypr_error_outcome(cmd, &e),
    };
    match classify_landing(end, got) {
        MoveResult::Landed => {
            let mut data = json!({ "button": button.as_str(), "x": got.x, "y": got.y });
            if let Some(((ix1, iy1), (ix2, iy2))) = image {
                data["image"] = json!({
                    "start": { "x": ix1, "y": iy1 },
                    "end": { "x": ix2, "y": iy2 },
                });
            }
            Outcome::ok(
                cmd,
                format!(
                    "dragged {} from {},{} to {},{}",
                    button.as_str(), start.x, start.y, got.x, got.y
                ),
            )
            .with_data(data)
        }
        MoveResult::Drifted { got } => Outcome::error(
            cmd,
            format!(
                "drift after release — pointer at {},{}, wanted {},{}: the button was already \
                 released by this point, not stuck",
                got.x, got.y, end.x, end.y
            ),
        )
        .with_data(json!({
            "reason": "pointer-drift",
            "x": got.x, "y": got.y,
            "wanted": { "x": end.x, "y": end.y },
        })),
    }
}

/// `hover`'s `--settle-ms` default/bounds (khoa, 2026-08-17, Phase B) — how
/// long the pointer parks at the target before the after-snapshot. 500ms
/// covers most toolkit hover-delay timers without a needlessly long block;
/// 1..=10000 keeps a pathological `--settle-ms` from either doing nothing
/// (0) or hanging the caller for an unreasonable stretch.
pub const HOVER_DEFAULT_SETTLE_MS: u64 = 500;
pub const HOVER_MIN_SETTLE_MS: u64 = 1;
pub const HOVER_MAX_SETTLE_MS: u64 = 10_000;

/// `aoide screen point hover <x> <y> [--settle-ms N]` (khoa, 2026-08-17,
/// Phase B). Snapshots the desktop (clients + layers, [`hypr::snapshot`])
/// BEFORE moving, moves to `(x,y)` through the same move+verify path
/// `move`/`drag` use (drift refuses exactly as usual), sleeps
/// `--settle-ms` (default [`HOVER_DEFAULT_SETTLE_MS`], bounds
/// [`HOVER_MIN_SETTLE_MS`]..=[`HOVER_MAX_SETTLE_MS`]), snapshots again, and
/// reports [`hypr::info_delta`] between the two. The delta IS the verb's
/// purpose, not a side note: a tooltip or context menu opening under a
/// synthesized hover is a new layer surface, and nothing else this crate
/// does would ever notice that happened. NOT executed live this phase
/// (HARD RULE 5) past the usage-error paths.
pub fn point_hover(inv: &Invocation) -> Outcome {
    let cmd = "screen.point.hover";
    if inv.args.len() < 2 {
        return Outcome::usage(
            cmd,
            format!("usage: aoide {} <x> <y> [--settle-ms N] [--json]", inv.path.join(" ")),
        );
    }
    let x: i64 = match inv.args[0].parse() {
        Ok(v) => v,
        Err(_) => return Outcome::usage(cmd, format!("<x> must be an integer, got `{}`", inv.args[0])),
    };
    let y: i64 = match inv.args[1].parse() {
        Ok(v) => v,
        Err(_) => return Outcome::usage(cmd, format!("<y> must be an integer, got `{}`", inv.args[1])),
    };
    let settle_ms: u64 = match inv.flags.get("settle-ms") {
        None => HOVER_DEFAULT_SETTLE_MS,
        Some(s) => match s.parse::<u64>() {
            Ok(n) if (HOVER_MIN_SETTLE_MS..=HOVER_MAX_SETTLE_MS).contains(&n) => n,
            Ok(n) => {
                return Outcome::usage(
                    cmd,
                    format!(
                        "--settle-ms must be {HOVER_MIN_SETTLE_MS}-{HOVER_MAX_SETTLE_MS}, got {n}"
                    ),
                )
            }
            Err(_) => return Outcome::usage(cmd, format!("--settle-ms must be an integer, got `{s}`")),
        },
    };
    let (target, image) = match resolve_from_shot_point(cmd, inv, x, y) {
        Ok(v) => v,
        Err(outcome) => return outcome,
    };

    let before = match hypr::snapshot() {
        Ok(s) => s,
        Err(e) => return hypr::hypr_error_outcome(cmd, &e),
    };

    let current = match hypr::cursor() {
        Ok(p) => p,
        Err(e) => return hypr::hypr_error_outcome(cmd, &e),
    };
    let (dx, dy) = move_delta(current, target);
    if let Err(e) = synth::synthesize(&move_seq(dx, dy)) {
        return pointer_error_outcome(cmd, &e);
    }
    let got = match hypr::cursor() {
        Ok(p) => p,
        Err(e) => return hypr::hypr_error_outcome(cmd, &e),
    };
    if let MoveResult::Drifted { got } = classify_landing(target, got) {
        return Outcome::error(
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
        }));
    }

    std::thread::sleep(std::time::Duration::from_millis(settle_ms));

    let after = match hypr::snapshot() {
        Ok(s) => s,
        Err(e) => return hypr::hypr_error_outcome(cmd, &e),
    };
    let delta = hypr::info_delta(&before, &after);

    let mut parts = Vec::new();
    if !delta.appeared.is_empty() {
        parts.push(format!("{} surface(s) appeared", delta.appeared.len()));
    }
    if !delta.disappeared.is_empty() {
        parts.push(format!("{} surface(s) disappeared", delta.disappeared.len()));
    }
    if !delta.retitled.is_empty() {
        parts.push(format!("{} retitled", delta.retitled.len()));
    }
    let summary = if parts.is_empty() { "no change".to_string() } else { parts.join(", ") };

    let mut data = json!({
        "x": got.x, "y": got.y,
        "appeared": delta.appeared,
        "disappeared": delta.disappeared,
        "retitled": delta.retitled,
    });
    if let Some((ix, iy)) = image {
        data["image"] = json!({ "x": ix, "y": iy });
    }
    Outcome::ok(cmd, format!("hover at {},{} — {summary}", got.x, got.y)).with_data(data)
}

/// `aoide screen point scroll <dy> [dx]` — positive `dy` down/`dx` right,
/// negative up/left (`dx` optional, default 0 — khoa 2026-08-17, Phase B
/// extends Phase A's single-axis `<n>`). Both axes independently clamp to
/// `±MAX_SCROLL_NOTCHES` (see [`clamp_notches`]'s doc, Opus's Phase A
/// review B2) — the `Outcome` says so for whichever axis(es) it fires on,
/// mirroring `capture.rs`'s clamp-announcement discipline. NOT executed
/// live this phase (HARD RULE 5) past the usage-error path
/// (missing/malformed `<dy>`/`<dx>`).
pub fn point_scroll(inv: &Invocation) -> Outcome {
    let cmd = "screen.point.scroll";
    let (dy, dx) = match parse_scroll_args(&inv.args) {
        Ok(v) => v,
        Err(msg) => return Outcome::usage(cmd, msg),
    };
    let clamped_dy = clamp_notches(dy);
    let clamped_dx = clamp_notches(dx);
    if let Err(e) = synth::synthesize(&scroll_seq(dy, dx)) {
        return pointer_error_outcome(cmd, &e);
    }
    // Axis-aware directions (Opus's Phase B review nit): a single shared
    // "direction" key described dy alone, so a dx-only scroll (dy: 0, dx: 5)
    // reported direction:"none" right beside a nonzero dx — technically not
    // a lie about dy, but a caller reading just "direction" would reasonably
    // read "none" as "nothing happened." Two keys, one per axis, instead.
    let dy_dir = match clamped_dy.cmp(&0) {
        std::cmp::Ordering::Greater => "down",
        std::cmp::Ordering::Less => "up",
        std::cmp::Ordering::Equal => "none",
    };
    let dx_dir = match clamped_dx.cmp(&0) {
        std::cmp::Ordering::Greater => "right",
        std::cmp::Ordering::Less => "left",
        std::cmp::Ordering::Equal => "none",
    };
    let mut message = format!("scroll {clamped_dy} notch(es) {dy_dir}");
    if clamped_dy != dy {
        message.push_str(&format!("; clamped from requested {dy}"));
    }
    if clamped_dx != 0 {
        message.push_str(&format!(", {clamped_dx} notch(es) {dx_dir}"));
        if clamped_dx != dx {
            message.push_str(&format!(" (clamped from requested {dx})"));
        }
    }
    Outcome::ok(cmd, message).with_data(json!({
        "dy": clamped_dy,
        "dx": clamped_dx,
        "dyDirection": dy_dir,
        "dxDirection": dx_dir,
        "requestedDy": dy,
        "requestedDx": dx,
        "clampedDy": clamped_dy != dy,
        "clampedDx": clamped_dx != dx,
    }))
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

    // ── point_in_bounds (F2 — Opus's Phase B review) ───────────────────────

    fn region(x: i64, y: i64, w: i64, h: i64) -> hypr::Region {
        hypr::Region { x, y, w, h }
    }

    #[test]
    fn point_in_bounds_inside_and_on_the_low_edges_is_true() {
        let b = region(0, 0, 1920, 1080);
        assert!(point_in_bounds(pt(0, 0), b), "the low corner is inclusive");
        assert!(point_in_bounds(pt(960, 540), b));
        assert!(point_in_bounds(pt(1919, 1079), b), "one px inside the high edge");
    }

    #[test]
    fn point_in_bounds_on_or_past_the_high_edge_is_false() {
        let b = region(0, 0, 1920, 1080);
        assert!(!point_in_bounds(pt(1920, 0), b), "the high edge is exclusive (x == x + w)");
        assert!(!point_in_bounds(pt(0, 1080), b));
        assert!(!point_in_bounds(pt(5000, 5000), b));
    }

    #[test]
    fn point_in_bounds_negative_origin_multi_monitor_layout() {
        // A monitor to the left/above the primary — negative-origin layouts
        // are real (multi-monitor), not just an edge case to humor.
        let b = region(-1920, -200, 3200, 1280);
        assert!(point_in_bounds(pt(-1920, -200), b));
        assert!(point_in_bounds(pt(-1, -1), b));
        assert!(!point_in_bounds(pt(-1921, 0), b));
        assert!(!point_in_bounds(pt(1280, 0), b), "1280 == -1920 + 3200, the high edge");
    }

    #[test]
    fn point_in_bounds_extremes_never_overflow() {
        // bounds.x + bounds.w would overflow plain `i64` addition here
        // (1 + i64::MAX) — saturating_add must clamp to i64::MAX rather than
        // panic; a pathological hyprctl reading must only ever answer
        // true/false, never crash the drag pre-flight.
        let b = region(1, 1, i64::MAX, i64::MAX);
        assert!(point_in_bounds(pt(500, 500), b), "well inside, nowhere near the saturated edge");
        assert!(!point_in_bounds(pt(0, 0), b), "below the low edge");
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

    // ── parse_count_flag (click --count, Phase B) ──────────────────────────

    #[test]
    fn count_flag_absent_defaults_to_one() {
        assert_eq!(parse_count_flag(None), Ok(1));
    }

    #[test]
    fn count_flag_within_bounds_is_accepted() {
        assert_eq!(parse_count_flag(Some(&"1".to_string())), Ok(1));
        assert_eq!(parse_count_flag(Some(&"10".to_string())), Ok(10));
        assert_eq!(parse_count_flag(Some(&"5".to_string())), Ok(5));
    }

    #[test]
    fn count_flag_zero_and_eleven_refuse() {
        assert!(parse_count_flag(Some(&"0".to_string())).is_err());
        assert!(parse_count_flag(Some(&"11".to_string())).is_err());
    }

    #[test]
    fn count_flag_non_numeric_is_a_usage_error() {
        assert!(parse_count_flag(Some(&"abc".to_string())).is_err());
        assert!(parse_count_flag(Some(&"".to_string())).is_err());
        assert!(parse_count_flag(Some(&"-1".to_string())).is_err(), "u32 parse rejects the sign");
    }

    // ── parse_drag_args ─────────────────────────────────────────────────

    #[test]
    fn drag_args_exactly_four_integers_including_negatives() {
        assert_eq!(
            parse_drag_args(&["10".into(), "20".into(), "-5".into(), "-15".into()]),
            Ok((10, 20, -5, -15)),
            "negative coordinates must parse (multi-monitor origins can be negative)"
        );
    }

    #[test]
    fn drag_args_wrong_arity_is_a_usage_error() {
        for n in 0..=5usize {
            if n == 4 {
                continue;
            }
            let args: Vec<String> = (0..n).map(|i| i.to_string()).collect();
            assert!(parse_drag_args(&args).is_err(), "arity {n} should refuse");
        }
    }

    #[test]
    fn drag_args_non_numeric_token_is_a_usage_error() {
        assert!(parse_drag_args(&["a".into(), "1".into(), "2".into(), "3".into()]).is_err());
        assert!(parse_drag_args(&["1".into(), "2".into(), "3".into(), "x".into()]).is_err());
    }

    // ── button_code ──────────────────────────────────────────────────────

    #[test]
    fn button_code_matches_linux_input_event_codes() {
        assert_eq!(button_code(Button::Left), 272);
        assert_eq!(button_code(Button::Right), 273);
        assert_eq!(button_code(Button::Middle), 274);
    }

    // ── Seq assembly ─────────────────────────────────────────────────────

    #[test]
    fn move_seq_shape() {
        assert_eq!(move_seq(12, -7), Seq(vec![Step::Motion { dx: 12, dy: -7 }]));
    }

    #[test]
    fn move_seq_zero_delta_is_empty() {
        assert_eq!(move_seq(0, 0), Seq(vec![]), "already at target — no motion event to send");
    }

    #[test]
    fn click_seq_shape_for_each_button() {
        for b in [Button::Left, Button::Right, Button::Middle] {
            let code = button_code(b);
            assert_eq!(
                click_seq(b, 1),
                Seq(vec![
                    Step::Button { code, pressed: true },
                    Step::Button { code, pressed: false },
                ])
            );
        }
    }

    #[test]
    fn click_seq_two_clicks_are_press_release_pause_press_release() {
        let code = button_code(Button::Left);
        assert_eq!(
            click_seq(Button::Left, 2),
            Seq(vec![
                Step::Button { code, pressed: true },
                Step::Button { code, pressed: false },
                Step::Pause { ms: 60 },
                Step::Button { code, pressed: true },
                Step::Button { code, pressed: false },
            ])
        );
    }

    // ── interpolate ──────────────────────────────────────────────────────

    #[test]
    fn interpolate_sums_exactly_to_total_delta_across_step_counts() {
        let cases: [((i64, i64), (i64, i64)); 7] = [
            ((0, 0), (100, 50)),
            ((0, 0), (-100, -60)),
            ((10, 10), (13, 7)), // delta smaller than the step count
            ((0, 0), (7, -7)),
            ((-5, 20), (5, -20)),
            // F1 (Opus's Phase B review): `500 -> i64::MIN` is exactly the
            // shape that overflowed plain `-` (panic in debug, wraparound in
            // release). The property must still hold against the SATURATED
            // total, not the mathematically-true one — `i64::MIN - 500` has
            // no `i64` representation at all, so "exact" can only mean
            // "exact against what `saturating_sub` actually produced".
            ((500, 300), (i64::MIN, 0)),
            ((i64::MIN, i64::MAX), (i64::MAX, i64::MIN)),
        ];
        for &steps in &[1u32, 2, 3, 7, 20, 200] {
            for &(start, end) in &cases {
                let deltas = interpolate(start, end, steps);
                assert_eq!(deltas.len() as u32, steps, "steps={steps} start={start:?} end={end:?}");
                let sum = deltas.iter().fold((0i64, 0i64), |acc, d| (acc.0 + d.0, acc.1 + d.1));
                let want = (end.0.saturating_sub(start.0), end.1.saturating_sub(start.1));
                assert_eq!(sum, want, "steps={steps} start={start:?} end={end:?} deltas={deltas:?}");
            }
        }
    }

    #[test]
    fn interpolate_zero_distance_is_empty_regardless_of_steps() {
        for steps in [1, 2, 20, 200] {
            assert_eq!(interpolate((5, 5), (5, 5), steps), Vec::<(i64, i64)>::new());
        }
    }

    // ── drag_seq ─────────────────────────────────────────────────────────

    #[test]
    fn drag_seq_shape_for_a_small_case() {
        let code = button_code(Button::Left);
        let deltas = interpolate((0, 0), (2, 0), 2);
        assert_eq!(
            drag_seq(Button::Left, &deltas),
            Seq(vec![
                Step::Button { code, pressed: true },
                Step::Pause { ms: 40 },
                Step::Motion { dx: 1, dy: 0 },
                Step::Pause { ms: 8 },
                Step::Motion { dx: 1, dy: 0 },
                Step::Pause { ms: 8 },
                Step::Pause { ms: 40 },
                Step::Button { code, pressed: false },
            ])
        );
    }

    #[test]
    fn drag_seq_empty_deltas_is_still_press_release_balanced() {
        // Not a real call shape (point_drag's handler refuses zero-distance
        // drags before ever calling this) but the builder itself must not
        // produce an unbalanced Seq if it somehow were.
        let code = button_code(Button::Right);
        assert_eq!(
            drag_seq(Button::Right, &[]),
            Seq(vec![
                Step::Button { code, pressed: true },
                Step::Pause { ms: 40 },
                Step::Pause { ms: 40 },
                Step::Button { code, pressed: false },
            ])
        );
    }

    #[test]
    fn drag_seq_skips_zero_motion_deltas_no_real_zero_motion_wire_events() {
        // interpolate((0,0), (1,0), 3) rounds two of the three steps down to
        // no movement at all — drag_seq must not emit a real
        // Motion{0,0}+Pause for those (Opus's Phase B review nit).
        let deltas = interpolate((0, 0), (1, 0), 3);
        assert_eq!(deltas, vec![(0, 0), (0, 0), (1, 0)]);
        let code = button_code(Button::Left);
        assert_eq!(
            drag_seq(Button::Left, &deltas),
            Seq(vec![
                Step::Button { code, pressed: true },
                Step::Pause { ms: 40 },
                Step::Motion { dx: 1, dy: 0 },
                Step::Pause { ms: 8 },
                Step::Pause { ms: 40 },
                Step::Button { code, pressed: false },
            ]),
            "the two (0,0) deltas must not produce Motion/Pause steps at all"
        );
    }

    #[test]
    fn scroll_seq_uses_raw_notches_no_wlrctl_era_scaling() {
        assert_eq!(scroll_seq(1, 0), Seq(vec![Step::Wheel { axis: Axis::Vertical, notches: 1 }]));
        assert_eq!(scroll_seq(-2, 0), Seq(vec![Step::Wheel { axis: Axis::Vertical, notches: -2 }]));
    }

    #[test]
    fn scroll_seq_both_axes() {
        assert_eq!(
            scroll_seq(3, -1),
            Seq(vec![
                Step::Wheel { axis: Axis::Vertical, notches: 3 },
                Step::Wheel { axis: Axis::Horizontal, notches: -1 },
            ])
        );
    }

    #[test]
    fn scroll_seq_zero_zero_is_empty() {
        assert_eq!(scroll_seq(0, 0), Seq(vec![]), "no-op stays a no-op");
    }

    // ── clamp_notches (B2 — was deleted with the old scroll_notches guard,
    // re-added per Opus's Phase A review) ──────────────────────────────────

    #[test]
    fn clamp_notches_within_bound_is_unchanged() {
        assert_eq!(clamp_notches(0), 0);
        assert_eq!(clamp_notches(50), 50);
        assert_eq!(clamp_notches(-50), -50);
        assert_eq!(clamp_notches(MAX_SCROLL_NOTCHES), MAX_SCROLL_NOTCHES);
        assert_eq!(clamp_notches(-MAX_SCROLL_NOTCHES), -MAX_SCROLL_NOTCHES);
    }

    #[test]
    fn clamp_notches_extremes_clamp_to_the_bound() {
        assert_eq!(clamp_notches(i64::MAX), MAX_SCROLL_NOTCHES);
        assert_eq!(clamp_notches(i64::MIN), -MAX_SCROLL_NOTCHES);
    }

    #[test]
    fn scroll_seq_clamps_an_unbounded_notch_count() {
        assert_eq!(
            scroll_seq(1_000_000, 0),
            Seq(vec![Step::Wheel { axis: Axis::Vertical, notches: MAX_SCROLL_NOTCHES }])
        );
        assert_eq!(
            scroll_seq(0, i64::MIN),
            Seq(vec![Step::Wheel { axis: Axis::Horizontal, notches: -MAX_SCROLL_NOTCHES }])
        );
    }

    // ── parse_scroll_args (Phase B: <dy> [dx]) ─────────────────────────────

    #[test]
    fn scroll_args_one_positional_defaults_dx_to_zero() {
        assert_eq!(parse_scroll_args(&["5".into()]), Ok((5, 0)));
        assert_eq!(parse_scroll_args(&["-5".into()]), Ok((-5, 0)));
    }

    #[test]
    fn scroll_args_two_positionals() {
        assert_eq!(parse_scroll_args(&["5".into(), "-3".into()]), Ok((5, -3)));
    }

    #[test]
    fn scroll_args_zero_or_too_many_positionals_is_a_usage_error() {
        assert!(parse_scroll_args(&[]).is_err());
        assert!(parse_scroll_args(&["1".into(), "2".into(), "3".into()]).is_err());
    }

    #[test]
    fn scroll_args_non_numeric_second_positional_is_a_usage_error() {
        assert!(parse_scroll_args(&["5".into(), "abc".into()]).is_err());
        assert!(parse_scroll_args(&["abc".into()]).is_err());
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
    fn pointer_error_reasons_never_name_the_backend() {
        let u = PointerError::Unavailable("no such file or directory".to_string());
        let f = PointerError::Failed("some backend stderr text".to_string());
        assert_eq!(u.reason(), "pointer-unavailable");
        assert_eq!(f.reason(), "pointer-failed");
        for reason in [u.reason(), f.reason()] {
            for backend_word in ["wlrctl", "wayland", "wlr", "zwlr"] {
                assert!(!reason.contains(backend_word), "reason `{reason}` names `{backend_word}`");
            }
        }
        // The DETAIL string is allowed to say whatever the backend said.
        assert_eq!(f.detail(), "some backend stderr text");
    }

    // ── The stuck-button invariant, at the Seq-shape level ────────────────
    //
    // `synth::synthesize` itself is not unit-tested (real socket connect —
    // see its own module header), so the invariant it exists to protect
    // ("never return with a button still logically held") is instead
    // verified here, one level up: every Seq this file's builders can
    // produce must already be press/release-balanced BEFORE it ever reaches
    // `synthesize`. A builder that ever emitted an unbalanced Seq would be
    // relying entirely on synthesize()'s own runtime cleanup to save it —
    // this test makes sure that's never the only thing standing between a
    // bug here and a stuck button.

    /// Folds a Seq's Button steps into a net-pressed count per code; a
    /// balanced Seq always folds to an empty map (every press has a
    /// matching release, in any order).
    fn net_pressed(seq: &Seq) -> std::collections::HashMap<u32, i32> {
        let mut net = std::collections::HashMap::new();
        for step in &seq.0 {
            if let Step::Button { code, pressed } = *step {
                *net.entry(code).or_insert(0) += if pressed { 1 } else { -1 };
            }
        }
        net.retain(|_, count| *count != 0);
        net
    }

    #[test]
    fn seq_never_leaves_a_button_held() {
        let seqs = [
            move_seq(0, 0),
            move_seq(100, -50),
            click_seq(Button::Left, 1),
            click_seq(Button::Right, 1),
            click_seq(Button::Middle, 3),
            click_seq(Button::Left, 0),
            click_seq(Button::Left, 10), // Phase B: --count's upper bound
            scroll_seq(0, 0),
            scroll_seq(5, 0),
            scroll_seq(-3, 2),
            // Phase B: drag_seq — the ONE builder whose whole purpose is
            // holding a button across a batch of motion steps, so this
            // invariant matters most here.
            drag_seq(Button::Left, &[]),
            drag_seq(Button::Left, &interpolate((0, 0), (100, 50), 20)),
            drag_seq(Button::Right, &interpolate((0, 0), (-30, 30), 1)),
            drag_seq(Button::Middle, &interpolate((10, 10), (10, 10), 5)), // zero-distance
        ];
        for seq in &seqs {
            assert!(net_pressed(seq).is_empty(), "unbalanced Seq: {seq:?}");
        }
    }

    // ── Phase D: --from-shot arg-flow, at the pure/file-I/O seams (no
    // hyprctl/pointer spawn anywhere in this section — HARD RULE) ────────

    fn tmp_capture_for_point_test(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "aoide-screen-point-from-shot-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        p.set_extension("png");
        p
    }

    fn write_sidecar_for_point_test(capture: &std::path::Path, origin: (i64, i64), size: (i64, i64), scale: f64) {
        std::fs::write(capture, b"fake").unwrap();
        let sidecar_path = capture.with_extension("json");
        std::fs::write(
            &sidecar_path,
            format!(
                r#"{{"schemaVersion":"0","capturedAt":"2026-08-17T00:00:00Z",
                   "origin":{{"x":{},"y":{}}},"size":{{"w":{},"h":{}}},"scale":{},
                   "format":"png","quality":80}}"#,
                origin.0, origin.1, size.0, size.1, scale
            ),
        )
        .unwrap();
    }

    fn cleanup_point_test_capture(capture: &std::path::Path) {
        let _ = std::fs::remove_file(capture);
        let _ = std::fs::remove_file(capture.with_extension("json"));
    }

    #[test]
    fn from_shot_sidecar_ok_reads_the_real_sidecar() {
        let capture = tmp_capture_for_point_test("ok");
        write_sidecar_for_point_test(&capture, (10, 20), (500, 400), 1.0);
        let sc = from_shot_sidecar("screen.point.move", capture.to_str().unwrap()).unwrap();
        assert_eq!(sc.origin, hypr::Point { x: 10, y: 20 });
        cleanup_point_test_capture(&capture);
    }

    #[test]
    fn from_shot_sidecar_missing_becomes_an_error_outcome_with_the_reason_code() {
        let capture = tmp_capture_for_point_test("missing");
        std::fs::write(&capture, b"fake").unwrap();
        // Deliberately no sidecar written next to it.
        let outcome = from_shot_sidecar("screen.point.move", capture.to_str().unwrap()).unwrap_err();
        assert_eq!(outcome.data.as_ref().and_then(|d| d.get("reason")).and_then(|r| r.as_str()), Some("sidecar-missing"));
        cleanup_point_test_capture(&capture);
    }

    #[test]
    fn from_shot_sidecar_corrupt_becomes_an_error_outcome_with_the_reason_code() {
        let capture = tmp_capture_for_point_test("corrupt");
        std::fs::write(&capture, b"fake").unwrap();
        std::fs::write(capture.with_extension("json"), b"{ not valid json").unwrap();
        let outcome = from_shot_sidecar("screen.point.move", capture.to_str().unwrap()).unwrap_err();
        assert_eq!(outcome.data.as_ref().and_then(|d| d.get("reason")).and_then(|r| r.as_str()), Some("sidecar-corrupt"));
        cleanup_point_test_capture(&capture);
    }

    #[test]
    fn from_shot_error_outcome_reports_both_spaces_on_out_of_bounds() {
        let e = capture::FromShotError::OutOfBounds { x: 500, y: 0, image_w: 500, image_h: 400 };
        let outcome = from_shot_error_outcome("screen.point.move", &e);
        let data = outcome.data.unwrap();
        assert_eq!(data["reason"], "from-shot-out-of-bounds");
        assert_eq!(data["image"]["x"], 500);
        assert_eq!(data["imageSize"]["w"], 500);
    }

    #[test]
    fn from_shot_error_outcome_reports_the_bad_scale() {
        let e = capture::FromShotError::BadScale { scale: -1.0 };
        let outcome = from_shot_error_outcome("screen.point.move", &e);
        let data = outcome.data.unwrap();
        assert_eq!(data["reason"], "from-shot-bad-scale");
        assert_eq!(data["scale"], -1.0);
    }

    /// A minimal `Invocation` for `resolve_from_shot_point` — only `flags`
    /// matters to that function; the rest are unused filler.
    fn inv_with_from_shot(capture: Option<&str>) -> Invocation {
        let mut flags = std::collections::BTreeMap::new();
        if let Some(c) = capture {
            flags.insert("from-shot".to_string(), c.to_string());
        }
        Invocation {
            path: vec!["screen".to_string(), "point".to_string(), "move".to_string()],
            args: vec![],
            flags,
            door: aoide_protocol::Door::Cli,
        }
    }

    #[test]
    fn resolve_from_shot_point_passes_through_unchanged_without_the_flag() {
        let inv = inv_with_from_shot(None);
        let (p, image) = resolve_from_shot_point("screen.point.move", &inv, 42, 7).unwrap();
        assert_eq!(p, hypr::Point { x: 42, y: 7 });
        assert_eq!(image, None);
    }

    #[test]
    fn resolve_from_shot_point_converts_and_reports_the_image_point() {
        let capture = tmp_capture_for_point_test("resolve-ok");
        write_sidecar_for_point_test(&capture, (100, 50), (500, 400), 2.0);
        let inv = inv_with_from_shot(Some(capture.to_str().unwrap()));
        // screen = origin + image_px / scale = (100,50) + (40,20)/2.0 = (120,60).
        let (p, image) = resolve_from_shot_point("screen.point.move", &inv, 40, 20).unwrap();
        assert_eq!(p, hypr::Point { x: 120, y: 60 });
        assert_eq!(image, Some((40, 20)));
        cleanup_point_test_capture(&capture);
    }

    #[test]
    fn resolve_from_shot_point_refuses_out_of_bounds_before_the_call_site_sees_a_point() {
        let capture = tmp_capture_for_point_test("resolve-oob");
        write_sidecar_for_point_test(&capture, (0, 0), (100, 100), 1.0);
        let inv = inv_with_from_shot(Some(capture.to_str().unwrap()));
        let outcome = resolve_from_shot_point("screen.point.move", &inv, 500, 0).unwrap_err();
        assert_eq!(
            outcome.data.as_ref().and_then(|d| d.get("reason")).and_then(|r| r.as_str()),
            Some("from-shot-out-of-bounds")
        );
        cleanup_point_test_capture(&capture);
    }

    // ── Phase D review nit: click --from-shot with no guard x/y is a usage
    // error, not a silent no-op ─────────────────────────────────────────

    #[test]
    fn click_from_shot_without_a_guard_is_a_usage_error_not_a_silent_no_op() {
        // Empty `args` — no button word, no guard x/y — with `--from-shot`
        // present. Reaches this refusal before touching hyprctl at all, so
        // it's safe to call the handler directly (HARD RULE: no live
        // pointer/hyprctl spawn in this test module).
        let mut flags = std::collections::BTreeMap::new();
        flags.insert("from-shot".to_string(), "/tmp/whatever.png".to_string());
        let inv = Invocation {
            path: vec!["screen".to_string(), "point".to_string(), "click".to_string()],
            args: vec![],
            flags,
            door: aoide_protocol::Door::Cli,
        };
        let outcome = point_click(&inv);
        assert_eq!(outcome.status, aoide_protocol::output::Status::Usage);
        assert!(outcome.message.contains("--from-shot"), "{}", outcome.message);
    }

    // ── Phase D review nit: drag's same-point refusal names the collapsed
    // IMAGE points when --from-shot's rounding is what caused it ─────────

    #[test]
    fn drag_same_point_without_from_shot_reports_the_plain_message() {
        let inv = Invocation {
            path: vec!["screen".to_string(), "point".to_string(), "drag".to_string()],
            args: vec!["10".to_string(), "20".to_string(), "10".to_string(), "20".to_string()],
            flags: std::collections::BTreeMap::new(),
            door: aoide_protocol::Door::Cli,
        };
        let outcome = point_drag(&inv);
        assert_eq!(outcome.status, aoide_protocol::output::Status::Usage);
        assert_eq!(outcome.message, "drag start and end are the same point");
    }

    #[test]
    fn drag_from_shot_two_distinct_image_points_that_collapse_at_scale_note_it_in_the_message() {
        let capture = tmp_capture_for_point_test("drag-collapse");
        // scale 4.0: scale_div_round(0,4.0) == scale_div_round(1,4.0) == 0 —
        // image (0,0) and image (1,1) are DISTINCT but both land on the same
        // screen pixel off this origin. Reaches the same-point refusal
        // before touching hyprctl (the pre-flight/move steps all come
        // after), so safe to call directly.
        write_sidecar_for_point_test(&capture, (0, 0), (100, 100), 4.0);
        let mut flags = std::collections::BTreeMap::new();
        flags.insert("from-shot".to_string(), capture.to_str().unwrap().to_string());
        let inv = Invocation {
            path: vec!["screen".to_string(), "point".to_string(), "drag".to_string()],
            args: vec!["0".to_string(), "0".to_string(), "1".to_string(), "1".to_string()],
            flags,
            door: aoide_protocol::Door::Cli,
        };
        let outcome = point_drag(&inv);
        assert_eq!(outcome.status, aoide_protocol::output::Status::Usage);
        assert!(
            outcome.message.contains("image points (0,0) and (1,1) differ but collapse"),
            "{}",
            outcome.message
        );
        cleanup_point_test_capture(&capture);
    }
}
