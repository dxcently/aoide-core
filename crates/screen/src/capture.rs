//! `aoide screen shot` — grim/slurp capture logic. Generic-wlr-protocol
//! territory, deliberately kept out of `hypr.rs` (Hyprland-specific JSON);
//! file-split only, per khoa's module-hygiene note (2026-08-16).
//!
//! ── The pixel-acquisition boundary (khoa, 2026-08-16) ──────────────────────
//! Everything in this file EXCEPT [`capture_image`] and [`pick_region`]
//! decides WHAT to capture (region math, format/quality/scale resolution,
//! the sidecar). Those two functions decide HOW, and are the ONLY places
//! `grim`/`slurp` are named: a [`CaptureRequest`] in, a written file (or a
//! [`CaptureError`]) out for the former; "ask a human for a region" in,
//! `Ok(Some(region))` / `Ok(None)` (cancelled) / `Err` (couldn't even ask)
//! out for the latter. grim/slurp are the shipped, permanent backend (not a
//! placeholder) — this boundary exists as hygiene, so a caller never learns
//! which tool did the work, not because a swap is scheduled.
//!
//! ── Sidecar (khoa's brief) ─────────────────────────────────────────────────
//! Every capture gets a `<name>.json` sidecar (same stem, `.json` extension)
//! written via `aoide_storage::fs::atomic_write` — the contract later
//! `screen` phases build on (OCR phase 3 writes into `ocr`, which is why that
//! field is present-and-`null` from day one rather than added later).

use super::hypr;
use aoide_protocol::output::Outcome;
use aoide_protocol::Invocation;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::PathBuf;

// ── Image format ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Png,
    Jpeg,
}

impl Format {
    pub fn parse(s: &str) -> Option<Format> {
        match s {
            "png" => Some(Format::Png),
            "jpeg" | "jpg" => Some(Format::Jpeg),
            _ => None,
        }
    }
    /// The sidecar's `format` field / this flag's own canonical spelling.
    pub fn label(self) -> &'static str {
        match self {
            Format::Png => "png",
            Format::Jpeg => "jpeg",
        }
    }
    /// Auto-named file extension — deliberately `jpg` (shorter, the common
    /// spelling) even though [`label`](Self::label) says `jpeg`; the two
    /// need not match, `-t`/the sidecar are what's authoritative.
    pub fn ext(self) -> &'static str {
        match self {
            Format::Png => "png",
            Format::Jpeg => "jpg",
        }
    }
    /// grim's own `-t` value.
    pub fn grim_type(self) -> &'static str {
        match self {
            Format::Png => "png",
            Format::Jpeg => "jpeg",
        }
    }
}

// ── Region resolution: which of --output/--region/--pick, parsing, clamp ──

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionSource {
    Full,
    Output,
    Region,
    Pick,
    /// Phase 4: an explicit Hyprland window address (`--window`).
    Window,
    /// Phase 4: a conducted-session id, resolved to its window (`--session`).
    Session,
}

/// Which region source wins — a usage error when more than one of
/// `--output`/`--region`/`--pick`/`--window`/`--session` is present (never a
/// silent precedence pick between them). Phase 4 extends the original
/// three-way (`--output`/`--region`/`--pick`) check with two more sources
/// rather than forking a second check — same rule, same error shape, now
/// five-way.
pub fn resolve_region_source(
    has_output: bool,
    has_region: bool,
    has_pick: bool,
    has_window: bool,
    has_session: bool,
) -> Result<RegionSource, &'static str> {
    let flags = [has_output, has_region, has_pick, has_window, has_session];
    if flags.iter().filter(|f| **f).count() > 1 {
        return Err(
            "--output, --region, --pick, --window, and --session are mutually exclusive (pick exactly one)",
        );
    }
    Ok(if has_output {
        RegionSource::Output
    } else if has_region {
        RegionSource::Region
    } else if has_pick {
        RegionSource::Pick
    } else if has_window {
        RegionSource::Window
    } else if has_session {
        RegionSource::Session
    } else {
        RegionSource::Full
    })
}

/// Parse a bare `"WxH"` size literal (khoa, 2026-08-17, Phase D of the
/// pointer-emulation workstream) — hoisted out of [`parse_region_literal`]'s
/// own size half so `--fit`'s `"WxH"` and `--region`'s `"X,Y WxH"` share
/// exactly one definition of that syntax rather than two copies free to
/// drift apart. `None` on anything that doesn't split on one `x` into two
/// integers.
pub fn parse_size_literal(spec: &str) -> Option<(i64, i64)> {
    let (w, h) = spec.trim().split_once('x')?;
    Some((w.trim().parse().ok()?, h.trim().parse().ok()?))
}

/// Parse `--region`'s one accepted syntax: `"X,Y WxH"` (canonical form only —
/// a stricter subset of `tools/pointer.sh`'s several accepted spellings;
/// YAGNI, this phase's brief asks for one syntax). `None` on anything else,
/// which the caller turns into a usage error (exit 2).
pub fn parse_region_literal(spec: &str) -> Option<(i64, i64, i64, i64)> {
    let (pos, size) = spec.trim().split_once(' ')?;
    let (x, y) = pos.split_once(',')?;
    let (w, h) = parse_size_literal(size)?;
    Some((x.trim().parse().ok()?, y.trim().parse().ok()?, w, h))
}

// ── Phase D: `--fit`/`--scale` mutual exclusion (khoa, 2026-08-17, Phase D
// of the pointer-emulation workstream) ─────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScaleSource {
    /// Neither flag given — `scale` defaults to `1.0` downstream.
    Default,
    Scale,
    Fit,
}

/// Which of `--scale`/`--fit` wins — mirrors [`resolve_region_source`]'s own
/// mutual-exclusion shape exactly (a usage error when both are present,
/// never a silent precedence pick between them), just two-way instead of
/// five-way. Resolved EARLY in `shot()`, before any `hyprctl` call, same as
/// the region source — so this usage error, like that one, is reachable
/// (and unit-testable) without a live compositor.
pub fn resolve_scale_source(has_scale: bool, has_fit: bool) -> Result<ScaleSource, &'static str> {
    match (has_scale, has_fit) {
        (true, true) => Err("--scale and --fit are mutually exclusive (pick exactly one)"),
        (true, false) => Ok(ScaleSource::Scale),
        (false, true) => Ok(ScaleSource::Fit),
        (false, false) => Ok(ScaleSource::Default),
    }
}

/// The largest scale `<= 1.0` such that `region` fits inside a `max_w x
/// max_h` box — `--fit`'s whole arithmetic (khoa, 2026-08-17, Phase D of the
/// pointer-emulation workstream). This is the computer-use doctrine
/// "downscale yourself and own the scale factor": hand a vision model a
/// model-friendly frame (~1280x800) with an EXACT inverse mapping back to
/// screen pixels — the sidecar's existing `scale` field already promises
/// that unconditionally (see [`Sidecar`]'s own doc) — rather than a bigger
/// frame it has to eyeball distances on. Detail lost to the downscale is
/// recovered by re-shotting a SMALLER region at native resolution
/// (`--region`), never by inflating the frame size.
///
/// NEVER upscales: a `region` already smaller than the box returns exactly
/// `1.0`, never a magnification factor — `min`ned against `1.0` at the end.
/// The constraining axis is whichever of width/height would otherwise
/// overflow the box first: the smaller of the two per-axis ratios wins.
///
/// `max_w`/`max_h` must be positive; a degenerate (zero/negative) box is a
/// USAGE ERROR AT THE CALL SITE (`shot()`'s own `--fit` parsing, before this
/// is ever reached) — this function has no opinion on CLI input validity,
/// only on the arithmetic once the inputs are known-good (mirrors
/// [`super::point::interpolate`]'s own "pure function, caller pre-validates"
/// split).
pub fn fit_scale(region: hypr::Region, max_w: i64, max_h: i64) -> f64 {
    let scale_w = max_w as f64 / region.w as f64;
    let scale_h = max_h as f64 / region.h as f64;
    scale_w.min(scale_h).min(1.0)
}

/// Resolve `--output <name>` against the live monitor list. `None` when no
/// monitor has that name — a usage error at the call site, not a hyprctl
/// failure (hyprctl answered fine; the name was just wrong).
pub fn monitor_region(monitors: &[hypr::Monitor], name: &str) -> Option<hypr::Region> {
    monitors.iter().find(|m| m.name == name).map(|m| hypr::Region {
        x: m.origin.x,
        y: m.origin.y,
        w: m.size.w,
        h: m.size.h,
    })
}

// ── Phase 4: `--window`/`--session` region sources ─────────────────────────
//
// Both resolve to a live `hypr::Client`, then flow through the exact same
// `client_rect` → clamp → capture → sidecar path as every other source —
// no forked capture path, just two more ways to name a rectangle.

/// A `hypr::Client`'s rectangle — the same `at`/`size` → `Region` shape
/// [`monitor_region`] already computes for a monitor, just off a window.
fn client_rect(c: &hypr::Client) -> hypr::Region {
    hypr::Region { x: c.at.x, y: c.at.y, w: c.size.w, h: c.size.h }
}

/// Which named target (if any) produced a capture's region — carried through
/// to the sidecar (`Sidecar::session`/`window`/`class`/`title`) so a caller
/// can tell WHAT was captured, not just where. All-`None` for
/// `Full`/`Region`/`Pick`; `--output` fills only `monitor` (unchanged from
/// before Phase 4); `--window` fills `window`/`class`/`title`; `--session`
/// fills all four.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CaptureTarget {
    pub monitor: Option<String>,
    pub session: Option<String>,
    pub window: Option<String>,
    pub class: Option<String>,
    pub title: Option<String>,
}

/// Resolve `--window <address>` against the live client list. `None` when no
/// client has that (normalized) address — a usage/error case at the call
/// site, never a panic or a full-screen fallback. Address comparison reuses
/// `graph::window`'s own `0x`/case-tolerant [`aoide_conduct::graph::normalize_addr`]
/// — the stored/typed address and what a human pastes off `hyprctl clients`
/// can disagree on both, exactly the same tolerance `graph::focus` already
/// needs for the same reason.
pub fn find_window<'a>(clients: &'a [hypr::Client], address: &str) -> Option<&'a hypr::Client> {
    let want = aoide_conduct::graph::normalize_addr(address);
    clients.iter().find(|c| aoide_conduct::graph::normalize_addr(&c.address) == want)
}

/// Resolve a pid to its Hyprland client, applying the documented multi-
/// window tie-break: a pid can own more than one mapped window (e.g. a
/// multi-window GUI app), so rather than guessing or capturing all of them,
/// prefer the FOCUSED client among the matches; if none of them is focused,
/// take the first in hyprctl's own z-order (the order `-j clients` returns
/// them in). `None` when the pid owns no live mapped window at all.
pub fn find_client_for_pid(clients: &[hypr::Client], pid: u32) -> Option<&hypr::Client> {
    let matches: Vec<&hypr::Client> = clients.iter().filter(|c| c.pid == pid as i64).collect();
    matches
        .iter()
        .find(|c| c.focused)
        .or_else(|| matches.first())
        .copied()
}

/// Why `--session <id>` could not resolve to a capturable window — each a
/// distinct sidecar-free reason code at the call site (`session-not-found` /
/// `session-no-window`), never a panic and never a silent full-screen
/// fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRegionError {
    /// The id is not in the session store at all.
    SessionNotFound,
    /// The session is known but has no live window right now — no pid on
    /// record, or its pid/windowAddress no longer matches any live client
    /// (the agent's terminal may have closed).
    SessionNoWindow,
}

/// Resolve `--session <id>` to its live window client — id → session record
/// (`graph::SessionRecord`) → that record's window.
///
/// **Two signals live on a `SessionRecord`, and they are NOT
/// interchangeable** (verified live against this rig's real
/// `song/stage/sessions.json`, 2026-08-16 — see the executor's report for
/// the full evidence trail):
///
///   * `windowAddress` — resolved by `graph::window`'s pid-ancestry walk (or
///     the `socket2` event listener) and stored directly on the record.
///     Correct for every session kind observed on this rig: `conduct`-
///     wrapped shells, `pi` agents, and hook-registered `claude` agents
///     alike. Tried FIRST, via the exact same [`find_window`] `--window`
///     itself uses — one resolver, two callers.
///   * `pid` — NOT uniformly "the window's owning pid". For a `conduct`-
///     wrapped session it is the CONDUCT WRAPPER's own pid
///     (`graph::conduct::session_conduct`'s own comment: "Record THIS
///     conduct process's pid (not the PTY child's)"), which is never a
///     `hyprctl clients` entry at all — confirmed live: `conduct-2284-…`'s
///     stored pid (2284) matches ZERO live clients, while its
///     `windowAddress` resolves to a real one. For a harness that
///     self-reports its own pid (pi's "payload-pid seam") it is likewise the
///     AGENT's pid, distinct from the terminal. It equals the window-owning
///     pid only where `graph::window::ensure_session_window` backfills it
///     (a harness with no self-reported pid). So `pid` is tried only as a
///     FALLBACK, via [`find_client_for_pid`] — for a session whose window
///     hasn't been discovered yet (or has gone stale) but still carries a
///     pid that happens to be the window's own.
pub fn find_session_client<'a>(
    sessions: &[aoide_conduct::graph::SessionRecord],
    clients: &'a [hypr::Client],
    session_id: &str,
) -> Result<&'a hypr::Client, SessionRegionError> {
    let rec = sessions
        .iter()
        .find(|s| s.session_id == session_id)
        .ok_or(SessionRegionError::SessionNotFound)?;
    if !rec.window_address.is_empty() {
        if let Some(c) = find_window(clients, &rec.window_address) {
            return Ok(c);
        }
        // windowAddress is stale (the window has since closed) — fall
        // through to the pid signal rather than failing immediately.
    }
    let pid = rec.pid.ok_or(SessionRegionError::SessionNoWindow)?;
    find_client_for_pid(clients, pid).ok_or(SessionRegionError::SessionNoWindow)
}

/// One resolved+clamped region: the rect to actually capture, plus what was
/// originally requested IF clamping had to move it — never a silently
/// different rectangle than the one asked for (mirrors `tools/pointer.sh`'s
/// `resolve_region` clamp discipline exactly, same four-sided math).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ResolvedRegion {
    pub rect: hypr::Region,
    pub clamped_from: Option<hypr::Region>,
}

/// Clamp `requested` into `bounds`. `None` when the requested rect has zero
/// (or negative) area to begin with, or lands with zero area after clamping
/// (it lay wholly outside `bounds`) — both are usage errors at the call
/// site.
///
/// Every arithmetic step is SATURATING, not wrapping/panicking: `--region`
/// takes raw `i64`s straight from agent input, and a pathological value near
/// the `i64` extremes (e.g. an origin of `i64::MIN`) can overflow plain `+`/
/// `-` — a debug-build panic, which CONTRACTS.md §3 rules out ("never a
/// panic"), a real one caught by the fix, not merely theoretical (khoa's
/// Phase 1 review, D3). Saturating arithmetic doesn't just avoid the panic,
/// it keeps giving the RIGHT answer: an origin so far outside `bounds` that
/// the true width would go deeply negative still correctly resolves to
/// `None` (no overlap) via the final `w <= 0 || h <= 0` check, and an
/// absurdly large width still clamps to the real edge distance, both without
/// the intermediate math ever overflowing. Ordinary in-range requests are
/// bit-for-bit unaffected (saturating ops behave identically to plain ones
/// when nothing would overflow) — every pre-existing clamp test still holds.
pub fn clamp_region(requested: hypr::Region, bounds: hypr::Region) -> Option<ResolvedRegion> {
    if requested.w <= 0 || requested.h <= 0 {
        return None;
    }
    let (mut x, mut y, mut w, mut h) = (requested.x, requested.y, requested.w, requested.h);
    let bx1 = bounds.x;
    let by1 = bounds.y;
    let bx2 = bounds.x.saturating_add(bounds.w);
    let by2 = bounds.y.saturating_add(bounds.h);

    if x < bx1 {
        w = w.saturating_sub(bx1.saturating_sub(x));
        x = bx1;
    }
    if y < by1 {
        h = h.saturating_sub(by1.saturating_sub(y));
        y = by1;
    }
    if x.saturating_add(w) > bx2 {
        w = bx2.saturating_sub(x);
    }
    if y.saturating_add(h) > by2 {
        h = by2.saturating_sub(y);
    }
    if w <= 0 || h <= 0 {
        return None;
    }
    let rect = hypr::Region { x, y, w, h };
    let clamped_from = if rect != requested { Some(requested) } else { None };
    Some(ResolvedRegion { rect, clamped_from })
}

/// The image's expected pixel dimensions for a `region` captured at `scale`.
/// Computed, never read back from the file: "capture region R at scale S"
/// MEANS "produce R.w*S x R.h*S pixels" by construction, for grim today and
/// for any future backend behind [`capture_image`] alike (verified against
/// grim empirically — see the executor's report). An image-DECODING
/// dependency (`image`) did arrive in this workspace, with Phase E's `screen
/// diff` command (khoa, 2026-08-17, pointer-emulation workstream) — but
/// decoding stays entirely out of the capture path: `screen::diff` is the
/// one module that calls into it, this function still never does. Rounds to
/// the nearest pixel.
pub fn expected_image_size(region: hypr::Region, scale: f64) -> (i64, i64) {
    (
        (region.w as f64 * scale).round() as i64,
        (region.h as f64 * scale).round() as i64,
    )
}

/// The sub-1px expected-size guard, pure (khoa, 2026-08-17, Phase E —
/// cleanup flagged in Phase D review): this check originally lived ONLY
/// inside `shot()`'s `ScaleSource::Fit` arm, so an explicit `--scale 0.0001`
/// could slip a degenerate (0px on at least one axis) image past validation
/// where `--fit` could not — the same failure `--fit`'s own guard exists to
/// catch, just reachable from the sibling flag. Moved here, below the
/// scale-source match in `shot()`, so BOTH `--fit` and `--scale` are covered
/// by the identical check — pure and unit-tested directly, mirroring
/// `fit_scale`/`expected_image_size`'s own "pure function, caller
/// pre-validates" split. `Some((ew, eh))` carries the degenerate size to
/// report; `None` means the image is healthy.
fn min_size_error(region: hypr::Region, scale: f64) -> Option<(i64, i64)> {
    let (ew, eh) = expected_image_size(region, scale);
    if ew < 1 || eh < 1 {
        Some((ew, eh))
    } else {
        None
    }
}

/// Auto-named capture filename when `--out` is absent: `screenshot-<unix
/// ts>-<pid>-<seq>.<ext>` — the same `<kind>-<pid>-<unixts>` shape
/// `graph::conduct`/`graph::session_store` already use for session ids
/// (`conduct-<pid>-<unixts>`, `wrap-<pid>-<unixts>`), just pid-then-ts
/// reordered so files with the same second still sort distinctly by pid.
/// Actually pid LAST-but-one here (unlike those ids) so a directory listing
/// sorts by capture TIME first — the more useful default order for a
/// captures dir a human might `ls`.
///
/// `seq` (Phase E review, NIT, khoa, 2026-08-17): `unix_ts` has 1-SECOND
/// resolution, so two auto-named captures from the SAME process inside the
/// same second used to collide on filename — `screen diff`'s own recapture
/// doubled the odds of that (two captures, one process, one settle window,
/// easily under 1s) enough to close it at the source rather than patch
/// around it in `diff()` alone. `auto_name` itself stays pure/testable: the
/// counter lives at the call site ([`next_auto_name_seq`]), read once and
/// handed in here as plain data — the same "impure only at the edges"
/// split `unix_ts()`/`std::process::id()` themselves already are for this
/// function's other two inputs.
pub fn auto_name(unix_ts: u64, pid: u32, seq: u64, fmt: Format) -> String {
    format!("screenshot-{unix_ts}-{pid}-{seq}.{}", fmt.ext())
}

/// The monotonic counter [`auto_name`]'s `seq` argument comes from — one
/// per process, starting at 0, `Relaxed` because ordering across threads
/// doesn't matter here, only that two calls in the same process never read
/// the same value.
static AUTO_NAME_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub(crate) fn next_auto_name_seq() -> u64 {
    AUTO_NAME_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Does `dest.with_extension("json")` land back on `dest` itself? True
/// exactly when `dest` already ends in `.json` — the collision an explicit
/// `--out foo.json` would create between a capture and its own sidecar (the
/// sidecar write would silently overwrite the just-captured image). Pure so
/// it's unit-tested directly; `shot()`'s own end-to-end path can't be (it
/// calls live `hyprctl` first) (khoa's Phase 1 review, D1).
pub(crate) fn sidecar_collides_with_dest(dest: &std::path::Path) -> bool {
    dest.with_extension("json") == dest
}

pub(crate) fn unix_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── The sidecar ────────────────────────────────────────────────────────

/// `<capture>.json` — written next to every capture (same stem, `.json`
/// extension: `dest.with_extension("json")`). `ocr` is a placeholder,
/// unconditionally present as `null` (never omitted) so phase 3's OCR write-
/// back is additive; `monitor`/`comment` are omitted-when-absent instead,
/// the ordinary optional-field convention (`aoide_storage::records`).
///
/// `origin` is logical (Hyprland) pixel space — the same space `screen
/// info`/`--region` use; `size` is DEVICE pixels (post-`scale`, what the
/// image file actually contains). The two coincide only at `scale == 1.0`
/// (the default); a phase-3 OCR consumer mapping a detected text box back to
/// a screen coordinate must divide by `scale` first. The outcome message
/// already warns "not 1:1" whenever `scale != 1.0` (khoa's Phase 1 review,
/// P2).
///
/// `schemaVersion` is a STRING, `"0"` — matching every other schema-versioned
/// shape in this codebase (`aoide_storage::records`' `ProjectsFile`/
/// `SessionsFile`/`HooksFile`, `peer_store`, `a2a_store`, CONTRACTS.md §3/§4)
/// rather than a bare number (khoa's Phase 1 review, Decision B: flagged by
/// the executor, confirmed and directed by the reviewer). `"0"`, not `"1"`,
/// because every OTHER first-cut schema in the repo starts at `"0"` — this
/// sidecar is no exception to that convention until someone says otherwise.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sidecar {
    #[serde(rename = "schemaVersion", default)]
    pub schema_version: String,
    #[serde(rename = "capturedAt")]
    pub captured_at: String,
    pub origin: hypr::Point,
    pub size: hypr::Size,
    pub scale: f64,
    /// The LOGICAL (Hyprland-space) region [`write_capture`] actually
    /// requested — recorded verbatim (Phase E review, B1, khoa, 2026-08-17).
    /// `size` above is DEVICE pixels post-`scale`, and inverting that
    /// forward rounding (`expected_image_size`'s `region * scale`, rounded
    /// to the nearest pixel) via division is LOSSY for roughly 1-in-`scale`
    /// widths/heights: `region.w = 1001` at `scale = 0.5` rounds forward to
    /// `image_w = 501`, but dividing back (`scale_div_round(501, 0.5)`)
    /// rounds to `1002`, not `1001`; a `--fit`-derived scale of `0.667` on
    /// `region.w = 100` rounds forward to `67`, back to `101`. `screen
    /// diff`'s recapture needs the EXACT original region — a 1px drift there
    /// silently resamples a slightly different rectangle, so the after-image
    /// can differ from the before-image at the edge even though nothing on
    /// screen actually changed, and `diff-size-mismatch` never catches it
    /// (both images still come out the SAME device-pixel size, `grim`
    /// rounding the drifted region forward again). Recorded once here rather
    /// than recomputed — the same "the value must be RECORDED, not
    /// recomputed" discipline `size` itself already holds. `None`/omitted
    /// for any pre-Phase-E sidecar (never back-filled retroactively);
    /// `diff.rs`'s `recover_region` falls back to the lossy division ONLY in
    /// that case, and says so in its outcome message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<hypr::Region>,
    pub format: String,
    pub quality: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitor: Option<String>,
    /// Phase 4 additions — which `--session`/`--window` target produced this
    /// capture, `None`/omitted for a plain full/output/region/pick capture.
    /// Additive to the v0 schema (CONTRACTS.md's "omitted-when-absent"
    /// optional-field convention, same as `monitor`/`comment`) — a sidecar
    /// written before Phase 4 still parses (`#[serde(default)]`), and reading
    /// it back never distinguishes "not applicable" from "not yet known".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// `--cursor` (Phase D) — `Some(true)` when grim was asked to draw the
    /// composited cursor into this capture, omitted otherwise. Never
    /// `Some(false)`: an absent key already means "not drawn," the same
    /// omitted-when-absent convention `monitor`/`comment` use, so a
    /// Phase-4-era sidecar with no key at all parses identically to one
    /// where `--cursor` simply wasn't passed.
    #[serde(rename = "cursorDrawn", default, skip_serializing_if = "Option::is_none")]
    pub cursor_drawn: Option<bool>,
    /// A full desktop snapshot (cursor + every mapped client/layer surface)
    /// taken at capture time (Phase D) — reuses `hypr::snapshot()`'s own
    /// clients/layers gathering plus one `hyprctl cursorpos` call
    /// ([`hypr::desktop_snapshot`]). `None`/omitted when a `hyprctl` call
    /// failed mid-snapshot (the shot itself is still the product — a failed
    /// snapshot degrades this field, it never fails the capture) OR for any
    /// sidecar written before Phase D. Additive to the v0 schema, same
    /// omitted-when-absent convention as every other optional field here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desktop: Option<hypr::DesktopSnapshot>,
    #[serde(default)]
    pub ocr: Option<serde_json::Value>,
    /// `screen diff`'s result (Phase E of the pointer-emulation workstream,
    /// khoa, 2026-08-17) — present-and-`null` on every new capture (the same
    /// day-one-placeholder convention `ocr` already established:
    /// `capture.rs`'s own header), populated only on the AFTER-capture a
    /// `screen diff` re-shot produces (never on the before-capture the
    /// caller supplied — diffing writes to the file IT wrote, not to an
    /// arbitrary caller-named one). `#[serde(default)]`, no
    /// `skip_serializing_if`: a pre-Phase-E sidecar on disk has no `diff` key
    /// at all and must still parse (forward tolerance), while every sidecar
    /// THIS crate writes from here on always carries the key, `null` or
    /// populated.
    #[serde(default)]
    pub diff: Option<serde_json::Value>,
}

/// The sidecar's current schema version (CONTRACTS.md's v0-first convention).
pub const SIDECAR_SCHEMA_VERSION: &str = "0";

// ── `--from-shot`: image-space → screen-space coordinate conversion (khoa,
// 2026-08-17, Phase D of the pointer-emulation workstream) ─────────────────
//
// Closes the loop `screen ocr` opened: a sidecar's `origin`/`scale` already
// let `ocr.rs` map a detected text box back to absolute screen pixels; this
// section lets an AGENT do the same for a coordinate IT read off the image
// (a click target it picked by eye, an OCR word's bbox center) — the exact
// inverse of "capture region R at scale S produces R.w*S x R.h*S pixels."

/// Is `scale` usable for the image→screen division? Moved HERE from
/// `ocr.rs` (this file already owns the origin/scale contract — see
/// [`Sidecar`]'s own doc above) so `Sidecar::image_point_to_screen` and
/// `screen ocr`'s coordinate transform share exactly one definition of
/// "usable scale," rather than two copies free to drift apart. `ocr.rs`
/// keeps a one-line delegation to this function under its own name, so its
/// call site and tests are untouched.
pub fn scale_is_valid(scale: f64) -> bool {
    scale > 0.0 && scale.is_finite()
}

/// `image_px / scale`, rounded to the nearest pixel — the ONE division this
/// whole transform reduces to, shared by both axes of a point AND by a
/// bbox's width/height (which aren't points, so they only ever need this
/// half, never the origin-add half [`transform_point`] adds on top).
/// `pub(crate)`, not private: `ocr::image_bbox_to_screen` needs it directly
/// for a bbox's width/height, which have no "point" to run
/// [`transform_point`] on.
pub(crate) fn scale_div_round(image_px: i64, scale: f64) -> i64 {
    (image_px as f64 / scale).round() as i64
}

/// The point-space half of the image→screen transform: `origin + (x,y) /
/// scale`. Pure, with NO bounds/scale-validity checking of its own —
/// [`Sidecar::image_point_to_screen`] does both BEFORE ever calling this;
/// `ocr::image_bbox_to_screen` calls it once for a bbox's top-left corner,
/// then [`scale_div_round`] again for width/height (there's no second
/// corner to run this on for an extent — same division, applied to a size
/// instead of a position, is the "or equivalent" this file's brief allows).
/// This is now the ONE transform implementation in the crate; both callers
/// share it rather than each carrying their own `origin + px / scale` copy.
pub fn transform_point(origin: hypr::Point, scale: f64, x: i64, y: i64) -> hypr::Point {
    // `saturating_add`, not plain `+` (khoa's Phase D review, L1): `origin`
    // is a raw `i64` off a caller-NAMED sidecar file (`--from-shot
    // <capture>`, an arbitrary path an agent points at), and
    // `scale_div_round`'s own `as i64` cast already saturates a wild division
    // to `i64::MAX`/`MIN` rather than overflow — but a SUBSEQUENT plain `+`
    // of that saturated value against `origin` can itself overflow. A
    // subnormal `scale` (e.g. `1e-320`) passes `scale_is_valid` (positive,
    // finite) yet `image_px / 1e-320` overflows `f64` to infinity, so
    // `scale_div_round` returns `i64::MAX` — exactly the caller-lie case
    // `BadScale`'s guard exists to catch elsewhere; this addition must not
    // repanic the same threat model on the one axis that guard doesn't
    // reach. This file's own D3 discipline (`clamp_region`/`interpolate`)
    // for the same reason.
    hypr::Point {
        x: origin.x.saturating_add(scale_div_round(x, scale)),
        y: origin.y.saturating_add(scale_div_round(y, scale)),
    }
}

/// Why [`Sidecar::image_point_to_screen`] refused — each variant reports
/// BOTH spaces it knows about, never just the one that failed, so a caller
/// building an `Outcome` has everything it needs without a second lookup.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FromShotError {
    /// `(x, y)` lies outside the sidecar's own recorded image size (DEVICE
    /// pixels, `Sidecar::size` — not logical/screen pixels). The classic
    /// failure this whole command exists to catch: an agent read coordinates
    /// off a DOWNSCALED shot (`--fit`/`--scale`) but reported them as if the
    /// image were full-resolution.
    OutOfBounds { x: i64, y: i64, image_w: i64, image_h: i64 },
    /// The sidecar's own `scale` is unusable (zero/negative/NaN/infinite) —
    /// can only happen via hand-editing/corruption of the `<capture>.json`
    /// file between the `shot` that wrote it and this read (an ordinary
    /// `screen shot` already rejects `--scale <= 0` at write time; mirrors
    /// `ocr.rs`'s own `scale_is_valid` call-site guard exactly).
    BadScale { scale: f64 },
}

/// Pull a [`transform_point`] result back inside the captured rect's own
/// half-open interior `[origin, origin + reconstructed_screen_size)` (khoa's
/// Phase D review, L5). `scale_div_round`'s rounding can legitimately land a
/// LAST-row/LAST-col in-bounds image pixel one px PAST that edge: at scale
/// 2.0 and image width 20 (valid image x up to 19), `scale_div_round(19,
/// 2.0)` rounds `9.5` up to `10`, landing exactly on the EXCLUSIVE boundary
/// of the reconstructed 10px-wide screen rect rather than inside it — a
/// legitimately in-image coordinate would otherwise be refused by a
/// downstream `point_in_bounds` check (`drag`'s pre-flight) or just drift
/// (`move`'s landing check), neither of which is the caller's fault.
///
/// **This is NOT `capture::clamp_region`'s caller-lie clamp** — that one
/// silently narrows a requested capture rectangle because the CALLER asked
/// for something outside the layout, and announces it. This clamp corrects
/// OUR OWN rounding on an input that already passed the bounds check above;
/// the input was never a lie, only the forward-transform arithmetic's
/// half-pixel rounding needs pulling back inside the rect it came from. An
/// actually out-of-bounds image point is still refused before this is ever
/// reached, never silently pulled in.
///
/// Reconstructs the screen-space extent via the SAME `scale_div_round` the
/// forward transform used (`size.w/h` divided by `scale`) rather than
/// storing a separate screen-space rect on `Sidecar` — one division
/// definition, symmetric with the transform it's correcting.
///
/// `pub(crate)`, not private (Phase E review, LOW, khoa, 2026-08-17):
/// `diff.rs`'s own image-rect-to-screen conversion has the identical
/// rounding-overhang exposure `image_point_to_screen` already closes here,
/// so it reuses this rather than growing a second copy.
pub(crate) fn clamp_into_capture_rect(p: hypr::Point, origin: hypr::Point, size: hypr::Size, scale: f64) -> hypr::Point {
    let screen_w = scale_div_round(size.w, scale);
    let screen_h = scale_div_round(size.h, scale);
    let max_x = origin.x.saturating_add(screen_w).saturating_sub(1);
    let max_y = origin.y.saturating_add(screen_h).saturating_sub(1);
    hypr::Point {
        x: p.x.min(max_x).max(origin.x),
        y: p.y.min(max_y).max(origin.y),
    }
}

impl Sidecar {
    /// `--from-shot`'s coordinate conversion (Phase D): `(x, y)` are IMAGE
    /// pixels (device pixels, the same space [`Sidecar::size`] records) —
    /// bounds-checked against that recorded size FIRST (half-open, the same
    /// `[0, size)` convention [`super::point::point_in_bounds`] already uses
    /// for screen-space refusal), THEN the sidecar's `scale` is validated,
    /// and only then is [`transform_point`] applied: `screen = origin +
    /// image_px / scale`, identical semantics to `ocr::image_bbox_to_screen`.
    /// Refuses (never silently clamps or guesses) on either failure — a
    /// caller acting on an out-of-bounds or bad-scale coordinate is exactly
    /// the "caller acts on a lie" failure mode this codebase's review
    /// culture rules out elsewhere (this file's own clamp-announcement
    /// discipline, `ocr.rs`'s `scale_is_valid` doc).
    ///
    /// The transformed point is then pulled back inside the captured rect's
    /// own half-open interior via [`clamp_into_capture_rect`] — see that
    /// function's doc on why this is a distinct kind of clamp from the
    /// refusal above (correcting our own rounding, never a caller's claim).
    pub fn image_point_to_screen(&self, x: i64, y: i64) -> Result<hypr::Point, FromShotError> {
        if x < 0 || y < 0 || x >= self.size.w || y >= self.size.h {
            return Err(FromShotError::OutOfBounds { x, y, image_w: self.size.w, image_h: self.size.h });
        }
        if !scale_is_valid(self.scale) {
            return Err(FromShotError::BadScale { scale: self.scale });
        }
        let p = transform_point(self.origin, self.scale, x, y);
        Ok(clamp_into_capture_rect(p, self.origin, self.size, self.scale))
    }
}

/// Load `<capture>.json` for a COORDINATE-CONVERTING caller (`--from-shot`,
/// wired into `point.rs`'s move/click/drag/hover) — same
/// `dest.with_extension("json")` convention `screen ocr`/`screen send`
/// already use. HARD errors (never a soft degrade) on missing/corrupt,
/// reusing `screen ocr`'s own reason-code vocabulary exactly
/// (`sidecar-missing`/`sidecar-corrupt`): unlike `send.rs`'s OWN
/// module-private `read_sidecar` (which degrades those same two cases to a
/// soft `SidecarRead::Missing`/`Corrupt` because a send's sidecar
/// enrichment is optional), a coordinate transform's `origin`/`scale` are
/// load-bearing — there is no reasonable "proceed anyway" here, so this one
/// refuses, mirroring `ocr()`'s own inline sidecar read.
pub fn read_sidecar(image_path: &std::path::Path) -> Result<Sidecar, (&'static str, String)> {
    let sidecar_path = image_path.with_extension("json");
    let text = std::fs::read_to_string(&sidecar_path).map_err(|e| {
        ("sidecar-missing", format!("cannot read sidecar {}: {e}", sidecar_path.display()))
    })?;
    serde_json::from_str(&text)
        .map_err(|e| ("sidecar-corrupt", format!("sidecar {} is corrupt: {e}", sidecar_path.display())))
}

// ── Boundary 1: pixel acquisition ─────────────────────────────────────────

/// Everything [`capture_image`] needs to produce a file — already fully
/// decided by the caller (region clamped, format/quality/scale/destination
/// resolved). No grim-specific vocabulary crosses this boundary.
#[derive(Debug, Clone, PartialEq)]
pub struct CaptureRequest {
    pub region: hypr::Region,
    pub format: Format,
    pub quality: u8,
    pub scale: f64,
    /// `--cursor` (khoa, 2026-08-17, Phase D of the pointer-emulation
    /// workstream) — draw the composited cursor into the capture (grim
    /// `-c`). Opt-in, not the default: a composited cursor makes a PURE
    /// pointer move register as a pixel change to the upcoming screen-diff
    /// command, which would otherwise treat "nothing moved but the mouse" as
    /// "nothing changed."
    pub cursor: bool,
    pub dest: PathBuf,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CaptureError {
    /// The tool doing the capture couldn't even be spawned.
    Unavailable(String),
    /// It ran but refused (bad geometry, unwritable destination, …).
    Failed(String),
}

/// Pure `grim` argv assembly — unit-tested directly; the only function that
/// speaks grim's flag vocabulary. `-s` is ALWAYS passed explicitly, even at
/// the default scale (`1.0`): grim's own default (`-s` absent) is "the
/// greatest OUTPUT scale factor," i.e. it silently follows the MONITOR's own
/// Hyprland `scale` rather than guaranteeing 1:1 with the requested region.
/// Forcing `-s` makes [`CaptureRequest::scale`] the single source of truth
/// for the image/region pixel ratio regardless of monitor DPI — which is
/// what lets the sidecar's `scale` field promise "1.0 always means 1:1"
/// unconditionally (confirmed: this rig's one monitor is scale 1.00, so the
/// divergence isn't independently observable here — the reasoning is
/// structural, not measured on a HiDPI output).
fn grim_argv(req: &CaptureRequest) -> Vec<String> {
    let mut args = vec![
        "-g".to_string(),
        format!("{},{} {}x{}", req.region.x, req.region.y, req.region.w, req.region.h),
        "-t".to_string(),
        req.format.grim_type().to_string(),
    ];
    if req.format == Format::Jpeg {
        args.push("-q".to_string());
        args.push(req.quality.to_string());
    }
    if req.cursor {
        args.push("-c".to_string());
    }
    args.push("-s".to_string());
    args.push(format_scale(req.scale));
    args.push(req.dest.to_string_lossy().into_owned());
    args
}

/// `f64` → grim's `-s` argument text: whole-number scales print without a
/// decimal (`"1"`, not `"1.000000..."`); anything else uses `{}`'s default
/// (shortest round-tripping) formatting.
fn format_scale(scale: f64) -> String {
    if scale.fract() == 0.0 {
        format!("{}", scale as i64)
    } else {
        format!("{scale}")
    }
}

/// THE PIXEL-ACQUISITION BOUNDARY (khoa, 2026-08-16). Everything above this
/// function in the call chain decides WHAT to capture; this decides HOW.
/// Today: one `grim` shell-out. Judged the ordinary way (unlike
/// `song::ipc`'s quirky void-IPC case) — grim prints its error to stderr and
/// exits nonzero on failure, exit 0 means the file is written; no
/// output-vs-exit-code mismatch to guard against (confirmed live — see the
/// executor's report). NOT unit-tested itself (spawns a real process); the
/// pure [`grim_argv`] it delegates to is.
pub fn capture_image(req: &CaptureRequest) -> Result<(), CaptureError> {
    let argv = grim_argv(req);
    match std::process::Command::new("grim").args(&argv).output() {
        Err(e) => Err(CaptureError::Unavailable(e.to_string())),
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => {
            let said = String::from_utf8_lossy(&out.stderr);
            let said = said.trim();
            Err(CaptureError::Failed(if said.is_empty() {
                format!("grim exited {:?} with no message", out.status.code())
            } else {
                said.to_string()
            }))
        }
    }
}

// ── Boundary 2: human-attended region pick ────────────────────────────────

/// THE HUMAN-REGION-PICK BOUNDARY (khoa, 2026-08-16): "ask a human to drag a
/// region" without naming the mechanism to callers. Today: one `slurp`
/// shell-out, whose plain-text `"X,Y WxH\n"` stdout is the exact syntax
/// [`parse_region_literal`] already parses, so slurp's own output-parsing
/// correctness rides that function's existing test coverage.
///
/// `Ok(None)` is a CLEAN CANCEL (Esc, or any other reason slurp exits
/// nonzero — it does not distinguish "the human cancelled" from other
/// refusals at the process level, so neither do we) — never treated as an
/// error by a caller, just "no region chosen". `Err` means we couldn't even
/// ask (the binary missing, or it answered with something that doesn't
/// parse as a region).
///
/// **Not live-proven by this phase** (khoa's brief, explicit): slurp blocks
/// on an actual human drag; nothing here can simulate that non-interactively
/// without either hanging the run or faking the very interaction being
/// tested. Exercised only via [`parse_region_literal`]'s own unit tests.
pub fn pick_region() -> Result<Option<hypr::Region>, String> {
    let out = std::process::Command::new("slurp")
        .output()
        .map_err(|e| format!("slurp unavailable: {e}"))?;
    if !out.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let text = text.trim();
    match parse_region_literal(text) {
        Some((x, y, w, h)) => Ok(Some(hypr::Region { x, y, w, h })),
        None => Err(format!("slurp produced unparseable output: `{text}`")),
    }
}

// ── The capture-to-sidecar tail (khoa, 2026-08-17, Phase E of the
// pointer-emulation workstream) ─────────────────────────────────────────────
//
// Extracted from `shot()`'s own tail so `screen diff`'s after-capture (which
// re-shoots the IDENTICAL rect/scale/format/quality a `screen shot` sidecar
// already recorded) routes through the exact same desktop-snapshot hoisting
// (Phase D review, L4 — unchanged here), `capture_image` call, and sidecar
// assembly as any ordinary `screen shot` — never a second, forked capture
// pipeline. `shot()` itself is rewritten below to call this too, so there is
// exactly one place that turns "a resolved region + format/quality/scale" into
// "a file on disk plus its sidecar."

/// What [`write_capture`] produces on success — everything a caller needs to
/// build its OWN `Outcome` (the message wording differs between `shot()` and
/// `diff()`; the mechanical steps behind it do not).
pub(crate) struct WrittenCapture {
    pub sidecar: Sidecar,
    pub bytes: u64,
    /// `hypr::desktop_snapshot()`'s own degrade note, if that hyprctl call
    /// failed — `None` on a healthy snapshot. Mirrors `shot()`'s prior
    /// inline handling exactly; a caller folds this into its own outcome
    /// message the same way `shot()` always did.
    pub desktop_note: Option<String>,
}

/// Why [`write_capture`] failed — each variant carries what its caller needs
/// to build a matching `Outcome`. Split the same way `shot()`'s own two
/// failure points already were before this extraction: the pixel acquisition
/// itself (`reason`/`detail`, backend-agnostic — see [`capture_image`]'s own
/// doc), or the sidecar write AFTER a real image already landed on disk
/// (`detail` only — the caller already knows the reason is
/// `sidecar-write-failed` and which `dest` succeeded).
pub(crate) enum WriteCaptureError {
    Capture { reason: &'static str, detail: String },
    Sidecar { detail: String },
}

/// THE CAPTURE-TO-SIDECAR TAIL. Takes already-fully-resolved geometry/format/
/// quality/scale/cursor plus whatever identity (`target`) and `comment` the
/// caller wants recorded in the sidecar — both empty/`None` for `diff()`'s
/// recapture is fine, `target`/`comment` are purely descriptive and never
/// feed the capture itself. Gathers the desktop snapshot BEFORE spawning the
/// capture (Phase D review, L4 — capturing takes real time, and the
/// snapshot must describe the desktop AS OF the capture, not a beat later),
/// then calls [`capture_image`], then assembles and `atomic_write`s the
/// sidecar. NOT unit-tested itself (spawns a real process via
/// `capture_image`) — same split every other real I/O boundary in this file
/// already draws.
pub(crate) fn write_capture(
    region: hypr::Region,
    format: Format,
    quality: u8,
    scale: f64,
    cursor: bool,
    dest: &std::path::Path,
    target: CaptureTarget,
    comment: Option<String>,
) -> Result<WrittenCapture, WriteCaptureError> {
    let (desktop, desktop_note) = match hypr::desktop_snapshot() {
        Ok(d) => (Some(d), None),
        Err(e) => (None, Some(format!("desktop snapshot unavailable ({}: {})", e.reason(), e.detail()))),
    };

    let req = CaptureRequest { region, format, quality, scale, cursor, dest: dest.to_path_buf() };
    if let Err(e) = capture_image(&req) {
        let (reason, detail) = match &e {
            CaptureError::Unavailable(s) => ("capture-unavailable", s.clone()),
            CaptureError::Failed(s) => ("capture-failed", s.clone()),
        };
        return Err(WriteCaptureError::Capture { reason, detail });
    }

    let bytes = std::fs::metadata(dest).map(|m| m.len()).unwrap_or(0);
    let (img_w, img_h) = expected_image_size(region, scale);

    let sidecar = Sidecar {
        schema_version: SIDECAR_SCHEMA_VERSION.to_string(),
        captured_at: aoide_storage::time::now_iso_utc(),
        origin: hypr::Point { x: region.x, y: region.y },
        size: hypr::Size { w: img_w, h: img_h },
        scale,
        region: Some(region),
        format: format.label().to_string(),
        quality,
        monitor: target.monitor,
        session: target.session,
        window: target.window,
        class: target.class,
        title: target.title,
        comment,
        cursor_drawn: cursor.then_some(true),
        desktop,
        ocr: None,
        diff: None,
    };
    let sidecar_path = dest.with_extension("json");
    let sidecar_text = serde_json::to_string_pretty(&sidecar).unwrap_or_default() + "\n";
    if let Err(e) = aoide_storage::fs::atomic_write(&sidecar_path, &sidecar_text) {
        return Err(WriteCaptureError::Sidecar { detail: e.to_string() });
    }

    Ok(WrittenCapture { sidecar, bytes, desktop_note })
}

// ── `aoide screen shot` ───────────────────────────────────────────────────

/// `aoide screen shot [--output <name> | --region "X,Y WxH" | --pick]
/// [--format png|jpeg] [--quality N] [--scale F] [--out PATH] [--comment
/// "text"]` — capture via the [`capture_image`] boundary, write the sidecar.
///
/// **Divergence from the brief's literal `-o PATH`**: aoide's CLI parser
/// (`crates/cli/src/cli.rs::parse`) only recognises `--long` flags (plus the
/// special-cased `--help`/`-h`) — there is no general single-dash short-flag
/// support to hang a bare `-o` off. Also, `--output` is already spoken for
/// (monitor selection, this same brief). Used `--out <PATH>` instead: a
/// distinct long name, no collision, same intent.
pub fn shot(inv: &Invocation) -> Outcome {
    let cmd = "screen.shot";

    let has_output = inv.flags.contains_key("output");
    let has_region = inv.flags.contains_key("region");
    let has_pick = inv.flag_present("pick");
    let has_window = inv.flags.contains_key("window");
    let has_session = inv.flags.contains_key("session");
    let source = match resolve_region_source(has_output, has_region, has_pick, has_window, has_session) {
        Ok(s) => s,
        Err(msg) => return Outcome::usage(cmd, msg),
    };
    // Phase D: resolved EARLY too, same reasoning as the region source above
    // — a usage error here must be reachable without a live compositor.
    let scale_source = match resolve_scale_source(inv.flags.contains_key("scale"), inv.flags.contains_key("fit")) {
        Ok(s) => s,
        Err(msg) => return Outcome::usage(cmd, msg),
    };

    let monitors = match hypr::monitors() {
        Ok(m) => m,
        Err(e) => return hypr::hypr_error_outcome(cmd, &e),
    };
    let Some(bounds) = hypr::layout_bounds(&monitors) else {
        return Outcome::error(cmd, "hyprctl reported no monitors")
            .with_data(json!({ "reason": "no-monitors" }));
    };

    let (requested, target) = match source {
        RegionSource::Full => (bounds, CaptureTarget::default()),
        RegionSource::Output => {
            let name = inv.flags.get("output").cloned().unwrap_or_default();
            match monitor_region(&monitors, &name) {
                Some(r) => (r, CaptureTarget { monitor: Some(name), ..Default::default() }),
                None => {
                    let known: Vec<&str> = monitors.iter().map(|m| m.name.as_str()).collect();
                    return Outcome::usage(
                        cmd,
                        format!("unknown --output `{name}` (known: {})", known.join(", ")),
                    );
                }
            }
        }
        RegionSource::Region => {
            let spec = inv.flags.get("region").cloned().unwrap_or_default();
            match parse_region_literal(&spec) {
                Some((x, y, w, h)) => (hypr::Region { x, y, w, h }, CaptureTarget::default()),
                None => {
                    return Outcome::usage(
                        cmd,
                        format!("malformed --region `{spec}` (want \"X,Y WxH\")"),
                    )
                }
            }
        }
        RegionSource::Pick => match pick_region() {
            Ok(Some(r)) => (r, CaptureTarget::default()),
            // A human pressing Esc is not a command failure — mirrors
            // `song::ipc`'s own precedent (`NotRunning` folds into a normal
            // Ok outcome, "never propagate as a hard error"). `changed`
            // stays empty (nothing was captured), so an agent reads "no
            // error, nothing happened" rather than a failure to handle
            // (khoa's Phase 1 review, P1).
            Ok(None) => {
                return Outcome::ok(cmd, "--pick: cancelled — no region chosen, nothing captured")
                    .with_data(json!({ "reason": "pick-cancelled" }))
            }
            Err(e) => {
                return Outcome::error(cmd, format!("--pick: {e}"))
                    .with_data(json!({ "reason": "pick-failed" }))
            }
        },
        // ── Phase 4: --window/--session — resolve to a live hypr::Client,
        // then fall into the EXACT SAME clamp/capture/sidecar path below as
        // every other source (no forked capture path).
        RegionSource::Window => {
            let addr = inv.flags.get("window").cloned().unwrap_or_default();
            let clients = match hypr::all_clients() {
                Ok(c) => c,
                Err(e) => return hypr::hypr_error_outcome(cmd, &e),
            };
            match find_window(&clients, &addr) {
                Some(c) => (
                    client_rect(c),
                    CaptureTarget {
                        window: Some(c.address.clone()),
                        class: Some(c.class.clone()),
                        title: Some(c.title.clone()),
                        ..Default::default()
                    },
                ),
                None => {
                    return Outcome::error(cmd, format!("no window with address `{addr}`"))
                        .with_data(json!({ "reason": "window-not-found", "window": addr }));
                }
            }
        }
        RegionSource::Session => {
            let id = inv.flags.get("session").cloned().unwrap_or_default();
            let store: aoide_conduct::graph::SessionsFile =
                match aoide_conduct::graph::load_stage(&aoide_conduct::graph::sessions_path()) {
                    Ok(f) => f,
                    Err(e) => {
                        return Outcome::error(cmd, format!("could not read session store: {e}"))
                            .with_data(json!({ "reason": "session-store-unreadable" }));
                    }
                };
            let clients = match hypr::all_clients() {
                Ok(c) => c,
                Err(e) => return hypr::hypr_error_outcome(cmd, &e),
            };
            match find_session_client(&store.sessions, &clients, &id) {
                Ok(c) => (
                    client_rect(c),
                    CaptureTarget {
                        session: Some(id),
                        window: Some(c.address.clone()),
                        class: Some(c.class.clone()),
                        title: Some(c.title.clone()),
                        ..Default::default()
                    },
                ),
                Err(SessionRegionError::SessionNotFound) => {
                    return Outcome::error(cmd, format!("unknown session `{id}`"))
                        .with_data(json!({ "reason": "session-not-found", "session": id }));
                }
                Err(SessionRegionError::SessionNoWindow) => {
                    return Outcome::error(
                        cmd,
                        format!("session `{id}` has no live window (its terminal may have closed)"),
                    )
                    .with_data(json!({ "reason": "session-no-window", "session": id }));
                }
            }
        }
    };

    let Some(resolved) = clamp_region(requested, bounds) else {
        return Outcome::usage(
            cmd,
            format!(
                "region {},{} {}x{} lies wholly outside the layout ({},{} {}x{})",
                requested.x, requested.y, requested.w, requested.h,
                bounds.x, bounds.y, bounds.w, bounds.h,
            ),
        );
    };

    let format = match inv.flags.get("format") {
        // Default PNG (khoa's Phase 1 review, Decision A — reverses the
        // original "jpeg is cheaper" call): vision-model cost is
        // resolution-bound, not format-bound, so "cheaper bytes" never
        // touched the stated goal; measured PNG SMALLER than jpeg q80 on
        // this rig's flat-UI desktop (324,450 vs 355,633 B, same
        // full-screen capture); and phase 3's OCR reads these same
        // captures, where jpeg's DCT artifacts hurt small-text
        // recognition — lossless-by-default hands that future consumer
        // clean input. `--format jpeg` remains for photographic/
        // wallpaper-heavy captures, where jpeg's real win lives. Not
        // content-adaptive on purpose: this workspace DOES carry an
        // image-decode dependency now (`image`, arrived with Phase E's
        // `screen diff`, khoa, 2026-08-17 — updated from this comment's
        // original "forbids" claim) but `capture.rs`'s own path
        // deliberately never decodes (`expected_image_size`'s doc,
        // `write_capture`'s header) — content-adaptive detection would mean
        // crossing that boundary just to guess a format, plus a heuristic
        // that can misfire — a fixed default + explicit override is simpler
        // and always correct.
        None => Format::Png,
        Some(s) => match Format::parse(s) {
            Some(f) => f,
            None => return Outcome::usage(cmd, format!("unsupported --format `{s}` (png|jpeg)")),
        },
    };
    let quality: u8 = match inv.flags.get("quality") {
        None => 80,
        Some(s) => match s.parse::<u8>() {
            Ok(q) if q <= 100 => q,
            _ => return Outcome::usage(cmd, format!("--quality must be 0-100, got `{s}`")),
        },
    };
    // `--fit`/`--scale`: mutually exclusive, resolved above (`scale_source`)
    // before any hyprctl call; here the WINNING flag's value is actually
    // parsed, now that `resolved.rect` (the real capture rectangle, post-
    // clamp) is known for `--fit`'s arithmetic to run against. `fit_used`
    // carries the requested `WxH` box through to the outcome message only
    // when `--fit` won; the sidecar's own `scale` field is what actually
    // records the result either way (this file's `--fit` doc).
    let mut fit_used: Option<(i64, i64)> = None;
    let scale: f64 = match scale_source {
        ScaleSource::Default => 1.0,
        ScaleSource::Scale => match inv.flags.get("scale") {
            None => 1.0,
            Some(s) => match s.parse::<f64>() {
                Ok(v) if v > 0.0 && v.is_finite() => v,
                _ => return Outcome::usage(cmd, format!("--scale must be a positive number, got `{s}`")),
            },
        },
        ScaleSource::Fit => {
            let spec = inv.flags.get("fit").cloned().unwrap_or_default();
            let Some((fw, fh)) = parse_size_literal(&spec) else {
                return Outcome::usage(cmd, format!("malformed --fit `{spec}` (want \"WxH\")"));
            };
            if fw <= 0 || fh <= 0 {
                return Outcome::usage(
                    cmd,
                    format!("--fit `{spec}` must have a positive width and height"),
                );
            }
            let fs = fit_scale(resolved.rect, fw, fh);
            fit_used = Some((fw, fh));
            fs
        }
    };
    // Phase D review nit, folded in as Phase E cleanup: an extreme-aspect
    // region into a tiny/extreme-aspect box (or a pathologically tiny
    // explicit `--scale`) can round ONE axis of the resulting image down to
    // 0px (e.g. `--fit 100x100` on a 1920x1 region: width ratio 100/1920 is
    // the binding constraint, so the 1px-tall height scales to `round(1 *
    // 0.052) == 0`) — a degenerate image no `--from-shot` coordinate could
    // ever land in. Refused here, below BOTH scale-source branches (see
    // `min_size_error`'s own doc for why this moved out of the `Fit` arm
    // alone), before anything is captured, rather than silently writing an
    // unusable image.
    if let Some((ew, eh)) = min_size_error(resolved.rect, scale) {
        // Echo the FLAG that actually produced this scale (Phase E review,
        // NIT, khoa, 2026-08-17): `--fit`'s own `WxH` reads more usefully
        // than the scale factor it derived, and either way a caller
        // shouldn't have to reverse-engineer which of the two mutually
        // exclusive flags (`resolve_scale_source` above) was in play.
        let flag_desc = match fit_used {
            Some((fw, fh)) => format!("--fit {fw}x{fh}"),
            None => format!("--scale {scale}"),
        };
        return Outcome::usage(
            cmd,
            format!(
                "{flag_desc} would round the captured image down to {ew}x{eh}px — too small on at least one axis"
            ),
        );
    }
    let has_cursor = inv.flag_present("cursor");
    let comment = inv.flags.get("comment").cloned();

    let dest = match inv.flags.get("out") {
        Some(p) => PathBuf::from(p),
        None => aoide_storage::fs::captures_dir().join(auto_name(
            unix_ts(),
            std::process::id(),
            next_auto_name_seq(),
            format,
        )),
    };
    // The sidecar lands at `dest.with_extension("json")` — computed and
    // validated HERE, before any work happens, not after the capture: an
    // explicit `--out foo.json` would otherwise resolve to the SAME path as
    // its own sidecar, so the later atomic_write of the sidecar would
    // silently overwrite the just-captured image with sidecar text — a
    // false-success `Outcome::ok` reporting a path that no longer contains
    // the image (khoa's Phase 1 review, D1: caught before landing, not a
    // live incident).
    if sidecar_collides_with_dest(&dest) {
        return Outcome::usage(
            cmd,
            "--out must not end in .json — it collides with the capture's own sidecar path",
        );
    }
    let sidecar_path = dest.with_extension("json");
    if let Some(parent) = dest.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return Outcome::error(cmd, format!("cannot create {}: {e}", parent.display()))
                .with_data(json!({ "reason": "dest-dir-unwritable" }));
        }
    }

    // Desktop-snapshot hoisting (Phase D review, L4), the capture_image
    // spawn, and the sidecar assembly/write all now live in `write_capture`
    // (this file's own section header above `shot()`) — `diff()`'s
    // after-capture routes through the exact same tail, never a forked
    // pipeline.
    let written = match write_capture(resolved.rect, format, quality, scale, has_cursor, &dest, target, comment) {
        Ok(w) => w,
        Err(WriteCaptureError::Capture { reason, detail }) => {
            // Reason codes stay backend-agnostic ("capture-*", not "grim-*")
            // — this file's own header promises "a caller never learns
            // which tool did the work," and that promise has to hold at the
            // door-facing JSON layer too, not just in the Rust types
            // (khoa's Phase 1 review, D2). The DETAIL string is whatever the
            // backend actually said (grim's stderr, or the OS spawn error)
            // — genuinely useful troubleshooting text, not an identity
            // leak; the machine-checkable surface an agent branches on is
            // `data.reason`, and that stays agnostic.
            return Outcome::error(cmd, format!("{reason}: {detail}"))
                .with_data(json!({ "reason": reason }));
        }
        Err(WriteCaptureError::Sidecar { detail }) => {
            // The image is already on disk and real (capture_image
            // succeeded) — report it in `changed` even though the SIDECAR
            // write is what failed, so an agent tracking changed files
            // doesn't lose track of the capture that DID land (khoa's Phase
            // 1 review, P3).
            return Outcome::error(cmd, format!("captured but failed to write sidecar: {detail}"))
                .changed(vec![dest.to_string_lossy().into_owned()])
                .with_data(json!({
                    "reason": "sidecar-write-failed",
                    "path": dest.to_string_lossy(),
                }));
        }
    };
    let bytes = written.bytes;
    let (img_w, img_h) = (written.sidecar.size.w, written.sidecar.size.h);
    // Machine-checkable, not just message-text (khoa's Phase D review, L3 —
    // mirrors `clamped`'s own precedent below: a silent adjustment/degrade
    // gets a `data` key an agent can branch on, not only prose in `message`
    // a human has to parse).
    let desktop_present = written.sidecar.desktop.is_some();

    let mut message = format!(
        "captured {img_w}x{img_h} ({}) to {} — sidecar {}",
        format.label(),
        dest.display(),
        sidecar_path.display()
    );
    if let Some(from) = resolved.clamped_from {
        message.push_str(&format!(
            "; clamped from requested {},{} {}x{}",
            from.x, from.y, from.w, from.h
        ));
    }
    // Phase D review, L2: the two clauses below are INDEPENDENT, not an
    // either/or — `--fit` is exactly where a non-1.0 scale is NORMAL (the
    // whole point of the flag), so the "not 1:1" warning must fire there
    // too, not only on an explicit `--scale`. Losing it on the `--fit` path
    // dropped the warning precisely where a caller is most likely to read
    // image-space distances and forget to divide.
    if let Some((fw, fh)) = fit_used {
        message.push_str(&format!("; fit {fw}x{fh} -> scale {scale}"));
    }
    if scale != 1.0 {
        message.push_str(&format!(
            "; scale {scale}x — pixel distances in the image are NOT 1:1 with the screen"
        ));
    }
    if let Some(note) = &written.desktop_note {
        message.push_str(&format!("; {note}"));
    }

    Outcome::ok(cmd, message)
        .changed(vec![dest.to_string_lossy().into_owned()])
        .with_data(json!({
            "path": dest.to_string_lossy(),
            "sidecarPath": sidecar_path.to_string_lossy(),
            "origin": { "x": resolved.rect.x, "y": resolved.rect.y },
            "size": { "w": img_w, "h": img_h },
            "regionRequested": {
                "x": requested.x, "y": requested.y, "w": requested.w, "h": requested.h
            },
            "clamped": resolved.clamped_from.is_some(),
            "format": format.label(),
            "quality": quality,
            "scale": scale,
            "bytes": bytes,
            "desktop": desktop_present,
        }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Format ──────────────────────────────────────────────────────────

    #[test]
    fn format_parses_known_spellings_and_rejects_unknown() {
        assert_eq!(Format::parse("png"), Some(Format::Png));
        assert_eq!(Format::parse("jpeg"), Some(Format::Jpeg));
        assert_eq!(Format::parse("jpg"), Some(Format::Jpeg));
        assert_eq!(Format::parse("webp"), None);
        assert_eq!(Format::parse(""), None);
    }

    // ── region source ───────────────────────────────────────────────────

    #[test]
    fn region_source_defaults_to_full_when_nothing_given() {
        assert_eq!(resolve_region_source(false, false, false, false, false), Ok(RegionSource::Full));
    }

    #[test]
    fn region_source_picks_the_one_flag_given() {
        assert_eq!(resolve_region_source(true, false, false, false, false), Ok(RegionSource::Output));
        assert_eq!(resolve_region_source(false, true, false, false, false), Ok(RegionSource::Region));
        assert_eq!(resolve_region_source(false, false, true, false, false), Ok(RegionSource::Pick));
        assert_eq!(resolve_region_source(false, false, false, true, false), Ok(RegionSource::Window));
        assert_eq!(resolve_region_source(false, false, false, false, true), Ok(RegionSource::Session));
    }

    #[test]
    fn region_source_rejects_any_combination_of_two_or_more() {
        // Every one of the C(5,2) = 10 pairs, each in isolation.
        let names = ["output", "region", "pick", "window", "session"];
        for i in 0..5 {
            for j in (i + 1)..5 {
                let mut flags = [false; 5];
                flags[i] = true;
                flags[j] = true;
                assert!(
                    resolve_region_source(flags[0], flags[1], flags[2], flags[3], flags[4]).is_err(),
                    "expected --{} + --{} to be rejected",
                    names[i],
                    names[j]
                );
            }
        }
        // A couple of higher-arity combinations too, for good measure.
        assert!(resolve_region_source(true, true, false, false, false).is_err());
        assert!(resolve_region_source(true, true, true, true, true).is_err());
    }

    // ── region literal parsing (good/bad) ───────────────────────────────

    #[test]
    fn parses_the_canonical_region_syntax() {
        assert_eq!(parse_region_literal("100,200 300x400"), Some((100, 200, 300, 400)));
    }

    #[test]
    fn parses_negative_origin_for_a_monitor_left_of_the_primary() {
        assert_eq!(parse_region_literal("-1920,0 1920x1080"), Some((-1920, 0, 1920, 1080)));
    }

    #[test]
    fn tolerates_incidental_whitespace() {
        assert_eq!(parse_region_literal("  10,20 30x40  "), Some((10, 20, 30, 40)));
    }

    #[test]
    fn rejects_missing_comma() {
        assert_eq!(parse_region_literal("10 20 30x40"), None);
    }

    #[test]
    fn rejects_missing_x_separator() {
        assert_eq!(parse_region_literal("10,20 30,40"), None);
    }

    #[test]
    fn rejects_non_numeric_fields() {
        assert_eq!(parse_region_literal("a,20 30x40"), None);
    }

    #[test]
    fn rejects_empty_string() {
        assert_eq!(parse_region_literal(""), None);
    }

    // ── Phase D: parse_size_literal ("WxH", --fit's syntax) ─────────────

    #[test]
    fn parse_size_literal_parses_good_input() {
        assert_eq!(parse_size_literal("1280x800"), Some((1280, 800)));
        assert_eq!(parse_size_literal("  100x200  "), Some((100, 200)), "tolerates incidental whitespace");
    }

    #[test]
    fn parse_size_literal_rejects_junk() {
        assert_eq!(parse_size_literal(""), None);
        assert_eq!(parse_size_literal("1280"), None, "missing the x separator");
        assert_eq!(parse_size_literal("1280,800"), None, "comma is not the size separator");
        assert_eq!(parse_size_literal("ax800"), None, "non-numeric width");
        assert_eq!(parse_size_literal("1280xb"), None, "non-numeric height");
    }

    #[test]
    fn parse_size_literal_accepts_zero_the_caller_validates_positivity() {
        // Zero PARSES fine here — `parse_size_literal` is pure "does this
        // split into two integers," not a positivity check; `shot()`'s own
        // `--fit` handling refuses a non-positive box at the call site (see
        // `fit_scale`'s own doc).
        assert_eq!(parse_size_literal("0x0"), Some((0, 0)));
    }

    #[test]
    fn parse_region_literal_still_works_after_the_size_half_was_hoisted_out() {
        // Regression check for the parse_size_literal extraction: the
        // region literal's own good/bad cases above must be bit-for-bit
        // unaffected by routing its size half through the new shared fn.
        assert_eq!(parse_region_literal("100,200 300x400"), Some((100, 200, 300, 400)));
        assert_eq!(parse_region_literal("10,20 30,40"), None);
    }

    // ── Phase D: resolve_scale_source (--scale/--fit mutual exclusion) ──

    #[test]
    fn scale_source_defaults_when_neither_flag_given() {
        assert_eq!(resolve_scale_source(false, false), Ok(ScaleSource::Default));
    }

    #[test]
    fn scale_source_picks_whichever_one_flag_is_given() {
        assert_eq!(resolve_scale_source(true, false), Ok(ScaleSource::Scale));
        assert_eq!(resolve_scale_source(false, true), Ok(ScaleSource::Fit));
    }

    #[test]
    fn scale_source_rejects_both_flags_together() {
        assert!(resolve_scale_source(true, true).is_err());
    }

    // ── Phase D: fit_scale ────────────────────────────────────────────────

    #[test]
    fn fit_scale_is_exactly_one_on_an_exact_fit() {
        let region = hypr::Region { x: 0, y: 0, w: 1280, h: 800 };
        assert_eq!(fit_scale(region, 1280, 800), 1.0);
    }

    #[test]
    fn fit_scale_never_upscales_a_region_already_smaller_than_the_box() {
        let region = hypr::Region { x: 0, y: 0, w: 400, h: 300 };
        assert_eq!(fit_scale(region, 1280, 800), 1.0, "must not magnify past 1.0");
    }

    #[test]
    fn fit_scale_constrains_on_the_wide_axis_for_a_wide_region() {
        // 1920x1080 into a 1280x800 box: width ratio 1280/1920 = 0.6667,
        // height ratio 800/1080 = 0.7407 — width is the tighter constraint.
        let region = hypr::Region { x: 0, y: 0, w: 1920, h: 1080 };
        let got = fit_scale(region, 1280, 800);
        assert!((got - (1280.0 / 1920.0)).abs() < 1e-9, "{got}");
    }

    #[test]
    fn fit_scale_constrains_on_the_tall_axis_for_a_tall_region() {
        // A portrait-ish 1080x1920 region into the same 1280x800 box: height
        // ratio 800/1920 = 0.4167 is tighter than width ratio 1280/1080.
        let region = hypr::Region { x: 0, y: 0, w: 1080, h: 1920 };
        let got = fit_scale(region, 1280, 800);
        assert!((got - (800.0 / 1920.0)).abs() < 1e-9, "{got}");
    }

    #[test]
    fn fit_on_an_extreme_aspect_region_can_round_an_axis_to_zero_the_usage_error_this_guards() {
        // Phase D review nit: a 1920x1 region fit into a 100x100 box — width
        // is the binding constraint (100/1920 ~= 0.052), which rounds the
        // 1px-tall region's height down to 0 in the resulting image. This
        // pins the exact arithmetic `shot()`'s own `--fit` handling refuses
        // on before ever capturing (`shot()` itself isn't unit-tested — see
        // this file's header, it calls live hyprctl).
        let region = hypr::Region { x: 0, y: 0, w: 1920, h: 1 };
        let scale = fit_scale(region, 100, 100);
        let (w, h) = expected_image_size(region, scale);
        assert_eq!((w, h), (100, 0), "the height axis rounds to zero — exactly what shot() must refuse");
    }

    // ── Phase E: min_size_error — moved below the scale-source match so it
    // covers BOTH --fit and --scale (khoa's Phase D review cleanup) ────────

    #[test]
    fn min_size_error_flags_the_fit_style_degenerate_case() {
        // Same arithmetic as the --fit test just above, run through the
        // shared guard directly.
        let region = hypr::Region { x: 0, y: 0, w: 1920, h: 1 };
        let scale = fit_scale(region, 100, 100);
        assert_eq!(min_size_error(region, scale), Some((100, 0)));
    }

    #[test]
    fn min_size_error_flags_an_explicit_scale_that_was_never_reachable_via_fit() {
        // --scale never goes through fit_scale at all — this is the case
        // the guard's old Fit-only placement could not catch: a tiny
        // explicit --scale on an ordinary (non-extreme-aspect) region.
        let region = hypr::Region { x: 0, y: 0, w: 100, h: 100 };
        assert_eq!(min_size_error(region, 0.001), Some((0, 0)));
    }

    #[test]
    fn min_size_error_is_none_for_a_healthy_image() {
        let region = hypr::Region { x: 0, y: 0, w: 800, h: 600 };
        assert_eq!(min_size_error(region, 1.0), None);
        assert_eq!(min_size_error(region, 0.5), None);
    }

    // ── monitor_region ──────────────────────────────────────────────────

    fn test_monitor(name: &str, x: i64, y: i64, w: i64, h: i64) -> hypr::Monitor {
        hypr::Monitor {
            name: name.to_string(),
            origin: hypr::Point { x, y },
            size: hypr::Size { w, h },
            scale: 1.0,
            transform: 0,
            reserved: [0; 4],
            usable: hypr::Region { x, y, w, h },
        }
    }

    #[test]
    fn monitor_region_finds_by_exact_name() {
        let mons = vec![test_monitor("DP-1", 0, 0, 1920, 1080), test_monitor("HDMI-A-1", 1920, 0, 1280, 1024)];
        assert_eq!(monitor_region(&mons, "HDMI-A-1"), Some(hypr::Region { x: 1920, y: 0, w: 1280, h: 1024 }));
    }

    #[test]
    fn monitor_region_is_none_for_unknown_name() {
        let mons = vec![test_monitor("DP-1", 0, 0, 1920, 1080)];
        assert_eq!(monitor_region(&mons, "nope"), None);
    }

    // ── Phase 4: --window / --session resolvers ─────────────────────────
    // Fixtures mirror the real `hyprctl -j clients` shape captured live on
    // this rig 2026-08-16 (see hypr.rs's own CLIENTS_JSON) — a conduct-
    // wrapped shell (kitty, workspace 1), an unrelated firefox window
    // (workspace 2), and a second kitty (workspace 1, focused) sharing that
    // FIRST kitty's pid — the multi-window-per-pid tie-break case.

    fn test_client(address: &str, class: &str, title: &str, pid: i64, focused: bool, at: (i64, i64), size: (i64, i64)) -> hypr::Client {
        hypr::Client {
            address: address.to_string(),
            class: class.to_string(),
            title: title.to_string(),
            at: hypr::Point { x: at.0, y: at.1 },
            size: hypr::Size { w: size.0, h: size.1 },
            pid,
            focused,
        }
    }

    #[test]
    fn find_window_matches_by_exact_and_normalized_address() {
        let clients = vec![
            test_client("0x642da11d7380", "kitty", "~", 205999, false, (10, 46), (1900, 1024)),
            test_client("0x642da10af920", "firefox", "unrelated", 248080, true, (10, 46), (1900, 1024)),
        ];
        assert_eq!(find_window(&clients, "0x642da11d7380").map(|c| c.class.as_str()), Some("kitty"));
        // Case- and 0x-prefix-tolerant, mirroring graph::window's own matching.
        assert_eq!(find_window(&clients, "642DA11D7380").map(|c| c.class.as_str()), Some("kitty"));
        assert_eq!(find_window(&clients, "0X642DA10AF920").map(|c| c.class.as_str()), Some("firefox"));
    }

    #[test]
    fn find_window_is_none_for_an_unknown_address() {
        let clients = vec![test_client("0xaaa", "kitty", "t", 1, false, (0, 0), (100, 100))];
        assert_eq!(find_window(&clients, "0xdeadbeef"), None);
        assert_eq!(find_window(&[], "0xaaa"), None);
    }

    #[test]
    fn find_client_for_pid_returns_the_sole_match() {
        let clients = vec![
            test_client("0xaaa", "kitty", "t1", 42, false, (0, 0), (100, 100)),
            test_client("0xbbb", "firefox", "t2", 99, false, (0, 0), (100, 100)),
        ];
        assert_eq!(find_client_for_pid(&clients, 42).map(|c| c.address.as_str()), Some("0xaaa"));
    }

    #[test]
    fn find_client_for_pid_is_none_when_the_pid_owns_no_window() {
        let clients = vec![test_client("0xaaa", "kitty", "t", 42, false, (0, 0), (100, 100))];
        assert_eq!(find_client_for_pid(&clients, 999), None);
        assert_eq!(find_client_for_pid(&[], 42), None);
    }

    #[test]
    fn find_client_for_pid_prefers_the_focused_window_among_multiple_matches() {
        // Same pid owns two windows; the second is focused — the documented
        // tie-break picks it over the first-in-z-order one.
        let clients = vec![
            test_client("0xaaa", "kitty", "unfocused", 42, false, (0, 0), (100, 100)),
            test_client("0xbbb", "kitty", "focused", 42, true, (200, 200), (300, 300)),
        ];
        let c = find_client_for_pid(&clients, 42).unwrap();
        assert_eq!(c.address, "0xbbb");
        assert!(c.focused);
    }

    #[test]
    fn find_client_for_pid_falls_back_to_first_z_order_when_none_focused() {
        // Same pid owns two windows, NEITHER focused — the documented
        // tie-break falls back to the first in hyprctl's own list order.
        let clients = vec![
            test_client("0xaaa", "kitty", "first", 42, false, (0, 0), (100, 100)),
            test_client("0xbbb", "kitty", "second", 42, false, (200, 200), (300, 300)),
        ];
        let c = find_client_for_pid(&clients, 42).unwrap();
        assert_eq!(c.address, "0xaaa", "first in z-order wins when no match is focused");
    }

    fn test_session(id: &str, pid: Option<u32>, window_address: &str) -> aoide_conduct::graph::SessionRecord {
        aoide_conduct::graph::SessionRecord {
            session_id: id.to_string(),
            pid,
            window_address: window_address.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn find_session_client_is_not_found_for_an_unknown_id() {
        let clients = vec![test_client("0xaaa", "kitty", "t", 42, false, (0, 0), (100, 100))];
        let sessions = vec![test_session("known", Some(42), "0xaaa")];
        assert_eq!(
            find_session_client(&sessions, &clients, "unknown"),
            Err(SessionRegionError::SessionNotFound)
        );
    }

    #[test]
    fn find_session_client_is_no_window_when_the_record_has_neither_address_nor_pid() {
        // The shape a `sub:*` Task node actually carries: no windowAddress,
        // no pid (SessionRecord::default() for both).
        let clients = vec![test_client("0xaaa", "kitty", "t", 42, false, (0, 0), (100, 100))];
        let sessions = vec![test_session("sub:abc", None, "")];
        assert_eq!(
            find_session_client(&sessions, &clients, "sub:abc"),
            Err(SessionRegionError::SessionNoWindow)
        );
    }

    #[test]
    fn find_session_client_is_no_window_when_pid_matches_nothing_live() {
        let clients = vec![test_client("0xaaa", "kitty", "t", 42, false, (0, 0), (100, 100))];
        let sessions = vec![test_session("gone", Some(999), "")];
        assert_eq!(
            find_session_client(&sessions, &clients, "gone"),
            Err(SessionRegionError::SessionNoWindow)
        );
    }

    #[test]
    fn find_session_client_prefers_window_address_over_a_mismatched_pid() {
        // The real-rig shape this resolver exists for: a `conduct`-wrapped
        // session's stored pid is the WRAPPER's own pid (never a hyprctl
        // client), but its windowAddress is correctly resolved — reusing
        // find_window must succeed here even though a pid-only search
        // would report session-no-window.
        let clients = vec![test_client("0x642da14eaf80", "kitty", "agent", 2262, true, (10, 46), (942, 1024))];
        let sessions = vec![test_session("conduct-2284-1786818165", Some(2284), "0x642da14eaf80")];
        let c = find_session_client(&sessions, &clients, "conduct-2284-1786818165").unwrap();
        assert_eq!(c.address, "0x642da14eaf80");
        assert_eq!(c.pid, 2262, "resolved via windowAddress, not the mismatched stored pid");
    }

    #[test]
    fn find_session_client_falls_back_to_pid_when_window_address_is_stale_or_absent() {
        // windowAddress either empty, or pointing at a window that's since
        // closed — either way, fall through to the pid signal.
        let clients = vec![test_client("0xnew", "kitty", "t", 555, false, (0, 0), (100, 100))];
        let empty_addr = vec![test_session("s1", Some(555), "")];
        assert_eq!(find_session_client(&empty_addr, &clients, "s1").unwrap().address, "0xnew");

        let stale_addr = vec![test_session("s2", Some(555), "0xclosed-long-ago")];
        assert_eq!(find_session_client(&stale_addr, &clients, "s2").unwrap().address, "0xnew");
    }

    // ── clamp (good/bad/clamp cases) ────────────────────────────────────

    const LAYOUT: hypr::Region = hypr::Region { x: 0, y: 0, w: 1920, h: 1080 };

    #[test]
    fn a_fully_inbounds_region_is_unchanged_and_not_reported_clamped() {
        let r = hypr::Region { x: 100, y: 100, w: 200, h: 200 };
        let resolved = clamp_region(r, LAYOUT).unwrap();
        assert_eq!(resolved.rect, r);
        assert_eq!(resolved.clamped_from, None);
    }

    #[test]
    fn a_region_extending_past_the_right_edge_is_clamped_and_reported() {
        // Mirrors the brief's own proof case: request past 1920x1080.
        let r = hypr::Region { x: 1800, y: 0, w: 400, h: 1080 };
        let resolved = clamp_region(r, LAYOUT).unwrap();
        assert_eq!(resolved.rect, hypr::Region { x: 1800, y: 0, w: 120, h: 1080 });
        assert_eq!(resolved.clamped_from, Some(r));
    }

    #[test]
    fn a_region_extending_past_the_bottom_edge_is_clamped() {
        let r = hypr::Region { x: 0, y: 1000, w: 1920, h: 200 };
        let resolved = clamp_region(r, LAYOUT).unwrap();
        assert_eq!(resolved.rect, hypr::Region { x: 0, y: 1000, w: 1920, h: 80 });
    }

    #[test]
    fn a_region_with_negative_origin_is_clamped_on_the_left_and_top() {
        let r = hypr::Region { x: -50, y: -50, w: 200, h: 200 };
        let resolved = clamp_region(r, LAYOUT).unwrap();
        assert_eq!(resolved.rect, hypr::Region { x: 0, y: 0, w: 150, h: 150 });
        assert_eq!(resolved.clamped_from, Some(r));
    }

    #[test]
    fn a_region_wholly_outside_the_layout_is_none() {
        let r = hypr::Region { x: 5000, y: 5000, w: 100, h: 100 };
        assert_eq!(clamp_region(r, LAYOUT), None);
    }

    #[test]
    fn a_zero_area_region_is_none() {
        assert_eq!(clamp_region(hypr::Region { x: 0, y: 0, w: 0, h: 100 }, LAYOUT), None);
        assert_eq!(clamp_region(hypr::Region { x: 0, y: 0, w: 100, h: 0 }, LAYOUT), None);
    }

    #[test]
    fn the_full_layout_itself_clamps_to_itself_unreported() {
        let resolved = clamp_region(LAYOUT, LAYOUT).unwrap();
        assert_eq!(resolved.rect, LAYOUT);
        assert_eq!(resolved.clamped_from, None);
    }

    // ── D3: saturating arithmetic near the i64 extremes never panics, and
    // still gives the semantically right answer ─────────────────────────

    #[test]
    fn an_origin_at_i64_min_has_no_overlap_and_does_not_panic() {
        // `--region "-9223372036854775808,0 100x100"`: the interval
        // [i64::MIN, i64::MIN+100) doesn't overlap the layout at all — the
        // right answer is None (no capturable region), computed without
        // ever overflowing i64.
        let r = hypr::Region { x: i64::MIN, y: 0, w: 100, h: 100 };
        assert_eq!(clamp_region(r, LAYOUT), None);
    }

    #[test]
    fn a_width_of_i64_max_clamps_to_the_real_edge_distance_without_panicking() {
        // `--region "1,0 9223372036854775807x100"`: x + w overflows plain
        // i64 addition; the saturating version still clamps to exactly the
        // distance from x=1 to the layout's right edge (1920).
        let r = hypr::Region { x: 1, y: 0, w: i64::MAX, h: 100 };
        let resolved = clamp_region(r, LAYOUT).unwrap();
        assert_eq!(resolved.rect, hypr::Region { x: 1, y: 0, w: 1919, h: 100 });
        assert_eq!(resolved.clamped_from, Some(r));
    }

    #[test]
    fn a_height_of_i64_max_clamps_symmetrically_on_the_y_axis() {
        let r = hypr::Region { x: 0, y: 1, w: 100, h: i64::MAX };
        let resolved = clamp_region(r, LAYOUT).unwrap();
        assert_eq!(resolved.rect, hypr::Region { x: 0, y: 1, w: 100, h: 1079 });
    }

    #[test]
    fn an_origin_at_i64_max_has_no_overlap_and_does_not_panic() {
        let r = hypr::Region { x: i64::MAX, y: 0, w: 100, h: 100 };
        assert_eq!(clamp_region(r, LAYOUT), None);
    }

    // ── D1: the --out/.json sidecar-collision predicate ─────────────────

    #[test]
    fn sidecar_collision_flags_an_explicit_dot_json_destination() {
        assert!(sidecar_collides_with_dest(std::path::Path::new("/tmp/shot.json")));
        assert!(sidecar_collides_with_dest(std::path::Path::new("shot.json")));
    }

    #[test]
    fn sidecar_collision_is_false_for_ordinary_image_destinations() {
        assert!(!sidecar_collides_with_dest(std::path::Path::new("/tmp/shot.png")));
        assert!(!sidecar_collides_with_dest(std::path::Path::new("/tmp/shot.jpg")));
        assert!(!sidecar_collides_with_dest(std::path::Path::new("/tmp/shot")), "no extension at all");
    }

    // ── expected_image_size ─────────────────────────────────────────────

    #[test]
    fn expected_image_size_at_scale_one_is_the_region_itself() {
        assert_eq!(expected_image_size(hypr::Region { x: 0, y: 0, w: 800, h: 600 }, 1.0), (800, 600));
    }

    #[test]
    fn expected_image_size_scales_and_rounds() {
        assert_eq!(expected_image_size(hypr::Region { x: 0, y: 0, w: 100, h: 50 }, 2.0), (200, 100));
        assert_eq!(expected_image_size(hypr::Region { x: 0, y: 0, w: 3, h: 3 }, 0.5), (2, 2)); // 1.5 rounds to 2
    }

    // ── grim argv assembly (pure) ───────────────────────────────────────

    #[test]
    fn grim_argv_for_png_omits_quality_and_always_states_scale() {
        let req = CaptureRequest {
            region: hypr::Region { x: 10, y: 20, w: 300, h: 400 },
            format: Format::Png,
            quality: 80,
            scale: 1.0,
            cursor: false,
            dest: PathBuf::from("/tmp/out.png"),
        };
        assert_eq!(
            grim_argv(&req),
            vec!["-g", "10,20 300x400", "-t", "png", "-s", "1", "/tmp/out.png"]
        );
    }

    #[test]
    fn grim_argv_for_jpeg_includes_quality() {
        let req = CaptureRequest {
            region: hypr::Region { x: 0, y: 0, w: 1920, h: 1080 },
            format: Format::Jpeg,
            quality: 80,
            scale: 1.0,
            cursor: false,
            dest: PathBuf::from("/tmp/out.jpg"),
        };
        assert_eq!(
            grim_argv(&req),
            vec!["-g", "0,0 1920x1080", "-t", "jpeg", "-q", "80", "-s", "1", "/tmp/out.jpg"]
        );
    }

    #[test]
    fn grim_argv_states_a_fractional_scale_exactly() {
        let req = CaptureRequest {
            region: hypr::Region { x: 0, y: 0, w: 100, h: 100 },
            format: Format::Png,
            quality: 80,
            scale: 0.5,
            cursor: false,
            dest: PathBuf::from("/tmp/out.png"),
        };
        let args = grim_argv(&req);
        let s_idx = args.iter().position(|a| a == "-s").unwrap();
        assert_eq!(args[s_idx + 1], "0.5");
        assert_eq!(args.last().unwrap(), "/tmp/out.png", "dest is always the final argv entry");
    }

    // ── Phase D: --cursor / grim -c ──────────────────────────────────────

    #[test]
    fn grim_argv_omits_dash_c_when_cursor_is_false() {
        let req = CaptureRequest {
            region: hypr::Region { x: 0, y: 0, w: 100, h: 100 },
            format: Format::Png,
            quality: 80,
            scale: 1.0,
            cursor: false,
            dest: PathBuf::from("/tmp/out.png"),
        };
        assert!(!grim_argv(&req).contains(&"-c".to_string()));
    }

    #[test]
    fn grim_argv_includes_dash_c_when_cursor_is_true() {
        let req = CaptureRequest {
            region: hypr::Region { x: 0, y: 0, w: 100, h: 100 },
            format: Format::Png,
            quality: 80,
            scale: 1.0,
            cursor: true,
            dest: PathBuf::from("/tmp/out.png"),
        };
        let args = grim_argv(&req);
        assert!(args.contains(&"-c".to_string()));
        // -c sits before -s (format-related flags grouped, scale/dest last).
        let c_idx = args.iter().position(|a| a == "-c").unwrap();
        let s_idx = args.iter().position(|a| a == "-s").unwrap();
        assert!(c_idx < s_idx);
    }

    #[test]
    fn format_scale_trims_whole_numbers() {
        assert_eq!(format_scale(1.0), "1");
        assert_eq!(format_scale(2.0), "2");
        assert_eq!(format_scale(1.5), "1.5");
    }

    // ── auto_name ────────────────────────────────────────────────────────

    #[test]
    fn auto_name_embeds_timestamp_pid_seq_and_extension() {
        assert_eq!(auto_name(1_700_000_000, 4242, 0, Format::Jpeg), "screenshot-1700000000-4242-0.jpg");
        assert_eq!(auto_name(1_700_000_000, 4242, 0, Format::Png), "screenshot-1700000000-4242-0.png");
    }

    #[test]
    fn auto_name_differs_for_different_pids_at_the_same_second() {
        let a = auto_name(1_700_000_000, 1, 0, Format::Jpeg);
        let b = auto_name(1_700_000_000, 2, 0, Format::Jpeg);
        assert_ne!(a, b, "two concurrent captures in the same second must not collide");
    }

    #[test]
    fn auto_name_differs_for_different_seqs_at_the_same_second_and_pid() {
        // The case this field exists to close (Phase E review nit): the
        // SAME process, the SAME wall-clock second — `screen diff`'s own
        // before/after pair, or two `screen shot`s issued back to back.
        let a = auto_name(1_700_000_000, 4242, 0, Format::Png);
        let b = auto_name(1_700_000_000, 4242, 1, Format::Png);
        assert_ne!(a, b, "two captures from one process in one second must not collide");
    }

    #[test]
    fn next_auto_name_seq_is_monotonic_and_never_repeats() {
        let a = next_auto_name_seq();
        let b = next_auto_name_seq();
        let c = next_auto_name_seq();
        assert!(a < b, "{a} !< {b}");
        assert!(b < c, "{b} !< {c}");
    }

    // ── sidecar round-trip ───────────────────────────────────────────────

    #[test]
    fn sidecar_round_trips_through_json_with_ocr_null_and_present() {
        let sc = Sidecar {
            schema_version: SIDECAR_SCHEMA_VERSION.to_string(),
            captured_at: "2026-08-16T12:00:00Z".to_string(),
            origin: hypr::Point { x: 0, y: 0 },
            size: hypr::Size { w: 1920, h: 1080 },
            scale: 1.0,
            format: "jpeg".to_string(),
            quality: 80,
            monitor: Some("DP-1".to_string()),
            session: None,
            window: None,
            class: None,
            title: None,
            comment: Some("test capture".to_string()),
            cursor_drawn: None,
            desktop: None,
            ocr: None,
            diff: None,
            region: None,
        };
        let text = serde_json::to_string(&sc).unwrap();
        // `ocr` is present-and-null, never omitted (day-one placeholder for
        // phase 3 — the brief's explicit requirement).
        assert!(text.contains("\"ocr\":null"), "{text}");
        // `diff` (Phase E) is present-and-null too, the same day-one
        // placeholder convention `ocr` established.
        assert!(text.contains("\"diff\":null"), "{text}");
        // schemaVersion is a STRING ("0"), matching every other
        // schema-versioned shape in the codebase — NOT a bare number
        // (khoa's Phase 1 review, Decision B).
        assert!(text.contains("\"schemaVersion\":\"0\""), "{text}");
        assert!(text.contains("\"capturedAt\""));

        let back: Sidecar = serde_json::from_str(&text).unwrap();
        assert_eq!(back, sc);
    }

    // ── Phase E: `diff` field — null on new captures, round-trips
    // populated, and a pre-Phase-E sidecar (no `diff` key at all) still
    // parses (forward tolerance, the same convention `ocr` established) ──

    #[test]
    fn sidecar_diff_round_trips_when_populated() {
        let mut sc = test_sidecar_for_conversion(hypr::Point { x: 0, y: 0 }, hypr::Size { w: 100, h: 100 }, 1.0);
        sc.diff = Some(json!({
            "changed": true,
            "changedFraction": 0.125,
            "changedRect": { "x": 1, "y": 2, "w": 3, "h": 4 },
            "changedRectImage": { "x": 1, "y": 2, "w": 3, "h": 4 },
            "appeared": [],
            "disappeared": [],
            "retitled": [],
            "afterPath": "/tmp/after.png",
            "sidecarPath": "/tmp/after.json",
        }));
        let text = serde_json::to_string(&sc).unwrap();
        assert!(text.contains("\"changedFraction\":0.125"), "{text}");

        let back: Sidecar = serde_json::from_str(&text).unwrap();
        assert_eq!(back.diff, sc.diff);
    }

    #[test]
    fn a_pre_phase_e_sidecar_string_missing_diff_entirely_still_deserializes() {
        // The exact shape every sidecar written before Phase E has — no
        // `diff` key at all, not even `null`. `#[serde(default)]` (no
        // skip_serializing_if, mirroring `ocr`'s own forward-tolerance
        // convention) is what makes this parse.
        let text = r#"{"schemaVersion":"0","capturedAt":"2026-08-16T12:00:00Z",
            "origin":{"x":0,"y":0},"size":{"w":10,"h":10},"scale":1.0,
            "format":"png","quality":80}"#;
        let sc: Sidecar = serde_json::from_str(text).unwrap();
        assert_eq!(sc.diff, None);
    }

    #[test]
    fn sidecar_omits_absent_monitor_and_comment_but_not_ocr() {
        let sc = Sidecar {
            schema_version: SIDECAR_SCHEMA_VERSION.to_string(),
            captured_at: "2026-08-16T12:00:00Z".to_string(),
            origin: hypr::Point { x: 0, y: 0 },
            size: hypr::Size { w: 100, h: 100 },
            scale: 1.0,
            format: "png".to_string(),
            quality: 80,
            monitor: None,
            session: None,
            window: None,
            class: None,
            title: None,
            comment: None,
            cursor_drawn: None,
            desktop: None,
            ocr: None,
            diff: None,
            region: None,
        };
        let text = serde_json::to_string(&sc).unwrap();
        assert!(!text.contains("monitor"), "{text}");
        assert!(!text.contains("comment"), "{text}");
        assert!(!text.contains("\"session\""), "{text}");
        assert!(!text.contains("\"window\""), "{text}");
        assert!(!text.contains("\"class\""), "{text}");
        assert!(!text.contains("\"title\""), "{text}");
        assert!(!text.contains("cursorDrawn"), "{text}");
        assert!(!text.contains("\"desktop\""), "{text}");
        assert!(text.contains("\"ocr\":null"), "{text}");
        assert!(text.contains("\"diff\":null"), "{text}");
        // `region` (Phase E review, B1) is omitted-when-absent, like
        // `monitor`/`comment` — NOT present-and-null like `ocr`/`diff`: a
        // pre-Phase-E sidecar never had one at all, and there's no
        // meaningful "known to be absent" placeholder for a geometry field
        // the way `null` works for a not-yet-run OCR/diff pass.
        assert!(!text.contains("\"region\""), "{text}");
    }

    // ── Phase E review, B1: `region` field — omitted when absent (pre-
    // Phase-E sidecars, or `Sidecar` literals built without it), round-trips
    // exactly when populated, and a pre-Phase-E JSON string with no `region`
    // key at all still deserializes (forward tolerance) ───────────────────

    #[test]
    fn sidecar_region_round_trips_when_populated() {
        let mut sc =
            test_sidecar_for_conversion(hypr::Point { x: 10, y: 20 }, hypr::Size { w: 501, h: 100 }, 0.5);
        sc.region = Some(hypr::Region { x: 10, y: 20, w: 1001, h: 200 });
        let text = serde_json::to_string(&sc).unwrap();
        assert!(text.contains("\"region\":{\"x\":10,\"y\":20,\"w\":1001,\"h\":200}"), "{text}");

        let back: Sidecar = serde_json::from_str(&text).unwrap();
        assert_eq!(back.region, sc.region);
    }

    #[test]
    fn a_pre_phase_e_sidecar_string_missing_region_entirely_still_deserializes() {
        // The exact shape every sidecar written before Phase E's B1 fix has
        // — no `region` key at all, not even `null`. `#[serde(default)]`
        // (mirroring `ocr`/`diff`'s own forward-tolerance convention) is
        // what makes this parse; `diff.rs`'s `recover_region` is what falls
        // back to the lossy division for exactly this case.
        let text = r#"{"schemaVersion":"0","capturedAt":"2026-08-16T12:00:00Z",
            "origin":{"x":0,"y":0},"size":{"w":10,"h":10},"scale":1.0,
            "format":"png","quality":80}"#;
        let sc: Sidecar = serde_json::from_str(text).unwrap();
        assert_eq!(sc.region, None);
    }

    // ── Phase 4: sidecar carries session/window/class/title when a
    // --session/--window capture produced it ───────────────────────────────

    #[test]
    fn sidecar_round_trips_session_and_window_target_fields() {
        let sc = Sidecar {
            schema_version: SIDECAR_SCHEMA_VERSION.to_string(),
            captured_at: "2026-08-16T12:00:00Z".to_string(),
            origin: hypr::Point { x: 10, y: 46 },
            size: hypr::Size { w: 942, h: 1024 },
            scale: 1.0,
            format: "png".to_string(),
            quality: 80,
            monitor: None,
            session: Some("conduct-2284-1786818165".to_string()),
            window: Some("0x642da14eaf80".to_string()),
            class: Some("kitty".to_string()),
            title: Some("agent window title".to_string()),
            comment: None,
            cursor_drawn: None,
            desktop: None,
            ocr: None,
            diff: None,
            region: None,
        };
        let text = serde_json::to_string(&sc).unwrap();
        assert!(text.contains("\"session\":\"conduct-2284-1786818165\""), "{text}");
        assert!(text.contains("\"window\":\"0x642da14eaf80\""), "{text}");
        assert!(text.contains("\"class\":\"kitty\""), "{text}");
        assert!(text.contains("\"title\":\"agent window title\""), "{text}");

        let back: Sidecar = serde_json::from_str(&text).unwrap();
        assert_eq!(back, sc);
    }

    #[test]
    fn sidecar_missing_the_new_phase_4_fields_still_parses_forward_tolerantly() {
        // A sidecar written before Phase 4 has none of session/window/class/
        // title — must still parse, defaulting all four to None.
        let text = r#"{"schemaVersion":"0","capturedAt":"2026-08-16T12:00:00Z",
            "origin":{"x":0,"y":0},"size":{"w":10,"h":10},"scale":1.0,
            "format":"png","quality":80}"#;
        let sc: Sidecar = serde_json::from_str(text).unwrap();
        assert_eq!(sc.session, None);
        assert_eq!(sc.window, None);
        assert_eq!(sc.class, None);
        assert_eq!(sc.title, None);
    }

    #[test]
    fn sidecar_deserializes_a_hand_written_doc_missing_ocr() {
        // Forward-tolerance: a sidecar written before `ocr` existed (or
        // hand-edited without it) still parses, defaulting to `None`.
        let text = r#"{"schemaVersion":"0","capturedAt":"2026-08-16T12:00:00Z",
            "origin":{"x":0,"y":0},"size":{"w":10,"h":10},"scale":1.0,
            "format":"png","quality":80}"#;
        let sc: Sidecar = serde_json::from_str(text).unwrap();
        assert_eq!(sc.ocr, None);
        assert_eq!(sc.monitor, None);
    }

    #[test]
    fn sidecar_schema_version_defaults_to_empty_string_when_the_key_is_absent() {
        // The `default` half of `#[serde(rename = "schemaVersion", default)]`
        // — mirrors `aoide_storage::records`' forgiving pattern (a legacy or
        // hand-edited doc missing the key entirely still parses).
        let text = r#"{"capturedAt":"2026-08-16T12:00:00Z",
            "origin":{"x":0,"y":0},"size":{"w":10,"h":10},"scale":1.0,
            "format":"png","quality":80}"#;
        let sc: Sidecar = serde_json::from_str(text).unwrap();
        assert_eq!(sc.schema_version, "");
    }

    // ── Phase D: sidecar round-trip WITH desktop + cursorDrawn, and WITHOUT
    // both (a Phase-4-era sidecar string must still deserialize) ─────────

    fn test_desktop_snapshot() -> hypr::DesktopSnapshot {
        hypr::DesktopSnapshot {
            cursor: hypr::Point { x: 640, y: 400 },
            clients: vec![hypr::Client {
                address: "0xabc".to_string(),
                class: "kitty".to_string(),
                title: "agent".to_string(),
                at: hypr::Point { x: 10, y: 46 },
                size: hypr::Size { w: 942, h: 1024 },
                pid: 5703,
                focused: true,
            }],
            layers: vec![hypr::Layer {
                monitor: "DP-1".to_string(),
                level: 2,
                namespace: "aoide-bar".to_string(),
                at: hypr::Point { x: 0, y: 0 },
                size: hypr::Size { w: 1920, h: 36 },
            }],
        }
    }

    #[test]
    fn sidecar_round_trips_with_cursor_drawn_and_desktop_present() {
        let sc = Sidecar {
            schema_version: SIDECAR_SCHEMA_VERSION.to_string(),
            captured_at: "2026-08-17T00:00:00Z".to_string(),
            origin: hypr::Point { x: 0, y: 0 },
            size: hypr::Size { w: 1280, h: 800 },
            scale: 0.6667,
            format: "png".to_string(),
            quality: 80,
            monitor: None,
            session: None,
            window: None,
            class: None,
            title: None,
            comment: None,
            cursor_drawn: Some(true),
            desktop: Some(test_desktop_snapshot()),
            ocr: None,
            diff: None,
            region: None,
        };
        let text = serde_json::to_string(&sc).unwrap();
        assert!(text.contains("\"cursorDrawn\":true"), "{text}");
        assert!(text.contains("\"desktop\":"), "{text}");
        assert!(text.contains("\"cursor\":{\"x\":640,\"y\":400}"), "{text}");
        assert!(text.contains("\"aoide-bar\""), "{text}");

        let back: Sidecar = serde_json::from_str(&text).unwrap();
        assert_eq!(back, sc);
    }

    #[test]
    fn sidecar_omits_cursor_drawn_and_desktop_when_absent() {
        let sc = Sidecar {
            schema_version: SIDECAR_SCHEMA_VERSION.to_string(),
            captured_at: "2026-08-17T00:00:00Z".to_string(),
            origin: hypr::Point { x: 0, y: 0 },
            size: hypr::Size { w: 100, h: 100 },
            scale: 1.0,
            format: "png".to_string(),
            quality: 80,
            monitor: None,
            session: None,
            window: None,
            class: None,
            title: None,
            comment: None,
            cursor_drawn: None,
            desktop: None,
            ocr: None,
            diff: None,
            region: None,
        };
        let text = serde_json::to_string(&sc).unwrap();
        assert!(!text.contains("cursorDrawn"), "{text}");
        assert!(!text.contains("\"desktop\""), "{text}");
    }

    #[test]
    fn a_phase_4_era_sidecar_string_missing_cursor_drawn_and_desktop_still_deserializes() {
        // The exact shape a pre-Phase-D `screen shot` wrote — neither key
        // exists at all, not even as `null`. Forward tolerance is the whole
        // point of `#[serde(default, skip_serializing_if = "Option::is_none")]`.
        let text = r#"{"schemaVersion":"0","capturedAt":"2026-08-16T12:00:00Z",
            "origin":{"x":0,"y":0},"size":{"w":10,"h":10},"scale":1.0,
            "format":"png","quality":80}"#;
        let sc: Sidecar = serde_json::from_str(text).unwrap();
        assert_eq!(sc.cursor_drawn, None);
        assert_eq!(sc.desktop, None);
    }

    // ── Phase D: FromShotError / Sidecar::image_point_to_screen ─────────

    fn test_sidecar_for_conversion(origin: hypr::Point, size: hypr::Size, scale: f64) -> Sidecar {
        Sidecar {
            schema_version: SIDECAR_SCHEMA_VERSION.to_string(),
            captured_at: "2026-08-17T00:00:00Z".to_string(),
            origin,
            size,
            scale,
            format: "png".to_string(),
            quality: 80,
            monitor: None,
            session: None,
            window: None,
            class: None,
            title: None,
            comment: None,
            cursor_drawn: None,
            desktop: None,
            ocr: None,
            diff: None,
            region: None,
        }
    }

    #[test]
    fn image_point_to_screen_at_scale_one_is_origin_plus_image_px() {
        let sc = test_sidecar_for_conversion(
            hypr::Point { x: 100, y: 50 },
            hypr::Size { w: 500, h: 400 },
            1.0,
        );
        assert_eq!(sc.image_point_to_screen(20, 10), Ok(hypr::Point { x: 120, y: 60 }));
    }

    #[test]
    fn image_point_to_screen_at_scale_half_doubles_the_image_offset() {
        // screen = origin + image_px / scale — at scale 0.5, image_px / 0.5
        // is DOUBLE image_px. Values chosen so halving vs. doubling produce
        // different, distinguishable answers (proves the DIVISION direction,
        // not just that some arithmetic ran): image (40, 20) at scale 0.5
        // must land at origin + (80, 40), never origin + (20, 10).
        let sc = test_sidecar_for_conversion(
            hypr::Point { x: 100, y: 50 },
            hypr::Size { w: 500, h: 400 },
            0.5,
        );
        assert_eq!(sc.image_point_to_screen(40, 20), Ok(hypr::Point { x: 180, y: 90 }));
    }

    #[test]
    fn image_point_to_screen_refuses_out_of_bounds_at_the_image_edge() {
        // Half-open against the sidecar's DEVICE-pixel size, not logical:
        // size.w == 500 means x == 500 is already out (the last valid x is
        // 499), the same [0, size) convention point::point_in_bounds uses.
        let sc = test_sidecar_for_conversion(
            hypr::Point { x: 0, y: 0 },
            hypr::Size { w: 500, h: 400 },
            1.0,
        );
        assert_eq!(sc.image_point_to_screen(499, 399), Ok(hypr::Point { x: 499, y: 399 }), "the last valid pixel is in bounds");
        assert_eq!(
            sc.image_point_to_screen(500, 0),
            Err(FromShotError::OutOfBounds { x: 500, y: 0, image_w: 500, image_h: 400 })
        );
        assert_eq!(
            sc.image_point_to_screen(0, 400),
            Err(FromShotError::OutOfBounds { x: 0, y: 400, image_w: 500, image_h: 400 })
        );
        assert_eq!(
            sc.image_point_to_screen(-1, 0),
            Err(FromShotError::OutOfBounds { x: -1, y: 0, image_w: 500, image_h: 400 }),
            "negative is out of bounds too"
        );
    }

    #[test]
    fn image_point_to_screen_refuses_bad_scale() {
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let sc = test_sidecar_for_conversion(hypr::Point { x: 0, y: 0 }, hypr::Size { w: 100, h: 100 }, bad);
            match sc.image_point_to_screen(10, 10) {
                Err(FromShotError::BadScale { scale }) => {
                    assert!(scale == bad || (scale.is_nan() && bad.is_nan()), "expected {bad}, got {scale}");
                }
                other => panic!("expected BadScale({bad}), got {other:?}"),
            }
        }
    }

    #[test]
    fn image_point_to_screen_bounds_check_runs_before_the_scale_check() {
        // An out-of-bounds point on a sidecar with an ALSO-bad scale must
        // still report OutOfBounds — bounds first, per this file's brief.
        let sc = test_sidecar_for_conversion(hypr::Point { x: 0, y: 0 }, hypr::Size { w: 100, h: 100 }, -1.0);
        assert_eq!(
            sc.image_point_to_screen(500, 0),
            Err(FromShotError::OutOfBounds { x: 500, y: 0, image_w: 100, image_h: 100 })
        );
    }

    // ── Phase D review, L1: transform_point saturates instead of
    // overflowing on an extreme origin + a wild division ─────────────────

    #[test]
    fn transform_point_saturates_instead_of_panicking_on_extreme_origin_plus_wild_division() {
        // A subnormal scale (e.g. 1e-320) passes `scale_is_valid` (positive,
        // finite) yet `image_px / scale` overflows f64 to +/-infinity, so
        // `scale_div_round`'s own `as i64` cast already saturates that to
        // i64::MAX/MIN — but the SUBSEQUENT origin-add must not overflow
        // plain i64 addition on top of that. origin chosen near the i64
        // extremes to prove it's the ADD that needed fixing, not just the
        // division (which was already safe via the saturating cast).
        let got = transform_point(
            hypr::Point { x: i64::MAX - 10, y: i64::MIN + 10 },
            1e-320,
            100,
            -100,
        );
        assert_eq!(got, hypr::Point { x: i64::MAX, y: i64::MIN });
    }

    // ── Phase D review, L5: image_point_to_screen clamps into the capture
    // rect's own half-open interior — correcting OUR OWN rounding, not a
    // caller's out-of-range claim (see clamp_into_capture_rect's own doc on
    // the distinction from capture::clamp_region) ─────────────────────────

    #[test]
    fn image_point_to_screen_clamps_the_last_valid_pixel_inside_the_capture_rect_at_scale_two() {
        // Region 10x10 captured at scale 2.0 -> image size 20x20; the last
        // VALID image pixel is x=y=19 (half-open [0,20)). Without the
        // rect-interior clamp, scale_div_round(19, 2.0) rounds 9.5 UP to 10,
        // landing on origin+10 — the EXCLUSIVE edge of the reconstructed
        // 10px screen rect, one px past where the capture actually ends.
        let sc = test_sidecar_for_conversion(hypr::Point { x: 0, y: 0 }, hypr::Size { w: 20, h: 20 }, 2.0);
        assert_eq!(sc.image_point_to_screen(19, 19), Ok(hypr::Point { x: 9, y: 9 }));
    }

    #[test]
    fn image_point_to_screen_clamp_is_a_no_op_for_a_safely_interior_pixel() {
        let sc = test_sidecar_for_conversion(hypr::Point { x: 100, y: 50 }, hypr::Size { w: 20, h: 20 }, 2.0);
        // image (10,10): scale_div_round(10, 2.0) = 5, well inside the
        // reconstructed 10px rect — the clamp must not disturb this.
        assert_eq!(sc.image_point_to_screen(10, 10), Ok(hypr::Point { x: 105, y: 55 }));
    }

    #[test]
    fn image_point_to_screen_clamp_holds_the_lower_edge_at_origin_too() {
        // image (0,0) is the FIRST valid pixel — must land exactly at
        // origin, never clamped below it (the max() half of the clamp is
        // symmetric, even though only the upper edge is where rounding
        // overshoots in practice).
        let sc = test_sidecar_for_conversion(hypr::Point { x: 100, y: 50 }, hypr::Size { w: 20, h: 20 }, 2.0);
        assert_eq!(sc.image_point_to_screen(0, 0), Ok(hypr::Point { x: 100, y: 50 }));
    }

    // ── Phase D: read_sidecar (--from-shot's sidecar loader) — real temp
    // files, ok / missing / corrupt ───────────────────────────────────────

    fn tmp_capture_for_from_shot(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "aoide-screen-capture-from-shot-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        p.set_extension("png");
        p
    }

    #[test]
    fn read_sidecar_parses_a_real_sidecar_next_to_the_capture() {
        let capture = tmp_capture_for_from_shot("ok");
        std::fs::write(&capture, b"fake").unwrap();
        let sidecar_path = capture.with_extension("json");
        std::fs::write(
            &sidecar_path,
            r#"{"schemaVersion":"0","capturedAt":"2026-08-17T00:00:00Z",
               "origin":{"x":10,"y":20},"size":{"w":100,"h":100},"scale":1.0,
               "format":"png","quality":80}"#,
        )
        .unwrap();

        let sc = read_sidecar(&capture).unwrap();
        assert_eq!(sc.origin, hypr::Point { x: 10, y: 20 });

        let _ = std::fs::remove_file(&capture);
        let _ = std::fs::remove_file(&sidecar_path);
    }

    #[test]
    fn read_sidecar_reports_sidecar_missing_not_a_panic() {
        let capture = tmp_capture_for_from_shot("missing");
        std::fs::write(&capture, b"fake").unwrap();
        // Deliberately no sidecar written next to it.
        let (reason, _detail) = read_sidecar(&capture).unwrap_err();
        assert_eq!(reason, "sidecar-missing");
        let _ = std::fs::remove_file(&capture);
    }

    #[test]
    fn read_sidecar_reports_sidecar_corrupt_not_a_panic() {
        let capture = tmp_capture_for_from_shot("corrupt");
        std::fs::write(&capture, b"fake").unwrap();
        let sidecar_path = capture.with_extension("json");
        std::fs::write(&sidecar_path, b"{ not valid json").unwrap();

        let (reason, _detail) = read_sidecar(&capture).unwrap_err();
        assert_eq!(reason, "sidecar-corrupt");

        let _ = std::fs::remove_file(&capture);
        let _ = std::fs::remove_file(&sidecar_path);
    }

    // ── pick_region's parse path (the interactive spawn itself is NOT
    // live-proven here — see the module docs and the executor's report) ──

    #[test]
    fn slurp_style_output_parses_via_the_same_region_literal_parser() {
        // slurp's own stdout shape, "X,Y WxH\n" — confirming pick_region's
        // parse step (not the live spawn) is covered by existing tests.
        assert_eq!(parse_region_literal("100,100 300x200\n".trim()), Some((100, 100, 300, 200)));
    }
}
