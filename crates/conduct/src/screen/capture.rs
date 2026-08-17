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

/// Parse `--region`'s one accepted syntax: `"X,Y WxH"` (canonical form only —
/// a stricter subset of `tools/pointer.sh`'s several accepted spellings;
/// YAGNI, this phase's brief asks for one syntax). `None` on anything else,
/// which the caller turns into a usage error (exit 2).
pub fn parse_region_literal(spec: &str) -> Option<(i64, i64, i64, i64)> {
    let (pos, size) = spec.trim().split_once(' ')?;
    let (x, y) = pos.split_once(',')?;
    let (w, h) = size.split_once('x')?;
    Some((
        x.trim().parse().ok()?,
        y.trim().parse().ok()?,
        w.trim().parse().ok()?,
        h.trim().parse().ok()?,
    ))
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
/// `graph::window`'s own `0x`/case-tolerant [`crate::graph::normalize_addr`]
/// — the stored/typed address and what a human pastes off `hyprctl clients`
/// can disagree on both, exactly the same tolerance `graph::focus` already
/// needs for the same reason.
pub fn find_window<'a>(clients: &'a [hypr::Client], address: &str) -> Option<&'a hypr::Client> {
    let want = crate::graph::normalize_addr(address);
    clients.iter().find(|c| crate::graph::normalize_addr(&c.address) == want)
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
    sessions: &[crate::graph::SessionRecord],
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
/// Computed, never read back from the file — this workspace carries no
/// image-decoding dependency (khoa, 2026-08-16: zero new deps), and it needs
/// none: "capture region R at scale S" MEANS "produce R.w*S x R.h*S pixels"
/// by construction, for grim today and for any future backend behind
/// [`capture_image`] alike (verified against grim empirically — see the
/// executor's report). Rounds to the nearest pixel.
pub fn expected_image_size(region: hypr::Region, scale: f64) -> (i64, i64) {
    (
        (region.w as f64 * scale).round() as i64,
        (region.h as f64 * scale).round() as i64,
    )
}

/// Auto-named capture filename when `--out` is absent: `screenshot-<unix
/// ts>-<pid>.<ext>` — the same `<kind>-<pid>-<unixts>` shape
/// `graph::conduct`/`graph::session_store` already use for session ids
/// (`conduct-<pid>-<unixts>`, `wrap-<pid>-<unixts>`), just pid-then-ts
/// reordered so files with the same second still sort distinctly by pid.
/// Actually pid LAST here (unlike those ids) so a directory listing sorts by
/// capture TIME first — the more useful default order for a captures dir a
/// human might `ls`.
pub fn auto_name(unix_ts: u64, pid: u32, fmt: Format) -> String {
    format!("screenshot-{unix_ts}-{pid}.{}", fmt.ext())
}

/// Does `dest.with_extension("json")` land back on `dest` itself? True
/// exactly when `dest` already ends in `.json` — the collision an explicit
/// `--out foo.json` would create between a capture and its own sidecar (the
/// sidecar write would silently overwrite the just-captured image). Pure so
/// it's unit-tested directly; `shot()`'s own end-to-end path can't be (it
/// calls live `hyprctl` first) (khoa's Phase 1 review, D1).
fn sidecar_collides_with_dest(dest: &std::path::Path) -> bool {
    dest.with_extension("json") == dest
}

fn unix_ts() -> u64 {
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
    #[serde(default)]
    pub ocr: Option<serde_json::Value>,
}

/// The sidecar's current schema version (CONTRACTS.md's v0-first convention).
pub const SIDECAR_SCHEMA_VERSION: &str = "0";

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
            let store: crate::graph::SessionsFile =
                match crate::graph::load_stage(&crate::graph::sessions_path()) {
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
        // content-adaptive on purpose: detecting photographic-vs-flat
        // would need an image-decode dependency this workspace forbids,
        // plus a heuristic that can misfire — a fixed default + explicit
        // override is simpler and always correct.
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
    let scale: f64 = match inv.flags.get("scale") {
        None => 1.0,
        Some(s) => match s.parse::<f64>() {
            Ok(v) if v > 0.0 && v.is_finite() => v,
            _ => return Outcome::usage(cmd, format!("--scale must be a positive number, got `{s}`")),
        },
    };
    let comment = inv.flags.get("comment").cloned();

    let dest = match inv.flags.get("out") {
        Some(p) => PathBuf::from(p),
        None => aoide_storage::fs::captures_dir().join(auto_name(unix_ts(), std::process::id(), format)),
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

    let req = CaptureRequest { region: resolved.rect, format, quality, scale, dest: dest.clone() };
    if let Err(e) = capture_image(&req) {
        // Reason codes stay backend-agnostic ("capture-*", not "grim-*") —
        // this file's own header promises "a caller never learns which tool
        // did the work," and that promise has to hold at the door-facing
        // JSON layer too, not just in the Rust types (khoa's Phase 1
        // review, D2). The DETAIL string is whatever the backend actually
        // said (grim's stderr, or the OS spawn error) — genuinely useful
        // troubleshooting text, not an identity leak; the machine-checkable
        // surface an agent branches on is `data.reason`, and that stays
        // agnostic.
        let (reason, detail) = match &e {
            CaptureError::Unavailable(s) => ("capture-unavailable", s.clone()),
            CaptureError::Failed(s) => ("capture-failed", s.clone()),
        };
        return Outcome::error(cmd, format!("{reason}: {detail}"))
            .with_data(json!({ "reason": reason }));
    }

    let bytes = std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
    let (img_w, img_h) = expected_image_size(resolved.rect, scale);

    let sidecar = Sidecar {
        schema_version: SIDECAR_SCHEMA_VERSION.to_string(),
        captured_at: aoide_storage::time::now_iso_utc(),
        origin: hypr::Point { x: resolved.rect.x, y: resolved.rect.y },
        size: hypr::Size { w: img_w, h: img_h },
        scale,
        format: format.label().to_string(),
        quality,
        monitor: target.monitor,
        session: target.session,
        window: target.window,
        class: target.class,
        title: target.title,
        comment,
        ocr: None,
    };
    let sidecar_text = serde_json::to_string_pretty(&sidecar).unwrap_or_default() + "\n";
    if let Err(e) = aoide_storage::fs::atomic_write(&sidecar_path, &sidecar_text) {
        // The image is already on disk and real (capture_image succeeded
        // above) — report it in `changed` even though the SIDECAR write is
        // what failed, so an agent tracking changed files doesn't lose
        // track of the capture that DID land (khoa's Phase 1 review, P3).
        return Outcome::error(cmd, format!("captured but failed to write sidecar: {e}"))
            .changed(vec![dest.to_string_lossy().into_owned()])
            .with_data(json!({
                "reason": "sidecar-write-failed",
                "path": dest.to_string_lossy(),
            }));
    }

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
    if scale != 1.0 {
        message.push_str(&format!(
            "; scale {scale}x — pixel distances in the image are NOT 1:1 with the screen"
        ));
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

    fn test_session(id: &str, pid: Option<u32>, window_address: &str) -> crate::graph::SessionRecord {
        crate::graph::SessionRecord {
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
            dest: PathBuf::from("/tmp/out.png"),
        };
        let args = grim_argv(&req);
        let s_idx = args.iter().position(|a| a == "-s").unwrap();
        assert_eq!(args[s_idx + 1], "0.5");
        assert_eq!(args.last().unwrap(), "/tmp/out.png", "dest is always the final argv entry");
    }

    #[test]
    fn format_scale_trims_whole_numbers() {
        assert_eq!(format_scale(1.0), "1");
        assert_eq!(format_scale(2.0), "2");
        assert_eq!(format_scale(1.5), "1.5");
    }

    // ── auto_name ────────────────────────────────────────────────────────

    #[test]
    fn auto_name_embeds_timestamp_pid_and_extension() {
        assert_eq!(auto_name(1_700_000_000, 4242, Format::Jpeg), "screenshot-1700000000-4242.jpg");
        assert_eq!(auto_name(1_700_000_000, 4242, Format::Png), "screenshot-1700000000-4242.png");
    }

    #[test]
    fn auto_name_differs_for_different_pids_at_the_same_second() {
        let a = auto_name(1_700_000_000, 1, Format::Jpeg);
        let b = auto_name(1_700_000_000, 2, Format::Jpeg);
        assert_ne!(a, b, "two concurrent captures in the same second must not collide");
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
            ocr: None,
        };
        let text = serde_json::to_string(&sc).unwrap();
        // `ocr` is present-and-null, never omitted (day-one placeholder for
        // phase 3 — the brief's explicit requirement).
        assert!(text.contains("\"ocr\":null"), "{text}");
        // schemaVersion is a STRING ("0"), matching every other
        // schema-versioned shape in the codebase — NOT a bare number
        // (khoa's Phase 1 review, Decision B).
        assert!(text.contains("\"schemaVersion\":\"0\""), "{text}");
        assert!(text.contains("\"capturedAt\""));

        let back: Sidecar = serde_json::from_str(&text).unwrap();
        assert_eq!(back, sc);
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
            ocr: None,
        };
        let text = serde_json::to_string(&sc).unwrap();
        assert!(!text.contains("monitor"), "{text}");
        assert!(!text.contains("comment"), "{text}");
        assert!(!text.contains("\"session\""), "{text}");
        assert!(!text.contains("\"window\""), "{text}");
        assert!(!text.contains("\"class\""), "{text}");
        assert!(!text.contains("\"title\""), "{text}");
        assert!(text.contains("\"ocr\":null"), "{text}");
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
            ocr: None,
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

    // ── pick_region's parse path (the interactive spawn itself is NOT
    // live-proven here — see the module docs and the executor's report) ──

    #[test]
    fn slurp_style_output_parses_via_the_same_region_literal_parser() {
        // slurp's own stdout shape, "X,Y WxH\n" — confirming pick_region's
        // parse step (not the live spawn) is covered by existing tests.
        assert_eq!(parse_region_literal("100,100 300x200\n".trim()), Some((100, 100, 300, 200)));
    }
}
