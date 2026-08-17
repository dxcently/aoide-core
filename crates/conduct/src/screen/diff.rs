//! `aoide screen diff <before-capture>` — mechanical act-verification (khoa,
//! 2026-08-17, Phase E of the pointer-emulation workstream). Turns "did my
//! click do anything?" from an LLM judgement call into a measurement: re-shoot
//! the IDENTICAL rect/scale/format/quality a prior `screen shot` sidecar
//! already recorded, decode both images, and report a pixel-level bounding
//! box of what changed plus a hyprctl-level inventory delta (windows/layers
//! that appeared, disappeared, or got retitled) — the payoff of Phase D's
//! `desktop` snapshot finally getting a BEFORE and an AFTER to compare.
//!
//! ── The recapture path ─────────────────────────────────────────────────
//! Reuses `capture::write_capture` (extracted from `shot()`'s own tail this
//! phase) rather than forking a second capture pipeline: the after-image gets
//! its own sidecar exactly like any `screen shot` would, desktop snapshot
//! included, with the exact same hoisted-before-capture ordering Phase D
//! established (`write_capture`'s own doc). The before-capture's geometry is
//! recovered entirely from ITS sidecar (`origin`/`region`/`scale` — never
//! re-asked of the caller) via [`recover_region`]: a Phase-E-or-later
//! sidecar carries its own logical `region` verbatim (`Sidecar::region`'s own
//! doc — recorded, not recomputed, review B1); only a pre-Phase-E sidecar
//! (no `region` key at all) falls back to reconstructing it by dividing
//! `size` (DEVICE pixels) back through `scale` — a LOSSY inverse of
//! `capture::expected_image_size`'s forward `region * scale` rounding that
//! can drift the recaptured rect by roughly 1px on either axis for about
//! 1-in-`scale` widths/heights — a division that is provably EXACT at
//! `scale >= 1.0` (an integer `size` divided by an integer-or-larger scale
//! never lands on a fractional boundary the way a downscale can), so
//! `diff()` notes that fallback drift in its own outcome message only when
//! the fallback fired AND `scale < 1.0` (khoa, 2026-08-17, Phase F review
//! nit): the fallback itself always still runs at any scale, only the
//! caveat text is gated.
//!
//! ── THE DECODE BOUNDARY ────────────────────────────────────────────────
//! [`decode_rgba`] is the ONLY place in this workspace that decodes image
//! bytes into raw pixel buffers — the first module with any reason to call
//! the `image` crate at all (`capture.rs`'s own `capture_image` never
//! decodes, only writes). Mirrors `capture_image`/`run_tesseract_tsv`'s own
//! boundary discipline exactly: backend-agnostic reason codes on the outside
//! (`diff-decode-failed` / `diff-size-mismatch`), the crate name never
//! leaking into a reason code. NOT unit-tested (opens real files) — same
//! split every other real I/O boundary in this crate already draws;
//! [`diff_pixels`], the pure comparison it feeds, is tested directly against
//! synthetic buffers instead.
//!
//! ── The pure differ ────────────────────────────────────────────────────
//! [`diff_pixels`] operates on already-decoded RGBA8 buffers (4 bytes/pixel,
//! straight `to_rgba8()` output) — never on encoded file bytes, so it needs
//! no image crate of its own and is exercised entirely with synthetic
//! `Vec<u8>`s in the test module below. A pixel counts as changed when ANY of
//! its R/G/B channels' absolute delta exceeds `--threshold` (default 8,
//! chosen to absorb JPEG quantization noise and subpixel antialiasing
//! without a real UI change vanishing under it — the same class of "measured
//! headroom, not tuned to the exact boundary" reasoning `ocr.rs`'s own
//! `MIN_CONFIDENCE` uses). Alpha (channel 3) is DELIBERATELY IGNORED: this
//! verb's whole question is "did the UI change," and grim's own composited
//! output has no meaningful per-pixel alpha variation to begin with (a
//! captured region is always fully opaque on screen) — treating a stray
//! alpha bit-flip as "changed" would be pure decode noise, not signal.
//!
//! ── Sidecar write-back ─────────────────────────────────────────────────
//! The SAME data object reported as the outcome's `data` is also written
//! into the after-capture's own sidecar `diff` field (`capture::Sidecar::diff`
//! — present-and-`null` on every capture since this phase, the identical
//! day-one-placeholder convention `ocr` established in phase 1). Never
//! written into the BEFORE-capture's sidecar: `diff` describes what changed
//! BETWEEN the two shots, and belongs on the shot that came second.
//!
//! ── "Nothing changed" is success ───────────────────────────────────────
//! A quiet region producing `changed: false` is `Outcome::ok`, never an
//! error — a no-op is a fact an agent reads off `data.changed`, not an
//! exception it has to catch (mirrors `point_hover`'s own "no change" outcome
//! for the identical reason).

use super::capture::{self, CaptureTarget, Format, Sidecar, WriteCaptureError};
use super::hypr;
use aoide_protocol::output::Outcome;
use aoide_protocol::Invocation;
use serde_json::json;
use std::path::{Path, PathBuf};

// ── Defaults / bounds (mirrors point.rs's own const-per-flag convention,
// e.g. HOVER_DEFAULT_SETTLE_MS/HOVER_MAX_SETTLE_MS) ─────────────────────────

/// `--settle-ms` default — long enough to let a just-issued click's visual
/// consequence (a redraw, an animation settling) actually land before the
/// after-shot, short enough not to make every diff feel slow. `0` is a valid
/// override ("diff right now," the brief's own words) — bounds are
/// `0..=MAX_SETTLE_MS`, not `1..=`, unlike `hover`'s settle window (a hover's
/// settle IS the point of that verb; a diff's settle is a courtesy delay).
pub const DEFAULT_SETTLE_MS: u64 = 250;
pub const MAX_SETTLE_MS: u64 = 60_000;

/// `--threshold` default — see the module header's measured justification.
pub const DEFAULT_THRESHOLD: u8 = 8;

/// Raw pixel buffers are RGBA8 — 4 bytes/pixel, straight `to_rgba8()`
/// output. Channel 3 (alpha) is read only to be skipped; see the module
/// header on why.
const RGBA_CHANNELS: usize = 4;

// ── The pure pixel differ ──────────────────────────────────────────────────

/// The bounding box of every changed pixel, plus how many pixels inside it
/// actually changed (the box itself can contain unchanged pixels — it's a
/// bounding rect, not a mask). Coordinates are IMAGE pixels (device space,
/// origin top-left of the buffer) — `diff()`'s own caller converts to screen
/// space via the before-sidecar's `origin`/`scale`, this type carries no
/// opinion on that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiffRect {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
    pub changed_pixels: u64,
}

/// Why [`diff_pixels`] refused — a buffer whose length doesn't match `w * h *
/// 4`. Never a panic (CONTRACTS.md §3): a caller-supplied `w`/`h` that
/// disagrees with the buffer it decoded from is a typed refusal, the same
/// discipline `capture::clamp_region`/`point::interpolate` already hold for
/// arithmetic on caller-influenced input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferLengthMismatch {
    pub expected: usize,
    pub before_len: usize,
    pub after_len: usize,
}

/// Pure pixel diff over two already-decoded RGBA8 buffers of identical `w x
/// h`. `Ok(None)` means nothing changed past `threshold`; `Ok(Some(rect))`
/// carries the bounding box union of every changed pixel plus how many
/// pixels inside it changed. A pixel counts as changed when ANY of its R/G/B
/// channels' absolute delta exceeds `threshold` — alpha (index 3) is never
/// read for comparison, see the module header. `Err` on a buffer whose
/// length doesn't match `w * h * 4`, checked BEFORE any indexing (never a
/// slice-index panic on a caller-supplied mismatch).
pub fn diff_pixels(
    before: &[u8],
    after: &[u8],
    w: u32,
    h: u32,
    threshold: u8,
) -> Result<Option<DiffRect>, BufferLengthMismatch> {
    let expected = (w as usize).saturating_mul(h as usize).saturating_mul(RGBA_CHANNELS);
    if before.len() != expected || after.len() != expected {
        return Err(BufferLengthMismatch { expected, before_len: before.len(), after_len: after.len() });
    }

    let mut min_x = u32::MAX;
    let mut min_y = u32::MAX;
    let mut max_x = 0u32;
    let mut max_y = 0u32;
    let mut changed_pixels: u64 = 0;

    for y in 0..h {
        for x in 0..w {
            let idx = ((y * w + x) as usize) * RGBA_CHANNELS;
            let bp = &before[idx..idx + RGBA_CHANNELS];
            let ap = &after[idx..idx + RGBA_CHANNELS];
            let changed = (0..3).any(|c| {
                let delta = (bp[c] as i16 - ap[c] as i16).unsigned_abs();
                delta > threshold as u16
            });
            if changed {
                changed_pixels += 1;
                min_x = min_x.min(x);
                min_y = min_y.min(y);
                max_x = max_x.max(x);
                max_y = max_y.max(y);
            }
        }
    }

    if changed_pixels == 0 {
        return Ok(None);
    }
    Ok(Some(DiffRect {
        x: min_x,
        y: min_y,
        w: max_x - min_x + 1,
        h: max_y - min_y + 1,
        changed_pixels,
    }))
}

/// `changed_pixels / (w * h)`, `0.0` on a zero-area image (never a NaN from
/// `0/0`). Pure, hoisted out of `diff()` so the arithmetic is unit-tested on
/// its own rather than only indirectly through the command handler.
pub fn changed_fraction(changed_pixels: u64, w: u32, h: u32) -> f64 {
    let total = (w as u64) * (h as u64);
    if total == 0 {
        0.0
    } else {
        changed_pixels as f64 / total as f64
    }
}

// ── THE DECODE BOUNDARY ─────────────────────────────────────────────────

/// One image file's decode failure — backend-agnostic at the call site
/// (`diff-decode-failed`, never naming the crate), mirroring
/// `CaptureError`/`OcrError`'s own single-reason-family shape where (unlike
/// those two) there is no separate "couldn't even spawn" case to split out:
/// decoding is in-process, not a subprocess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    Failed(String),
}

/// THE DECODE BOUNDARY (khoa, 2026-08-17, Phase E). The only place in this
/// workspace that calls into the `image` crate — everything above this
/// function in the call chain works with typed rectangles/paths; this
/// decides HOW to turn a file's bytes into a `(width, height, RGBA8 bytes)`
/// tuple. NOT unit-tested (opens a real file) — see the module header.
fn decode_rgba(path: &Path) -> Result<(u32, u32, Vec<u8>), DecodeError> {
    let img = image::open(path).map_err(|e| DecodeError::Failed(e.to_string()))?;
    let rgba = img.into_rgba8();
    let (w, h) = rgba.dimensions();
    Ok((w, h, rgba.into_raw()))
}

// ── Geometry recovered from the before-sidecar (Phase E review, B1) ────────

/// Recovers the LOGICAL (Hyprland-space) region a before-capture's shot was
/// taken at, plus whether the LOSSY division fallback was used. Prefers
/// `sidecar.region` (recorded verbatim by `write_capture` since Phase E's
/// B1 fix — exact, no rounding). Falls back to inverting `size` through
/// `scale` ONLY when `region` is `None` (a pre-Phase-E sidecar that never
/// recorded it) — see [`super::capture::Sidecar::region`]'s own doc for why
/// that inversion is lossy for roughly 1-in-`scale` widths/heights. Pure:
/// takes exactly what it needs off the sidecar rather than the whole struct,
/// so it's testable without constructing a full `Sidecar`.
pub fn recover_region(origin: hypr::Point, region: Option<hypr::Region>, size: hypr::Size, scale: f64) -> (hypr::Region, bool) {
    if let Some(r) = region {
        return (r, false);
    }
    let w = capture::scale_div_round(size.w, scale);
    let h = capture::scale_div_round(size.h, scale);
    (hypr::Region { x: origin.x, y: origin.y, w, h }, true)
}

/// Converts a changed-pixel bounding box (IMAGE space — the before-sidecar's
/// own device-pixel buffer, origin top-left) to SCREEN space, via the same
/// transform `Sidecar::image_point_to_screen` uses for `--from-shot` (Phase
/// E review, LOW, khoa, 2026-08-17): the top-left corner is pulled back
/// inside the capture rect's own interior via `capture::clamp_into_capture_rect`
/// — `capture::transform_point` alone can overhang the rect by 1px on its
/// own rounding (Phase D review L5's exact case), which is not a caller lie
/// here either, just the same half-pixel rounding needing the same
/// correction. Width/height are floored to `.max(1)`: at `scale > 1`, a
/// sub-`scale`-wide image-space change (e.g. a single changed pixel at
/// `--scale 3`) would otherwise round DOWN to a zero-size screen rect via
/// `scale_div_round` — not a valid answer when `changed` is already `true`
/// and this rect exists purely to say WHERE.
fn image_rect_to_screen(image_rect: hypr::Region, origin: hypr::Point, size: hypr::Size, scale: f64) -> hypr::Region {
    let top_left = capture::transform_point(origin, scale, image_rect.x, image_rect.y);
    let top_left = capture::clamp_into_capture_rect(top_left, origin, size, scale);
    hypr::Region {
        x: top_left.x,
        y: top_left.y,
        w: capture::scale_div_round(image_rect.w, scale).max(1),
        h: capture::scale_div_round(image_rect.h, scale).max(1),
    }
}

// ── `aoide screen diff <before-capture>` ────────────────────────────────

/// `aoide screen diff <before-capture> [--settle-ms N] [--threshold N] [--out
/// PATH] [--json]` — see the module header for the full design.
pub fn diff(inv: &Invocation) -> Outcome {
    let cmd = "screen.diff";

    let Some(before_arg) = inv.args.first() else {
        return Outcome::usage(
            cmd,
            format!(
                "usage: aoide {} <before-capture> [--settle-ms N] [--threshold N] [--out PATH] [--json]",
                inv.path.join(" ")
            ),
        );
    };
    let before_path = PathBuf::from(before_arg);
    if !before_path.is_file() {
        return Outcome::error(cmd, format!("no such capture file: {}", before_path.display()))
            .with_data(json!({ "reason": "capture-not-found" }));
    }
    // Hard-erroring reader (khoa's Phase D review nit already resolved this
    // split for `--from-shot`): `origin`/`scale`/`size` are load-bearing for
    // the recapture geometry below, there is no reasonable "proceed anyway."
    let before_sidecar: Sidecar = match capture::read_sidecar(&before_path) {
        Ok(s) => s,
        Err((reason, detail)) => return Outcome::error(cmd, detail).with_data(json!({ "reason": reason })),
    };
    if !capture::scale_is_valid(before_sidecar.scale) {
        return Outcome::error(
            cmd,
            format!(
                "sidecar {} has an invalid scale ({}) — must be positive and finite",
                before_path.with_extension("json").display(),
                before_sidecar.scale
            ),
        )
        .with_data(json!({ "reason": "sidecar-corrupt" }));
    }
    let Some(format) = Format::parse(&before_sidecar.format) else {
        return Outcome::error(
            cmd,
            format!("sidecar records an unrecognised format `{}`", before_sidecar.format),
        )
        .with_data(json!({ "reason": "sidecar-corrupt" }));
    };

    let settle_ms: u64 = match inv.flags.get("settle-ms") {
        None => DEFAULT_SETTLE_MS,
        Some(s) => match s.parse::<u64>() {
            Ok(n) if n <= MAX_SETTLE_MS => n,
            Ok(n) => {
                return Outcome::usage(cmd, format!("--settle-ms must be 0-{MAX_SETTLE_MS}, got {n}"))
            }
            Err(_) => {
                return Outcome::usage(cmd, format!("--settle-ms must be a non-negative integer, got `{s}`"))
            }
        },
    };
    let threshold: u8 = match inv.flags.get("threshold") {
        None => DEFAULT_THRESHOLD,
        Some(s) => match s.parse::<u8>() {
            Ok(t) => t,
            Err(_) => return Outcome::usage(cmd, format!("--threshold must be 0-255, got `{s}`")),
        },
    };

    // Recover the LOGICAL region the before-capture was taken at — prefers
    // the sidecar's own recorded `region` (exact), falls back to the lossy
    // scale inversion only for a pre-Phase-E sidecar (see `recover_region`'s
    // own doc, Phase E review B1). Never re-derived from --output/--region/
    // etc — the before-sidecar IS the geometry contract (this module's own
    // header).
    let (region, used_region_fallback) =
        recover_region(before_sidecar.origin, before_sidecar.region, before_sidecar.size, before_sidecar.scale);

    let dest = match inv.flags.get("out") {
        Some(p) => PathBuf::from(p),
        None => aoide_storage::fs::captures_dir().join(capture::auto_name(
            capture::unix_ts(),
            std::process::id(),
            capture::next_auto_name_seq(),
            format,
        )),
    };
    if capture::sidecar_collides_with_dest(&dest) {
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

    std::thread::sleep(std::time::Duration::from_millis(settle_ms));

    // The recapture: same rect/format/quality/scale/cursor the before-shot
    // used, the identity fields (monitor/session/window/class/title) carried
    // over too so the after-sidecar still says what this was a capture OF —
    // `write_capture` is `shot()`'s own tail, extracted this phase precisely
    // so this is not a second capture pipeline. Note (Phase E review, NIT):
    // `window`/`class`/`title` describe the BEFORE-capture's own resolution,
    // copied onto a now-fixed rectangle — a window that moved, closed, or got
    // replaced between the two shots doesn't retroactively update these
    // fields. The `inventory` delta below (`appeared`/`disappeared`/
    // `retitled`) is the honest current signal for "is this still what's
    // there," not these carried-over identity strings.
    let target = CaptureTarget {
        monitor: before_sidecar.monitor.clone(),
        session: before_sidecar.session.clone(),
        window: before_sidecar.window.clone(),
        class: before_sidecar.class.clone(),
        title: before_sidecar.title.clone(),
    };
    let cursor = before_sidecar.cursor_drawn.unwrap_or(false);
    let mut written = match capture::write_capture(
        region,
        format,
        before_sidecar.quality,
        before_sidecar.scale,
        cursor,
        &dest,
        target,
        None,
    ) {
        Ok(w) => w,
        Err(WriteCaptureError::Capture { reason, detail }) => {
            return Outcome::error(cmd, format!("{reason}: {detail}"))
                .with_data(json!({ "reason": reason }));
        }
        Err(WriteCaptureError::Sidecar { detail }) => {
            return Outcome::error(cmd, format!("captured after-image but failed to write sidecar: {detail}"))
                .changed(vec![dest.to_string_lossy().into_owned()])
                .with_data(json!({ "reason": "sidecar-write-failed", "path": dest.to_string_lossy() }));
        }
    };

    let (before_w, before_h, before_buf) = match decode_rgba(&before_path) {
        Ok(v) => v,
        Err(DecodeError::Failed(detail)) => {
            return Outcome::error(cmd, format!("diff-decode-failed: {detail}"))
                .with_data(json!({ "reason": "diff-decode-failed", "path": before_path.to_string_lossy() }));
        }
    };
    let (after_w, after_h, after_buf) = match decode_rgba(&dest) {
        Ok(v) => v,
        Err(DecodeError::Failed(detail)) => {
            return Outcome::error(cmd, format!("diff-decode-failed: {detail}"))
                .with_data(json!({ "reason": "diff-decode-failed", "path": dest.to_string_lossy() }));
        }
    };
    if (before_w, before_h) != (after_w, after_h) {
        // The monitor layout changed mid-flight (or the before-capture's own
        // recorded size disagrees with the file on disk) — never silently
        // diff mismatched buffers.
        return Outcome::error(
            cmd,
            format!(
                "size mismatch: before-capture is {before_w}x{before_h}, after-capture is {after_w}x{after_h}"
            ),
        )
        .with_data(json!({
            "reason": "diff-size-mismatch",
            "before": { "w": before_w, "h": before_h },
            "after": { "w": after_w, "h": after_h },
        }));
    }

    let pixel_diff = match diff_pixels(&before_buf, &after_buf, before_w, before_h, threshold) {
        Ok(v) => v,
        Err(_) => {
            // Unreachable in ordinary operation: `to_rgba8()` always yields
            // exactly `w * h * 4` bytes for its own reported dimensions, and
            // the size check just above already proved before/after agree
            // on `w`/`h`. Kept as a typed refusal rather than an `unwrap`
            // regardless (CONTRACTS.md §3: never a panic).
            return Outcome::error(cmd, "diff-decode-failed: decoded buffer length disagreed with its own reported dimensions")
                .with_data(json!({ "reason": "diff-decode-failed" }));
        }
    };

    let changed = pixel_diff.is_some();
    let changed_pixels = pixel_diff.map(|r| r.changed_pixels).unwrap_or(0);
    let fraction = changed_fraction(changed_pixels, before_w, before_h);

    let changed_rect_image = pixel_diff.map(|r| hypr::Region {
        x: r.x as i64,
        y: r.y as i64,
        w: r.w as i64,
        h: r.h as i64,
    });
    // Screen-space conversion via the Phase D transform, run against the
    // BEFORE-sidecar's own origin/size/scale (the rect it's meaningful
    // against — the after-sidecar shares the identical origin/scale by
    // construction, since `write_capture` was handed the same
    // `region`/`scale` above, but the before-sidecar is the one this whole
    // verb was asked to explain). `image_rect_to_screen` (Phase E review,
    // LOW) both clamps the corner back inside the capture rect's own
    // interior and floors width/height to `.max(1)` — see its own doc.
    let changed_rect_screen = changed_rect_image
        .map(|r| image_rect_to_screen(r, before_sidecar.origin, before_sidecar.size, before_sidecar.scale));

    // Inventory delta: before-sidecar's desktop snapshot vs the after-shot's
    // own (already fresh — gathered by `write_capture` immediately before
    // ITS capture, post-settle). Skipped (null, noted) when either side
    // lacks a desktop snapshot: a pre-Phase-D before-capture never had one,
    // or `write_capture`'s own hyprctl call degraded this particular
    // after-shot's snapshot to `None` (its own `desktop_note` already
    // explains that half) — and (Phase E review, LOW) a Phase-D-ERA
    // before-capture's OWN hyprctl call could equally have degraded to
    // `None` at capture time, which looks identical to "predates desktop
    // snapshots" from here; the before-arm's note can't tell those apart, so
    // it says so rather than asserting a cause it doesn't actually know.
    let (inventory, inventory_note) = match (&before_sidecar.desktop, &written.sidecar.desktop) {
        (Some(b), Some(a)) => {
            let before_snap = hypr::InfoSnapshot { clients: b.clients.clone(), layers: b.layers.clone() };
            let after_snap = hypr::InfoSnapshot { clients: a.clients.clone(), layers: a.layers.clone() };
            (Some(hypr::info_delta(&before_snap, &after_snap)), None)
        }
        (None, _) => (
            None,
            Some("inventory: before-capture has no desktop snapshot (predates desktop snapshots, or its own snapshot degraded)"),
        ),
        (Some(_), None) => (None, Some("inventory: after-capture's desktop snapshot unavailable")),
    };

    let data = json!({
        "changed": changed,
        "changedFraction": fraction,
        "changedRect": changed_rect_screen.map(|r| json!({ "x": r.x, "y": r.y, "w": r.w, "h": r.h })),
        "changedRectImage": changed_rect_image.map(|r| json!({ "x": r.x, "y": r.y, "w": r.w, "h": r.h })),
        "appeared": inventory.as_ref().map(|d| d.appeared.clone()),
        "disappeared": inventory.as_ref().map(|d| d.disappeared.clone()),
        "retitled": inventory.as_ref().map(|d| d.retitled.clone()),
        "afterPath": dest.to_string_lossy(),
        "sidecarPath": sidecar_path.to_string_lossy(),
    });

    // Write the SAME object back into the after-capture's own sidecar `diff`
    // field — never the before-capture's (this module's own header).
    written.sidecar.diff = Some(data.clone());
    let sidecar_text = serde_json::to_string_pretty(&written.sidecar).unwrap_or_default() + "\n";
    if let Err(e) = aoide_storage::fs::atomic_write(&sidecar_path, &sidecar_text) {
        // `write_capture` already landed a valid (if now-stale, pre-diff)
        // sidecar at `sidecar_path` before this second write ran — list BOTH
        // real files this invocation produced, not just the image (Phase E
        // review, NIT: mirrors `shot()`'s own "never lose track of what
        // actually landed" reporting for its one sidecar write, applied here
        // to this verb's two).
        return Outcome::error(cmd, format!("diffed but failed to write sidecar: {e}"))
            .changed(vec![dest.to_string_lossy().into_owned(), sidecar_path.to_string_lossy().into_owned()])
            .with_data(json!({ "reason": "sidecar-write-failed", "path": sidecar_path.to_string_lossy() }));
    }

    let mut message = if changed {
        // "past threshold", not "within threshold" (Phase E review, LOW):
        // "within threshold 8" reads as "stayed inside the allowed bound" —
        // exactly backwards for the branch where a change WAS detected.
        format!(
            "changed: {changed_pixels} px ({fraction:.4}) past threshold {threshold} after {settle_ms}ms settle"
        )
    } else {
        format!("no change within threshold {threshold} after {settle_ms}ms settle")
    };
    // Gated on `scale < 1.0` (Phase F review nit, khoa, 2026-08-17): at
    // scale >= 1.0 the inverse-scale division is provably exact (see the
    // module header), so the drift caveat would be pure noise there — the
    // fallback itself still ran (`used_region_fallback` is unaffected),
    // only this message is scale-conditional.
    if used_region_fallback && before_sidecar.scale < 1.0 {
        message.push_str(
            "; region recovered by inverse scale; may drift ±1px for downscaled pre-Phase-E captures",
        );
    }
    if let Some(note) = inventory_note {
        message.push_str(&format!("; {note}"));
    }
    if let Some(note) = &written.desktop_note {
        message.push_str(&format!("; {note}"));
    }

    // Nothing-changed is NOT an error (this module's own header) — both
    // branches above already produced a normal message; only the wording
    // differs, never the Outcome variant.
    Outcome::ok(cmd, message)
        .changed(vec![dest.to_string_lossy().into_owned(), sidecar_path.to_string_lossy().into_owned()])
        .with_data(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── diff_pixels ──────────────────────────────────────────────────────

    /// Build a flat RGBA8 buffer of `w x h` pixels, every pixel the same
    /// `(r, g, b, a)`.
    fn solid(w: u32, h: u32, r: u8, g: u8, b: u8, a: u8) -> Vec<u8> {
        let mut buf = Vec::with_capacity((w * h * 4) as usize);
        for _ in 0..(w * h) {
            buf.extend_from_slice(&[r, g, b, a]);
        }
        buf
    }

    fn set_pixel(buf: &mut [u8], w: u32, x: u32, y: u32, r: u8, g: u8, b: u8, a: u8) {
        let idx = ((y * w + x) as usize) * 4;
        buf[idx..idx + 4].copy_from_slice(&[r, g, b, a]);
    }

    #[test]
    fn identical_buffers_report_no_change() {
        let before = solid(4, 4, 10, 20, 30, 255);
        let after = before.clone();
        assert_eq!(diff_pixels(&before, &after, 4, 4, 8).unwrap(), None);
    }

    #[test]
    fn a_single_changed_pixel_is_a_one_by_one_rect_at_exactly_that_pixel() {
        let before = solid(10, 10, 0, 0, 0, 255);
        let mut after = before.clone();
        set_pixel(&mut after, 10, 3, 4, 255, 0, 0, 255);
        let got = diff_pixels(&before, &after, 10, 10, 8).unwrap().unwrap();
        assert_eq!(got, DiffRect { x: 3, y: 4, w: 1, h: 1, changed_pixels: 1 });
    }

    #[test]
    fn two_far_apart_changes_union_into_one_bounding_rect() {
        let before = solid(20, 20, 0, 0, 0, 255);
        let mut after = before.clone();
        set_pixel(&mut after, 20, 2, 3, 255, 255, 255, 255);
        set_pixel(&mut after, 20, 15, 17, 255, 255, 255, 255);
        let got = diff_pixels(&before, &after, 20, 20, 8).unwrap().unwrap();
        // Bounding box from (2,3) to (15,17) inclusive: 14 wide, 15 tall.
        assert_eq!(got.x, 2);
        assert_eq!(got.y, 3);
        assert_eq!(got.w, 14);
        assert_eq!(got.h, 15);
        assert_eq!(got.changed_pixels, 2, "only the two touched pixels count, not the whole bbox");
    }

    #[test]
    fn rect_union_covers_changes_at_all_four_extremes() {
        let before = solid(10, 10, 0, 0, 0, 255);
        let mut after = before.clone();
        // Top-left, top-right, bottom-left, bottom-right corners.
        set_pixel(&mut after, 10, 0, 0, 255, 0, 0, 255);
        set_pixel(&mut after, 10, 9, 0, 255, 0, 0, 255);
        set_pixel(&mut after, 10, 0, 9, 255, 0, 0, 255);
        set_pixel(&mut after, 10, 9, 9, 255, 0, 0, 255);
        let got = diff_pixels(&before, &after, 10, 10, 8).unwrap().unwrap();
        assert_eq!(got, DiffRect { x: 0, y: 0, w: 10, h: 10, changed_pixels: 4 });
    }

    #[test]
    fn delta_exactly_at_threshold_does_not_count_but_one_more_does() {
        let before = solid(2, 2, 100, 100, 100, 255);
        let mut at_threshold = before.clone();
        set_pixel(&mut at_threshold, 2, 0, 0, 108, 100, 100, 255); // delta == 8
        assert_eq!(diff_pixels(&before, &at_threshold, 2, 2, 8).unwrap(), None, "delta == threshold must NOT count");

        let mut over_threshold = before.clone();
        set_pixel(&mut over_threshold, 2, 0, 0, 109, 100, 100, 255); // delta == 9
        let got = diff_pixels(&before, &over_threshold, 2, 2, 8).unwrap().unwrap();
        assert_eq!(got, DiffRect { x: 0, y: 0, w: 1, h: 1, changed_pixels: 1 });
    }

    #[test]
    fn alpha_only_change_is_ignored() {
        // R/G/B identical, only alpha differs — per the module header's
        // documented decision, this must NOT count as a change.
        let before = solid(3, 3, 50, 60, 70, 255);
        let mut after = before.clone();
        set_pixel(&mut after, 3, 1, 1, 50, 60, 70, 0);
        assert_eq!(diff_pixels(&before, &after, 3, 3, 8).unwrap(), None, "alpha-only delta must be ignored");
    }

    #[test]
    fn any_single_channel_over_threshold_counts_even_if_others_are_identical() {
        let before = solid(2, 2, 0, 0, 0, 255);
        let mut after = before.clone();
        // Only the green channel moves, but by more than the threshold.
        set_pixel(&mut after, 2, 0, 1, 0, 50, 0, 255);
        let got = diff_pixels(&before, &after, 2, 2, 8).unwrap().unwrap();
        assert_eq!(got, DiffRect { x: 0, y: 1, w: 1, h: 1, changed_pixels: 1 });
    }

    #[test]
    fn buffer_length_mismatch_is_a_typed_error_not_a_panic() {
        let before = solid(4, 4, 0, 0, 0, 255); // 64 bytes
        let after = solid(3, 4, 0, 0, 0, 255); // 48 bytes — wrong for w=4,h=4
        let err = diff_pixels(&before, &after, 4, 4, 8).unwrap_err();
        assert_eq!(err, BufferLengthMismatch { expected: 64, before_len: 64, after_len: 48 });
    }

    #[test]
    fn both_buffers_wrong_length_still_refuses_cleanly() {
        let before = vec![0u8; 10];
        let after = vec![0u8; 11];
        let err = diff_pixels(&before, &after, 4, 4, 8).unwrap_err();
        assert_eq!(err, BufferLengthMismatch { expected: 64, before_len: 10, after_len: 11 });
    }

    // ── changed_fraction ─────────────────────────────────────────────────

    #[test]
    fn changed_fraction_arithmetic() {
        assert_eq!(changed_fraction(0, 10, 10), 0.0);
        assert_eq!(changed_fraction(50, 10, 10), 0.5);
        assert_eq!(changed_fraction(100, 10, 10), 1.0);
        assert!((changed_fraction(1, 3, 3) - (1.0 / 9.0)).abs() < 1e-12);
    }

    #[test]
    fn changed_fraction_of_a_zero_area_image_is_zero_not_nan() {
        assert_eq!(changed_fraction(0, 0, 0), 0.0);
        assert_eq!(changed_fraction(0, 0, 10), 0.0);
    }

    // ── recover_region (Phase E review, B1 — BLOCKING) ─────────────────────
    // The lossy fallback drift is not hypothetical: these two cases are the
    // exact ones the review flagged, reproduced with full float precision
    // (not the display-rounded "0.5"/"0.667" the review text uses).

    #[test]
    fn recover_region_prefers_the_recorded_region_over_reconstruction_for_the_1001_at_half_scale_drift_case() {
        // region.w = 1001 @ scale = 0.5 rounds FORWARD to image_w = 501
        // (`expected_image_size`), but dividing back (`scale_div_round(501,
        // 0.5)`) rounds to 1002, not 1001 — the exact drift B1 closes.
        let origin = hypr::Point { x: 0, y: 0 };
        let recorded = hypr::Region { x: 0, y: 0, w: 1001, h: 10 };
        let size = hypr::Size { w: 501, h: 5 };
        let scale = 0.5;

        // `region` recorded (Phase E or later): exact, no drift, no
        // fallback.
        let (got, used_fallback) = recover_region(origin, Some(recorded), size, scale);
        assert_eq!(got, recorded);
        assert!(!used_fallback);

        // `region` absent (pre-Phase-E sidecar): the lossy division drifts
        // `w` by exactly +1 — proving the fallback reproduces the drift
        // rather than silently matching by luck.
        let (got, used_fallback) = recover_region(origin, None, size, scale);
        assert_eq!(got.w, 1002, "expected the documented +1 drift, got {}", got.w);
        assert!(used_fallback);
    }

    #[test]
    fn recover_region_prefers_the_recorded_region_over_reconstruction_for_the_100_at_two_thirds_fit_scale_drift_case() {
        // region.w = 100 @ a fit-derived scale of 2/3 (`fit_scale`'s own
        // full-precision output, not the display-rounded "0.667" the review
        // text uses) rounds FORWARD to image_w = 67, but dividing back
        // rounds to 101, not 100.
        let origin = hypr::Point { x: 0, y: 0 };
        let scale = 2.0_f64 / 3.0_f64;
        let recorded = hypr::Region { x: 0, y: 0, w: 100, h: 100 };
        let size = hypr::Size { w: 67, h: 67 };

        let (got, used_fallback) = recover_region(origin, Some(recorded), size, scale);
        assert_eq!(got, recorded);
        assert!(!used_fallback);

        let (got, used_fallback) = recover_region(origin, None, size, scale);
        assert_eq!(got.w, 101, "expected the documented +1 drift, got {}", got.w);
        assert!(used_fallback);
    }

    #[test]
    fn recover_region_falls_back_correctly_for_a_pre_phase_e_sidecar_parsed_from_json() {
        // The exact shape a pre-Phase-E sidecar has on disk: no `region` key
        // at all. Proves the fallback path end to end off a real
        // deserialize, not just a hand-built `None`.
        let text = r#"{"schemaVersion":"0","capturedAt":"2026-08-16T12:00:00Z",
            "origin":{"x":10,"y":20},"size":{"w":501,"h":5},"scale":0.5,
            "format":"png","quality":80}"#;
        let sc: Sidecar = serde_json::from_str(text).unwrap();
        assert_eq!(sc.region, None, "precondition: this fixture carries no region key");

        let (got, used_fallback) = recover_region(sc.origin, sc.region, sc.size, sc.scale);
        assert!(used_fallback);
        assert_eq!(got, hypr::Region { x: 10, y: 20, w: 1002, h: 10 });
    }

    // ── image_rect_to_screen (Phase E review, LOW) ──────────────────────────

    #[test]
    fn image_rect_to_screen_floors_a_sub_scale_change_to_a_one_by_one_rect_not_zero() {
        // At scale 3.0, a single changed image pixel maps to
        // `scale_div_round(1, 3.0) == 0` on each axis before flooring — a
        // zero-size rect is not a valid answer when `changed` is already
        // `true`.
        let origin = hypr::Point { x: 0, y: 0 };
        let size = hypr::Size { w: 30, h: 30 };
        let scale = 3.0;
        let image_rect = hypr::Region { x: 5, y: 5, w: 1, h: 1 };
        let got = image_rect_to_screen(image_rect, origin, size, scale);
        assert_eq!(got, hypr::Region { x: 2, y: 2, w: 1, h: 1 });
    }

    #[test]
    fn image_rect_to_screen_clamps_a_corner_that_would_otherwise_overhang_the_capture_rect() {
        // The exact scenario `clamp_into_capture_rect`'s own doc walks
        // through: scale 2.0, image size 20x20 (valid image x/y up to 19).
        // `scale_div_round(19, 2.0)` rounds 9.5 UP to 10 — one past the
        // reconstructed 10px-wide screen rect's exclusive edge — so the raw
        // `transform_point` result must be pulled back to x=9,y=9, not
        // reported as x=10,y=10.
        let origin = hypr::Point { x: 0, y: 0 };
        let size = hypr::Size { w: 20, h: 20 };
        let scale = 2.0;
        let image_rect = hypr::Region { x: 19, y: 19, w: 1, h: 1 };
        let got = image_rect_to_screen(image_rect, origin, size, scale);
        assert_eq!(got, hypr::Region { x: 9, y: 9, w: 1, h: 1 });
    }
}
