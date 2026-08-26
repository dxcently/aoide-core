//! `aoide screen ocr <capture>` — tesseract OCR over a `screen shot` capture,
//! writing per-word bounding boxes (converted to ABSOLUTE SCREEN
//! coordinates) into the capture's own JSON sidecar. Phase 3 of the `screen`
//! command family — `capture.rs`'s `Sidecar::ocr` field has carried this file's
//! output shape as an explicit `null` placeholder since phase 1
//! (`capture.rs`'s own header), so this phase's only schema change is
//! POPULATING that field, never adding a new one.
//!
//! ── The OCR boundary (mirrors capture.rs's pixel-acquisition boundary and
//! point.rs's pointer-synthesis boundary exactly) ──────────────────────────
//! [`run_tesseract_tsv`] is the ONLY place `tesseract` is named anywhere in
//! this crate. Everything above it decides WHAT to do with the result
//! (parse TSV, filter, transform coordinates, write the sidecar); this
//! function decides HOW. [`OcrError`]'s reason codes stay backend-agnostic
//! (`ocr-*`, never `tesseract-*`) — phase 1's own review caught exactly this
//! leak once already (`"grim-failed"`, `capture.rs`'s D2) and this phase
//! does not repeat it.
//!
//! ── PSM choice: 11 (sparse text, no OSD), not tesseract's own default of 3
//! (fully automatic page segmentation) — MEASURED on this rig, 2026-08-16
//! ───────────────────────────────────────────────────────────────────────
//! `screen shot`'s own capture shapes are frequently NOT page-like: a bar
//! strip, a single widget, a popup — sparse UI chrome, not a document. Tried
//! both PSMs live against two real captures on this rig:
//!   - A 1920x36 status-bar strip: PSM 3 returned "Empty page!!" — ZERO
//!     words, a complete miss. PSM 11 found 4 word-level detections.
//!   - A 1900x1024 text-dense terminal window: PSM 3 found 629 word rows
//!     (conf > 0), PSM 11 found 604 — a ~4% shortfall, not a miss.
//!
//! PSM 11 loses a little on dense paragraph text but never goes to zero on
//! sparse UI captures, which are this tool's primary expected input (an
//! agent screenshotting a widget/bar/popup, not scanning a document) — the
//! asymmetry decides it.
//!
//! ── Confidence floor: 10.0 — MEASURED on the same bar capture ─────────────
//! Tesseract's own non-word rows (page/block/par/line, level 1-4) always
//! carry the sentinel conf `-1` and are excluded structurally by the
//! level==5 filter below; [`MIN_CONFIDENCE`] is a SEPARATE cut for
//! low-but-real word-level confidence. On the bar capture above, three
//! detections were icon-glyph misreads ("sosiizaw", "swdayagoo", a stray
//! "S") that all landed at EXACTLY 0.0 confidence, while three genuine
//! detections ("4", "==", "I" — tray/workspace glyphs that happen to render
//! as real characters) scored 68-78%. `10.0` sits with margin inside that
//! gap on the measured sample, not tuned to the exact observed boundary.
//!
//! ── Line-break heuristic: vertical bbox overlap, not (block,par,line)
//! grouping — a real PSM-11 quirk, also measured ───────────────────────────
//! PSM 11's "sparse text" mode increments `block_num` per detected
//! fragment, even for words sharing one visual line (measured live: four
//! words of one on-screen sentence split across TWO different `block_num`s
//! despite an identical `top` row). Grouping by the TSV's own (block_num,
//! par_num, line_num) columns would therefore insert spurious line breaks
//! mid-sentence under PSM 11. Comparing each word's image-pixel vertical
//! span `[top, top+height)` against the PREVIOUS word's for a nonzero
//! overlap is robust to that quirk (fragments on one visual line still
//! overlap vertically) and works identically for PSM 3's more conventional
//! grouping (real same-line words overlap vertically there too) — one rule
//! covers both rather than branching on which PSM produced the input.
//!
//! ── Sidecar write-back ─────────────────────────────────────────────────
//! Reads `<capture>.json` (written by `screen shot`), fills its `ocr` field
//! (present-and-`null` since phase 1) with `{ text, words }`, and
//! `atomic_write`s the whole sidecar back — `origin`/`size`/`scale`/every
//! other field pass through untouched. The coordinate transform (image
//! pixels → absolute screen pixels) reverses `capture.rs`'s own
//! `expected_image_size` (screen → image, `px * scale`); this goes image →
//! screen, `origin + px / scale` — see [`image_bbox_to_screen`].

use super::capture::Sidecar;
use super::hypr;
use aoide_protocol::output::Outcome;
use aoide_protocol::Invocation;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::{Path, PathBuf};

// ── Output shape: written into the sidecar's `ocr` field verbatim ─────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Word {
    pub text: String,
    pub conf: f64,
    pub bbox: hypr::Region,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OcrResult {
    pub text: String,
    pub words: Vec<Word>,
}

// ── Coordinate transform: image pixels → ABSOLUTE SCREEN pixels ───────────

/// Is `scale` usable for [`image_bbox_to_screen`]'s division? Must be
/// positive and finite. `capture.rs`'s own `shot()` already rejects `--scale
/// <= 0` at write-time (`Ok(v) if v > 0.0 && v.is_finite() => v`), so a
/// sidecar failing this check cannot have come from an ordinary `screen
/// shot` — only from hand-editing/corruption of the `<capture>.json` file
/// sitting on disk between that write and this read (`screen shot` and
/// `screen ocr` are two separate invocations). Checked explicitly at the
/// `ocr()` call site rather than left implicit in the division: `scale ==
/// 0.0` doesn't panic (`f64` division to infinity, then a saturating
/// float→int cast to `i64::MAX`/`MIN` — loud, obviously-wrong garbage) but a
/// NEGATIVE scale silently MIRRORS every coordinate to a plausible-looking
/// WRONG value instead, with no saturation to flag it — exactly the "caller
/// acts on a lie" failure mode this codebase's review culture rules out
/// elsewhere (`capture.rs`'s clamp-announcement discipline). This feeds
/// agent clicks downstream, so it fails loudly (`sidecar-corrupt`) instead.
///
/// One-line delegation to `capture::scale_is_valid` (khoa, 2026-08-17, Phase
/// D of the pointer-emulation workstream) — moved there so `screen ocr`'s
/// guard and `Sidecar::image_point_to_screen`'s own (the `--from-shot`
/// coordinate conversion) share exactly one definition; this file keeps its
/// own name so nothing downstream (this module's own tests included) has to
/// change.
fn scale_is_valid(scale: f64) -> bool {
    super::capture::scale_is_valid(scale)
}

/// `screen = origin + image_px / scale` — the inverse of
/// `capture::expected_image_size`'s `region * scale`. `origin` is already
/// logical (screen) pixel space (`capture.rs`'s own doc on `Sidecar::origin`);
/// `image_bbox` is DEVICE pixels straight from tesseract's TSV `left/top/
/// width/height`, which only coincide with logical pixels at `scale == 1.0`.
/// Rounds to the nearest pixel — same convention `expected_image_size`
/// already uses for the forward direction.
///
/// The math itself now lives in `capture::transform_point`/
/// `capture::scale_div_round` (khoa, 2026-08-17, Phase D) — hoisted out so
/// there is exactly ONE transform implementation in the crate, shared with
/// `Sidecar::image_point_to_screen` (`--from-shot`'s conversion). This
/// function calls the point version once for the bbox's top-left corner,
/// then the shared division again for width/height (an extent has no
/// corner of its own to transform) — same semantics as before the hoist,
/// this file's own tests below prove the delegation didn't change a single
/// output.
pub fn image_bbox_to_screen(origin: hypr::Point, scale: f64, image_bbox: hypr::Region) -> hypr::Region {
    let top_left = super::capture::transform_point(origin, scale, image_bbox.x, image_bbox.y);
    hypr::Region {
        x: top_left.x,
        y: top_left.y,
        w: super::capture::scale_div_round(image_bbox.w, scale),
        h: super::capture::scale_div_round(image_bbox.h, scale),
    }
}

// ── TSV parsing (pure) ─────────────────────────────────────────────────────

/// Confidence floor for a word-level (`level == 5`) TSV row — see the module
/// header for the measured justification.
const MIN_CONFIDENCE: f64 = 10.0;

/// One parsed word-level TSV row, IMAGE-pixel space, pre-transform.
#[derive(Debug, Clone, PartialEq)]
struct RawWord {
    left: i64,
    top: i64,
    width: i64,
    height: i64,
    conf: f64,
    text: String,
}

/// Do two `[top, top+height)` vertical spans overlap at all? THE same-line
/// predicate this module's line-break heuristic reduces to — see the module
/// header's PSM-11 quirk note. `pub(crate)` (khoa, 2026-08-17, Phase F of the
/// pointer-emulation workstream): `screen::text`'s multi-word phrase matcher
/// reuses this EXACT rule for its own same-line join, rather than growing a
/// second copy of "what counts as one line" free to drift from this one.
/// Saturating on purpose: `assemble`'s own call site only ever passes real
/// tesseract TSV rows (small, well-formed, plain `+` would do), but
/// `screen::text`'s phrase matcher now feeds this the same function bbox
/// values straight off a sidecar `.json` file on disk — a hand-edited
/// `"y": 9223372036854775807` is agent-reachable input, not a hypothetical,
/// and plain `+` on that panics in debug / silently wraps in release
/// (`union_bbox` one call away in `text.rs` already saturates for the exact
/// same reason). No behavior change on the tesseract path: real TSV rows
/// never get near either bound.
pub(crate) fn vertical_spans_overlap(a_top: i64, a_height: i64, b_top: i64, b_height: i64) -> bool {
    let a_bottom = a_top.saturating_add(a_height);
    let b_bottom = b_top.saturating_add(b_height);
    a_bottom.min(b_bottom) > a_top.max(b_top)
}

/// Do `a`'s and `b`'s vertical spans overlap at all? Thin delegation to
/// [`vertical_spans_overlap`] (this file's own call sites/tests keep this
/// `RawWord`-shaped name unchanged).
fn vertically_overlaps(a: &RawWord, b: &RawWord) -> bool {
    vertical_spans_overlap(a.top, a.height, b.top, b.height)
}

/// Parse tesseract's `--psm N tsv` stdout into word-level rows, image-pixel
/// space. Pure — the only thing that knows tesseract's fixed TSV column
/// order (level, page_num, block_num, par_num, line_num, word_num, left,
/// top, width, height, conf, text). Tolerant by construction, not by special
/// case: the header row (`level` reads literally `"level"`, not a number)
/// and any other malformed row (too few tab-separated fields, a non-numeric
/// numeric field) fail the same `let Ok(..) = ... .parse() else { continue
/// }` path as ordinary bad input — no dedicated header check needed. Also
/// drops: non-word rows (`level != 5` — page/block/par/line summaries, which
/// always carry the `-1` sentinel conf), empty-after-trim text, and
/// confidence below [`MIN_CONFIDENCE`].
fn parse_word_rows(tsv: &str) -> Vec<RawWord> {
    let mut out = Vec::new();
    for line in tsv.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 12 {
            continue;
        }
        let Ok(level) = fields[0].parse::<i64>() else { continue };
        if level != 5 {
            continue;
        }
        let Ok(left) = fields[6].parse::<i64>() else { continue };
        let Ok(top) = fields[7].parse::<i64>() else { continue };
        let Ok(width) = fields[8].parse::<i64>() else { continue };
        let Ok(height) = fields[9].parse::<i64>() else { continue };
        let Ok(conf) = fields[10].parse::<f64>() else { continue };
        // `text` is field 11 through end-of-line, rejoined on tab in case a
        // (never observed, but unproven-impossible) embedded tab shows up —
        // ordinary rows have exactly one field here.
        let text = fields[11..].join("\t");
        let text = text.trim();
        if text.is_empty() || conf < MIN_CONFIDENCE {
            continue;
        }
        out.push(RawWord { left, top, width, height, conf, text: text.to_string() });
    }
    out
}

/// Assemble [`parse_word_rows`]'s output into the final [`OcrResult`]:
/// `text` is every surviving word's text, in TSV row order (tesseract's own
/// reading order), space-joined within a line and newline-joined across
/// lines per [`vertically_overlaps`]; `words` carries each one's confidence
/// and its bbox converted to absolute screen coordinates via
/// [`image_bbox_to_screen`].
fn assemble(tsv: &str, origin: hypr::Point, scale: f64) -> OcrResult {
    let rows = parse_word_rows(tsv);
    let mut text = String::new();
    let mut words = Vec::with_capacity(rows.len());
    let mut prev: Option<&RawWord> = None;
    for row in &rows {
        if let Some(p) = prev {
            text.push(if vertically_overlaps(p, row) { ' ' } else { '\n' });
        }
        text.push_str(&row.text);
        prev = Some(row);

        let bbox = image_bbox_to_screen(
            origin,
            scale,
            hypr::Region { x: row.left, y: row.top, w: row.width, h: row.height },
        );
        words.push(Word { text: row.text.clone(), conf: row.conf, bbox });
    }
    OcrResult { text, words }
}

// ── THE OCR BOUNDARY ────────────────────────────────────────────────────

/// One `tesseract` shell-out's failure, split the same way `CaptureError`/
/// `PointerError` already split theirs (spawn-failed vs ran-but-refused).
#[derive(Debug, Clone, PartialEq)]
pub enum OcrError {
    /// tesseract couldn't even be spawned.
    Unavailable(String),
    /// It ran but exited nonzero.
    Failed(String),
}

impl OcrError {
    /// Backend-agnostic reason code — `ocr-*`, NEVER `tesseract-*` (khoa's
    /// Phase 1 review, D2, applied here per this phase's own brief: a
    /// caller must never learn which tool did the work from the reason
    /// code).
    pub fn reason(&self) -> &'static str {
        match self {
            OcrError::Unavailable(_) => "ocr-unavailable",
            OcrError::Failed(_) => "ocr-failed",
        }
    }
    /// The actual backend detail (tesseract's stderr, or the OS spawn
    /// error) — genuinely useful troubleshooting text; unlike `reason()`,
    /// allowed to say whatever tesseract actually said.
    pub fn detail(&self) -> &str {
        match self {
            OcrError::Unavailable(s) | OcrError::Failed(s) => s,
        }
    }
}

/// Pure tesseract argv assembly — unit-tested directly; the only function
/// that speaks tesseract's own CLI vocabulary (`<img> stdout --psm N tsv`).
fn tesseract_argv(image: &Path, psm: u8) -> Vec<String> {
    vec![
        image.to_string_lossy().into_owned(),
        "stdout".to_string(),
        "--psm".to_string(),
        psm.to_string(),
        "tsv".to_string(),
    ]
}

/// PSM 11 (sparse text, no OSD) — see the module header for the measured
/// A/B against tesseract's own default (PSM 3).
const OCR_PSM: u8 = 11;

/// THE OCR BOUNDARY (khoa, 2026-08-16, Phase 3). Everything above this
/// function decides WHAT to do with the result; this decides HOW. Today:
/// one `tesseract` shell-out — the ONLY place `tesseract` is named anywhere
/// in this crate. Judged the ordinary way (like `capture_image`/
/// `synth::synthesize`): tesseract prints diagnostics to stderr and TSV to
/// stdout, exit 0 means stdout holds the result — CONFIRMED live on this rig
/// (2026-08-16): `Estimating resolution as N` / `Empty page!!` land on
/// stderr only, never stdout, so there is no output-vs-exit-code mismatch to
/// guard against here (unlike `song::ipc`'s quirky void-IPC case). NOT
/// unit-tested itself (spawns a real process); [`tesseract_argv`] is.
pub fn run_tesseract_tsv(image: &Path, psm: u8) -> Result<String, OcrError> {
    let argv = tesseract_argv(image, psm);
    match std::process::Command::new("tesseract").args(&argv).output() {
        Err(e) => Err(OcrError::Unavailable(e.to_string())),
        Ok(out) if out.status.success() => Ok(String::from_utf8_lossy(&out.stdout).into_owned()),
        Ok(out) => {
            let said = String::from_utf8_lossy(&out.stderr);
            let said = said.trim();
            Err(OcrError::Failed(if said.is_empty() {
                format!("tesseract exited {:?} with no message", out.status.code())
            } else {
                said.to_string()
            }))
        }
    }
}

// ── `aoide screen ocr <capture>` ────────────────────────────────────────

/// `aoide screen ocr <capture>` — OCR an existing `screen shot` capture via
/// tesseract, writing the result into the capture's own `<name>.json`
/// sidecar (`ocr` field). See the module header for the PSM/threshold/
/// coordinate-transform reasoning.
pub fn ocr(inv: &Invocation) -> Outcome {
    let cmd = "screen.ocr";
    let Some(image_arg) = inv.args.first() else {
        return Outcome::usage(cmd, format!("usage: aoide {} <capture> [--json]", inv.path.join(" ")));
    };
    let image_path = PathBuf::from(image_arg);
    if !image_path.is_file() {
        return Outcome::error(cmd, format!("no such capture file: {}", image_path.display()))
            .with_data(json!({ "reason": "capture-not-found" }));
    }
    let sidecar_path = image_path.with_extension("json");
    // Delegates to `capture::read_sidecar` (khoa's Phase D review nit) —
    // this was a byte-identical inline copy of that function's own missing/
    // corrupt handling (same two reason codes, same message shapes), the
    // third reader of the same two-case logic where two already sufficed
    // (`capture::read_sidecar` itself, and `send.rs`'s own deliberately
    // DIFFERENT lenient reader — see that function's doc on why THAT one
    // stays separate).
    let mut sidecar: Sidecar = match super::capture::read_sidecar(&image_path) {
        Ok(s) => s,
        Err((reason, detail)) => return Outcome::error(cmd, detail).with_data(json!({ "reason": reason })),
    };
    if !scale_is_valid(sidecar.scale) {
        // Same `sidecar-corrupt` reason as a JSON-parse failure above — this
        // IS a corrupt sidecar, just one that still happens to be valid
        // JSON. See `scale_is_valid`'s own doc for why this can't come from
        // an ordinary `screen shot`.
        return Outcome::error(
            cmd,
            format!(
                "sidecar {} has an invalid scale ({}) — must be positive and finite",
                sidecar_path.display(),
                sidecar.scale
            ),
        )
        .with_data(json!({ "reason": "sidecar-corrupt" }));
    }

    let tsv = match run_tesseract_tsv(&image_path, OCR_PSM) {
        Ok(t) => t,
        Err(e) => {
            let (reason, detail) = match &e {
                OcrError::Unavailable(s) => ("ocr-unavailable", s.clone()),
                OcrError::Failed(s) => ("ocr-failed", s.clone()),
            };
            return Outcome::error(cmd, format!("{reason}: {detail}"))
                .with_data(json!({ "reason": reason }));
        }
    };

    let result = assemble(&tsv, sidecar.origin, sidecar.scale);
    let word_count = result.words.len();
    let mean_conf = if word_count == 0 {
        0.0
    } else {
        result.words.iter().map(|w| w.conf).sum::<f64>() / word_count as f64
    };
    let text = result.text.clone();

    sidecar.ocr = Some(serde_json::to_value(&result).unwrap_or_default());
    let sidecar_text_out = serde_json::to_string_pretty(&sidecar).unwrap_or_default() + "\n";
    if let Err(e) = aoide_storage::fs::atomic_write(&sidecar_path, &sidecar_text_out) {
        return Outcome::error(cmd, format!("ocr succeeded but failed to write sidecar: {e}"))
            .with_data(json!({ "reason": "sidecar-write-failed" }));
    }

    Outcome::ok(
        cmd,
        format!(
            "ocr: {word_count} word(s), mean confidence {mean_conf:.1} — sidecar {}",
            sidecar_path.display()
        ),
    )
    .changed(vec![sidecar_path.to_string_lossy().into_owned()])
    .with_data(json!({
        "sidecarPath": sidecar_path.to_string_lossy(),
        "wordCount": word_count,
        "meanConfidence": mean_conf,
        "text": text,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Real tesseract TSV output, captured live on this rig (2026-08-16,
    // tesseract 5.5.2, eng-only tessdata) and trimmed — not invented.

    /// PSM 11 TSV over a synthetic two-line 400x80 PNG (drawn with
    /// imagemagick: "aoide screen ocr" / "phase 3 fixture", neutral
    /// placeholder text — not scraped from any real capture). Proves:
    /// header-row skip, non-word-row (level 1-4) skip, word parsing,
    /// multi-line concatenation in reading order, all-above-threshold (no
    /// filtering noise in this one).
    const TSV_MULTILINE: &str = "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext\n1\t1\t0\t0\t0\t0\t0\t0\t400\t80\t-1\t\n2\t1\t1\t0\t0\t0\t11\t11\t198\t19\t-1\t\n3\t1\t1\t1\t0\t0\t11\t11\t198\t19\t-1\t\n4\t1\t1\t1\t1\t0\t11\t11\t198\t19\t-1\t\n5\t1\t1\t1\t1\t1\t11\t11\t64\t19\t91.616821\taoide\n5\t1\t1\t1\t1\t2\t85\t16\t77\t14\t89.212616\tscreen\n5\t1\t1\t1\t1\t3\t172\t16\t37\t14\t89.212616\tocr\n2\t1\t2\t0\t0\t0\t12\t46\t178\t24\t-1\t\n3\t1\t2\t1\t0\t0\t12\t46\t178\t24\t-1\t\n4\t1\t2\t1\t1\t0\t12\t46\t178\t24\t-1\t\n5\t1\t2\t1\t1\t1\t12\t46\t69\t24\t92.226273\tphase\n5\t1\t2\t1\t1\t2\t92\t47\t11\t18\t92.678146\t3\n5\t1\t2\t1\t1\t3\t113\t46\t77\t19\t92.678146\tfixture\n";

    /// PSM 11 TSV over a real 1920x36 capture of this rig's own status bar.
    /// Proves the confidence filter against GENUINE tesseract noise (not a
    /// synthetic low-conf row): three icon-glyph misreads ("sosiizaw",
    /// "swdayagoo", a stray "S") all measured at exactly 0.0 confidence
    /// alongside three legitimate glyph detections ("4", "==", "I") at
    /// 68-78% — see the module header.
    const TSV_BAR: &str = "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext\n1\t1\t0\t0\t0\t0\t0\t0\t1920\t36\t-1\t\n2\t1\t1\t0\t0\t0\t8\t4\t494\t28\t-1\t\n3\t1\t1\t1\t0\t0\t8\t4\t494\t28\t-1\t\n4\t1\t1\t1\t1\t0\t8\t4\t494\t28\t-1\t\n5\t1\t1\t1\t1\t1\t8\t4\t11\t28\t68.086349\t4\n5\t1\t1\t1\t1\t2\t34\t0\t96\t36\t0.000000\tsosiizaw\n5\t1\t1\t1\t1\t3\t145\t0\t141\t36\t0.000000\tswdayagoo\n2\t1\t2\t0\t0\t0\t957\t14\t32\t15\t-1\t\n3\t1\t2\t1\t0\t0\t957\t14\t32\t15\t-1\t\n4\t1\t2\t1\t1\t0\t957\t14\t32\t15\t-1\t\n5\t1\t2\t1\t1\t1\t957\t14\t32\t15\t74.038628\t==\n2\t1\t3\t0\t0\t0\t1783\t11\t62\t15\t-1\t\n3\t1\t3\t1\t0\t0\t1783\t11\t62\t15\t-1\t\n4\t1\t3\t1\t1\t0\t1783\t11\t62\t15\t-1\t\n5\t1\t3\t1\t1\t1\t1783\t12\t8\t14\t0.000000\tS\n2\t1\t4\t0\t0\t0\t1905\t9\t7\t18\t-1\t\n3\t1\t4\t1\t0\t0\t1905\t9\t7\t18\t-1\t\n4\t1\t4\t1\t1\t0\t1905\t9\t7\t18\t-1\t\n5\t1\t4\t1\t1\t1\t1905\t9\t7\t18\t77.647636\tI\n";

    // ── parse_word_rows / assemble against the real fixtures ────────────

    #[test]
    fn multiline_fixture_skips_header_and_non_word_rows_keeping_only_the_six_words() {
        let rows = parse_word_rows(TSV_MULTILINE);
        assert_eq!(rows.len(), 6, "{rows:?}");
        assert_eq!(rows.iter().map(|r| r.text.as_str()).collect::<Vec<_>>(),
            vec!["aoide", "screen", "ocr", "phase", "3", "fixture"]);
    }

    #[test]
    fn multiline_fixture_concatenates_in_order_with_a_real_line_break() {
        let result = assemble(TSV_MULTILINE, hypr::Point { x: 0, y: 0 }, 1.0);
        assert_eq!(result.text, "aoide screen ocr\nphase 3 fixture");
        assert_eq!(result.words.len(), 6);
    }

    #[test]
    fn bar_fixture_drops_the_three_zero_confidence_glyph_misreads() {
        let rows = parse_word_rows(TSV_BAR);
        let texts: Vec<&str> = rows.iter().map(|r| r.text.as_str()).collect();
        assert_eq!(texts, vec!["4", "==", "I"], "sosiizaw/swdayagoo/S (all 0.0 conf) must be filtered");
        for r in &rows {
            assert!(r.conf >= MIN_CONFIDENCE, "{r:?}");
        }
    }

    #[test]
    fn bar_fixture_survivors_share_one_line_space_joined() {
        // All three surviving words' vertical spans overlap (they sit
        // within the same 36px bar strip) — no line break among them.
        let result = assemble(TSV_BAR, hypr::Point { x: 0, y: 0 }, 1.0);
        assert_eq!(result.text, "4 == I");
    }

    #[test]
    fn word_rows_carry_the_real_measured_confidences() {
        let rows = parse_word_rows(TSV_BAR);
        let confs: Vec<f64> = rows.iter().map(|r| r.conf).collect();
        assert!((confs[0] - 68.086349).abs() < 1e-6);
        assert!((confs[1] - 74.038628).abs() < 1e-6);
        assert!((confs[2] - 77.647636).abs() < 1e-6);
    }

    // ── malformed-row tolerance — HAND-CORRUPTED from the real multiline
    // fixture (real tesseract never emits genuinely malformed TSV; this
    // case exists to prove the parser doesn't panic/misparse on bad input,
    // stated plainly rather than passed off as live output) ─────────────

    #[test]
    fn malformed_rows_are_skipped_not_panicked_on() {
        let tsv = "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext\n\
                   truncated\trow\twith\tfar\ttoo\tfew\tfields\n\
                   5\t1\t1\t1\t1\t1\tNaN\t11\t64\t19\t91.6\taoide\n\
                   5\t1\t1\t1\t1\t2\t85\t16\t77\t14\tnot-a-number\tscreen\n\
                   \n\
                   5\t1\t1\t1\t1\t3\t172\t16\t37\t14\t89.21\tocr\n";
        let rows = parse_word_rows(tsv);
        // Only the one well-formed word row survives; the truncated row,
        // the non-numeric-left row, the non-numeric-conf row, and the blank
        // line are all silently skipped — no panic, no garbage entry.
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].text, "ocr");
    }

    #[test]
    fn empty_text_after_trim_is_dropped() {
        let tsv = "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext\n\
                   5\t1\t1\t1\t1\t1\t10\t10\t10\t10\t95.0\t   \n\
                   5\t1\t1\t1\t1\t2\t20\t10\t10\t10\t95.0\treal\n";
        let rows = parse_word_rows(tsv);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].text, "real");
    }

    // ── vertically_overlaps ──────────────────────────────────────────────

    fn rw(top: i64, height: i64) -> RawWord {
        RawWord { left: 0, top, width: 10, height, conf: 90.0, text: "x".into() }
    }

    #[test]
    fn overlapping_spans_are_the_same_line() {
        assert!(vertically_overlaps(&rw(10, 20), &rw(15, 20))); // [10,30) vs [15,35)
    }

    #[test]
    fn disjoint_spans_are_different_lines() {
        assert!(!vertically_overlaps(&rw(0, 10), &rw(20, 10))); // [0,10) vs [20,30)
    }

    #[test]
    fn exactly_touching_spans_do_not_overlap() {
        // [0,10) then [10,20): edges touch but no shared pixel row.
        assert!(!vertically_overlaps(&rw(0, 10), &rw(10, 10)));
    }

    #[test]
    fn vertical_spans_overlap_saturates_instead_of_panicking_on_adversarial_extremes() {
        // A hand-edited sidecar `.json` can carry any i64 in `bbox.y`/`bbox.h`
        // — `screen::text`'s phrase matcher feeds this function that field
        // straight off disk, unlike `assemble`'s own real-TSV call site.
        // Plain `+` here would panic in debug / wrap in release; must not.

        // An overflow-prone height (10 + i64::MAX would panic/wrap) still
        // correctly detects a genuine overlap once saturated.
        assert!(vertical_spans_overlap(10, i64::MAX, 8, 5));

        // Saturating the bottom to i64::MAX doesn't fabricate an overlap —
        // the OTHER span's top (100) is still past where it actually ends.
        assert!(!vertical_spans_overlap(100, i64::MAX, 0, 10));

        // Opposite extremes, one side saturates: genuinely far apart, no
        // panic, no false overlap.
        assert!(!vertical_spans_overlap(i64::MIN, 5, i64::MAX, 5));
    }

    // ── scale_is_valid — the ocr() call-site guard (khoa's review polish:
    // a hand-edited/corrupt sidecar's scale must not reach the division in
    // image_bbox_to_screen unchecked) ───────────────────────────────────

    #[test]
    fn scale_is_valid_accepts_ordinary_positive_values() {
        assert!(scale_is_valid(1.0));
        assert!(scale_is_valid(0.5));
        assert!(scale_is_valid(2.0));
    }

    #[test]
    fn scale_is_valid_rejects_zero_negative_nan_and_infinite() {
        assert!(!scale_is_valid(0.0));
        assert!(!scale_is_valid(-1.0));
        assert!(!scale_is_valid(f64::NAN));
        assert!(!scale_is_valid(f64::INFINITY));
        assert!(!scale_is_valid(f64::NEG_INFINITY));
    }

    // ── image_bbox_to_screen: scale 1.0 (identity-ish) and fractional ───

    #[test]
    fn transform_at_scale_one_is_origin_plus_image_px_unchanged() {
        let got = image_bbox_to_screen(
            hypr::Point { x: 100, y: 50 },
            1.0,
            hypr::Region { x: 20, y: 10, w: 5, h: 3 },
        );
        assert_eq!(got, hypr::Region { x: 120, y: 60, w: 5, h: 3 });
    }

    #[test]
    fn transform_at_scale_two_halves_every_image_pixel_dimension() {
        // The scaled case that silently breaks if you forget to divide.
        let got = image_bbox_to_screen(
            hypr::Point { x: 100, y: 50 },
            2.0,
            hypr::Region { x: 40, y: 20, w: 10, h: 6 },
        );
        assert_eq!(got, hypr::Region { x: 120, y: 60, w: 5, h: 3 });
    }

    #[test]
    fn transform_at_a_non_power_of_two_fractional_scale() {
        let got = image_bbox_to_screen(
            hypr::Point { x: 0, y: 0 },
            1.5,
            hypr::Region { x: 150, y: 75, w: 30, h: 15 },
        );
        assert_eq!(got, hypr::Region { x: 100, y: 50, w: 20, h: 10 });
    }

    #[test]
    fn transform_rounds_to_the_nearest_pixel_rather_than_truncating() {
        // 10 / 3 = 3.333... — must round to 3, not truncate weirdly or floor
        // differently; mirrors `expected_image_size`'s own rounding
        // convention for the forward direction.
        let got = image_bbox_to_screen(
            hypr::Point { x: 0, y: 0 },
            3.0,
            hypr::Region { x: 10, y: 10, w: 10, h: 10 },
        );
        assert_eq!(got, hypr::Region { x: 3, y: 3, w: 3, h: 3 });
    }

    #[test]
    fn a_real_bar_word_transforms_correctly_at_identity_scale_zero_origin() {
        // Cross-check against the real fixture: "4"'s image bbox
        // (8,4,11,28) at origin (0,0) scale 1.0 must land unchanged — this
        // rig's one monitor captures at scale 1.00 (khoa's Phase 1 note),
        // so this is the common case in practice.
        let got = image_bbox_to_screen(hypr::Point { x: 0, y: 0 }, 1.0, hypr::Region { x: 8, y: 4, w: 11, h: 28 });
        assert_eq!(got, hypr::Region { x: 8, y: 4, w: 11, h: 28 });
    }

    // ── tesseract argv assembly (pure) ──────────────────────────────────

    #[test]
    fn tesseract_argv_shape() {
        let args = tesseract_argv(Path::new("/tmp/shot.png"), 11);
        assert_eq!(args, vec!["/tmp/shot.png", "stdout", "--psm", "11", "tsv"]);
    }

    // ── OcrError reason codes never name tesseract ──────────────────────

    #[test]
    fn ocr_error_reasons_never_name_tesseract() {
        let u = OcrError::Unavailable("no such file or directory".to_string());
        let f = OcrError::Failed("some tesseract stderr text".to_string());
        assert_eq!(u.reason(), "ocr-unavailable");
        assert_eq!(f.reason(), "ocr-failed");
        assert!(!u.reason().contains("tesseract"));
        assert!(!f.reason().contains("tesseract"));
        assert_eq!(f.detail(), "some tesseract stderr text");
    }

    // ── Sidecar round-trip: ocr:null → populated → reserialized, the rest
    // of the sidecar untouched ───────────────────────────────────────────

    #[test]
    fn sidecar_round_trips_with_the_ocr_block_populated_and_the_rest_intact() {
        // `desktop` is POPULATED here, not `None` (khoa's Phase D review nit)
        // — `ocr()`'s write-back reserializes the WHOLE sidecar, and only a
        // typed `Option<hypr::DesktopSnapshot>` field surviving that
        // round-trip actually proves it; a `None` value would pass even if
        // the field were silently dropped somewhere in the pipe.
        let desktop = hypr::DesktopSnapshot {
            cursor: hypr::Point { x: 500, y: 18 },
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
        };
        let mut sidecar = Sidecar {
            schema_version: super::super::capture::SIDECAR_SCHEMA_VERSION.to_string(),
            captured_at: "2026-08-16T05:00:00Z".to_string(),
            origin: hypr::Point { x: 0, y: 0 },
            size: hypr::Size { w: 1920, h: 36 },
            scale: 1.0,
            format: "png".to_string(),
            quality: 80,
            monitor: None,
            session: None,
            window: None,
            class: None,
            title: None,
            comment: None,
            cursor_drawn: Some(true),
            desktop: Some(desktop),
            ocr: None,
            // Populated here too (khoa, 2026-08-17, Phase E) — same reason
            // as `desktop` just above: only a POPULATED `Option<Value>`
            // actually proves ocr()'s write-back doesn't silently drop a
            // field it never reads, a `None` would pass even if the field
            // vanished somewhere in the pipe.
            diff: Some(serde_json::json!({ "changed": false, "changedFraction": 0.0 })),
            region: None,
        };
        let before_text = serde_json::to_string(&sidecar).unwrap();
        assert!(before_text.contains("\"ocr\":null"));
        assert!(before_text.contains("\"desktop\":"));
        assert!(before_text.contains("\"diff\":{"));

        let result = assemble(TSV_BAR, sidecar.origin, sidecar.scale);
        sidecar.ocr = Some(serde_json::to_value(&result).unwrap());

        let after_text = serde_json::to_string_pretty(&sidecar).unwrap() + "\n";
        let back: Sidecar = serde_json::from_str(&after_text).unwrap();

        // The ocr block landed...
        assert!(back.ocr.is_some());
        let ocr_value = back.ocr.unwrap();
        assert_eq!(ocr_value["text"], "4 == I");
        assert_eq!(ocr_value["words"].as_array().unwrap().len(), 3);
        // ...and everything else round-tripped untouched — desktop/
        // cursorDrawn/diff INCLUDED, pinning that ocr()'s write-back doesn't
        // silently drop the Phase D/E fields it never even reads.
        assert_eq!(back.origin, sidecar.origin);
        assert_eq!(back.size, sidecar.size);
        assert_eq!(back.scale, sidecar.scale);
        assert_eq!(back.format, sidecar.format);
        assert_eq!(back.quality, sidecar.quality);
        assert_eq!(back.schema_version, sidecar.schema_version);
        assert_eq!(back.captured_at, sidecar.captured_at);
        assert_eq!(back.cursor_drawn, sidecar.cursor_drawn);
        assert_eq!(back.desktop, sidecar.desktop);
        assert_eq!(back.diff, sidecar.diff);
    }

    // ── OcrResult / Word JSON shape matches the brief's contract exactly ─

    #[test]
    fn ocr_result_serializes_to_the_specified_shape() {
        let result = assemble(TSV_MULTILINE, hypr::Point { x: 0, y: 0 }, 1.0);
        let v = serde_json::to_value(&result).unwrap();
        assert!(v.get("text").is_some());
        assert!(v.get("words").is_some());
        let w0 = &v["words"][0];
        assert!(w0.get("text").is_some());
        assert!(w0.get("conf").is_some());
        let bbox = &w0["bbox"];
        assert!(bbox.get("x").is_some());
        assert!(bbox.get("y").is_some());
        assert!(bbox.get("w").is_some());
        assert!(bbox.get("h").is_some());
    }
}
