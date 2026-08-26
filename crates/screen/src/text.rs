//! `aoide screen point text <text>` — click a word/phrase `screen ocr`
//! already located (khoa, 2026-08-17, Phase F of the pointer-emulation
//! workstream). The cheapest high-value grounding primitive this whole
//! family has: tesseract's word bboxes are ALREADY absolute screen
//! coordinates by the time they land in a capture's sidecar (`ocr.rs`'s own
//! module header, "Coordinate transform: image pixels → ABSOLUTE SCREEN
//! coordinates") — so an agent that OCR'd a capture can click a word by
//! NAME instead of picking a pixel off the image by eye.
//!
//! ── `--from-shot` means something DIFFERENT here (state it loudly) ────────
//! Every other coordinate-taking `screen point` command (`move`/`click`/
//! `drag`/`hover`) treats `--from-shot <capture>` as "the x/y I gave you are
//! IMAGE pixels off that capture — convert them to screen space before
//! moving" ([`super::point::resolve_from_shot_point`]). `screen point text`
//! reuses the exact same FLAG NAME for consistency — an agent that has
//! learned `--from-shot` from any other command should not have to learn a
//! second spelling — but the SEMANTICS diverge: here it names the OCR
//! SOURCE (which sidecar's `ocr` block to search), never a coordinate space
//! to convert out of. [`ocr::Word::bbox`] is already screen space (see
//! above); running it through [`super::capture::Sidecar::image_point_to_screen`]
//! (or any other image→screen transform) a SECOND time would silently
//! double-apply `origin`/`scale` and click the wrong spot — the classic bug
//! a caller lured by the shared flag name could reintroduce. This file never
//! calls that transform; it only reads `sidecar.ocr` off the same sidecar
//! `--from-shot` already names.
//!
//! ── The matcher is pure ────────────────────────────────────────────────
//! [`find_text_matches`] takes a `&[ocr::Word]` and a needle and returns
//! every match, sorted top-left-first — no hyprctl, no synth boundary, unit-
//! tested directly. `point_text`'s handler is the only impure part: it reads
//! a sidecar off disk, then (past `--dry-run`) crosses the pointer-synthesis
//! boundary via the SAME move+verify and guarded-click primitives
//! [`super::point::point_move`]/[`super::point::point_click`] already use —
//! nothing new invented at that boundary, just composed: move to the
//! match's centre (drift refuses, as usual), then the same exact-match
//! guard `click`'s own optional `x y` guard performs, then one click.

use super::hypr;
use super::ocr;
use super::point::{self, Button};
use super::synth;
use aoide_protocol::output::Outcome;
use aoide_protocol::Invocation;
use serde_json::json;

// ── The match shape ─────────────────────────────────────────────────────

/// One resolved match: `nth` is 1-based, in the SAME top-left-first order
/// [`find_text_matches`] returns (so `--nth` on the CLI and this struct's
/// own `nth` always agree). `text` is the matched word's (or phrase's)
/// original-case text off the sidecar, space-joined for a multi-word match
/// — never the lowercased form used to compare it against the needle.
#[derive(Debug, Clone, PartialEq)]
pub struct Match {
    pub nth: usize,
    pub text: String,
    pub bbox: hypr::Region,
    pub centre: hypr::Point,
}

/// The union of every word's bbox in `span` — never empty (callers only
/// pass a non-empty slice, one word per matched token). Saturating: a
/// hand-edited/corrupt sidecar can carry adversarial `i64` bbox values (the
/// same threat model `capture.rs`'s `clamp_region`/`transform_point` already
/// guard against for the same reason — this is a JSON file on disk, not
/// necessarily one `screen ocr` itself wrote).
fn union_bbox(span: &[ocr::Word]) -> hypr::Region {
    let mut min_x = i64::MAX;
    let mut min_y = i64::MAX;
    let mut max_x = i64::MIN;
    let mut max_y = i64::MIN;
    for w in span {
        min_x = min_x.min(w.bbox.x);
        min_y = min_y.min(w.bbox.y);
        max_x = max_x.max(w.bbox.x.saturating_add(w.bbox.w));
        max_y = max_y.max(w.bbox.y.saturating_add(w.bbox.h));
    }
    hypr::Region {
        x: min_x,
        y: min_y,
        w: max_x.saturating_sub(min_x).max(0),
        h: max_y.saturating_sub(min_y).max(0),
    }
}

/// Integer centre of `bbox` — `x + w/2, y + h/2`, floor. `w`/`h` are always
/// `>= 0` (see [`union_bbox`]), so plain integer division already floors;
/// no separate rounding rule needed for the odd-width case.
fn centre_of(bbox: hypr::Region) -> hypr::Point {
    hypr::Point { x: bbox.x.saturating_add(bbox.w / 2), y: bbox.y.saturating_add(bbox.h / 2) }
}

/// Find every place `needle` appears among `words`, case-insensitively
/// (Unicode-aware — `str::to_lowercase` on both sides, not an ASCII-only
/// fold, so e.g. `"Ä"`/`"ä"` compare equal). Exact equality, never
/// substring: a needle `"Save"` does NOT match a word `"Saved"` — the
/// "helpful" edit a future pass might be tempted to make, pinned by test.
///
/// A single-token needle matches any ONE word whose trimmed, lowercased
/// text equals the needle's own trimmed, lowercased text. A multi-word
/// needle (split on whitespace) matches a run of CONSECUTIVE words — in
/// `words`' own order, which is tesseract TSV order VERBATIM (`assemble`
/// does not sort; see that function's own doc) — whose texts match
/// token-for-token AND form one plausible phrase, checked pairwise,
/// adjacent word to adjacent word:
///
/// - vertically: bboxes overlap ([`ocr::vertical_spans_overlap`], the EXACT
///   same same-line predicate `ocr::assemble` itself uses deciding a space
///   vs. a newline — reused here, not reinvented, so a caller never has to
///   reason about two different "same line" rules agreeing);
/// - horizontally: the gap between one word's right edge and the next
///   word's left edge is no more than the taller of the two words' own
///   height — a cheap, scale-independent stand-in for "a plausible
///   inter-word space." Without this bound, two words that are merely
///   TSV-adjacent and happen to vertically overlap — e.g. sitting in
///   different columns of the same table row — would form one "phrase"
///   whose union bbox spans the whitespace between them, and the live path
///   would click that gap. Rejecting the span is the correct read: two
///   words on opposite sides of a table row aren't a phrase.
///
/// Every match's `bbox` is the union of its span's word bboxes
/// ([`union_bbox`]); `centre` is that union's integer centre
/// ([`centre_of`]). Returned SORTED top-left-first: matches are bucketed by
/// row first (via the same [`ocr::vertical_spans_overlap`] predicate, not
/// by comparing `y` corners directly — two same-line matches with
/// different ink heights can have their `y` corners invert even though
/// their spans plainly overlap) and sorted left-to-right within a row;
/// `nth` is 1-based in that same order. Pure — no I/O, no hyprctl, no synth
/// boundary; unit-tested directly.
pub fn find_text_matches(words: &[ocr::Word], needle: &str) -> Vec<Match> {
    let tokens: Vec<String> = needle.split_whitespace().map(|t| t.to_lowercase()).collect();
    if tokens.is_empty() || tokens.len() > words.len() {
        return Vec::new();
    }
    let span = tokens.len();
    let mut found: Vec<(hypr::Region, String)> = Vec::new();
    for start in 0..=(words.len() - span) {
        let candidate = &words[start..start + span];
        let texts_match = candidate
            .iter()
            .zip(tokens.iter())
            .all(|(w, t)| w.text.trim().to_lowercase() == *t);
        if !texts_match {
            continue;
        }
        // Both vacuously true for a single-token span (`windows(2)` yields
        // no pairs) — these checks only apply once there is a neighbour to
        // compare against.
        let same_line = candidate.windows(2).all(|pair| {
            ocr::vertical_spans_overlap(pair[0].bbox.y, pair[0].bbox.h, pair[1].bbox.y, pair[1].bbox.h)
        });
        if !same_line {
            continue;
        }
        // Order-independent separation, not `next.x - prev.right`: tesseract
        // TSV order is reading order, not left-to-right x order, so a word
        // can legitimately sit to the LEFT of its TSV-predecessor across a
        // PSM-11 block boundary. `next.x - prev.right` goes NEGATIVE in
        // that case and `gap <= bound` accepts it unconditionally — a
        // right-then-left pair spanning the whole row would "match" with a
        // whitespace centre. `sep` instead measures the true horizontal gap
        // between the two bboxes regardless of which one is which side:
        // <= 0 whenever they overlap/kern, the real x-distance otherwise.
        let plausible_gap = candidate.windows(2).all(|pair| {
            let (a, b) = (pair[0].bbox, pair[1].bbox);
            let sep = a.x.max(b.x).saturating_sub(a.x.saturating_add(a.w).min(b.x.saturating_add(b.w)));
            sep <= a.h.max(b.h)
        });
        if !plausible_gap {
            continue;
        }
        let bbox = union_bbox(candidate);
        let text = candidate.iter().map(|w| w.text.trim()).collect::<Vec<_>>().join(" ");
        found.push((bbox, text));
    }
    // Row-bucket first (same-line via vertical overlap, not raw `y` corner
    // comparison, and NOT a `sort_by` predicate over the pair — vertical
    // overlap is intransitive: a "staircase" of three matches can have
    // A~B and B~C overlap while A and C don't, a genuine cycle a
    // comparator can't express. `slice::sort_by` detects that and panics
    // ("does not correctly implement a total order"); reachable both from
    // a hand-edited sidecar and from ordinary OCR with mixed ink heights.
    // Grouping instead: sort by `y` corner first (a real total order, just
    // not always the right VISUAL order — that's what rows fix), then walk
    // once, testing each candidate against its row's FIRST element only
    // (a fixed reference, so membership never depends on join order),
    // finally sorting left-to-right within each row.
    found.sort_by_key(|m| (m.0.y, m.0.x));
    let mut rows: Vec<Vec<(hypr::Region, String)>> = Vec::new();
    for m in found {
        match rows.last_mut() {
            Some(row) if ocr::vertical_spans_overlap(row[0].0.y, row[0].0.h, m.0.y, m.0.h) => {
                row.push(m)
            }
            _ => rows.push(vec![m]),
        }
    }
    for row in &mut rows {
        row.sort_by_key(|m| m.0.x);
    }
    rows.into_iter()
        .flatten()
        .enumerate()
        .map(|(i, (bbox, text))| Match { nth: i + 1, centre: centre_of(bbox), bbox, text })
        .collect()
}

fn match_to_json(m: &Match) -> serde_json::Value {
    json!({
        "nth": m.nth,
        "text": m.text,
        "bbox": { "x": m.bbox.x, "y": m.bbox.y, "w": m.bbox.w, "h": m.bbox.h },
        "centre": { "x": m.centre.x, "y": m.centre.y },
    })
}

// ── `--nth` ──────────────────────────────────────────────────────────────

/// `--nth`'s flag value, parsed and 1-based-validated — but NOT yet checked
/// against a match count, which is only known once [`find_text_matches`] has
/// run (see [`nth_in_range`] for that half). `None` (flag absent) is not an
/// error; `0` and anything non-numeric are.
pub fn parse_nth_flag(raw: Option<&String>) -> Result<Option<u32>, String> {
    match raw {
        None => Ok(None),
        Some(s) => match s.parse::<u32>() {
            Ok(0) => Err("--nth is 1-based, got 0".to_string()),
            Ok(n) => Ok(Some(n)),
            Err(_) => Err(format!("--nth must be a positive integer, got `{s}`")),
        },
    }
}

/// Why `--nth` was refused once a match count is known — carries both
/// numbers so the caller's usage error can name the valid range without a
/// second lookup (mirrors this crate's other refusal shapes, e.g.
/// `point::ClickRefusal`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NthOutOfRange {
    pub requested: u32,
    pub available: usize,
}

/// `nth` (1-based) → a 0-based index into a `matches` slice of length
/// `available`, or the bound it violated. Pure — takes the count rather
/// than the slice itself, so it's unit-tested without constructing a real
/// match set.
pub fn nth_in_range(nth: u32, available: usize) -> Result<usize, NthOutOfRange> {
    let idx = nth as usize;
    if idx >= 1 && idx <= available {
        Ok(idx - 1)
    } else {
        Err(NthOutOfRange { requested: nth, available })
    }
}

// ── `aoide screen point text <text>` ────────────────────────────────────

/// `aoide screen point text <text> --from-shot <capture> [--nth N]
/// [--button left|right|middle] [--dry-run]` — see the module header for
/// the full design, especially the `--from-shot` semantics warning.
///
/// `--dry-run` is a pure read (safe to run live: resolves the match and
/// reports its centre, no pointer motion at all). Past that point the
/// handler crosses the pointer-synthesis boundary and is NOT unit-tested —
/// same split every other click-capable command in this file already draws
/// (khoa's Phase 2 brief, HARD RULE 5, still the rule here even though this
/// command isn't itself phase-gated: a live click must never run in a test).
pub fn point_text(inv: &Invocation) -> Outcome {
    let cmd = "screen.point.text";
    let usage = || {
        format!(
            "usage: aoide {} <text> --from-shot <capture> [--nth N] [--button left|right|middle] [--dry-run] [--json]",
            inv.path.join(" ")
        )
    };
    let Some(needle) = inv.args.first() else {
        return Outcome::usage(cmd, usage());
    };
    if inv.args.len() > 1 {
        // The CLI parser gives one positional token per (unquoted) shell
        // arg — `point text Save Changes --from-shot X` lands here as TWO
        // args, not one two-word phrase. Silently searching just "Save" and
        // clicking it would be an irreversible click on possibly the wrong
        // target with no signal anything was discarded — the same
        // never-silently-drop policy `point::parse_click_args` already
        // holds for its own extra-args case. Refuse instead.
        let extra = inv.args.len() - 1;
        return Outcome::usage(
            cmd,
            format!(
                "quote a multi-word phrase as one argument — {extra} trailing arg(s) don't fit that shape"
            ),
        );
    }
    let Some(capture_path) = inv.flags.get("from-shot") else {
        return Outcome::usage(
            cmd,
            format!("{} — --from-shot is required: the sidecar is where the OCR words live", usage()),
        );
    };
    let button = match inv.flags.get("button") {
        None => Button::Left,
        Some(s) => match Button::parse(s) {
            Some(b) => b,
            None => return Outcome::usage(cmd, format!("--button must be left|right|middle, got `{s}`")),
        },
    };
    let nth = match parse_nth_flag(inv.flags.get("nth")) {
        Ok(v) => v,
        Err(msg) => return Outcome::usage(cmd, msg),
    };
    let dry_run = inv.flag_present("dry-run");

    // ── Read the sidecar named by --from-shot (the OCR SOURCE here, never a
    // coordinate space — see the module header). Hard-erroring reader, same
    // as every other `--from-shot` consumer in this crate.
    let sidecar = match point::from_shot_sidecar(cmd, capture_path) {
        Ok(s) => s,
        Err(outcome) => return outcome,
    };
    let Some(ocr_value) = sidecar.ocr else {
        return Outcome::error(cmd, "capture has no OCR data (run `screen ocr <capture>` first)")
            .with_data(json!({ "reason": "text-no-ocr" }));
    };
    let ocr_result: ocr::OcrResult = match serde_json::from_value(ocr_value) {
        Ok(r) => r,
        Err(e) => {
            return Outcome::error(cmd, format!("sidecar's ocr block is malformed: {e}"))
                .with_data(json!({ "reason": "sidecar-corrupt" }));
        }
    };
    let words = ocr_result.words;

    let matches = find_text_matches(&words, needle);
    if matches.is_empty() {
        return Outcome::error(cmd, format!("no match for \"{needle}\" among {} word(s)", words.len()))
            .with_data(json!({
                "reason": "text-not-found",
                "needle": needle,
                "wordsSearched": words.len(),
            }));
    }

    let chosen: &Match = match nth {
        Some(n) => match nth_in_range(n, matches.len()) {
            Ok(i) => &matches[i],
            Err(e) => {
                return Outcome::usage(cmd, format!("--nth must be 1-{}, got {}", e.available, e.requested))
            }
        },
        None if matches.len() == 1 => &matches[0],
        None => {
            return Outcome::error(
                cmd,
                format!(
                    "{} matches for \"{needle}\" — pass --nth 1-{} to pick one",
                    matches.len(),
                    matches.len()
                ),
            )
            .with_data(json!({
                "reason": "text-ambiguous",
                "needle": needle,
                "candidates": matches.iter().map(match_to_json).collect::<Vec<_>>(),
            }));
        }
    };

    if dry_run {
        return Outcome::ok(
            cmd,
            format!(
                "would click {} at {},{} on \"{}\"",
                button.as_str(),
                chosen.centre.x,
                chosen.centre.y,
                chosen.text
            ),
        )
        .with_data(json!({ "match": match_to_json(chosen), "button": button.as_str() }));
    }

    // ── Live path — NOT unit-tested past here (crosses the
    // pointer-synthesis boundary). Move+verify to the match's centre —
    // identical shape to `point_move`'s own drift check — then the SAME
    // guarded click `point_click`'s own optional `x y` guard performs
    // (`guard_click` against the centre) before firing, catching a human
    // bump in the tiny window between the move and the press.
    let current = match hypr::cursor() {
        Ok(p) => p,
        Err(e) => return hypr::hypr_error_outcome(cmd, &e),
    };
    let (dx, dy) = point::move_delta(current, chosen.centre);
    if let Err(e) = synth::synthesize(&point::move_seq(dx, dy)) {
        return point::pointer_error_outcome(cmd, &e);
    }
    let landed = match hypr::cursor() {
        Ok(p) => p,
        Err(e) => return hypr::hypr_error_outcome(cmd, &e),
    };
    if let point::MoveResult::Drifted { got } = point::classify_landing(chosen.centre, landed) {
        return Outcome::error(
            cmd,
            format!(
                "drift — pointer at {},{}, wanted {},{}: a human moved the mouse, or the target is off-screen",
                got.x, got.y, chosen.centre.x, chosen.centre.y
            ),
        )
        .with_data(json!({
            "reason": "pointer-drift",
            "x": got.x, "y": got.y,
            "wanted": { "x": chosen.centre.x, "y": chosen.centre.y },
        }));
    }

    let actual = match hypr::cursor() {
        Ok(p) => p,
        Err(e) => return hypr::hypr_error_outcome(cmd, &e),
    };
    if let Err(refusal) = point::guard_click(Some(chosen.centre), actual) {
        return Outcome::error(
            cmd,
            format!(
                "pointer at {},{}, expected {},{} — not pressing blind",
                refusal.at.x, refusal.at.y, refusal.expected.x, refusal.expected.y
            ),
        )
        .with_data(json!({ "reason": "pointer-refused" }));
    }

    if let Err(e) = synth::synthesize(&point::click_seq(button, 1)) {
        return point::pointer_error_outcome(cmd, &e);
    }

    Outcome::ok(
        cmd,
        format!(
            "clicked {} at {},{} on \"{}\"",
            button.as_str(),
            chosen.centre.x,
            chosen.centre.y,
            chosen.text
        ),
    )
    .with_data(json!({ "match": match_to_json(chosen), "button": button.as_str() }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(text: &str, x: i64, y: i64, w: i64, h: i64) -> ocr::Word {
        ocr::Word { text: text.to_string(), conf: 90.0, bbox: hypr::Region { x, y, w, h } }
    }

    // ── find_text_matches: single token ─────────────────────────────────

    #[test]
    fn exact_single_word_matches() {
        let words = vec![word("Save", 10, 10, 40, 20)];
        let matches = find_text_matches(&words, "Save");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].nth, 1);
        assert_eq!(matches[0].text, "Save");
        assert_eq!(matches[0].bbox, hypr::Region { x: 10, y: 10, w: 40, h: 20 });
    }

    #[test]
    fn case_folding_matches_mixed_case_needle_against_mixed_case_word() {
        let words = vec![word("SaVe", 0, 0, 10, 10)];
        assert_eq!(find_text_matches(&words, "sAvE").len(), 1);
    }

    #[test]
    fn non_ascii_case_folding_matches_capital_a_umlaut() {
        let words = vec![word("Ä", 0, 0, 10, 10)];
        assert_eq!(find_text_matches(&words, "ä").len(), 1, "Ä should fold to ä");
    }

    #[test]
    fn non_ascii_case_folding_matches_lowercase_a_umlaut_needle() {
        let words = vec![word("ä", 0, 0, 10, 10)];
        assert_eq!(find_text_matches(&words, "Ä").len(), 1, "ä should fold to match Ä");
    }

    // ── find_text_matches: multi-word phrase / same-line heuristic ──────

    #[test]
    fn phrase_spanning_two_same_line_words_matches() {
        let words = vec![word("Save", 0, 0, 40, 20), word("Changes", 45, 2, 60, 20)];
        let matches = find_text_matches(&words, "Save Changes");
        assert_eq!(matches.len(), 1, "{matches:?}");
        assert_eq!(matches[0].text, "Save Changes");
    }

    #[test]
    fn same_words_split_across_different_lines_does_not_match() {
        // [0,20) vs [50,70) — no vertical overlap at all.
        let words = vec![word("Save", 0, 0, 40, 20), word("Changes", 0, 50, 60, 20)];
        assert!(find_text_matches(&words, "Save Changes").is_empty());
    }

    #[test]
    fn exact_match_never_substring_matches_a_longer_word() {
        // The exact "helpful" edit a future pass would be tempted to make:
        // swapping the `==` for `.contains()`. Pinned so that slip can't
        // land silently — "Save" must never match a word that merely
        // starts with it.
        let words = vec![word("Saved", 0, 0, 50, 20)];
        assert!(find_text_matches(&words, "Save").is_empty());
    }

    #[test]
    fn phrase_tokens_must_be_consecutive_not_scattered_across_other_words() {
        // "Save" and "Changes" both appear, but "All" sits between them —
        // no window of the search ever lines up ["save", "changes"].
        let words =
            vec![word("Save", 0, 0, 30, 20), word("All", 35, 0, 20, 20), word("Changes", 60, 0, 60, 20)];
        assert!(find_text_matches(&words, "Save Changes").is_empty());
    }

    #[test]
    fn phrase_words_within_a_plausible_gap_match() {
        // gap = 55 - (0+40) = 15; bound = taller word's height = 20 -> within.
        let words = vec![word("Save", 0, 0, 40, 20), word("Changes", 55, 0, 60, 20)];
        assert_eq!(find_text_matches(&words, "Save Changes").len(), 1);
    }

    #[test]
    fn phrase_words_separated_by_a_wide_gap_do_not_match() {
        // gap = 100 - (0+40) = 60; bound = 20 -> 3x over, rejected. This is
        // the table-row case: two words that are TSV-adjacent and
        // vertically overlap but sit in different columns aren't a phrase
        // — their union centre would be the whitespace between them.
        let words = vec![word("Save", 0, 0, 40, 20), word("Changes", 100, 0, 60, 20)];
        assert!(find_text_matches(&words, "Save Changes").is_empty());
    }

    #[test]
    fn phrase_gap_bound_is_order_independent_a_reversed_pair_with_a_huge_jump_is_rejected() {
        // TSV order says "Right" comes before "Left", but "Left" sits far
        // to the LEFT on screen (reachable across a PSM-11 block boundary).
        // `next.x - prev.right` goes NEGATIVE here and would pass
        // unconditionally under the old order-assuming gap check — exactly
        // the false-phrase case the order-independent `sep` formula exists
        // to catch (a right-then-left pair spanning the whole row is not a
        // phrase; its union centre would be empty space).
        let words = vec![word("Right", 500, 0, 50, 20), word("Left", 0, 0, 50, 20)];
        assert!(find_text_matches(&words, "Right Left").is_empty());
    }

    #[test]
    fn zero_matches_when_needle_is_absent() {
        let words = vec![word("Foo", 0, 0, 10, 10)];
        assert!(find_text_matches(&words, "Bar").is_empty());
    }

    #[test]
    fn zero_matches_when_phrase_is_longer_than_the_word_list() {
        let words = vec![word("Foo", 0, 0, 10, 10)];
        assert!(find_text_matches(&words, "Foo Bar Baz").is_empty());
    }

    // ── find_text_matches: ordering ──────────────────────────────────────

    #[test]
    fn multiple_matches_ordered_top_left_first_even_when_words_are_scrambled() {
        // Deliberately out of order: the lower/righter "Ok" comes FIRST in
        // the input slice.
        let words = vec![word("Ok", 100, 50, 20, 20), word("Ok", 10, 10, 20, 20)];
        let matches = find_text_matches(&words, "Ok");
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].nth, 1);
        assert_eq!(matches[0].bbox.y, 10, "top-left-first: smallest y wins nth=1");
        assert_eq!(matches[1].nth, 2);
        assert_eq!(matches[1].bbox.y, 50);
    }

    #[test]
    fn matches_at_the_same_y_order_by_x() {
        let words = vec![word("Hi", 100, 0, 10, 10), word("Hi", 10, 0, 10, 10)];
        let matches = find_text_matches(&words, "Hi");
        assert_eq!(matches[0].bbox.x, 10);
        assert_eq!(matches[1].bbox.x, 100);
    }

    #[test]
    fn same_line_matches_with_different_ink_heights_sort_by_x_not_by_y_corner() {
        // A's top y=10 < B's top y=12, so comparing raw y CORNERS would put
        // A (x=50) before B (x=10) — backwards. Their spans plainly overlap
        // ([10,15) vs [12,32)), so row-bucketing (vertical_spans_overlap,
        // not a corner comparison) puts them in one row and sorts
        // left-to-right instead.
        let words = vec![word("Hi", 50, 10, 10, 5), word("Hi", 10, 12, 10, 20)];
        let matches = find_text_matches(&words, "Hi");
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].bbox.x, 10, "leftmost word in the shared row is nth=1");
        assert_eq!(matches[1].bbox.x, 50);
    }

    #[test]
    fn staircase_overlap_pattern_does_not_panic_and_orders_deterministically() {
        // Intransitive vertical overlap: A ([0,10)) overlaps B ([8,18)),
        // B overlaps C ([16,26)), but A and C are disjoint — a genuine
        // cycle no comparator can express as a total order. A `sort_by`
        // over this triple panics on Rust 1.81+ ("does not correctly
        // implement a total order"); undetected, nth assignment would be
        // arbitrary. Grouping against each row's FIXED first element (not
        // a pairwise comparator) sidesteps the cycle: A opens row 1, B
        // joins it (overlaps A), C does NOT join (does not overlap A, even
        // though it overlaps B) and opens row 2 alone.
        let words = vec![
            word("X", 100, 0, 20, 10),  // A: y-span [0,10)
            word("X", 50, 8, 20, 10),   // B: y-span [8,18)  — overlaps A and C
            word("X", 10, 16, 20, 10),  // C: y-span [16,26) — disjoint from A
        ];
        let matches = find_text_matches(&words, "X");
        assert_eq!(matches.len(), 3, "{matches:?}");
        // Row 1 = {A, B}, sorted left-to-right: B (x=50) then A (x=100).
        assert_eq!(matches[0].bbox.x, 50, "B first in row 1");
        assert_eq!(matches[0].nth, 1);
        assert_eq!(matches[1].bbox.x, 100, "A second in row 1");
        assert_eq!(matches[1].nth, 2);
        // Row 2 = {C} alone.
        assert_eq!(matches[2].bbox.x, 10, "C alone in row 2");
        assert_eq!(matches[2].nth, 3);
    }

    // ── union bbox / centre math ──────────────────────────────────────────

    #[test]
    fn union_bbox_spans_both_words_extents() {
        let words = vec![word("Save", 10, 20, 40, 20), word("Changes", 60, 15, 30, 30)];
        let matches = find_text_matches(&words, "Save Changes");
        // min x=10, min y=15, max x=60+30=90, max y=max(20+20, 15+30)=45 -> w=80, h=30
        assert_eq!(matches[0].bbox, hypr::Region { x: 10, y: 15, w: 80, h: 30 });
    }

    #[test]
    fn centre_is_the_floor_of_half_extent_including_odd_widths() {
        // w=5 -> w/2=2 (floor of 2.5); h=7 -> h/2=3 (floor of 3.5).
        let words = vec![word("X", 0, 0, 5, 7)];
        let matches = find_text_matches(&words, "X");
        assert_eq!(matches[0].centre, hypr::Point { x: 2, y: 3 });
    }

    #[test]
    fn centre_offsets_by_a_nonzero_origin_too() {
        let words = vec![word("X", 100, 200, 10, 10)];
        let matches = find_text_matches(&words, "X");
        assert_eq!(matches[0].centre, hypr::Point { x: 105, y: 205 });
    }

    // ── --nth parsing and range bounds ───────────────────────────────────

    #[test]
    fn parse_nth_flag_absent_is_none() {
        assert_eq!(parse_nth_flag(None), Ok(None));
    }

    #[test]
    fn parse_nth_flag_zero_is_refused() {
        assert!(parse_nth_flag(Some(&"0".to_string())).is_err());
    }

    #[test]
    fn parse_nth_flag_non_numeric_is_refused() {
        assert!(parse_nth_flag(Some(&"abc".to_string())).is_err());
    }

    #[test]
    fn parse_nth_flag_positive_integer_parses() {
        assert_eq!(parse_nth_flag(Some(&"3".to_string())), Ok(Some(3)));
    }

    #[test]
    fn nth_in_range_zero_is_refused() {
        assert_eq!(nth_in_range(0, 5), Err(NthOutOfRange { requested: 0, available: 5 }));
    }

    #[test]
    fn nth_in_range_within_bounds_is_zero_based() {
        assert_eq!(nth_in_range(1, 5), Ok(0));
        assert_eq!(nth_in_range(5, 5), Ok(4));
    }

    #[test]
    fn nth_in_range_past_the_end_is_refused_naming_the_bound() {
        assert_eq!(nth_in_range(6, 5), Err(NthOutOfRange { requested: 6, available: 5 }));
    }

    // ── point_text: argument-parsing usage errors (no sidecar touched) ───

    fn inv(args: Vec<&str>, flags: &[(&str, &str)]) -> Invocation {
        let mut m = std::collections::BTreeMap::new();
        for (k, v) in flags {
            m.insert(k.to_string(), v.to_string());
        }
        Invocation {
            path: vec!["screen".to_string(), "point".to_string(), "text".to_string()],
            args: args.into_iter().map(|s| s.to_string()).collect(),
            flags: m,
            door: aoide_protocol::Door::Cli,
        }
    }

    #[test]
    fn missing_text_is_a_usage_error() {
        let outcome = point_text(&inv(vec![], &[]));
        assert_eq!(outcome.status, aoide_protocol::output::Status::Usage);
        assert!(outcome.message.contains("<text>"), "{}", outcome.message);
    }

    #[test]
    fn missing_from_shot_is_a_usage_error() {
        let outcome = point_text(&inv(vec!["Save"], &[]));
        assert_eq!(outcome.status, aoide_protocol::output::Status::Usage);
        assert!(outcome.message.contains("--from-shot"), "{}", outcome.message);
    }

    #[test]
    fn trailing_positional_args_are_refused_not_silently_dropped() {
        // Unquoted `point text Save Changes --from-shot X` lands as TWO
        // args. Searching just "Save" and clicking it while discarding
        // "Changes" would be an irreversible click on possibly the wrong
        // target with no signal anything was dropped — refuse instead.
        let outcome =
            point_text(&inv(vec!["Save", "Changes"], &[("from-shot", "/tmp/nonexistent.png")]));
        assert_eq!(outcome.status, aoide_protocol::output::Status::Usage);
        assert!(
            outcome.message.contains("quote a multi-word phrase as one argument"),
            "{}",
            outcome.message
        );
    }

    #[test]
    fn bad_button_is_a_usage_error() {
        let outcome = point_text(&inv(vec!["Save"], &[("from-shot", "/tmp/nonexistent.png"), ("button", "up")]));
        assert_eq!(outcome.status, aoide_protocol::output::Status::Usage);
        assert!(outcome.message.contains("--button"), "{}", outcome.message);
    }

    #[test]
    fn bad_nth_is_a_usage_error_before_touching_the_sidecar() {
        let outcome = point_text(&inv(vec!["Save"], &[("from-shot", "/tmp/nonexistent.png"), ("nth", "0")]));
        assert_eq!(outcome.status, aoide_protocol::output::Status::Usage);
        assert!(outcome.message.contains("--nth"), "{}", outcome.message);
    }

    // ── point_text: sidecar-backed paths, --dry-run only (never crosses the
    // pointer-synthesis boundary — safe without a live compositor) ───────

    fn tmp_capture(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "aoide-screen-text-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        p.set_extension("png");
        p
    }

    fn write_sidecar_with_ocr(capture: &std::path::Path, ocr_json: Option<&str>) {
        std::fs::write(capture, b"fake").unwrap();
        let ocr_field = ocr_json.unwrap_or("null");
        let text = format!(
            "{{\"schemaVersion\":\"0\",\"capturedAt\":\"2026-08-17T00:00:00Z\",\
             \"origin\":{{\"x\":0,\"y\":0}},\"size\":{{\"w\":200,\"h\":100}},\"scale\":1.0,\
             \"format\":\"png\",\"quality\":80,\"ocr\":{ocr_field}}}"
        );
        std::fs::write(capture.with_extension("json"), text).unwrap();
    }

    fn cleanup(capture: &std::path::Path) {
        let _ = std::fs::remove_file(capture);
        let _ = std::fs::remove_file(capture.with_extension("json"));
    }

    #[test]
    fn no_ocr_block_is_text_no_ocr() {
        let capture = tmp_capture("no-ocr");
        write_sidecar_with_ocr(&capture, None);

        let outcome = point_text(&inv(vec!["Save"], &[("from-shot", capture.to_str().unwrap())]));
        assert_eq!(outcome.status, aoide_protocol::output::Status::Error);
        assert_eq!(outcome.data.unwrap()["reason"], "text-no-ocr");

        cleanup(&capture);
    }

    #[test]
    fn no_match_is_text_not_found_with_the_needle_and_word_count() {
        let capture = tmp_capture("not-found");
        write_sidecar_with_ocr(
            &capture,
            Some(r#"{"text":"Cancel","words":[{"text":"Cancel","conf":90.0,"bbox":{"x":5,"y":5,"w":40,"h":20}}]}"#),
        );

        let outcome = point_text(&inv(vec!["Save"], &[("from-shot", capture.to_str().unwrap())]));
        assert_eq!(outcome.status, aoide_protocol::output::Status::Error);
        let data = outcome.data.unwrap();
        assert_eq!(data["reason"], "text-not-found");
        assert_eq!(data["wordsSearched"], 1);
        assert!(outcome.message.contains("Save"), "{}", outcome.message);

        cleanup(&capture);
    }

    #[test]
    fn ambiguous_match_without_nth_lists_all_candidates() {
        let capture = tmp_capture("ambiguous");
        write_sidecar_with_ocr(
            &capture,
            Some(
                r#"{"text":"Ok Ok","words":[
                    {"text":"Ok","conf":90.0,"bbox":{"x":100,"y":50,"w":20,"h":20}},
                    {"text":"Ok","conf":90.0,"bbox":{"x":10,"y":10,"w":20,"h":20}}
                ]}"#,
            ),
        );

        let outcome = point_text(&inv(vec!["Ok"], &[("from-shot", capture.to_str().unwrap())]));
        assert_eq!(outcome.status, aoide_protocol::output::Status::Error);
        let data = outcome.data.unwrap();
        assert_eq!(data["reason"], "text-ambiguous");
        let candidates = data["candidates"].as_array().unwrap();
        assert_eq!(candidates.len(), 2);
        // top-left-first: nth=1 is the y=10 one.
        assert_eq!(candidates[0]["nth"], 1);
        assert_eq!(candidates[0]["bbox"]["y"], 10);
        assert!(outcome.message.contains("--nth"), "{}", outcome.message);

        cleanup(&capture);
    }

    #[test]
    fn nth_out_of_range_against_real_matches_is_a_usage_error() {
        let capture = tmp_capture("nth-range");
        write_sidecar_with_ocr(
            &capture,
            Some(r#"{"text":"Ok","words":[{"text":"Ok","conf":90.0,"bbox":{"x":10,"y":10,"w":20,"h":20}}]}"#),
        );

        let outcome =
            point_text(&inv(vec!["Ok"], &[("from-shot", capture.to_str().unwrap()), ("nth", "2")]));
        assert_eq!(outcome.status, aoide_protocol::output::Status::Usage);
        assert!(outcome.message.contains("1-1"), "{}", outcome.message);

        cleanup(&capture);
    }

    #[test]
    fn dry_run_reports_the_match_and_centre_with_no_pointer_motion() {
        let capture = tmp_capture("dry-run");
        write_sidecar_with_ocr(
            &capture,
            Some(r#"{"text":"Save","words":[{"text":"Save","conf":90.0,"bbox":{"x":10,"y":10,"w":40,"h":20}}]}"#),
        );

        let outcome = point_text(&inv(
            vec!["Save"],
            &[("from-shot", capture.to_str().unwrap()), ("dry-run", "true")],
        ));
        assert_eq!(outcome.status, aoide_protocol::output::Status::Ok);
        assert!(outcome.message.contains("would click"), "{}", outcome.message);
        assert!(outcome.message.contains("30,20"), "{}", outcome.message);
        let data = outcome.data.unwrap();
        assert_eq!(data["match"]["text"], "Save");
        assert_eq!(data["match"]["centre"]["x"], 30);
        assert_eq!(data["match"]["centre"]["y"], 20);
        assert_eq!(data["button"], "left");

        cleanup(&capture);
    }

    #[test]
    fn dry_run_honours_nth_to_pick_among_ambiguous_matches() {
        let capture = tmp_capture("dry-run-nth");
        write_sidecar_with_ocr(
            &capture,
            Some(
                r#"{"text":"Ok Ok","words":[
                    {"text":"Ok","conf":90.0,"bbox":{"x":100,"y":50,"w":20,"h":20}},
                    {"text":"Ok","conf":90.0,"bbox":{"x":10,"y":10,"w":20,"h":20}}
                ]}"#,
            ),
        );

        let outcome = point_text(&inv(
            vec!["Ok"],
            &[("from-shot", capture.to_str().unwrap()), ("dry-run", "true"), ("nth", "2")],
        ));
        assert_eq!(outcome.status, aoide_protocol::output::Status::Ok);
        let data = outcome.data.unwrap();
        // nth=2 in top-left-first order is the y=50 one.
        assert_eq!(data["match"]["bbox"]["y"], 50);

        cleanup(&capture);
    }

    #[test]
    fn malformed_ocr_block_is_sidecar_corrupt() {
        let capture = tmp_capture("malformed-ocr");
        // `words` is a string, not an array — deserialize failure.
        write_sidecar_with_ocr(&capture, Some(r#"{"text":"x","words":"not-an-array"}"#));

        let outcome = point_text(&inv(vec!["Save"], &[("from-shot", capture.to_str().unwrap())]));
        assert_eq!(outcome.status, aoide_protocol::output::Status::Error);
        assert_eq!(outcome.data.unwrap()["reason"], "sidecar-corrupt");

        cleanup(&capture);
    }
}
