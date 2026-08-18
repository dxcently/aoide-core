//! The hand-rolled numbered picker (§7 dual entrance, phase A8): one
//! implementation of every verb that serves the User AND an agent, where a
//! bare invocation with no selecting flag opens on a real tty and a
//! flag-driven or non-tty invocation never touches stdin at all.
//!
//! **Location is a decision, not a default** (advisor verdict, fork 5): the
//! picker is door behavior — [`Door`] and [`interactive`]'s tty gate both
//! live here in `aoide-protocol` because every domain crate (`song`, and
//! whichever comes after it) already depends on this crate, and a per-domain
//! copy would duplicate the exact same read/parse/reprompt loop for no
//! reason. `rice back`'s bare-tty branch (`crates/song/src/commands/take.rs`,
//! phase A8) is the first caller; `rice take prune`'s multi-select (phase
//! A9, §7.1) is [`choose_many`]'s own in-plan consumer — built now, not
//! speculatively, because that consumer already exists in the plan.
//!
//! **No TUI crate, on purpose.** The plan calls for a hand-rolled numbered
//! picker, not a curses-style full-screen one, and this repo takes no new
//! dependencies for it: `std::io::IsTerminal` is the only surface this file
//! needs.
//!
//! **The testable seam.** [`choose`]/[`choose_many`] are the real entry
//! points a caller reaches for, but they open the real [`std::io::stdin`]
//! directly and are therefore not unit-testable on their own. Both are thin
//! wrappers around a private `*_reading` core that takes `&mut dyn BufRead`
//! instead — the seam this module's own tests drive input through, and the
//! whole reason `choose`/`choose_many` never read a global handle inside the
//! parsing logic itself.

use crate::audit::Door;
use std::io::{self, BufRead, IsTerminal, Write};

/// True only when a bare (no selecting flag) invocation is allowed to open
/// the picker: the [`Door::Cli`] door, AND stdin, AND stdout are all a real
/// terminal (advisor verdict, fork 6). Every other door — [`Door::Mcp`],
/// [`Door::Daemon`], [`Door::A2a`] — is an agent regardless of what its
/// underlying transport happens to look like, so the door check is checked
/// FIRST and short-circuits before either tty probe ever runs: a non-CLI
/// door is never interactive no matter what stdin/stdout are wired to.
/// Piped/redirected CLI stdio (a script, a test harness, a CI runner) is
/// exactly what [`std::io::IsTerminal`] is for — it reads false there, which
/// is what keeps a non-interactive CLI invocation on the flags-only path
/// too.
pub fn interactive(door: Door) -> bool {
    door == Door::Cli && io::stdin().is_terminal() && io::stdout().is_terminal()
}

/// The picker's row layout, split out as a **pure** function so the numbered
/// list is testable without a tty or an injected reader — [`choose`]/
/// [`choose_many`] both call this to build what they print, and a caller
/// that only wants to preview the layout (or assert its exact text in a
/// test) can call it directly. One row per line, numbered from 1 (never 0 —
/// the number a User types is the number a User sees), with `(default)`
/// appended to whichever row `default` names, if any. An out-of-range
/// `default` (a caller bug — an index past the end of `rows`) marks nothing
/// rather than panicking; the callers here already guard against that
/// before it reaches this function, but the guard belongs to them, not to a
/// pure renderer.
pub fn render_rows(rows: &[String], default: Option<usize>) -> String {
    let mut out = String::new();
    for (i, row) in rows.iter().enumerate() {
        let marker = if default == Some(i) { " (default)" } else { "" };
        out.push_str(&format!("  {}) {row}{marker}\n", i + 1));
    }
    out
}

/// Parse one line of raw picker input against `len` rows, `1`-indexed on the
/// way in and `0`-indexed on the way out (matching [`render_rows`]'s own
/// numbering). Shared by [`choose_reading`]'s single-index parse and
/// [`choose_many_reading`]'s list parse — a single token IS a one-element
/// list from the parser's point of view, so [`choose_many_reading`] calls
/// this once per token rather than duplicating the range check.
fn parse_index(token: &str, len: usize) -> Option<usize> {
    let n: usize = token.parse().ok()?;
    if n >= 1 && n <= len {
        Some(n - 1)
    } else {
        None
    }
}

/// The single-select testable core — see the module doc's "testable seam"
/// section. `rows.is_empty()` returns `None` immediately without printing
/// or reading anything: there is nothing to choose from, and prompting for
/// a choice among zero options has no reading. An out-of-range `default` is
/// treated the same as no default at all, so a caller's stale index can
/// never make an empty-input Enter silently pick the wrong row (or panic
/// indexing [`render_rows`]).
///
/// Reads at most two lines: the first attempt, and — only on unparseable or
/// out-of-range input — ONE re-prompt. `q`/`Q` aborts immediately on either
/// attempt; empty input selects `default` when one is set (fork 6's
/// one-Enter undo is exactly this branch, with `default` = the head's
/// parent), or aborts when there is none to fall back to. A second bad
/// attempt, or an EOF (a closed/exhausted reader) on either attempt, aborts
/// the same way `q` does — `None` throughout means "nothing was chosen,
/// nothing should be done," never a distinct error shape, because the
/// caller's job on `None` is identical in every one of these cases: stop.
fn choose_reading(reader: &mut dyn BufRead, prompt: &str, rows: &[String], default: Option<usize>) -> Option<usize> {
    if rows.is_empty() {
        return None;
    }
    let default = default.filter(|&d| d < rows.len());

    print!("{}", render_rows(rows, default));
    let hint = match default {
        Some(d) => format!("{prompt} [1-{}, Enter for {}, q to abort]: ", rows.len(), d + 1),
        None => format!("{prompt} [1-{}, q to abort]: ", rows.len()),
    };

    for attempt in 0..2 {
        print!("{hint}");
        let _ = io::stdout().flush();

        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return None; // EOF — nothing more will ever arrive.
        }
        let trimmed = line.trim();
        if trimmed.eq_ignore_ascii_case("q") {
            return None;
        }
        if trimmed.is_empty() {
            return default;
        }
        if let Some(idx) = parse_index(trimmed, rows.len()) {
            return Some(idx);
        }
        if attempt == 0 {
            println!("not a valid choice -- try again.");
        }
    }
    None
}

/// The multi-select testable core — same shape as [`choose_reading`], but
/// parses a comma-and/or-whitespace-separated list of numbers instead of
/// one. Every token must resolve via [`parse_index`] for the whole line to
/// count as valid; one bad token invalidates the entire attempt (a partial
/// selection that silently drops the token nobody could tell they mistyped
/// is worse than asking again). Empty input selects `[default]` — a single-
/// element selection — when a default is set, mirroring [`choose_reading`]'s
/// own empty-input rule; aborts otherwise.
fn choose_many_reading(
    reader: &mut dyn BufRead,
    prompt: &str,
    rows: &[String],
    default: Option<usize>,
) -> Option<Vec<usize>> {
    if rows.is_empty() {
        return None;
    }
    let default = default.filter(|&d| d < rows.len());

    print!("{}", render_rows(rows, default));
    let hint = format!("{prompt} [comma-separated 1-{}, q to abort]: ", rows.len());

    for attempt in 0..2 {
        print!("{hint}");
        let _ = io::stdout().flush();

        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return None;
        }
        let trimmed = line.trim();
        if trimmed.eq_ignore_ascii_case("q") {
            return None;
        }
        if trimmed.is_empty() {
            return default.map(|d| vec![d]);
        }

        let tokens: Vec<&str> = trimmed.split(|c: char| c == ',' || c.is_whitespace()).filter(|s| !s.is_empty()).collect();
        let parsed: Option<Vec<usize>> = tokens.iter().map(|t| parse_index(t, rows.len())).collect();
        if let Some(sel) = parsed.filter(|s| !s.is_empty()) {
            return Some(sel);
        }
        if attempt == 0 {
            println!("not a valid choice -- try again.");
        }
    }
    None
}

/// Open a single-select picker on the real terminal — the entry point a
/// caller reaches for once [`interactive`] has already said yes. `prompt` is
/// the caller's own question (e.g. "revert to which take?"); `rows` are
/// already-rendered row texts (a caller building rows off a domain type,
/// like `rice back`'s takes lane, renders them itself — this module knows
/// nothing about takes); `default` is the row index Enter selects, if any.
/// See [`choose_reading`] for the exact read/reprompt/abort rules.
pub fn choose(prompt: &str, rows: &[String], default: Option<usize>) -> Option<usize> {
    let stdin = io::stdin();
    let mut lock = stdin.lock();
    choose_reading(&mut lock, prompt, rows, default)
}

/// Open a multi-select picker on the real terminal — `rice take prune`'s
/// picker (phase A9, §7.1) is the in-plan consumer this exists for. Same
/// shape as [`choose`]; see [`choose_many_reading`] for the list-parsing and
/// abort rules.
pub fn choose_many(prompt: &str, rows: &[String], default: Option<usize>) -> Option<Vec<usize>> {
    let stdin = io::stdin();
    let mut lock = stdin.lock();
    choose_many_reading(&mut lock, prompt, rows, default)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows3() -> Vec<String> {
        vec!["0004  drift".to_string(), "0002  stage [A]".to_string(), "0001  explicit".to_string()]
    }

    // ── interactive: door gates before either tty probe ─────────────────

    #[test]
    fn interactive_is_false_for_every_non_cli_door_regardless_of_tty() {
        // The door check short-circuits first, so this holds even though
        // cargo test's own stdin/stdout are never a real tty either --
        // Mcp/Daemon/A2a must read false on a genuine terminal too.
        assert!(!interactive(Door::Mcp));
        assert!(!interactive(Door::Daemon));
        assert!(!interactive(Door::A2a));
    }

    #[test]
    fn interactive_is_false_for_cli_off_a_non_tty_test_harness() {
        // cargo test's stdin/stdout are pipes/files, never a real tty, so
        // this exercises the tty half of the AND from the non-interactive
        // side -- the genuinely-interactive case can only be proven by
        // hand, on a real terminal, which is why the plan gates the picker
        // on this function rather than on the door alone.
        assert!(!interactive(Door::Cli));
    }

    // ── render_rows: pure layout, no tty needed ──────────────────────────

    #[test]
    fn render_rows_numbers_from_one_and_marks_the_default() {
        let out = render_rows(&rows3(), Some(1));
        assert_eq!(
            out,
            "  1) 0004  drift\n  2) 0002  stage [A] (default)\n  3) 0001  explicit\n"
        );
    }

    #[test]
    fn render_rows_marks_nothing_when_default_is_none_or_out_of_range() {
        assert_eq!(render_rows(&rows3(), None), "  1) 0004  drift\n  2) 0002  stage [A]\n  3) 0001  explicit\n");
        assert_eq!(
            render_rows(&rows3(), Some(99)),
            "  1) 0004  drift\n  2) 0002  stage [A]\n  3) 0001  explicit\n"
        );
    }

    #[test]
    fn render_rows_is_empty_for_an_empty_list() {
        assert_eq!(render_rows(&[], None), "");
    }

    // ── parse_index: boundaries, correct by inspection, now pinned ──────

    #[test]
    fn parse_index_rejects_zero_never_reaching_the_underflow_prone_subtraction() {
        // Rows display from 1 (render_rows numbers `i + 1`); `0` must be
        // caught by the `n >= 1` guard and never reach `n - 1`, which would
        // underflow a `usize` if the guard were ever removed.
        assert_eq!(parse_index("0", 5), None);
    }

    #[test]
    fn parse_index_rejects_a_negative_token() {
        // `usize::from_str` has no sign to parse -- `"-1"` fails at the
        // `.parse().ok()?` step, before the range check ever runs.
        assert_eq!(parse_index("-1", 5), None);
    }

    #[test]
    fn parse_index_rejects_whitespace_padding_the_caller_already_trims() {
        // parse_index itself never trims -- choose_reading trims the whole
        // line and choose_many_reading's split already drops surrounding
        // whitespace per token, so a raw padded token reaching this
        // function unfiltered is correctly rejected the same way
        // `usize::from_str` rejects surrounding whitespace.
        assert_eq!(parse_index("  2  ", 5), None);
    }

    // ── choose_reading: the injectable seam, driven with no real stdin ──

    #[test]
    fn choose_empty_input_selects_the_default_row() {
        let mut input = io::Cursor::new(b"\n".to_vec());
        let picked = choose_reading(&mut input, "revert to which take?", &rows3(), Some(1));
        assert_eq!(picked, Some(1), "Enter on a set default is fork 6's one-step undo");
    }

    #[test]
    fn choose_empty_input_aborts_when_there_is_no_default() {
        let mut input = io::Cursor::new(b"\n".to_vec());
        let picked = choose_reading(&mut input, "pick one", &rows3(), None);
        assert_eq!(picked, None);
    }

    #[test]
    fn choose_q_aborts_even_with_a_default_set() {
        let mut input = io::Cursor::new(b"q\n".to_vec());
        let picked = choose_reading(&mut input, "pick one", &rows3(), Some(0));
        assert_eq!(picked, None);
    }

    #[test]
    fn choose_a_valid_number_selects_that_row_zero_indexed() {
        let mut input = io::Cursor::new(b"3\n".to_vec());
        let picked = choose_reading(&mut input, "pick one", &rows3(), None);
        assert_eq!(picked, Some(2), "row 3 as typed is index 2 in the slice");
    }

    #[test]
    fn choose_reprompts_exactly_once_on_bad_input_then_gives_up() {
        // First line is out of range, second is unparseable -- two bad
        // attempts in a row, so this must abort rather than read a third.
        let mut input = io::Cursor::new(b"99\nnotanumber\n".to_vec());
        let picked = choose_reading(&mut input, "pick one", &rows3(), None);
        assert_eq!(picked, None);
    }

    #[test]
    fn choose_recovers_on_the_one_allowed_reprompt() {
        let mut input = io::Cursor::new(b"nope\n2\n".to_vec());
        let picked = choose_reading(&mut input, "pick one", &rows3(), None);
        assert_eq!(picked, Some(1), "the second line, valid this time, is still read");
    }

    #[test]
    fn choose_eof_aborts_like_q() {
        let mut input = io::Cursor::new(Vec::new());
        let picked = choose_reading(&mut input, "pick one", &rows3(), Some(0));
        assert_eq!(picked, None, "a closed reader never falls back to the default");
    }

    #[test]
    fn choose_on_an_empty_row_list_never_reads_anything() {
        let mut input = io::Cursor::new(b"1\n".to_vec());
        let picked = choose_reading(&mut input, "pick one", &[], None);
        assert_eq!(picked, None);
    }

    // ── choose_many_reading: the multi-select seam (A9's consumer) ──────

    #[test]
    fn choose_many_parses_a_comma_and_space_separated_list() {
        let mut input = io::Cursor::new(b"1, 3\n".to_vec());
        let picked = choose_many_reading(&mut input, "prune which takes?", &rows3(), None);
        assert_eq!(picked, Some(vec![0, 2]));
    }

    #[test]
    fn choose_many_empty_input_selects_the_default_as_a_single_element() {
        let mut input = io::Cursor::new(b"\n".to_vec());
        let picked = choose_many_reading(&mut input, "prune which takes?", &rows3(), Some(2));
        assert_eq!(picked, Some(vec![2]));
    }

    #[test]
    fn choose_many_q_aborts() {
        let mut input = io::Cursor::new(b"q\n".to_vec());
        let picked = choose_many_reading(&mut input, "prune which takes?", &rows3(), None);
        assert_eq!(picked, None);
    }

    #[test]
    fn choose_many_one_bad_token_invalidates_the_whole_line_then_reprompts_once() {
        let mut input = io::Cursor::new(b"1,nope\n2\n".to_vec());
        let picked = choose_many_reading(&mut input, "prune which takes?", &rows3(), None);
        assert_eq!(picked, Some(vec![1]), "the retry line is read fresh, not merged with the bad one");
    }
}
