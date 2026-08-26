//! The hand-rolled numbered picker (§7 dual entrance, phase A8): one
//! implementation of every command that serves the User AND an agent, where a
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
//! **`inquire` backs the tty path (ONBOARD.md decision 9, the first
//! User-authorized break of the zero-new-deps discipline for UX since
//! ed25519-dalek).** [`choose`]/[`choose_many`] now fork on
//! [`stdio_is_terminal`]: a real terminal gets `inquire::Select`/
//! `MultiSelect`, everything else (piped, redirected, or any non-CLI door)
//! keeps the ORIGINAL hand-rolled `*_reading` core byte-identical — that
//! core is still the tested contract, untouched by this module doc's own
//! edit. [`confirm`] and [`hidden_input`] are two NEW entry points the same
//! phase adds: `confirm` is `choose`'s y/N sibling (`inquire::Confirm` on a
//! tty, the same plain stdin read otherwise), and `hidden_input` is the
//! password-entry sibling (`inquire::Password`, tty-only — like `choose`/
//! `choose_many`, it's the entry point a caller reaches for once it already
//! knows stdin is a terminal, the same precondition the picker's own
//! [`interactive`] gate establishes upstream of `choose`). `inquire` lives
//! in THIS crate's `Cargo.toml` only — every other crate reaches these four
//! functions, never `inquire` directly (ONBOARD.md's "wrap, don't scatter").
//!
//! **The testable seam.** [`choose`]/[`choose_many`]/[`confirm`]'s non-tty
//! halves open the real [`std::io::stdin`] directly and are therefore not
//! unit-testable on their own. Each is a thin wrapper around a private
//! `*_reading` core that takes `&mut dyn BufRead` instead — the seam this
//! module's own tests drive input through, and the whole reason none of
//! them read a global handle inside the parsing logic itself. `inquire`'s
//! own tty path renders through a real terminal backend and is exercised by
//! hand, the same way [`interactive`]'s genuinely-interactive branch always
//! has been (its own test's comment already says so).

use crate::audit::Door;
use inquire::{Confirm, InquireError, MultiSelect, Password, PasswordDisplayMode, Select};
use std::io::{self, BufRead, IsTerminal, Write};

/// Both stdin AND stdout are a real terminal — the tty half of
/// [`interactive`]'s own check, split out so [`choose`]/[`choose_many`]/
/// [`confirm`] can reuse the identical probe to decide which BACKEND serves
/// a prompt they've already been called to open, without re-deriving it
/// (this crate's own "no cross-crate copying" discipline, applied in-file).
/// TERM=dumb is deliberately NOT checked here — see [`tty_capable`], the
/// one place that distinction is made.
fn stdio_is_terminal() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
}

/// [`stdio_is_terminal`], narrowed by one more fact: `TERM=dumb` is a real
/// terminal (a pty an `is_terminal` probe reads true on) that has told every
/// program attached to it, by convention, that it cannot render cursor
/// movement or other ANSI control sequences. On Linux (this crate's only
/// platform), `inquire`'s `crossterm` backend does NOT consult `TERM` to
/// decide whether to emit those sequences at all (source-checked this
/// phase: the one crossterm module that gates on `TERM=dumb`,
/// `ansi_support`, is `#[cfg(windows)]`-only; the lone Linux-reachable
/// `TERM` read, in `style.rs`, only tiers HOW MANY colors render, never
/// whether cursor-movement escapes are sent) — so left unguarded, it would
/// emit the identical ANSI a normal terminal gets regardless of what `TERM`
/// claims. Verified empirically, on a real pty via `script`(1) (this
/// phase's own commit): under a normal `TERM` the same code path renders
/// full ANSI cursor/color escapes (captured raw, `cat -v`); THIS function
/// is what keeps that path from ever running under `TERM=dumb` — the
/// numbered `choose_reading`/`confirm_reading` fallback is ordinary
/// `print!`/`read_line`, ANSI-free by construction, and running the guarded
/// code under `TERM=dumb` on a real pty confirms it takes exactly that
/// fallback, prompting and reading cleanly with no escape sequence
/// anywhere in the transcript. A PIPED/redirected stdin is unaffected
/// either way — `stdio_is_terminal` already reads false there regardless
/// of `TERM`.
fn tty_capable() -> bool {
    stdio_is_terminal() && std::env::var("TERM").map(|t| t != "dumb").unwrap_or(true)
}

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
    door == Door::Cli && stdio_is_terminal()
}

/// The picker's row layout, split out as a **pure** function so the numbered
/// list is testable without a tty or an injected reader — [`choose`]/
/// [`choose_many`] both call this to build what they print, and a caller
/// that only wants to preview the layout (or assert its exact text in a
/// test) can call it directly. One row per line, numbered from 1 (never 0 —
/// the number a User types is the number a User sees), with `(default)`
/// appended to every row named in `default` — a slice rather than one index
/// since [`choose_many`]'s onboard consumer (ONBOARD.md decision 7) can
/// preselect several rows at once ([`choose`]'s own single-select callers
/// pass a 0-or-1-element slice). An out-of-range index in `default` (a
/// caller bug — past the end of `rows`) marks nothing rather than panicking;
/// the callers here already guard against that before it reaches this
/// function, but the guard belongs to them, not to a pure renderer.
pub fn render_rows(rows: &[String], default: &[usize]) -> String {
    let mut out = String::new();
    for (i, row) in rows.iter().enumerate() {
        let marker = if default.contains(&i) { " (default)" } else { "" };
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

    print!("{}", render_rows(rows, &default.into_iter().collect::<Vec<_>>()));
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
/// is worse than asking again). `default` is a SET of preselected rows
/// (widened from a single `Option<usize>` for onboard's harness picker,
/// ONBOARD.md decision 7 — several harnesses can sit on `PATH` at once):
/// empty input selects the whole set when it's non-empty, mirroring
/// [`choose_reading`]'s own empty-input rule; aborts when `default` is empty.
fn choose_many_reading(
    reader: &mut dyn BufRead,
    prompt: &str,
    rows: &[String],
    default: &[usize],
) -> Option<Vec<usize>> {
    if rows.is_empty() {
        return None;
    }
    let default: Vec<usize> = default.iter().copied().filter(|&d| d < rows.len()).collect();

    print!("{}", render_rows(rows, &default));
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
            return if default.is_empty() { None } else { Some(default.clone()) };
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
/// See [`choose_reading`] for the exact read/reprompt/abort rules on the
/// non-tty half; on a capable tty ([`tty_capable`]) this now opens
/// `inquire::Select` instead (ONBOARD.md decision 9) — see [`choose_tty`].
pub fn choose(prompt: &str, rows: &[String], default: Option<usize>) -> Option<usize> {
    if tty_capable() {
        return choose_tty(prompt, rows, default);
    }
    let stdin = io::stdin();
    let mut lock = stdin.lock();
    choose_reading(&mut lock, prompt, rows, default)
}

/// The `inquire::Select`-backed tty half of [`choose`] — same contract as
/// [`choose_reading`] (`rows.is_empty()` -> `None` with nothing rendered, an
/// out-of-range `default` treated as no default, an abort -> `None`,
/// never a distinct error shape), a different renderer underneath. `Esc`
/// (`InquireError::OperationCanceled`, `raw_prompt_skippable`'s own
/// documented mapping) and every other `inquire` error (a `Ctrl-C`
/// interrupt, an I/O failure) both fall to `None` in the `_ =>` arm — this
/// module's own "`None` throughout means nothing was chosen, nothing should
/// be done" rule ([`choose_reading`]'s doc) applies identically to the tty
/// backend, so there is no second error shape for a caller to handle.
/// `raw_prompt_skippable` (not `prompt_skippable`) is what hands back a
/// [`inquire::list_option::ListOption`] carrying the ORIGINAL list's index
/// alongside the picked value — `choose`'s own return type is an index, not
/// a value, and `Select` has no other way to recover one.
fn choose_tty(prompt: &str, rows: &[String], default: Option<usize>) -> Option<usize> {
    if rows.is_empty() {
        return None;
    }
    let default = default.filter(|&d| d < rows.len());
    let mut select = Select::new(prompt, rows.to_vec());
    if let Some(d) = default {
        select = select.with_starting_cursor(d);
    }
    match select.raw_prompt_skippable() {
        Ok(Some(picked)) => Some(picked.index),
        _ => None,
    }
}

/// Open a multi-select picker on the real terminal — `rice take prune`'s
/// picker (phase A9, §7.1) and onboard's harness picker (ONBOARD.md
/// decision 7) are the in-plan consumers this exists for. Same shape as
/// [`choose`]; `default` is a SET of preselected rows (widened at the
/// onboard phase — `rice take prune` passes `&[]`, onboard preselects every
/// harness found on `PATH`). See [`choose_many_reading`] for the non-tty
/// list-parsing and abort rules, [`choose_many_tty`] for the tty backend
/// (ONBOARD.md decision 9).
pub fn choose_many(prompt: &str, rows: &[String], default: &[usize]) -> Option<Vec<usize>> {
    if tty_capable() {
        return choose_many_tty(prompt, rows, default);
    }
    let stdin = io::stdin();
    let mut lock = stdin.lock();
    choose_many_reading(&mut lock, prompt, rows, default)
}

/// The `inquire::MultiSelect`-backed tty half of [`choose_many`] — same
/// empty-rows/out-of-range-default/abort contract as [`choose_tty`], one
/// selection widened to many, several defaults instead of one. Empty input
/// on the non-tty side selects the whole `default` set ([`choose_many_reading`]'s
/// own doc); `MultiSelect::with_default` reproduces that by pre-checking the
/// same rows, so Enter with nothing toggled still submits them.
fn choose_many_tty(prompt: &str, rows: &[String], default: &[usize]) -> Option<Vec<usize>> {
    if rows.is_empty() {
        return None;
    }
    let default: Vec<usize> = default.iter().copied().filter(|&d| d < rows.len()).collect();
    let mut multi = MultiSelect::new(prompt, rows.to_vec());
    if !default.is_empty() {
        multi = multi.with_default(&default);
    }
    match multi.raw_prompt_skippable() {
        Ok(Some(picked)) => Some(picked.into_iter().map(|lo| lo.index).collect()),
        _ => None,
    }
}

/// `choose`'s y/N sibling (ONBOARD.md's prompt substrate section) —
/// `client`'s `confirm_spawn`/`confirm_sas` retrofit onto this. `prompt` is
/// the caller's own question with NO trailing `[y/N]` decoration — this
/// function owns that suffix itself on the non-tty path, the same way
/// [`choose_reading`] owns its own `[1-N, q to abort]` hint text, so a
/// caller's wording survives verbatim on either backend. Default is always
/// No (ONBOARD.md's prompt substrate section, matching every hand-rolled
/// y/N confirm this replaces): `Confirm::with_default(false)` on a tty,
/// and [`confirm_reading`]'s own `Ok(false)` on anything but an explicit
/// `y`/`yes` otherwise. `Esc`/`Ctrl-C` on a tty both read as a decline —
/// same "no distinct abort shape" rule [`choose_tty`] holds — everything
/// else that reaches `inquire` (an I/O failure) is a genuine `Err`, since a
/// confirm's caller (`peer spawn`, a pairing SAS check) needs to know a
/// real read failure apart from an ordinary decline.
pub fn confirm(prompt: &str) -> Result<bool, String> {
    if tty_capable() {
        return match Confirm::new(prompt).with_default(false).prompt() {
            Ok(answer) => Ok(answer),
            Err(InquireError::OperationCanceled) | Err(InquireError::OperationInterrupted) => Ok(false),
            Err(e) => Err(format!("reading confirmation: {e}")),
        };
    }
    let stdin = io::stdin();
    let mut lock = stdin.lock();
    confirm_reading(&mut lock, prompt)
}

/// The testable non-tty core behind [`confirm`] — byte-identical to every
/// hand-rolled `confirm_*` helper it replaces (`client::confirm_spawn`/
/// `confirm_sas`, before this phase): prompt text plus a literal `[y/N] `
/// suffix to STDERR, one line read from `reader`, `true` only for `y`/`yes`
/// (case-insensitive, trimmed) — an EOF (`read_line` returning `Ok(0)`) or
/// any other input defaults to `false`, never a reprompt (a confirm gets
/// exactly one chance, unlike the picker's one-retry rule).
fn confirm_reading(reader: &mut dyn BufRead, prompt: &str) -> Result<bool, String> {
    eprint!("{prompt} [y/N] ");
    let _ = io::stderr().flush();
    let mut line = String::new();
    let read = reader.read_line(&mut line).map_err(|e| format!("reading confirmation from stdin: {e}"))?;
    Ok(read > 0 && matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}

/// The password-entry sibling of [`choose`]/[`confirm`] (ONBOARD.md's
/// prompt substrate section) — `secrets put`'s hidden value entry and
/// `secrets watch`'s TOTP code entry retrofit onto this. Tty-only, like
/// [`choose`]/[`choose_many`]: it is the entry point a caller reaches for
/// once it ALREADY knows stdin is a terminal (the exact precondition the
/// old hand-rolled `read_hidden_line` it replaces always assumed — neither
/// function ever had a non-tty branch of its own, since every call site
/// gates on tty itself first). `PasswordDisplayMode::Hidden` is `inquire`'s
/// own default; named explicitly here so a future edit can't silently drift
/// to `Masked`'s asterisk echo — "no masking surprises" (this phase's own
/// brief): the old termios-based read gave no indication of input at all,
/// and `Hidden` is the one display mode that preserves that. Confirmation
/// (`inquire::Password` normally asks twice and compares) is turned off —
/// the old read asked once, and a caller here already has its own
/// overwrite-confirmation flow (`secrets put`'s `y/N`) where one is wanted.
pub fn hidden_input(prompt: &str) -> Result<String, String> {
    Password::new(prompt)
        .without_confirmation()
        .with_display_mode(PasswordDisplayMode::Hidden)
        .prompt()
        .map_err(|e| format!("reading hidden input: {e}"))
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
        let out = render_rows(&rows3(), &[1]);
        assert_eq!(
            out,
            "  1) 0004  drift\n  2) 0002  stage [A] (default)\n  3) 0001  explicit\n"
        );
    }

    #[test]
    fn render_rows_marks_every_row_in_a_multi_default_set() {
        // Onboard's harness picker (ONBOARD.md decision 7) preselects every
        // harness found on PATH at once -- the whole reason this widened
        // from one index to a slice.
        let out = render_rows(&rows3(), &[0, 2]);
        assert_eq!(
            out,
            "  1) 0004  drift (default)\n  2) 0002  stage [A]\n  3) 0001  explicit (default)\n"
        );
    }

    #[test]
    fn render_rows_marks_nothing_when_default_is_empty_or_out_of_range() {
        assert_eq!(render_rows(&rows3(), &[]), "  1) 0004  drift\n  2) 0002  stage [A]\n  3) 0001  explicit\n");
        assert_eq!(
            render_rows(&rows3(), &[99]),
            "  1) 0004  drift\n  2) 0002  stage [A]\n  3) 0001  explicit\n"
        );
    }

    #[test]
    fn render_rows_is_empty_for_an_empty_list() {
        assert_eq!(render_rows(&[], &[]), "");
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
        let picked = choose_many_reading(&mut input, "prune which takes?", &rows3(), &[]);
        assert_eq!(picked, Some(vec![0, 2]));
    }

    #[test]
    fn choose_many_empty_input_selects_the_default_as_a_single_element() {
        let mut input = io::Cursor::new(b"\n".to_vec());
        let picked = choose_many_reading(&mut input, "prune which takes?", &rows3(), &[2]);
        assert_eq!(picked, Some(vec![2]));
    }

    #[test]
    fn choose_many_empty_input_selects_every_default_when_several_are_set() {
        // Onboard's harness picker (ONBOARD.md decision 7): several
        // harnesses can sit on PATH at once, and Enter should wire all of
        // them, not just one -- the case that forced `default` to widen
        // from `Option<usize>` to `&[usize]`.
        let mut input = io::Cursor::new(b"\n".to_vec());
        let picked = choose_many_reading(&mut input, "which harnesses?", &rows3(), &[0, 2]);
        assert_eq!(picked, Some(vec![0, 2]));
    }

    #[test]
    fn choose_many_q_aborts() {
        let mut input = io::Cursor::new(b"q\n".to_vec());
        let picked = choose_many_reading(&mut input, "prune which takes?", &rows3(), &[]);
        assert_eq!(picked, None);
    }

    #[test]
    fn choose_many_one_bad_token_invalidates_the_whole_line_then_reprompts_once() {
        let mut input = io::Cursor::new(b"1,nope\n2\n".to_vec());
        let picked = choose_many_reading(&mut input, "prune which takes?", &rows3(), &[]);
        assert_eq!(picked, Some(vec![1]), "the retry line is read fresh, not merged with the bad one");
    }

    // ── confirm_reading: the injectable seam behind `confirm` ───────────

    #[test]
    fn confirm_reading_accepts_y_and_yes_case_insensitively() {
        for line in ["y\n", "Y\n", "yes\n", "YES\n", "Yes\n"] {
            let mut input = io::Cursor::new(line.as_bytes().to_vec());
            assert_eq!(confirm_reading(&mut input, "proceed?"), Ok(true), "input was {line:?}");
        }
    }

    #[test]
    fn confirm_reading_defaults_to_false_on_empty_input() {
        let mut input = io::Cursor::new(b"\n".to_vec());
        assert_eq!(confirm_reading(&mut input, "proceed?"), Ok(false));
    }

    #[test]
    fn confirm_reading_defaults_to_false_on_eof() {
        let mut input = io::Cursor::new(Vec::new());
        assert_eq!(confirm_reading(&mut input, "proceed?"), Ok(false), "a closed reader never falls back to yes");
    }

    #[test]
    fn confirm_reading_defaults_to_false_on_anything_else() {
        let mut input = io::Cursor::new(b"n\n".to_vec());
        assert_eq!(confirm_reading(&mut input, "proceed?"), Ok(false));
        let mut input = io::Cursor::new(b"maybe\n".to_vec());
        assert_eq!(confirm_reading(&mut input, "proceed?"), Ok(false));
    }
}
