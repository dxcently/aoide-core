//! The conducted-session log tail — a STRIPPED MIRROR of a pty transcript,
//! never a terminal.
//!
//! Every conduct-owned pty mirrors its master-read bytes into
//! `state/sessions/<id>.log` — headless and interactive conduct alike
//! (task #15, the "everything tees" ruling; CONTRACTS §4 ~829: raw pty
//! bytes, append-only, UNROTATED, mirrored verbatim, "not necessarily valid
//! UTF-8"). This module is the read side of that contract for ANY
//! conducted session's log, though the conductor UI reaches for it
//! specifically when a session has no controlling tty for the conductor to
//! focus instead — a `--headless` `aoide conduct` session, today's only
//! caller (`ui.rs`'s Enter handler: cue the window if one exists, else tail
//! the log). [`tail_file`] takes the last slice of that log and
//! [`render_tail`] turns it into plain lines a ratatui overlay can paint.
//! It does not interpret cursor moves, colour, or alternate-screen
//! flips — a full-screen TUI in the log reads back as its own redraw
//! chatter, not a picture. That is accepted, not fixed: teaching this reader
//! real terminal semantics (a vt100 dependency) is exactly the complexity
//! the conductor's "frontend, never a second implementation" rule and the
//! no-embedded-terminal kill-list rule out. If the mirror proves unreadable
//! in practice, a real emulator is the flagged future line — not today's.
//!
//! Two pieces, thin IO over a pure core:
//!   * [`tail_file`] opens the file, seeks to the last [`TAIL_BYTES`] (or the
//!     start, for a shorter file), and reads to EOF. It never reads the whole
//!     file — the log is unrotated and can grow without bound.
//!   * [`render_tail`] takes those bytes plus whether the read was truncated
//!     and does everything else: lossy UTF-8, ANSI stripping, `\r`
//!     (spinner/progress) collapse, and windowing to the last N lines. It
//!     takes no IO, so it is exhaustively unit-tested with hand-built byte
//!     fixtures instead of files on disk.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// How much of the log's tail [`tail_file`] reads, at most. The log is
/// append-only and unrotated (CONTRACTS §4 ~829) — reading the whole thing
/// is the one thing this module must never do.
pub const TAIL_BYTES: u64 = 64 * 1024;

/// How many rendered lines the overlay shows. [`render_tail`] windows to this
/// even when the raw read (and thus the stripped line count) holds more.
pub const TAIL_LINES: usize = 400;

/// The stripper's state machine. [`Csi`](State::Csi) and [`Osc`](State::Osc)
/// parse to their real terminator; [`EscIntermediate`](State::EscIntermediate)
/// parses the third ECMA-48 sequence family — an intermediate byte
/// (`0x20..=0x2F`) followed eventually by a final byte (`0x30..=0x7E`), e.g.
/// `ESC ( B` (select ASCII as G0). That is still tokenizing by the standard's
/// byte-class rules, not vt100 emulation — no cursor/colour semantics are
/// interpreted, only "where does this sequence end." What is left as a
/// one-byte-and-done heuristic is the two-byte Fp/Fs family (`ESC 7`, `ESC
/// M`, `ESC =`, ...) — those have no intermediate byte, so "consume the one
/// byte after ESC" is already exactly correct for them, not a shortcut.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    /// Ordinary text.
    Normal,
    /// Just saw a lone `ESC` (0x1B); one more byte decides what it was.
    Esc,
    /// Inside `ESC [ ... final` (CSI) — swallowing params/intermediates
    /// until a byte in `0x40..=0x7E` ends it.
    Csi,
    /// Inside `ESC ] ...` (OSC) — swallowing until `BEL` or the `ESC \`
    /// (ST) terminator.
    Osc,
    /// Inside OSC, just saw an `ESC`; one more byte decides whether it
    /// completes the `ESC \` terminator.
    OscEsc,
    /// Inside a non-CSI, non-OSC escape that has an ECMA-48 intermediate
    /// byte (`0x20..=0x2F`), e.g. the `(` of `ESC ( B` — swallowing further
    /// intermediates until a final byte (`0x30..=0x7E`) ends it.
    EscIntermediate,
}

/// Strip terminal escape sequences and non-`\n`/`\t`/`\r` control bytes from
/// already-lossily-decoded text.
///
/// Runs over `char`s of a valid `&str`, not raw bytes: ESC and the other
/// bytes this state machine keys off of are all single-byte ASCII, so
/// `from_utf8_lossy` carries them through unchanged (see [`render_tail`]),
/// and scanning `char`s means every step is on a UTF-8 boundary for free —
/// no separate byte-boundary bookkeeping, even with multi-byte characters
/// sitting right next to an escape sequence.
///
/// `\r` is kept, not dropped, despite being a control byte: [`render_tail`]
/// needs it downstream to collapse spinner/progress overwrites (keep only
/// the segment after the last `\r` on a line). It is the one control byte
/// with its own explicit rule instead of the blanket drop.
///
/// An escape sequence left unterminated at end of input (any state other
/// than `Normal` when the chars run out) simply stops advancing the output —
/// nothing after the last complete char was ever pushed, so "consumes to
/// end and emits nothing" falls out of the loop ending, no special case
/// needed.
fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut state = State::Normal;
    for ch in input.chars() {
        state = match (state, ch) {
            (State::Normal, '\x1b') => State::Esc,
            (State::Normal, '\n' | '\t' | '\r') => {
                out.push(ch);
                State::Normal
            }
            (State::Normal, c) if (c as u32) < 0x20 || c as u32 == 0x7f => State::Normal,
            (State::Normal, c) => {
                out.push(c);
                State::Normal
            }
            (State::Esc, '[') => State::Csi,
            (State::Esc, ']') => State::Osc,
            // ECMA-48 intermediate byte: a non-CSI/OSC escape with a real
            // terminator to find (e.g. the `(` of `ESC ( B`) — go find it
            // instead of guessing at one byte.
            (State::Esc, c) if (0x20..=0x2f).contains(&(c as u32)) => State::EscIntermediate,
            // Everything else is a two-byte Fp/Fs escape (`ESC 7`, `ESC M`,
            // `ESC =`, ...) — no intermediate byte, so consuming this one
            // byte and returning to Normal is exactly correct, not a guess.
            (State::Esc, _) => State::Normal,
            (State::Csi, c) if (0x40..=0x7e).contains(&(c as u32)) => State::Normal,
            (State::Csi, _) => State::Csi,
            (State::Osc, '\x07') => State::Normal,
            (State::Osc, '\x1b') => State::OscEsc,
            (State::Osc, _) => State::Osc,
            (State::OscEsc, '\\') => State::Normal,
            // Not a real ST — treat the ESC as more OSC content and keep
            // swallowing (this byte along with it; a lone stray ESC inside
            // an OSC body is itself malformed input, not worth a second
            // heuristic layered on top of the first).
            (State::OscEsc, _) => State::Osc,
            // Stay put on further intermediates; a final byte ends the
            // sequence and drops back to plain text.
            (State::EscIntermediate, c) if (0x30..=0x7e).contains(&(c as u32)) => State::Normal,
            (State::EscIntermediate, _) => State::EscIntermediate,
        };
    }
    out
}

/// Turn raw pty-log bytes into the lines an overlay paints.
///
/// Pipeline: lossy UTF-8 decode (raw bytes are "not necessarily valid
/// UTF-8", CONTRACTS §4) → strip escapes/control bytes ([`strip_ansi`]) →
/// normalize `\r\n` to `\n` → split on `\n` → per line, keep only the text
/// after the last remaining `\r` (a spinner or progress bar overwrites the
/// same line with `\r`, never `\n`; keeping everything before it would
/// print every frame) → trim trailing whitespace. Blank lines are kept —
/// they're honest chatter, not noise.
///
/// The `\r\n` normalization exists because real logs are not `\n`-terminated:
/// every headless session runs its child in raw mode, and every substantial
/// log sampled from `state/sessions/*.log` has `\r\n` count exactly equal to
/// `\n` count (242/242, 182/182, 350/350) — CRLF line endings are the normal
/// shape here, not an edge case. Without this step the terminating `\r` of
/// every line reads as "the last `\r`," and the after-last-`\r` rule above
/// keeps the empty tail past it — every line renders blank. Normalizing
/// first removes exactly the `\r` that immediately precedes a `\n`, so a
/// genuine mid-line spinner `\r` (never followed by `\n`) still reaches the
/// per-line collapse untouched.
///
/// `truncated` (from [`tail_file`]: did the read start mid-file?) drops the
/// first line unconditionally. One rule, two reasons: a truncated read may
/// start mid-escape-sequence (the stripper would emit garbage — or leaked
/// bytes — for a partial CSI/OSC with no terminator in view), and it may
/// start mid ordinary line (a partial line reads as truncated garbage
/// either way). Dropping line 0 whenever the read didn't start at byte 0
/// covers both without telling them apart.
///
/// Finally, windows to the last `max_lines`.
pub fn render_tail(bytes: &[u8], truncated: bool, max_lines: usize) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes);
    let stripped = strip_ansi(&text).replace("\r\n", "\n");
    if stripped.is_empty() {
        return Vec::new();
    }
    let mut lines: Vec<String> = stripped
        .split('\n')
        .map(|line| {
            let after_cr = line.rsplit('\r').next().unwrap_or(line);
            after_cr.trim_end().to_string()
        })
        .collect();
    if truncated && !lines.is_empty() {
        lines.remove(0);
    }
    let start = lines.len().saturating_sub(max_lines);
    lines.split_off(start)
}

/// Read the tail of a headless session's log file.
///
/// Opens `path`, seeks to `len.saturating_sub(`[`TAIL_BYTES`]`)`, and reads
/// at most [`TAIL_BYTES`] — never [`std::fs::read_to_string`] or an
/// unbounded [`Read::read_to_end`] from byte 0. The log is append-only and
/// unrotated (CONTRACTS §4 ~829), so whole-file reads are the one mistake
/// that grows without bound. The read is capped with [`Read::take`], not
/// just seeked-past: `metadata().len()` and the read are two syscalls, and
/// the file can grow between them (a headless session's log is being
/// appended to live), so seeking on the stale length alone would not bound
/// how much a since-grown file hands back. Any IO failure (missing file,
/// permission, mid-read error) yields an empty tail rather than
/// propagating — the same "missing = empty" convention `App::load_json`
/// uses elsewhere in this crate; a headless session whose log briefly
/// doesn't exist yet is not a crash.
pub fn tail_file(path: &Path, max_lines: usize) -> Vec<String> {
    let Ok(mut file) = File::open(path) else {
        return Vec::new();
    };
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let start = len.saturating_sub(TAIL_BYTES);
    if start > 0 && file.seek(SeekFrom::Start(start)).is_err() {
        return Vec::new();
    }
    let mut buf = Vec::new();
    if file.take(TAIL_BYTES).read_to_end(&mut buf).is_err() {
        return Vec::new();
    }
    render_tail(&buf, start > 0, max_lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sgr_strip() {
        // `\x1b[1;31m` (bold red) ... `\x1b[0m` (reset) around plain text.
        let raw = b"plain \x1b[1;31mred bold\x1b[0m plain again";
        assert_eq!(
            render_tail(raw, false, 10),
            vec!["plain red bold plain again"]
        );
    }

    #[test]
    fn osc_to_bel_and_osc_to_st() {
        // OSC 0 (set window title) terminated by BEL, then the same
        // terminated by ST (`ESC \`) instead.
        let raw = b"a\x1b]0;title one\x07b\x1b]0;title two\x1b\\c";
        assert_eq!(render_tail(raw, false, 10), vec!["abc"]);
    }

    #[test]
    fn esc_non_csi_osc_intermediate_sequence_leaks_nothing() {
        // ESC ( B — select ASCII as G0 — is a real, common terminal
        // sequence: ESC, then one ECMA-48 intermediate byte ('('), then a
        // final byte ('B'). EscIntermediate tokenizes to that final byte
        // instead of guessing at one, so nothing from the sequence prints.
        let raw = b"before\x1b(Bafter";
        assert_eq!(render_tail(raw, false, 10), vec!["beforeafter"]);
    }

    #[test]
    fn crlf_terminated_lines_survive_real_pty_shape() {
        // Real pty logs (raw-mode child, sampled from state/sessions/*.log)
        // terminate EVERY line with `\r\n`, not bare `\n` — `\r\n` count
        // equals `\n` count exactly in every substantial sampled log
        // (242/242, 182/182, 350/350). This is the normal shape, not an
        // edge case, and it is deliberately mixed here with ANSI styling
        // AND one genuine mid-line spinner `\r` (three progress frames on
        // one line, no `\n` between them, only a trailing `\r\n` at the
        // end) to prove the two `\r` uses don't get confused for each
        // other.
        let raw = [
            b"\x1b[1;32mstatus: running\x1b[0m\r\n".as_slice(),
            b"build output line one\r\n".as_slice(),
            b"downloading |=   | 10%\rdownloading |==  | 50%\rdownloading |====| 100%\r\n"
                .as_slice(),
            b"build output line two\r\n".as_slice(),
        ]
        .concat();
        let lines = render_tail(&raw, false, 10);
        assert_eq!(
            lines,
            vec![
                "status: running",
                "build output line one",
                "downloading |====| 100%",
                "build output line two",
                "",
            ]
        );
        // (a) every real content line survived non-blank — the historical
        // bug collapsed all of these to "" because the CRLF terminator read
        // as "the last \r" on every line.
        for line in &lines[..lines.len() - 1] {
            assert!(!line.is_empty(), "a content line went blank: {lines:?}");
        }
        // (b) the spinner line still collapsed to its last frame, not all
        // three concatenated.
        assert_eq!(lines[2], "downloading |====| 100%");
        // (c) no bare \r survived into any rendered line.
        for line in &lines {
            assert!(!line.contains('\r'), "bare \\r leaked into {line:?}");
        }
    }

    #[test]
    fn alternate_screen_fixture_reads_clean_with_zero_escape_bytes() {
        // A realistic redraw burst: enter alt screen, clear, home, a
        // styled status line, clear-to-eol, then plain content.
        let raw = [
            b"\x1b[?1049h".as_slice(), // enter alternate screen
            b"\x1b[2J",                // clear screen
            b"\x1b[H",                 // cursor home
            b"\x1b[1;32mstatus: running\x1b[0m\n".as_slice(),
            b"\x1b[K",                 // clear to end of line
            b"build output line one\n".as_slice(),
            b"build output line two\n".as_slice(),
        ]
        .concat();
        let lines = render_tail(&raw, false, 10);
        assert_eq!(
            lines,
            vec![
                "status: running",
                "build output line one",
                "build output line two",
                "",
            ]
        );
        for line in &lines {
            assert!(!line.contains('\x1b'), "escape byte leaked into {line:?}");
        }
    }

    #[test]
    fn carriage_return_collapses_spinner_overwrites() {
        // Three progress-bar frames on one visual line, `\r`-separated, no
        // `\n` between them; only the last frame should survive.
        let raw = b"downloading |=   | 10%\r\
                     downloading |==  | 50%\r\
                     downloading |====| 100%\ndone\n";
        assert_eq!(
            render_tail(raw, false, 10),
            vec!["downloading |====| 100%", "done", ""]
        );
    }

    #[test]
    fn truncated_drops_first_line_true_and_false() {
        let raw = b"line one\nline two\nline three";
        assert_eq!(
            render_tail(raw, true, 10),
            vec!["line two", "line three"]
        );
        assert_eq!(
            render_tail(raw, false, 10),
            vec!["line one", "line two", "line three"]
        );
    }

    #[test]
    fn split_escape_boundary_leaks_nothing_past_line_one() {
        // A tail read that starts mid-CSI-sequence: the previous byte (the
        // ESC that opened it) fell just before our read window, so what we
        // see is bare params-and-final with no opening ESC — "31m garbage"
        // leading a line, exactly what a live 64KB seek boundary produces
        // when it lands inside `\x1b[31m`. `truncated` drops line one
        // unconditionally, so this garbage never reaches the rendered
        // output regardless of how the stripper would have parsed it.
        let raw = b"31m garbage from a split escape\nreal line two\nreal line three";
        let lines = render_tail(raw, true, 10);
        assert_eq!(lines, vec!["real line two", "real line three"]);
        for line in &lines {
            assert!(!line.contains("garbage"));
        }
    }

    #[test]
    fn invalid_utf8_is_lossily_decoded() {
        let mut raw = b"before ".to_vec();
        raw.extend_from_slice(&[0xff, 0xfe]); // not valid UTF-8 on their own
        raw.extend_from_slice(b" after");
        let lines = render_tail(&raw, false, 10);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with("before "));
        assert!(lines[0].ends_with(" after"));
        assert!(lines[0].contains('\u{fffd}'));
    }

    #[test]
    fn multibyte_utf8_adjacent_to_escapes_stays_on_a_char_boundary() {
        // A multi-byte character immediately touching SGR sequences on both
        // sides — exercises the char-boundary-safe design of `strip_ansi`
        // (scanning `char`s of an already-valid `&str`, never raw bytes).
        let raw = "café \x1b[31m日本語\x1b[0m more".as_bytes();
        assert_eq!(render_tail(raw, false, 10), vec!["café 日本語 more"]);
    }

    #[test]
    fn last_n_windows_to_the_tail() {
        // No trailing `\n` here on purpose: `split('\n')` would otherwise add
        // one trailing blank element, which is exercised separately by the
        // `\n`-terminated fixtures above — keep this one about windowing only.
        let raw = "one\ntwo\nthree\nfour\nfive".as_bytes();
        assert_eq!(render_tail(raw, false, 2), vec!["four", "five"]);
        assert_eq!(render_tail(raw, false, 100).len(), 5);
    }

    #[test]
    fn empty_file_renders_no_lines() {
        assert_eq!(render_tail(b"", false, 10), Vec::<String>::new());
        assert_eq!(render_tail(b"", true, 10), Vec::<String>::new());
    }

    #[test]
    fn tail_file_missing_path_is_empty_not_a_panic() {
        let missing = Path::new("/nonexistent/aoide-logtail-test-path/does-not-exist.log");
        assert_eq!(tail_file(missing, TAIL_LINES), Vec::<String>::new());
    }

    #[test]
    fn tail_file_reads_a_real_short_file_untruncated() {
        let dir = std::env::temp_dir().join(format!(
            "aoide-logtail-test-{}-{}",
            std::process::id(),
            "short"
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("session.log");
        std::fs::write(&path, b"hello\nworld\n").unwrap();
        assert_eq!(tail_file(&path, TAIL_LINES), vec!["hello", "world", ""]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tail_file_truncates_a_file_larger_than_tail_bytes() {
        let dir = std::env::temp_dir().join(format!(
            "aoide-logtail-test-{}-{}",
            std::process::id(),
            "long"
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("session.log");
        // One line per `\n`, well past TAIL_BYTES, so the seek must land
        // inside the file rather than at its start.
        let mut content = String::new();
        for i in 0..20_000 {
            content.push_str(&format!("line {i}\n"));
        }
        assert!(content.len() as u64 > TAIL_BYTES);
        std::fs::write(&path, &content).unwrap();
        let lines = tail_file(&path, TAIL_LINES);
        // Truncated: the read started mid-file, so the first (partial) line
        // in the window is dropped, and the very last original line ("line
        // 19999") together with the trailing blank from the final `\n`
        // should still be present.
        assert!(!lines.is_empty());
        assert_eq!(lines.last().map(String::as_str), Some(""));
        assert_eq!(
            lines[lines.len() - 2],
            "line 19999",
            "last real line should survive the tail read"
        );
        assert!(lines.len() <= TAIL_LINES);
        std::fs::remove_dir_all(&dir).ok();
    }
}
