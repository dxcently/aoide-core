//! Shared chrome + colour — the rice identity, rendered in a terminal.
//!
//! The frames echo the gadget dock: `╔═[ TITLE ]═╗` double box-drawing, a
//! footer rule, and the ornament alphabet lifted verbatim from the Quickshell
//! QML — the `ৎ𝄢` clef-tail end-cap ([`END_CAP`], from `GadgetFrame.qml`) and
//! the `𝄂𝄚𝅦𝄚` stave-run divider ([`DIVIDER`], from `AoideBar.qml` /
//! `PowerGadget.qml`). Legibility first: one ornament per seam, never in the
//! alignment-critical box math.
//!
//! Colour comes from `stage/notes.json`'s palette `{bg,fg,accent,urgent}` when
//! present, each hex mapped to the nearest ANSI-256 index so a rice's key tints
//! the TUI too; absent a palette we emit no colour and inherit the terminal's
//! own theme.

use crate::baton::app::Palette;

/// Clef-tail end-cap ornament — verbatim from `GadgetFrame.qml` / `AoideBar.qml`.
pub const END_CAP: &str = "ৎ𝄢";
/// Short stave-run divider — verbatim from `AoideBar.qml` / `PowerGadget.qml`.
pub const DIVIDER: &str = "𝄂𝄚𝅦𝄚";

/// SGR: set foreground to an ANSI-256 index.
pub fn fg256(idx: u8) -> String {
    format!("\x1b[38;5;{idx}m")
}
/// SGR: set background to an ANSI-256 index.
pub fn bg256(idx: u8) -> String {
    format!("\x1b[48;5;{idx}m")
}
/// SGR reset (also appended per-row by the renderer, but panels use it to end a
/// styled span mid-line).
pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";
pub const REVERSE: &str = "\x1b[7m";

/// Named ANSI-16 fallbacks (used for log status colouring where a palette key
/// doesn't apply): green ok, red error, dim not-implemented, etc.
pub const GREEN: &str = "\x1b[32m";
pub const RED: &str = "\x1b[31m";
pub const YELLOW: &str = "\x1b[33m";
pub const CYAN: &str = "\x1b[36m";
pub const MAGENTA: &str = "\x1b[35m";
pub const BLUE: &str = "\x1b[34m";

/// Visible (display) width of a string, ignoring ANSI SGR escape sequences and
/// counting most codepoints as one cell. This is deliberately simple: our chrome
/// uses ASCII box characters (width 1) and the musical SMP ornaments are placed
/// OFF the alignment-critical seams, exactly as the QML does — so we never need
/// full grapheme-width tables to keep the boxes square.
pub fn display_width(s: &str) -> usize {
    let mut w = 0usize;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip a CSI sequence: ESC [ ... <final byte 0x40..=0x7e>.
            if chars.peek() == Some(&'[') {
                chars.next();
                for e in chars.by_ref() {
                    if ('\x40'..='\x7e').contains(&e) {
                        break;
                    }
                }
            }
            continue;
        }
        w += 1;
    }
    w
}

/// Truncate a (possibly styled) string to `max` display cells, then pad with
/// spaces to exactly `max`. ANSI escapes pass through without counting. A reset
/// is appended if we truncated inside a styled span, so trailing colour never
/// leaks into the padding.
pub fn fit(s: &str, max: usize) -> String {
    let mut out = String::new();
    let mut w = 0usize;
    let mut had_escape = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            had_escape = true;
            out.push(c);
            if chars.peek() == Some(&'[') {
                out.push(chars.next().unwrap());
                for e in chars.by_ref() {
                    out.push(e);
                    if ('\x40'..='\x7e').contains(&e) {
                        break;
                    }
                }
            }
            continue;
        }
        if w >= max {
            // Truncated mid-content: close any open style.
            if had_escape {
                out.push_str(RESET);
            }
            // Pad nothing — we're already at width.
            return out;
        }
        out.push(c);
        w += 1;
    }
    if had_escape {
        out.push_str(RESET);
    }
    if w < max {
        out.push_str(&" ".repeat(max - w));
    }
    out
}

/// One framed panel: `╔═[ TITLE ]══…═╗`, body rows walled in `║ … ║`, and a
/// footer `╚═…═╝` carrying the clef-tail end-cap. `focused` inverts the title so
/// the active panel reads at a glance. `width` is the full panel width in cells.
///
/// Body lines are fit to the interior width; short frames pad with blank walled
/// rows up to `height` (when `height > 0`) so panels keep a stable size.
pub fn frame(
    title: &str,
    body: &[String],
    width: u16,
    height: u16,
    focused: bool,
    pal: &Palette,
) -> Vec<String> {
    let w = width.max(10) as usize;
    let interior = w - 2; // the two vertical bars
    let accent = pal.accent.map(fg256).unwrap_or_default();
    let reset = if pal.accent.is_some() { RESET } else { "" };

    // ── Title rule: ╔═[ TITLE ]═…═╗ padded to width ──
    let head = format!("╔═[ {title} ]");
    let head_w = display_width(&head); // ASCII + title, width-1 each
    let fill = w.saturating_sub(head_w + 1); // +1 for the closing ╗
    let title_text = format!("{head}{}╗", "═".repeat(fill));
    let title_line = if focused {
        format!("{accent}{BOLD}{REVERSE}{title_text}{RESET}")
    } else {
        format!("{accent}{title_text}{reset}")
    };

    let mut out = vec![title_line];

    // ── Body rows, each walled ║ … ║ ──
    let body_rows = if height > 2 {
        (height - 2) as usize
    } else {
        body.len()
    };
    for i in 0..body_rows.max(body.len()) {
        if i >= body_rows && height > 2 {
            break;
        }
        let content = body.get(i).map(String::as_str).unwrap_or("");
        let filled = fit(content, interior);
        out.push(format!("{accent}║{reset}{filled}{accent}║{reset}"));
    }

    // ── Footer rule: ╚═…═╝ with the end-cap ornament tucked at the right ──
    // The ornament is placed inside the run (its SMP cells are off the box
    // corners), so the ╝ still lands exactly at the edge visually.
    let footer_core = "═".repeat(w.saturating_sub(2));
    let footer = format!("{accent}╚{footer_core}╝{reset}");
    out.push(footer);
    // End-cap ornament on its own trailing seam, dim + accent, right-tucked.
    let cap = format!("{accent}{DIM}{END_CAP}{RESET}");
    let pad = w.saturating_sub(display_width(END_CAP) + 1);
    out.push(format!("{}{cap}", " ".repeat(pad)));

    out
}

/// A one-line status bar: the current Outcome message + a hint of the keymap,
/// tinted with the palette accent. Always fits to `width`.
pub fn status_bar(message: &str, hint: &str, width: u16, pal: &Palette) -> String {
    let accent = pal.accent.map(fg256).unwrap_or_default();
    let reset = if pal.accent.is_some() { RESET } else { "" };
    let left = format!(" {DIVIDER} {message}");
    let hint_styled = format!("{DIM}{hint}{RESET}");
    // Right-align the hint if there is room.
    let lw = display_width(&left);
    let hw = display_width(&hint_styled);
    let total = width as usize;
    let line = if lw + hw + 1 <= total {
        let gap = total - lw - hw;
        format!("{left}{}{hint_styled}", " ".repeat(gap))
    } else {
        left
    };
    format!("{accent}{}{reset}", fit(&line, total))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baton::app::Palette;

    #[test]
    fn display_width_ignores_ansi() {
        assert_eq!(display_width("abc"), 3);
        assert_eq!(display_width("\x1b[31mabc\x1b[0m"), 3);
        assert_eq!(display_width(&fg256(9)), 0);
    }

    #[test]
    fn fit_pads_and_truncates() {
        assert_eq!(display_width(&fit("hi", 5)), 5);
        assert_eq!(display_width(&fit("hello world", 5)), 5);
        // ANSI is preserved but not counted.
        let styled = format!("{GREEN}ok{RESET}");
        assert_eq!(display_width(&fit(&styled, 4)), 4);
    }

    #[test]
    fn frame_carries_title_ornament_and_walls() {
        let pal = Palette::default();
        let lines = frame("DAG", &["● a session".into()], 30, 0, true, &pal);
        assert!(lines[0].contains("╔═[ DAG ]"), "title rule present");
        assert!(lines[0].contains("╗"));
        // A body row is walled.
        assert!(lines
            .iter()
            .any(|l| l.contains("║") && l.contains("a session")));
        // Footer + the verbatim end-cap ornament.
        assert!(lines.iter().any(|l| l.contains("╚") && l.contains("╝")));
        assert!(
            lines.iter().any(|l| l.contains(END_CAP)),
            "clef-tail end-cap present"
        );
    }

    #[test]
    fn frame_title_line_is_exact_width_without_palette() {
        let pal = Palette::default(); // no colour → no escapes to discount
        let lines = frame("LOG", &[], 24, 0, false, &pal);
        assert_eq!(
            display_width(&lines[0]),
            24,
            "title rule fills the width exactly"
        );
    }
}
