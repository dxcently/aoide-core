//! The hand-rolled differential renderer + the `Component` contract.
//!
//! pi's renderer in ~100 lines: components hand up `Vec<String>` (one string
//! per screen row, already styled with SGR); the compositor stacks them into a
//! frame; [`Renderer::paint`] writes only what changed.
//!
//! Differential paint: we keep the last frame's lines. On the next frame we
//! find the FIRST row that differs, move the cursor there, clear from there to
//! the bottom, and repaint from that row down — untouched rows above are never
//! rewritten. A resize forces a full repaint (`full: true`) because the diff
//! base is meaningless once the geometry moved. Every frame is wrapped in the
//! synchronized-output pair (CSI ?2026h/l) so a partial write never flickers,
//! and every emitted row ends in an SGR reset (`\x1b[0m`) so a colour can't
//! bleed past its line.

use std::io::{self, Write};

/// One frame: the exact rows to show, top to bottom. `Renderer` diffs this
/// against the previous frame and paints the minimum.
pub struct Frame {
    pub lines: Vec<String>,
}

impl Frame {
    pub fn new(lines: Vec<String>) -> Self {
        Frame { lines }
    }
}

/// A drawable: given a width, hand up the rows to show. Pure — same state, same
/// lines — which is what makes every panel unit-testable without a terminal.
pub trait Component {
    fn render(&self, width: u16) -> Vec<String>;
}

/// SGR reset appended to every emitted row so colour never bleeds downward.
const RESET: &str = "\x1b[0m";
/// Synchronized-output begin/end (CSI ?2026h / ?2026l): the terminal buffers
/// the enclosed writes and flips them atomically, so a mid-frame read can't
/// show a torn paint.
const SYNC_BEGIN: &str = "\x1b[?2026h";
const SYNC_END: &str = "\x1b[?2026l";

/// The differential compositor. Holds the previously painted frame so the next
/// paint can skip unchanged rows.
pub struct Renderer {
    last: Vec<String>,
}

impl Renderer {
    pub fn new() -> Self {
        Renderer { last: Vec::new() }
    }

    /// Index of the first row that differs between `last` and `next`. `None`
    /// means the visible prefix is identical AND there are no extra/short rows
    /// to reconcile — i.e. nothing to paint. Extra or missing trailing rows
    /// count as a difference at the first divergent index.
    ///
    /// Pure and side-effect-free so the diff math is unit-testable.
    pub fn first_diff(last: &[String], next: &[String]) -> Option<usize> {
        let n = last.len().max(next.len());
        for i in 0..n {
            match (last.get(i), next.get(i)) {
                (Some(a), Some(b)) if a == b => continue,
                _ => return Some(i),
            }
        }
        None
    }

    /// Paint `frame`. When `full` is set (first frame or a resize) the whole
    /// screen is cleared and every row rewritten; otherwise only rows from the
    /// first change downward are touched.
    pub fn paint(&mut self, out: &mut impl Write, frame: &Frame, full: bool) -> io::Result<()> {
        let next = &frame.lines;

        let start = if full {
            Some(0)
        } else {
            Self::first_diff(&self.last, next)
        };

        let Some(start) = start else {
            // Nothing changed — don't even open a synchronized block.
            return Ok(());
        };

        let mut buf = String::new();
        buf.push_str(SYNC_BEGIN);
        if full {
            // Home + clear entire screen for a fresh start.
            buf.push_str("\x1b[H\x1b[2J");
        }
        // Move to the first changed row (1-based rows/cols in CSI H), column 1.
        buf.push_str(&format!("\x1b[{};1H", start + 1));
        // Clear from the cursor to the end of the screen: this erases any rows
        // that used to exist below but no longer do (a shorter new frame).
        buf.push_str("\x1b[J");

        for (i, line) in next.iter().enumerate().skip(start) {
            // Position each row explicitly (robust against wide glyphs the
            // terminal may advance the cursor past inconsistently).
            buf.push_str(&format!("\x1b[{};1H", i + 1));
            buf.push_str(line);
            buf.push_str(RESET);
        }
        buf.push_str(SYNC_END);

        out.write_all(buf.as_bytes())?;
        out.flush()?;
        self.last = next.clone();
        Ok(())
    }
}

impl Default for Renderer {
    fn default() -> Self {
        Renderer::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_diff_finds_the_first_changed_row() {
        let a = vec!["one".to_string(), "two".to_string(), "three".to_string()];
        let mut b = a.clone();
        b[1] = "TWO".to_string();
        assert_eq!(Renderer::first_diff(&a, &b), Some(1));
    }

    #[test]
    fn first_diff_none_when_identical() {
        let a = vec!["x".to_string(), "y".to_string()];
        assert_eq!(Renderer::first_diff(&a, &a.clone()), None);
    }

    #[test]
    fn first_diff_handles_growth_and_shrink() {
        // New frame is longer: the first extra row is the diff point.
        let a = vec!["a".to_string()];
        let b = vec!["a".to_string(), "b".to_string()];
        assert_eq!(Renderer::first_diff(&a, &b), Some(1));
        // New frame is shorter: the now-missing row is the diff point.
        assert_eq!(Renderer::first_diff(&b, &a), Some(1));
    }

    #[test]
    fn paint_full_then_noop_then_partial() {
        let mut r = Renderer::new();
        let mut buf: Vec<u8> = Vec::new();

        let f1 = Frame::new(vec!["line one".into(), "line two".into()]);
        r.paint(&mut buf, &f1, true).unwrap();
        let full = String::from_utf8(std::mem::take(&mut buf)).unwrap();
        assert!(full.contains("\x1b[2J"), "full paint clears the screen");
        assert!(full.contains(SYNC_BEGIN) && full.contains(SYNC_END));
        assert!(full.contains("line one") && full.contains("line two"));
        assert!(full.contains(RESET), "each row ends with an SGR reset");

        // Identical frame → nothing written.
        r.paint(&mut buf, &f1, false).unwrap();
        assert!(buf.is_empty(), "identical frame is a no-op");

        // Change only the second line → paint starts at row 2, not row 1.
        let f2 = Frame::new(vec!["line one".into(), "LINE TWO".into()]);
        r.paint(&mut buf, &f2, false).unwrap();
        let partial = String::from_utf8(buf).unwrap();
        assert!(
            partial.contains("\x1b[2;1H"),
            "cursor jumps to the changed row"
        );
        assert!(
            !partial.contains("\x1b[2J"),
            "partial paint never clears all"
        );
        assert!(partial.contains("LINE TWO"));
        assert!(
            !partial.contains("line one"),
            "unchanged row above is not repainted"
        );
    }
}
