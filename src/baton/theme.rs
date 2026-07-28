//! Shared chrome, colour, glyphs, and the small pure helpers the views lean on.
//!
//! The renderer is ratatui now, so "style" is a [`ratatui::style::Style`] rather
//! than a hand-emitted SGR string — but the *identity* is unchanged: the frames
//! echo the gadget dock, the ornament alphabet is lifted verbatim from the
//! Quickshell QML (the `ৎ𝄢` clef-tail end-cap [`END_CAP`] from `GadgetFrame.qml`
//! and the `𝄂𝄚𝅦𝄚` stave-run divider [`DIVIDER`] from `AoideBar.qml`), and the
//! roster reads in musical notation (♪ working, 𝄐 awaiting, 𝄽 idle, 𝄂 done).
//!
//! Colour comes from `stage/drachma.json`'s palette `{bg,fg,accent,urgent}` when
//! present, each hex already mapped to the nearest ANSI-256 index in
//! [`crate::baton::app`]; here we wrap those indices as `Color::Indexed`. Absent
//! a palette key we fall back to a named ANSI colour so the TUI still reads,
//! exactly as the hand-rolled renderer did.

use crate::baton::app::{is_done, Palette};
use crate::graph::SessionRecord;
use ratatui::style::{Color, Modifier, Style};

/// Clef-tail end-cap ornament — verbatim from `GadgetFrame.qml` / `AoideBar.qml`.
pub const END_CAP: &str = "ৎ𝄢";
/// Short stave-run divider — verbatim from `AoideBar.qml` / `PowerGadget.qml`.
pub const DIVIDER: &str = "𝄂𝄚𝅦𝄚";

/// A palette index → ratatui colour (none → inherit the terminal).
pub fn opt_color(idx: Option<u8>) -> Option<Color> {
    idx.map(Color::Indexed)
}

/// The accent colour: the palette's, or `None` to inherit (the brand header /
/// frame borders use this and simply stay uncoloured on a paletteless rig).
pub fn accent(pal: &Palette) -> Option<Color> {
    opt_color(pal.accent)
}

/// A `Style` foreground-tinted with the accent when present (else unchanged).
pub fn accent_style(pal: &Palette) -> Style {
    match accent(pal) {
        Some(c) => Style::default().fg(c),
        None => Style::default(),
    }
}

/// Dim modifier — the "inherit, but quieter" style the chrome uses for paths,
/// footers, and settled detail.
pub fn dim() -> Style {
    Style::default().add_modifier(Modifier::DIM)
}

// ── Session state → glyph + colour ──────────────────────────────────────────

/// The coarse state classes the roster paints, derived once so glyph and colour
/// never disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateClass {
    Working,
    Awaiting,
    Idle,
    Done,
    Unknown,
}

/// Classify a raw state/phase string (the same buckets the hand-rolled renderer
/// used: `done`/Stop → done, await/block/notification → awaiting, running/tool
/// phases/active → working, idle → idle, everything else → unknown).
pub fn classify(state: &str) -> StateClass {
    let l = state.to_ascii_lowercase();
    if is_done(state) {
        StateClass::Done
    } else if l.contains("await") || l.contains("block") || l == "notification" {
        StateClass::Awaiting
    } else if l.contains("running")
        || l.contains("pretooluse")
        || l.contains("posttooluse")
        || l.contains("active")
    {
        StateClass::Working
    } else if l.contains("idle") {
        StateClass::Idle
    } else {
        StateClass::Unknown
    }
}

/// A musical glyph for a session state — working a note (♪), awaiting-input a
/// fermata (𝄐, the "hold" sign), idle a rest (𝄽), done the final barline (𝄂),
/// and anything unrecognised a modest dot (·).
pub fn state_glyph(state: &str) -> &'static str {
    match classify(state) {
        StateClass::Working => "♪",
        StateClass::Awaiting => "𝄐",
        StateClass::Idle => "𝄽",
        StateClass::Done => "𝄂",
        StateClass::Unknown => "·",
    }
}

/// The colour that partners the glyph — green working, the palette's urgent hue
/// (yellow fallback) for an awaiting/blocked session that needs a human, cyan
/// idle, dim done, inherit for the unknown.
pub fn state_style(state: &str, pal: &Palette) -> Style {
    match classify(state) {
        StateClass::Working => Style::default().fg(Color::Green),
        StateClass::Awaiting => Style::default().fg(opt_color(pal.urgent).unwrap_or(Color::Yellow)),
        StateClass::Idle => Style::default().fg(Color::Cyan),
        StateClass::Done => dim(),
        StateClass::Unknown => Style::default(),
    }
}

// ── Read-only tags (the seam: no CLI tag surface yet — see report) ──────────

/// Tags carried on a session record. The graph/schema has NO tag surface today
/// (`aoide schema --json` exposes no tag field or command), so we read them
/// from the record's round-tripped `extra` map under a `tags` array — the shape
/// a future `aoide graph tag` (or a shellbridge that writes `tags`) would use.
/// Purely READ-ONLY: the baton renders tags it finds but cannot mint them,
/// because inventing CLI surface here would break the two-doors-one-schema
/// contract. A string value is accepted as a single tag for tolerance.
pub fn session_tags(rec: &SessionRecord) -> Vec<String> {
    match rec.extra.get("tags") {
        Some(serde_json::Value::Array(a)) => a
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

// ── Audit-log colouring (LOG panel) ─────────────────────────────────────────

/// The colour an audit status wears — green for the flavours of success, red
/// error, yellow usage, dim not-implemented, cyan otherwise.
pub fn status_color(status: &str) -> Color {
    match status {
        "ok" | "started" | "proposed" | "forwarded" => Color::Green,
        "error" => Color::Red,
        "usage" => Color::Yellow,
        "not-implemented" => Color::DarkGray,
        _ => Color::Cyan,
    }
}

/// One hue per event class so a scanning eye sorts audit from gate from rice.
pub fn class_color(class: &str) -> Option<Color> {
    match class {
        "audit" => Some(Color::Cyan),
        "gate" => Some(Color::Yellow),
        "rice" => Some(Color::Magenta),
        "content" => Some(Color::Blue),
        "notification" => Some(Color::Red),
        _ => None,
    }
}

// ── Small pure formatters (moved verbatim from the old panels module) ───────

/// A `[▓░]` meter — `filled` shaded cells of `width`, the rest hollow.
pub fn ascii_bar(filled: usize, width: usize) -> String {
    let f = filled.min(width);
    format!("[{}{}]", "▓".repeat(f), "░".repeat(width - f))
}

/// Shorten a cwd to its last two components — the tail tells sessions apart.
pub fn shorten_cwd(cwd: &str) -> String {
    let parts: Vec<&str> = cwd
        .trim_end_matches('/')
        .split('/')
        .filter(|p| !p.is_empty())
        .collect();
    match parts.len() {
        0 => cwd.to_string(),
        1 => format!("/{}", parts[0]),
        n => format!("…/{}/{}", parts[n - 2], parts[n - 1]),
    }
}

/// A relative elapsed clock from an ISO-8601 `startedAt`: mm:ss under the hour,
/// `Hh MMm` under the day, whole days beyond. An unparseable stamp or a start in
/// the future yields the empty string.
pub fn elapsed_str(started_at: &str) -> String {
    let Some(epoch) = parse_iso_utc(started_at) else {
        return String::new();
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let secs = now - epoch;
    if secs < 0 {
        return String::new();
    }
    if secs < 3600 {
        format!("{:02}:{:02}", secs / 60, secs % 60)
    } else if secs < 86400 {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d", secs / 86400)
    }
}

/// Parse `YYYY-MM-DDTHH:MM:SS` (a trailing `Z` tolerated) to UTC epoch seconds,
/// or `None` when the shape doesn't hold — a hand-rolled civil-days conversion
/// so the lock never grows a chrono just to subtract two timestamps.
pub fn parse_iso_utc(s: &str) -> Option<i64> {
    let s = s.trim();
    let bytes = s.as_bytes();
    if bytes.len() < 19 || bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' {
        return None;
    }
    let num = |a: usize, b: usize| -> Option<i64> { s.get(a..b)?.parse().ok() };
    let year = num(0, 4)?;
    let month = num(5, 7)?;
    let day = num(8, 10)?;
    let hour = num(11, 13)?;
    let min = num(14, 16)?;
    let sec = num(17, 19)?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + hour * 3600 + min * 60 + sec)
}

/// `—` for an empty field, else the field.
pub fn disp(s: &str) -> &str {
    if s.is_empty() {
        "—"
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Map;

    fn rec_with_tags(tags: serde_json::Value) -> SessionRecord {
        let mut extra = Map::new();
        extra.insert("tags".into(), tags);
        SessionRecord {
            session_id: "s".into(),
            extra,
            ..Default::default()
        }
    }

    #[test]
    fn glyphs_track_state_classes() {
        assert_eq!(state_glyph("running"), "♪");
        assert_eq!(state_glyph("Notification"), "𝄐");
        assert_eq!(state_glyph("awaiting-input"), "𝄐");
        assert_eq!(state_glyph("idle"), "𝄽");
        assert_eq!(state_glyph("done"), "𝄂");
        assert_eq!(state_glyph("Stop"), "𝄂");
        assert_eq!(state_glyph("weird"), "·");
        // The blocked fermata: a session that needs a human wears the same 𝄐
        // hold-sign and the Awaiting (urgent) class as any awaiting state — the
        // contract the baton and the Rust door agree on.
        assert_eq!(state_glyph("blocked"), "𝄐");
        assert_eq!(classify("blocked"), StateClass::Awaiting);
        // PostToolUse (the new clearing edge) reads as Working, not Awaiting.
        assert_eq!(classify("PostToolUse"), StateClass::Working);
    }

    #[test]
    fn tags_read_array_and_string_but_never_invent() {
        assert_eq!(
            session_tags(&rec_with_tags(serde_json::json!(["a", "b"]))),
            vec!["a".to_string(), "b".to_string()]
        );
        assert_eq!(
            session_tags(&rec_with_tags(serde_json::json!("solo"))),
            vec!["solo".to_string()]
        );
        assert!(session_tags(&SessionRecord::default()).is_empty());
    }

    #[test]
    fn iso_parse_and_elapsed() {
        assert_eq!(parse_iso_utc("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_iso_utc("1970-01-02T00:00:00Z"), Some(86400));
        assert!(parse_iso_utc("not-a-date").is_none());
        assert_eq!(elapsed_str("2999-01-01T00:00:00Z"), "");
    }

    #[test]
    fn shorten_cwd_keeps_tail() {
        assert_eq!(shorten_cwd("/home/k/Aoide/pkgs/aoide"), "…/pkgs/aoide");
        assert_eq!(shorten_cwd("/tmp"), "/tmp");
    }
}
