//! Shared chrome, colour, glyphs, and the small pure helpers the views lean on.
//!
//! The renderer is ratatui now, so "style" is a [`ratatui::style::Style`] rather
//! than a hand-emitted SGR string — but the *identity* is unchanged: the frames
//! echo the gadget dock, the ornament alphabet is lifted verbatim from the
//! Quickshell QML (the `ৎ𝄢` clef-tail end-cap [`END_CAP`] from `GadgetFrame.qml`
//! and the `𝄂𝄚𝅦𝄚` stave-run divider [`DIVIDER`] from `AoideBar.qml`), and the
//! roster reads in musical notation (♪ working, 𝄐 awaiting, 𝄁 stopped, 𝄽 idle,
//! 𝄂 done).
//!
//! Colour comes from stage livery palette and Base16 tokens as exact RGB.
//! Missing semantic tokens retain ANSI fallbacks; focused tabs use role fills,
//! while inactive selections keep subdued foreground/background-derived shades.

use crate::app::{is_done, Palette};
use aoide_conduct::graph::SessionRecord;
use ratatui::style::{Color, Modifier, Style};

/// Semantic hues use the livery's Base16 slots, with ANSI fallback.
#[derive(Debug, Clone, Copy)]
pub enum Role {
    Project,
    Agent,
    Terminal,
    Mail,
    /// Mesh hosts / nodes (base0F).
    Host,
    /// Past sessions and resurrection (base03).
    History,
    Success,
    Warning,
    Error,
    Muted,
}

/// Identity marks — ONE table, used by the header counts, the tab row, the
/// project tree, the roster legends, the graph cards and the action menus,
/// so a thing wears the same mark everywhere. Every mark is a BMP code point
/// that renders one cell wide in kitty/wezterm/foot and is covered by DejaVu
/// Sans Mono, JetBrainsMono and Noto Sans Symbols (measured 2026-09-13); no
/// SMP music glyphs (they fall back to specks) and no icon-font PUA. `@` is
/// reserved for addresses (`name@node`). Colour never lives here — the
/// partner hue is always a [`Role`] slot, so the livery stays in charge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    Home,
    Mail,
    Agent,
    Terminal,
    Host,
    Review,
    Project,
    Folder,
    Graph,
    Log,
    Status,
    Past,
    Resurrect,
    Model,
    Cursor,
}

pub fn mark(m: Mark) -> &'static str {
    match m {
        Mark::Home => "⌂",      // U+2302
        Mark::Mail => "✉",      // U+2709
        Mark::Agent => "♜",     // U+265C the rook, one piece the User moves
        Mark::Terminal => "▣",  // U+25A3 a screen
        Mark::Host => "🖧", // U+1F5A7 three networked computers (width 1; Noto Symbols 2 fallback)
        Mark::Review => "⚑", // U+2691 held for a human
        Mark::Project => "◆", // U+25C6
        Mark::Folder => "◇", // U+25C7 a root under the project
        Mark::Graph => "∴", // U+2234 three nodes
        Mark::Log => "≡",  // U+2261
        Mark::Status => "⚙", // U+2699
        Mark::Past => "◌", // U+25CC a session that was
        Mark::Resurrect => "↻", // U+21BB
        Mark::Model => "⊚", // U+229A
        Mark::Cursor => "◉", // U+25C9 the one selection mark
    }
}

pub fn role_color(pal: &Palette, role: Role) -> Color {
    let (slot, fallback) = match role {
        Role::Project => (13, Color::Blue),
        Role::Agent => (14, Color::Magenta),
        Role::Terminal => (12, Color::Cyan),
        Role::Mail => (9, Color::Yellow),
        Role::Host => (15, Color::LightRed),
        Role::History => (3, Color::DarkGray),
        Role::Success => (11, Color::Green),
        Role::Warning => (10, Color::Yellow),
        Role::Error => (8, Color::Red),
        Role::Muted => (4, Color::DarkGray),
    };
    pal.base16[slot]
        .map(|(r, g, b)| Color::Rgb(r, g, b))
        .or_else(|| {
            if matches!(role, Role::Error) {
                pal.urgent_rgb
                    .map(|(r, g, b)| Color::Rgb(r, g, b))
                    .or_else(|| opt_color(pal.urgent))
            } else {
                None
            }
        })
        .unwrap_or(fallback)
}

/// Only the keyboard-focused selection receives a bright semantic fill.
pub fn tab_style(pal: &Palette, role: Role, selected: bool, focused: bool) -> Style {
    let hue = role_color(pal, role);
    if selected && focused {
        let (r, g, b) = match hue {
            Color::Rgb(r, g, b) => (r, g, b),
            Color::Indexed(i) => rgb(i),
            _ => {
                return Style::default()
                    .fg(Color::Black)
                    .bg(hue)
                    .add_modifier(Modifier::BOLD)
            }
        };
        let luminance = u32::from(r) * 299 + u32::from(g) * 587 + u32::from(b) * 114;
        let candidates = [pal.bg_rgb.or(pal.base16[0]), pal.fg_rgb.or(pal.base16[5])];
        let ink = candidates
            .into_iter()
            .flatten()
            .max_by_key(|&(r, g, b)| {
                luminance.abs_diff(u32::from(r) * 299 + u32::from(g) * 587 + u32::from(b) * 114)
            })
            .map(|(r, g, b)| Color::Rgb(r, g, b))
            .unwrap_or(if luminance >= 128000 {
                Color::Black
            } else {
                Color::White
            });
        Style::default()
            .fg(ink)
            .bg(hue)
            .add_modifier(Modifier::BOLD)
    } else {
        surface(pal, if selected { 12 } else { 4 }).fg(hue)
    }
}

fn rgb(index: u8) -> (u8, u8, u8) {
    const BASIC: [(u8, u8, u8); 16] = [
        (0, 0, 0),
        (128, 0, 0),
        (0, 128, 0),
        (128, 128, 0),
        (0, 0, 128),
        (128, 0, 128),
        (0, 128, 128),
        (192, 192, 192),
        (128, 128, 128),
        (255, 0, 0),
        (0, 255, 0),
        (255, 255, 0),
        (0, 0, 255),
        (255, 0, 255),
        (0, 255, 255),
        (255, 255, 255),
    ];
    if index < 16 {
        return BASIC[index as usize];
    }
    if index >= 232 {
        let c = 8 + (index - 232) * 10;
        return (c, c, c);
    }
    let n = index - 16;
    let v = |x: u8| if x == 0 { 0 } else { 55 + x * 40 };
    (v(n / 36), v((n / 6) % 6), v(n % 6))
}
/// Surface shades derive from the same foreground/background, in either light or dark livery.
pub fn surface(pal: &Palette, amount: u16) -> Style {
    let mut style = Style::default();
    if let Some((r, g, b)) = pal.fg_rgb.or_else(|| pal.fg.map(rgb)) {
        style = style.fg(Color::Rgb(r, g, b));
    }
    if let (Some((a, b, c)), Some((x, y, z))) = (
        pal.bg_rgb.or_else(|| pal.bg.map(rgb)),
        pal.fg_rgb.or_else(|| pal.fg.map(rgb)),
    ) {
        let mix = |a: u8, b: u8| {
            ((u16::from(a) * (100 - amount.min(100)) + u16::from(b) * amount.min(100)) / 100) as u8
        };
        style = style.bg(Color::Rgb(mix(a, x), mix(b, y), mix(c, z)));
    }
    style
}

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
    pal.accent_rgb
        .map(|(r, g, b)| Color::Rgb(r, g, b))
        .or_else(|| opt_color(pal.accent))
}

/// A `Style` foreground-tinted with the accent when present (else unchanged).
pub fn accent_style(pal: &Palette) -> Style {
    match accent(pal) {
        Some(c) => Style::default().fg(c),
        None => Style::default(),
    }
}

/// Secondary text keeps terminal contrast; terminal DIM can erase light-palette text.
pub fn dim() -> Style {
    Style::default()
}

// ── Session state → glyph + colour ──────────────────────────────────────────

/// The coarse state classes the roster paints, derived once so glyph and colour
/// never disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateClass {
    Working,
    Awaiting,
    Stopped,
    Idle,
    Done,
    Unknown,
}

/// Classify a raw state/phase string (the same buckets the hand-rolled renderer
/// used: `done`/exit → done, await/block/notification → awaiting, stop/stopped →
/// stopped, running/tool phases/active → working, idle → idle, everything else →
/// unknown).
pub fn classify(state: &str) -> StateClass {
    let l = state.to_ascii_lowercase();
    if is_done(state) {
        StateClass::Done
    } else if l.contains("await") || l.contains("block") || l == "notification" {
        StateClass::Awaiting
    } else if l.contains("running")
        || l == "working"
        || l.contains("pretooluse")
        || l.contains("posttooluse")
        || l.contains("active")
    {
        StateClass::Working
    } else if l.contains("stop") {
        // The turn ended, recently — alive at the prompt, NOT past the final
        // barline. (`SubagentStop` lands here too, which is right: it names a
        // finished turn, not a finished session.)
        StateClass::Stopped
    } else if l.contains("idle") {
        StateClass::Idle
    } else {
        StateClass::Unknown
    }
}

/// A musical glyph for a session state — working a note (♪), awaiting-input a
/// fermata (𝄐, the "hold" sign), stopped the SECTION barline (𝄁 — the turn ended,
/// the piece has not), idle a rest (𝄽), done the FINAL barline (𝄂), and anything
/// unrecognised a modest dot (·).
pub fn state_glyph(state: &str) -> &'static str {
    match classify(state) {
        StateClass::Working => "♪",
        StateClass::Awaiting => "𝄐",
        StateClass::Stopped => "𝄁",
        StateClass::Idle => "𝄽",
        StateClass::Done => "𝄂",
        StateClass::Unknown => "·",
    }
}

/// The colour that partners the glyph — green working, the palette's urgent hue
/// (yellow fallback) for an awaiting/blocked session that needs a human, blue
/// stopped (warm, just finished), cyan idle, dim done, inherit for the unknown.
pub fn state_style(state: &str, pal: &Palette) -> Style {
    match classify(state) {
        StateClass::Working => Style::default().fg(role_color(pal, Role::Success)),
        StateClass::Awaiting => Style::default().fg(role_color(pal, Role::Warning)),
        StateClass::Stopped => Style::default().fg(role_color(pal, Role::Project)),
        StateClass::Idle => Style::default().fg(role_color(pal, Role::Terminal)),
        StateClass::Done => Style::default().fg(role_color(pal, Role::Muted)),
        StateClass::Unknown => Style::default(),
    }
}

// ── Read-only tags (the seam: no CLI tag surface yet — see report) ──────────

/// Tags carried on a session record. The graph/schema has NO tag surface today
/// (`aoide schema --json` exposes no tag field or command), so we read them
/// from the record's round-tripped `extra` map under a `tags` array — the shape
/// a future `aoide graph tag` (or a shellbridge that writes `tags`) would use.
/// Purely READ-ONLY: the conductor renders tags it finds but cannot mint them,
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

/// Parse `YYYY-MM-DDTHH:MM:SS` (a trailing `Z` tolerated) to UTC epoch
/// seconds, or `None` when the shape doesn't hold. Moved to `aoide-storage`
/// (Phase 3a restructure, docs/architecture/PACKAGE-LAYOUT.md) as
/// `storage::time::parse_iso_utc` (the exact inverse of
/// `storage::time::iso_utc_from_epoch`, the writer); re-exported here so
/// every existing `crate::theme::parse_iso_utc` caller is
/// untouched.
pub use aoide_storage::time::parse_iso_utc;

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

    #[test]
    fn semantic_tokens_and_focus_preserve_livery() {
        let mut pal = Palette::default();
        pal.base16[13] = Some((31, 62, 93));
        pal.base16[11] = Some((41, 82, 123));
        pal.bg_rgb = Some((240, 230, 220));
        pal.fg_rgb = Some((20, 30, 40));
        assert_eq!(role_color(&pal, Role::Project), Color::Rgb(31, 62, 93));
        assert_eq!(
            state_style("working", &pal).fg,
            Some(Color::Rgb(41, 82, 123))
        );
        let active = tab_style(&pal, Role::Project, true, true);
        assert_eq!(active.bg, Some(Color::Rgb(31, 62, 93)));
        assert_eq!(active.fg, Some(Color::Rgb(240, 230, 220)));
        assert_ne!(tab_style(&pal, Role::Project, true, false).bg, active.bg);
        assert_eq!(role_color(&Palette::default(), Role::Agent), Color::Magenta);
    }

    #[test]
    fn loader_reads_actual_base16_keys_and_ignores_invalid_tokens() {
        let path = std::env::temp_dir().join(format!(
            "conductor-livery-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, r##"{"palette":{"bg":"#f2ebde","fg":"#2f2a33","urgent":"#b0472f"},"base16":{"base0D":"#345f81","base0E":"bad-token","base0B":"#4e8b45"}}"##).unwrap();
        let pal = crate::app::load_palette(&path);
        std::fs::remove_file(path).unwrap();
        assert_eq!(pal.base16[13], Some((52, 95, 129)));
        assert_eq!(pal.base16[14], None);
        assert_eq!(pal.base16[0], None);
        assert_eq!(pal.urgent_rgb, Some((176, 71, 47)));
    }

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
        // `Stop` is the TURN's section barline, not the session's final one — a
        // stopped session is still live (and still counts toward `[live/total]`).
        assert_eq!(state_glyph("Stop"), "𝄁");
        assert_eq!(state_glyph("stopped"), "𝄁");
        assert_eq!(classify("stopped"), StateClass::Stopped);
        assert!(!is_done("stopped"));
        assert_eq!(state_glyph("weird"), "·");
        // The blocked fermata: a session that needs a human wears the same 𝄐
        // hold-sign and the Awaiting (urgent) class as any awaiting state — the
        // contract the conductor and the Rust door agree on.
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
