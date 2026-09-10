//! The ratatui view layer — top-level layout, the six panel widgets, the
//! status bar, and two overlays: help and the headless-session log tail.
//!
//! This replaces the hand-rolled differential renderer + the `Vec<String>`
//! panels: ratatui owns the double buffer and the diff now, so every panel is a
//! `draw(frame, area, app)` that composes ratatui widgets. The identity is
//! preserved wholesale — the double box-drawing frames, the clef-tail end-cap on
//! each footer seam, the musical state glyphs, the accent tint from
//! `livery.json` — but expressed as [`ratatui::style::Style`] rather than raw
//! SGR. Panels stay pure over `&App`, so a `TestBackend` can render any of them
//! headless and assert on the buffer (see the tests below).
//!
//! Two of the seven panels are the expansion this port carries: `DAG` (the
//! visual graph, drawn by [`crate::graphview`]) and `SESSION` (the
//! terminal roster, now split into a scrolling list + a live detail card with a
//! focus affordance). The other three — PROJECTS, LOG, STATUS — are ports of the
//! originals. `ROSTER` (messaging/presence plan, P-C4; selection + compose
//! added P-C5) and `PENDING` (P-C5) are later, distinct additions. ROSTER is
//! presence over this box plus every registered node, sourced from a
//! throttled, backgrounded `session --hosts` dispatch (`app`'s "ROSTER" section covers
//! the threading; this file only paints what `App::roster_flat_rows` hands
//! it) — plus, since P-C5, selection and an `s`-to-compose affordance.
//! PENDING is held `send`/A2A entries from `session pending list`, a
//! synchronous local read (`app`'s "PENDING" section) with `a`/`d`
//! approve/deny.

use crate::app::{App, DagRow, Panel};
use crate::graphview;
use crate::theme::{self, DIVIDER, END_CAP};
use aoide_conduct::graph;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph};
use ratatui::Frame;

/// Compose the whole screen: brand header, tab strip, the active panel filling
/// the body, and the status line — then the help or log-tail overlay when
/// either is open (mutually exclusive by construction — see [`crate::app`]).
pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();
    let rows = Layout::vertical([
        Constraint::Length(1), // brand header
        Constraint::Length(1), // tab strip
        Constraint::Min(3),    // body
        Constraint::Length(1), // status bar
    ])
    .split(area);

    draw_header(f, rows[0], app);
    draw_tabs(f, rows[1], app);
    draw_body(f, rows[2], app);
    draw_status(f, rows[3], app);

    if app.help_open {
        draw_help(f, area, app);
    }
    if app.tail.is_some() {
        draw_log_tail(f, area, app);
    }
}

// ── Chrome: header, tabs, status bar ────────────────────────────────────────

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let brand = format!("{END_CAP} aoide · conductor {DIVIDER}  conduct the agent sessions");
    let p = Paragraph::new(Line::from(brand)).style(theme::accent_style(&app.palette));
    f.render_widget(p, area);
}

fn draw_tabs(f: &mut Frame, area: Rect, app: &App) {
    let mut spans: Vec<Span> = Vec::new();
    let accent = theme::accent(&app.palette);
    for (i, p) in Panel::ALL.iter().enumerate() {
        let label = format!(" {} {} ", i + 1, p.title());
        if *p == app.panel {
            let mut st = Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD);
            if let Some(c) = accent {
                st = st.fg(c);
            }
            spans.push(Span::styled(label, st));
        } else {
            spans.push(Span::styled(label, theme::dim()));
        }
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_status(f: &mut Frame, area: Rect, app: &App) {
    let hint = keymap_hint(app.panel);
    let msg = if let Some(input) = &app.input {
        format!("{}: {}▏", input.label, input.buffer)
    } else {
        app.status_message()
    };
    let left = format!(" {DIVIDER} {msg}");

    let hint_w = (hint.len() as u16 + 1).min(area.width.saturating_sub(4));
    let cols = Layout::horizontal([Constraint::Min(0), Constraint::Length(hint_w)]).split(area);
    f.render_widget(
        Paragraph::new(Line::from(left)).style(theme::accent_style(&app.palette)),
        cols[0],
    );
    f.render_widget(
        Paragraph::new(Line::from(hint).style(theme::dim()).right_aligned()),
        cols[1],
    );
}

/// The status-line keymap hint per panel — Aoide cues only, the commands this
/// frontend owns.
fn keymap_hint(panel: Panel) -> &'static str {
    match panel {
        Panel::Graph => {
            "j/k walk · g/G ends · Enter jump · p prune · Tab panel · ? help · q quit"
        }
        Panel::Session => {
            "j/k select · Enter jump/fold · h/l fold · L link · a add · d rm · p prune · ? help · q quit"
        }
        Panel::Projects => "j/k select · a add · d remove · Tab panel · ? help · q quit",
        Panel::Log => "Tab panel · ? help · q quit",
        Panel::Status => "Tab panel · ? help · q quit",
        Panel::Roster => {
            "j/k select · s compose · r refresh (auto ~15s while open) · Tab panel · ? help · q quit"
        }
        Panel::Pending => "j/k select · a approve · d deny · Tab panel · ? help · q quit",
    }
}

/// A framed panel block: the double box, an accent border, a reverse-video
/// title, and the clef-tail end-cap tucked on the bottom-right seam (the same
/// ornament placement the QML uses).
fn panel_block(title: &str, app: &App) -> Block<'static> {
    let accent = theme::accent(&app.palette);
    let mut title_style = Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED);
    if let Some(c) = accent {
        title_style = title_style.fg(c);
    }
    let mut border_style = Style::default();
    if let Some(c) = accent {
        border_style = border_style.fg(c);
    }
    Block::new()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(border_style)
        .title(Span::styled(format!(" {title} "), title_style))
        .title_bottom(Line::from(Span::styled(END_CAP, theme::dim())).right_aligned())
}

// ── Body dispatch ───────────────────────────────────────────────────────────

fn draw_body(f: &mut Frame, area: Rect, app: &App) {
    let block = panel_block(app.panel.title(), app);
    let inner = block.inner(area);
    f.render_widget(block, area);
    match app.panel {
        Panel::Graph => graphview::render(f, inner, app, app.graph_sel),
        Panel::Session => draw_sessions(f, inner, app),
        Panel::Projects => draw_projects(f, inner, app),
        Panel::Log => draw_log(f, inner, app),
        Panel::Status => draw_status_panel(f, inner, app),
        Panel::Roster => draw_roster(f, inner, app),
        Panel::Pending => draw_pending(f, inner, app),
    }
}

// ── [1] SESSION — the roster + a live detail card ───────────────────────────

fn draw_sessions(f: &mut Frame, area: Rect, app: &App) {
    let rows = app.dag_rows();
    if rows.is_empty() {
        let lines = vec![
            Line::from(""),
            Line::from("   no agent sessions — nothing to conduct.").style(theme::dim()),
            Line::from("   𝄽  𝄽  𝄽").style(theme::dim()),
            Line::from(""),
            Line::from("   Seed a stage tree:  pkgs/aoide/tests/fixtures/seed.sh $AOIDE_STAGE_DIR")
                .style(theme::dim()),
            Line::from("   Or register a project (PROJECTS panel, press a).").style(theme::dim()),
        ];
        f.render_widget(Paragraph::new(lines), area);
        return;
    }

    let parts = Layout::vertical([
        Constraint::Length(1), // glyph legend
        Constraint::Min(3),    // roster list
        Constraint::Length(9), // detail card
    ])
    .split(area);

    // Legend: the musical glyphs ARE the content here.
    let legend = Line::from(
        " ♪ working  𝄐 awaiting  𝄁 stopped  𝄽 idle  𝄂 done  ◆ project (h/l fold)  ‣ fresh",
    )
    .style(theme::dim());
    f.render_widget(Paragraph::new(legend), parts[0]);

    // Roster: a stateful list so selection auto-scrolls.
    let accent = theme::accent(&app.palette);
    let items: Vec<ListItem> = rows.iter().map(|r| roster_item(r, app)).collect();
    let mut hl = Style::default().add_modifier(Modifier::REVERSED);
    if let Some(c) = accent {
        hl = hl.fg(c);
    }
    let list = List::new(items).highlight_style(hl);
    let mut state = ListState::default();
    state.select(Some(app.dag_sel.min(rows.len().saturating_sub(1))));
    f.render_stateful_widget(list, parts[1], &mut state);

    // Detail card for whatever the cursor is on.
    f.render_widget(Paragraph::new(detail_lines(&rows, app)), parts[2]);
}

fn roster_item<'a>(row: &DagRow, app: &App) -> ListItem<'a> {
    let pal = &app.palette;
    let accent = theme::accent(pal);
    match row {
        DagRow::Group {
            name,
            path,
            live,
            total,
            folded,
        } => {
            let caret = if *folded { "▸" } else { "▾" };
            let mut spans = vec![Span::styled(
                format!("{caret} ◆ {name}  "),
                Style::default().add_modifier(Modifier::BOLD),
            )];
            if !path.is_empty() {
                spans.push(Span::styled(format!("{path}  "), theme::dim()));
            }
            spans.push(Span::styled(
                format!("[{live}/{total}]"),
                Style::default().add_modifier(Modifier::BOLD),
            ));
            ListItem::new(Line::from(spans))
        }
        DagRow::Session { rec, prefix } => {
            let st = theme::state_style(&rec.state, pal);
            let glyph = theme::state_glyph(&rec.state);
            let fresh = app.fresh.contains_key(&rec.session_id);
            let cue_style = accent.map(|c| Style::default().fg(c)).unwrap_or_default();
            let elapsed = theme::elapsed_str(&rec.started_at);
            let cwd = theme::shorten_cwd(&rec.cwd);
            let mut spans = vec![
                Span::styled(if fresh { "‣" } else { " " }.to_string(), cue_style),
                Span::raw(prefix.clone()),
                Span::styled(format!("{glyph} "), st),
                Span::raw(format!("{}  ", rec.session_id)),
                Span::styled(format!("{}  ", rec.agent), theme::dim()),
                Span::styled(format!("{}  ", rec.state), st),
                Span::styled(format!("{}  ", elapsed), theme::dim()),
                Span::raw(cwd),
            ];
            // The running Claude model, when known — same `⟐` glyph the
            // gadget dock uses for a subagent's model text, shown uniformly
            // on agent and subagent rows alike; absent for shells.
            if let Some(model) = rec.model.as_deref().filter(|m| !m.is_empty()) {
                let ms = accent
                    .map(|c| Style::default().fg(c).add_modifier(Modifier::DIM))
                    .unwrap_or_else(theme::dim);
                spans.push(Span::styled(format!("  ⟐{model}"), ms));
            }
            for t in theme::session_tags(rec) {
                let ts = accent
                    .map(|c| Style::default().fg(c).add_modifier(Modifier::DIM))
                    .unwrap_or_else(theme::dim);
                spans.push(Span::styled(format!("  ⟨{t}⟩"), ts));
            }
            ListItem::new(Line::from(spans))
        }
    }
}

fn detail_lines<'a>(rows: &[DagRow], app: &App) -> Vec<Line<'a>> {
    let pal = &app.palette;
    let sel = app.dag_sel.min(rows.len().saturating_sub(1));
    let rule = Line::from(Span::styled(
        "──── selected ─────────────────────────────────────────",
        theme::dim(),
    ));
    match rows.get(sel) {
        Some(DagRow::Session { rec, .. }) => {
            let st = theme::state_style(&rec.state, pal);
            let merged = app.merged();
            let chain = parent_chain(&rec.session_id, &merged);
            let mut header_spans = vec![
                Span::raw("  "),
                Span::styled(format!("{} ", theme::state_glyph(&rec.state)), st),
                Span::raw(format!("{}   ", rec.session_id)),
                Span::styled(
                    format!(
                        "agent {}   ",
                        if rec.agent.is_empty() {
                            "?"
                        } else {
                            &rec.agent
                        }
                    ),
                    theme::dim(),
                ),
                Span::styled(format!("state {}", rec.state), st),
            ];
            // `log_path` is the CONTRACTS §4-exact headless marker
            // (`App::cue_session`'s own branch) — a headless session has no
            // window to report, so the header names it explicitly rather
            // than let a stale/spawner `window_address` mislead.
            if rec.log_path.is_some() {
                header_spans.push(Span::styled("   headless", theme::dim()));
            }
            let mut lines = vec![
                rule,
                Line::from(header_spans),
                Line::from(format!("  cwd     {}", rec.cwd)),
                match rec.log_path.as_deref() {
                    Some(path) => Line::from(format!(
                        "  log     {path}   started {}",
                        theme::disp(&rec.started_at)
                    )),
                    None => Line::from(format!(
                        "  window  {}   started {}",
                        theme::disp(&rec.window_address),
                        theme::disp(&rec.started_at)
                    )),
                },
            ];
            if let Some(model) = rec.model.as_deref().filter(|m| !m.is_empty()) {
                lines.push(Line::from(format!("  model   {model}")));
            }
            if let Some(activity) = rec.activity.as_deref().filter(|a| !a.is_empty()) {
                lines.push(Line::from(Span::styled(
                    format!("  doing   ▸ {activity}"),
                    st,
                )));
            }
            if let Some(say) = rec.say.as_deref().filter(|s| !s.is_empty()) {
                lines.push(Line::from(Span::styled(
                    format!("  says    \"{say}\""),
                    theme::dim(),
                )));
            }
            if !chain.is_empty() {
                lines.push(Line::from(format!("  chain   {}", chain.join(" ← "))));
            }
            let tags = theme::session_tags(rec);
            if !tags.is_empty() {
                lines.push(Line::from(format!(
                    "  tags    {}   (read-only)",
                    tags.join(" ")
                )));
            } else {
                lines.push(
                    Line::from("  tags    —   (no tag surface in the CLI yet)").style(theme::dim()),
                );
            }
            lines
        }
        Some(DagRow::Group {
            name,
            path,
            live,
            total,
            folded,
        }) => vec![
            rule,
            Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    format!("◆ {name}   "),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("[{live}/{total}] live/total"), theme::dim()),
            ]),
            Line::from(format!(
                "  path    {}",
                if path.is_empty() { "—" } else { path }
            )),
            Line::from(format!(
                "  {}   Enter or h/l folds this group",
                if *folded { "folded" } else { "open" }
            ))
            .style(theme::dim()),
        ],
        None => vec![rule],
    }
}

/// Walk a session's parent chain upward, child-to-root (cycle-guarded); empty
/// for a lone session so the detail card omits the line.
fn parent_chain(id: &str, merged: &[graph::SessionRecord]) -> Vec<String> {
    let by_id: std::collections::BTreeMap<&str, &graph::SessionRecord> =
        merged.iter().map(|r| (r.session_id.as_str(), r)).collect();
    let Some(start) = by_id.get(id) else {
        return Vec::new();
    };
    let mut chain = vec![id.to_string()];
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    seen.insert(id.to_string());
    let mut cur = start.parent_session_id.clone();
    while let Some(p) = cur {
        if !seen.insert(p.clone()) {
            break;
        }
        chain.push(p.clone());
        cur = by_id
            .get(p.as_str())
            .and_then(|r| r.parent_session_id.clone());
    }
    if chain.len() <= 1 {
        return Vec::new();
    }
    chain
}

// ── [2] PROJECTS ────────────────────────────────────────────────────────────

fn draw_projects(f: &mut Frame, area: Rect, app: &App) {
    let mut projects = app.projects.clone();
    projects.sort_by(|a, b| a.name.cmp(&b.name));

    if projects.is_empty() && app.input.is_none() {
        let lines = vec![
            Line::from(""),
            Line::from("   No projects. Press a to add one.").style(theme::dim()),
            Line::from(""),
            Line::from("   A project anchors sessions by cwd prefix.").style(theme::dim()),
        ];
        f.render_widget(Paragraph::new(lines), area);
        return;
    }

    let parts = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).split(area);
    f.render_widget(
        Paragraph::new(Line::from(" project        sessions  path").style(theme::dim())),
        parts[0],
    );

    let merged = app.merged();
    let items: Vec<ListItem> = projects
        .iter()
        .map(|p| {
            let anchored = merged
                .iter()
                .filter(|s| {
                    graph::anchor_for(&s.cwd, &projects)
                        .map(|idx| projects[idx].name == p.name)
                        .unwrap_or(false)
                })
                .count();
            let bar = theme::ascii_bar(anchored, 6);
            ListItem::new(Line::from(format!(
                "◆ {:<12} {bar} {:>2}  {}",
                p.name, anchored, p.path
            )))
        })
        .collect();

    let accent = theme::accent(&app.palette);
    let mut hl = Style::default().add_modifier(Modifier::REVERSED);
    if let Some(c) = accent {
        hl = hl.fg(c);
    }
    let list = List::new(items).highlight_style(hl);
    let mut state = ListState::default();
    if app.input.is_none() {
        state.select(Some(app.proj_sel.min(projects.len().saturating_sub(1))));
    }
    f.render_stateful_widget(list, parts[1], &mut state);
}

// ── [3] LOG — the audit tail ────────────────────────────────────────────────

fn draw_log(f: &mut Frame, area: Rect, app: &App) {
    if app.log.is_empty() {
        f.render_widget(
            Paragraph::new(Line::from("   The audit log is empty.").style(theme::dim())),
            area,
        );
        return;
    }
    let lines: Vec<Line> = app
        .log
        .iter()
        .map(|l| {
            let mut class_style = Style::default();
            if let Some(c) = theme::class_color(&l.class) {
                class_style = class_style.fg(c);
            }
            Line::from(vec![
                Span::styled(format!("{:<12}", trunc(&l.class, 12)), class_style),
                Span::styled(format!(" {:<6}", trunc(&l.door, 6)), theme::dim()),
                Span::styled(
                    format!(" {:<15}", trunc(&l.status, 15)),
                    Style::default().fg(theme::status_color(&l.status)),
                ),
                Span::raw(format!(" {}: {}", l.command, l.message)),
            ])
        })
        .collect();

    // Scroll so the newest lines (the tail) are on screen.
    let h = area.height as usize;
    let scroll = lines.len().saturating_sub(h) as u16;
    f.render_widget(Paragraph::new(lines).scroll((scroll, 0)), area);
}

fn trunc(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect()
    }
}

// ── [4] STATUS — stage-tree health ──────────────────────────────────────────

fn draw_status_panel(f: &mut Frame, area: Rect, app: &App) {
    // Two roots since command-defrag S1 (2026-08-27): conducting state
    // (`sessions.json`/`hooks.json`/`projects.json`/`graph.json`) lives under
    // `state/stage/`; rice/paint state (`livery.json`) stays `song/stage/`.
    // They coincide under an `$AOIDE_STAGE_DIR` override (every test fixture
    // here), and diverge only on the default production layout.
    let stage = aoide_storage::fs::conducting_stage_dir();
    let rice_stage = aoide_storage::fs::stage_dir();
    let sock = aoide_conduct::shellbridge::socket_path();
    let audit = aoide_protocol::default_audit_log();

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(format!(" stage dir   {}", stage.display())));
    if rice_stage != stage {
        lines.push(Line::from(format!(" rice dir    {}", rice_stage.display())));
    }
    lines.push(Line::from(""));
    lines.push(file_status(
        &stage.join("projects.json"),
        "projects",
        app.projects.len(),
    ));
    lines.push(file_status(
        &stage.join("sessions.json"),
        "sessions",
        app.sessions.len(),
    ));
    lines.push(file_status(
        &stage.join("hooks.json"),
        "hooks",
        app.hooks.len(),
    ));
    lines.push(file_status(
        &stage.join("graph.json"),
        "graph",
        graph_node_count(&stage.join("graph.json")),
    ));
    lines.push(file_status(
        &rice_stage.join("livery.json"),
        "livery",
        palette_count(app),
    ));
    lines.push(Line::from(""));
    lines.push(Line::from(format!(
        " shellbridge sock  {}  {}",
        if sock.exists() { "●" } else { "○" },
        sock.display()
    )));
    let last_ts = app.log.last().map(|l| l.ts).unwrap_or(0);
    lines.push(Line::from(format!(
        " audit log         {}  ({} line(s), last ts {last_ts})",
        audit.display(),
        app.log.len()
    )));
    lines.push(Line::from(""));
    lines.push(palette_summary(app));

    f.render_widget(Paragraph::new(lines), area);
}

fn file_status<'a>(path: &std::path::Path, label: &str, count: usize) -> Line<'a> {
    let (present, mtime) = match std::fs::metadata(path) {
        Ok(m) => (
            true,
            m.modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0),
        ),
        Err(_) => (false, 0),
    };
    if present {
        Line::from(format!(
            " ● {label:<9} {count:>3} entr(y/ies)  mtime {mtime}"
        ))
    } else {
        Line::from(format!(" ○ {label:<9} (absent)")).style(theme::dim())
    }
}

fn graph_node_count(path: &std::path::Path) -> usize {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.get("nodes").and_then(|n| n.as_array()).map(Vec::len))
        .unwrap_or(0)
}

fn palette_count(app: &App) -> usize {
    let p = &app.palette;
    [p.bg, p.fg, p.accent, p.urgent]
        .iter()
        .filter(|x| x.is_some())
        .count()
}

fn palette_summary<'a>(app: &App) -> Line<'a> {
    let p = &app.palette;
    if palette_count(app) == 0 {
        return Line::from(" palette          (none — terminal defaults)").style(theme::dim());
    }
    let mut spans = vec![Span::raw(" palette          ")];
    let swatch = |c: Option<u8>, name: &str| -> Vec<Span<'a>> {
        match c {
            Some(idx) => vec![
                Span::styled("██", Style::default().fg(Color::Indexed(idx))),
                Span::raw(format!(" {name}  ")),
            ],
            None => vec![Span::raw(format!("·· {name}  "))],
        }
    };
    spans.extend(swatch(p.bg, "bg"));
    spans.extend(swatch(p.fg, "fg"));
    spans.extend(swatch(p.accent, "accent"));
    spans.extend(swatch(p.urgent, "urgent"));
    Line::from(spans)
}

// ── [5] ROSTER — presence over this box + every registered node ────────────
//
// Read-only (messaging/presence plan, P-C4): rows come straight from the
// cached `session --hosts --json` `Outcome` (`App::roster_nodes` — a
// reshape, never a re-derivation), local box first then nodes in the
// roster's own order. Node glyphs (`●`/`◐`/`○`) call
// `aoide_conduct::graph::glyph` DIRECTLY — widened to `pub` for exactly this
// (P-C4 review nits; no forked copy here); session glyphs are the
// conductor's existing musical-note set (`theme::state_glyph`) applied to
// the roster's canonical `state` string — the SAME mapping the SESSION
// panel paints, since the roster classifies sessions off the identical
// vocabulary. Staleness wording ("last seen") is also the roster's own —
// `render_nodes` in `who.rs` says it first; this pane matches rather than
// inventing "as of".

fn draw_roster(f: &mut Frame, area: Rect, app: &App) {
    let rows = app.roster_flat_rows();

    let parts = Layout::vertical([
        Constraint::Length(1), // glyph legend
        Constraint::Length(1), // fetch status (probing… / fetched Ns ago)
        Constraint::Min(3),    // node/session list
    ])
    .split(area);

    let legend = Line::from(
        " ● online  ◐ unreachable  ○ never-pulled    ♪ working  𝄐 awaiting  𝄁 stopped  𝄽 idle  𝄂 done",
    )
    .style(theme::dim());
    f.render_widget(Paragraph::new(legend), parts[0]);

    let status = Line::from(format!(" {}", app.roster_status())).style(theme::dim());
    f.render_widget(Paragraph::new(status), parts[1]);

    if rows.is_empty() {
        let lines = vec![
            Line::from(""),
            Line::from("   no roster data yet — press r to fetch.").style(theme::dim()),
        ];
        f.render_widget(Paragraph::new(lines), parts[2]);
        return;
    }

    // A stateful list (P-C5 adds selection to C4's read-only pane) — same
    // shape [`draw_sessions`] uses over the DAG's flattened rows.
    let pal = &app.palette;
    let accent = theme::accent(pal);
    let items: Vec<ListItem> = rows.iter().map(|r| roster_row_item(r, pal)).collect();
    let mut hl = Style::default().add_modifier(Modifier::REVERSED);
    if let Some(c) = accent {
        hl = hl.fg(c);
    }
    let list = List::new(items).highlight_style(hl);
    let mut state = ListState::default();
    state.select(Some(app.roster_sel.min(rows.len().saturating_sub(1))));
    f.render_stateful_widget(list, parts[2], &mut state);
}

fn roster_row_item<'a>(row: &crate::app::RosterRow, pal: &crate::app::Palette) -> ListItem<'a> {
    match row {
        crate::app::RosterRow::NodeHeader { name, is_local, presence, fetched_at } => {
            let glyph = graph::glyph(presence);
            let head = match presence.as_str() {
                "unreachable" => format!(
                    "{glyph} {} — unreachable (last seen {})",
                    name,
                    fetched_at.as_deref().unwrap_or("unknown")
                ),
                "never-pulled" => format!("{glyph} {} — never pulled", name),
                _ if *is_local => format!("{glyph} {} (this host)", name),
                _ => format!("{glyph} {}", name),
            };
            ListItem::new(Line::from(Span::styled(
                head,
                Style::default().add_modifier(Modifier::BOLD),
            )))
        }
        crate::app::RosterRow::Session { session: s, is_last } => {
            let branch = if *is_last { "└─ " } else { "├─ " };
            let st = theme::state_style(&s.state, pal);
            let sg = theme::state_glyph(&s.state);
            ListItem::new(Line::from(vec![
                Span::raw(format!("  {branch}")),
                Span::styled(format!("{sg} "), st),
                Span::raw(format!("{}  ", s.label)),
                Span::styled(s.state.clone(), st),
            ]))
        }
        crate::app::RosterRow::Empty => {
            ListItem::new(Line::from("     (no sessions)").style(theme::dim()))
        }
    }
}

// ── [6] PENDING ──────────────────────────────────────────────────────────

/// Held `send` / A2A entries (messaging/presence plan, P-C5) — rows
/// from `session pending list --json`, dispatched through the same injected
/// `DispatchFn` as every other pane, never re-derived. `a`/`d` approve/deny
/// the selected row; `id` in each row is an ARRAY POSITION, not a stable id
/// (`conduct/src/graph/pending.rs`'s module doc), so [`App`] always re-lists
/// immediately after a resolve — this view never trusts a row across one.
fn draw_pending(f: &mut Frame, area: Rect, app: &App) {
    let rows = app.pending_rows();

    let parts = Layout::vertical([
        Constraint::Length(1), // fetch status
        Constraint::Min(3),    // pending list
    ])
    .split(area);

    let status = Line::from(format!(" {}", app.pending_status())).style(theme::dim());
    f.render_widget(Paragraph::new(status), parts[0]);

    if rows.is_empty() {
        let lines = vec![
            Line::from(""),
            Line::from("   nothing held — state/stage/pending.json is empty.").style(theme::dim()),
        ];
        f.render_widget(Paragraph::new(lines), parts[1]);
        return;
    }

    let accent = theme::accent(&app.palette);
    let items: Vec<ListItem> = rows.iter().map(pending_row_item).collect();
    let mut hl = Style::default().add_modifier(Modifier::REVERSED);
    if let Some(c) = accent {
        hl = hl.fg(c);
    }
    let list = List::new(items).highlight_style(hl);
    let mut state = ListState::default();
    state.select(Some(app.pending_sel.min(rows.len().saturating_sub(1))));
    f.render_stateful_widget(list, parts[1], &mut state);
}

fn pending_row_item<'a>(row: &crate::app::PendingRow) -> ListItem<'a> {
    let marker = if row.state == "malformed" { "⚠ " } else { "" };
    let from = row
        .from
        .as_deref()
        .map(|f| format!(" (from {f})"))
        .unwrap_or_default();
    let submit = if row.submit { " [submit]" } else { "" };
    let line = format!(
        "[{}] {marker}{} ← {}{submit}{from}  ({})",
        row.id, row.session_id, row.text, row.queued_at
    );
    let style = if row.state == "malformed" {
        theme::dim()
    } else {
        Style::default()
    };
    ListItem::new(Line::from(Span::styled(line, style)))
}

// ── Log-tail overlay ────────────────────────────────────────────────────────

/// The headless-session log tail — Enter's other destination
/// ([`crate::app::App::cue_session`]), painted the same modal way
/// [`draw_help`] is: `Clear` the region under it, float a framed panel over
/// the frame, centered at ~90% of the screen. A no-op when `app.tail` is
/// `None` (the caller in [`draw`] already gates this).
fn draw_log_tail(f: &mut Frame, area: Rect, app: &App) {
    let Some(tail) = &app.tail else { return };

    let w = (area.width as u32 * 9 / 10) as u16;
    let h = (area.height as u32 * 9 / 10) as u16;
    let rect = centered(w, h, area);

    f.render_widget(Clear, rect);

    // The subtitle is the record's honesty clause verbatim (see
    // `crate::logtail`'s module doc): this is a stripped mirror of raw pty
    // bytes, not a terminal — a full-screen TUI in the log reads back as its
    // own redraw chatter.
    let block = panel_block(&format!("{} — headless log", tail.session_id), app).title(
        Line::from(Span::styled(
            " stripped mirror · not a terminal ",
            theme::dim(),
        ))
        .right_aligned(),
    );
    let inner = block.inner(rect);
    f.render_widget(block, rect);

    // The path line reuses `theme::shorten_cwd`'s "last two components" rule
    // (the same one the SESSION panel's cwd row already applies) rather than
    // painting the raw absolute path unbounded: `Paragraph` has no wrap here,
    // so an unshortened path longer than the overlay's inner width is
    // silently clipped by the terminal buffer with no ellipsis — on a deep
    // `$TMPDIR`/state-dir tree that clip can land BEFORE the `.log`
    // extension, so the line stops looking like a log path at all. Shortened
    // display is deterministic (bounded by component count, not by whatever
    // ancestor directories the path happens to have) and still names the
    // exact file — only the invariant this overlay actually promises.
    let shown_path = theme::shorten_cwd(&tail.path.display().to_string());
    let mut lines: Vec<Line> = vec![Line::from(shown_path).style(theme::dim())];
    if tail.lines.is_empty() {
        lines.push(Line::from("(none yet)").style(theme::dim()));
    } else {
        let body_h = (inner.height as usize).saturating_sub(1).max(1);
        let start = tail.lines.len().saturating_sub(body_h);
        for l in &tail.lines[start..] {
            lines.push(Line::from(l.as_str()).style(theme::dim()));
        }
    }
    f.render_widget(Paragraph::new(lines), inner);
}

// ── Help overlay ────────────────────────────────────────────────────────────

fn draw_help(f: &mut Frame, area: Rect, app: &App) {
    let help: &[&str] = &[
        "",
        "  Tab / Shift-Tab   cycle panels",
        "  1 2 3 4 5 6 7     DAG / SESSION / PROJECTS / LOG / STATUS / ROSTER / PENDING",
        "  j / k  ↓ / ↑      move selection",
        "",
        "  DAG (the visual graph)",
        "    j / k            walk nodes (preorder)",
        "    g / G            jump to first / last node",
        "    Enter            cue window · tail the log if headless",
        "    Esc / q          close the log tail (Enter also closes it)",
        "    p                prune done sessions (also restages graph.json)",
        "    ◆ project  ● session   ⟨tag⟩ read-only tag",
        "",
        "  SESSION",
        "    Enter            cue window · tail the log if headless",
        "    Esc / q          close the log tail (Enter also closes it)",
        "    h / l            fold / unfold the group",
        "    L                link the session under a parent",
        "    a / d            add / remove a project anchor",
        "    p                prune done sessions (restages the DAG)",
        "    ♪ 𝄐 𝄁 𝄽 𝄂        working · awaiting · stopped · idle · done   ‣ fresh",
        "",
        "  PROJECTS: a add · d remove",
        "",
        "  ROSTER: j/k select · s compose (send to the selected session)",
        "    r forces a refresh; auto-probes every ~15s while the pane is",
        "    open. ● online  ◐ unreachable  ○ never-pulled",
        "",
        "  PENDING: j/k select · a approve · d deny — held send/A2A",
        "    entries; resolving always re-lists (ids are positions, not",
        "    stable — they shift the moment any entry resolves)",
        "",
        "  ?                 toggle this help      q / Ctrl-C  quit",
        "  Every cue runs through the one door; the audit log records it.",
        "",
    ];
    let title = " aoide conductor — keys ";
    let box_w = help
        .iter()
        .map(|l| l.chars().count())
        .max()
        .unwrap_or(20)
        .max(title.len())
        + 4;
    let box_w = (box_w as u16).min(area.width.saturating_sub(2));
    let box_h = (help.len() as u16 + 2).min(area.height.saturating_sub(2));
    let rect = centered(box_w, box_h, area);

    f.render_widget(Clear, rect);
    let block = panel_block("HELP", app).title(Span::styled(
        title,
        Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED),
    ));
    let lines: Vec<Line> = help.iter().map(|s| Line::from(*s)).collect();
    f.render_widget(Paragraph::new(lines).block(block), rect);
}

fn centered(w: u16, h: u16, area: Rect) -> Rect {
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    Rect {
        x,
        y,
        width: w.min(area.width),
        height: h.min(area.height),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{App, Panel};
    use aoide_conduct::graph::{Project, SessionRecord};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use serde_json::Map;

    /// Flatten a rendered buffer to one string (row-major), so a test can search
    /// it for expected glyphs/labels — the snapshot-ish assertion style.
    fn dump(buf: &ratatui::buffer::Buffer) -> String {
        buf.content
            .chunks(buf.area.width.max(1) as usize)
            .map(|row| row.iter().map(|c| c.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn session(id: &str, cwd: &str, state: &str, parent: Option<&str>) -> SessionRecord {
        SessionRecord {
            session_id: id.into(),
            enduring_agent_id: None,
            agent: "claude".into(),
            window_address: format!("0x{id}"),
            cwd: cwd.into(),
            state: state.into(),
            started_at: id.into(),
            parent_session_id: parent.map(str::to_string),
            conductable: None,
            socket: None,
            title: None,
            pid: None,
            workspace: None,
            activity: None,
            kind: None,
            say: None,
            tool: None,
            model: None,
            context_tokens: None,
            needs_sudo: None,
            context_ceiling: None,
            log_path: None,
            petname: None,
            hook_ancestry: Vec::new(),
            headless: false,
            spawned: false,
            exempt: false,
            harness_session_id: None,
            resumed_from: None,
            origin: None,
            seal: None,
            sealed_issued_at: None,
            restore: None,
            extra: Map::new(),
        }
    }

    fn render_panel(app: &App, panel: Panel, w: u16, h: u16) -> String {
        let mut a = App::for_test(
            app.projects.clone(),
            app.sessions.clone(),
            app.hooks.clone(),
        );
        a.panel = panel;
        a.dag_sel = app.dag_sel;
        a.graph_sel = app.graph_sel;
        a.log = app.log.clone();
        let backend = TestBackend::new(w, h);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| draw(f, &a)).unwrap();
        dump(term.backend().buffer())
    }

    fn app_with(projects: Vec<Project>, sessions: Vec<SessionRecord>) -> App {
        App::for_test(projects, sessions, Vec::new())
    }

    #[test]
    fn graph_panel_draws_nodes_edges_and_tags() {
        // Short ids/state/tag: the display-grammar label (petnames plan
        // P3 — `<host>/<role>/<sessionId>` on a legacy/petname-less
        // fixture) now shares the chip's CHIP_MAX budget with the state
        // word and the tag chip, so this fixture stays lean to leave room
        // for both on any reasonably short box hostname.
        let mut root = session("r", "/home/k/Aoide", "idle", None);
        root.extra.insert("tags".into(), serde_json::json!(["x"]));
        let kid = session("k", "/home/k/Aoide", "idle", Some("r"));
        let app = app_with(
            vec![Project {
                name: "aoide".into(),
                path: "/home/k/Aoide".into(),
                ..Default::default()
            }],
            vec![root, kid],
        );
        let out = render_panel(&app, Panel::Graph, 120, 30);
        assert!(out.contains("DAG"), "panel title rendered");
        assert!(out.contains("◆ aoide"), "project node drawn");
        // Session chips render the display grammar (petnames plan P3), not
        // the bare id — neither fixture session has a minted petname, so
        // each degrades to `<host>/<role>/<sessionId>`.
        let host = aoide_storage::display::local_host_name();
        assert!(
            out.contains(&format!("● {host}/root/r")) && out.contains(&format!("{host}/child/k")),
            "session nodes drawn: {out}"
        );
        assert!(
            out.contains('├') || out.contains('└') || out.contains('─'),
            "box-drawing edges present"
        );
        assert!(out.contains("⟨x⟩"), "read-only tag chip drawn: {out}");
    }

    #[test]
    fn sessions_panel_shows_roster_glyphs_and_detail() {
        let app = app_with(
            vec![Project {
                name: "aoide".into(),
                path: "/home/k/Aoide".into(),
                ..Default::default()
            }],
            vec![session("s1", "/home/k/Aoide", "running", None)],
        );
        let out = render_panel(&app, Panel::Session, 100, 30);
        assert!(out.contains("SESSION"), "panel title");
        assert!(out.contains("◆ aoide"), "group header");
        assert!(out.contains("[1/1]"), "live/total badge");
        assert!(out.contains("s1") && out.contains("claude"), "session row");
        assert!(out.contains('♪'), "working glyph in legend/row");
        assert!(out.contains("selected"), "detail card rule");
        assert!(
            !out.contains("doing") && !out.contains("says"),
            "no activity/say on the fixture — lines must be gated off"
        );
    }

    #[test]
    fn sessions_panel_detail_shows_activity_and_say_when_present() {
        let mut rec = session("s1", "/home/k/Aoide", "running", None);
        rec.activity = Some("Editing ui.rs".into());
        rec.say = Some("checking layout".into());
        let mut app = app_with(
            vec![Project {
                name: "aoide".into(),
                path: "/home/k/Aoide".into(),
                ..Default::default()
            }],
            vec![rec],
        );
        app.dag_sel = 1; // row 0 is the ◆ aoide group header; row 1 is the session
        let out = render_panel(&app, Panel::Session, 100, 30);
        assert!(
            out.contains("doing   ▸ Editing ui.rs"),
            "activity line rendered in detail card"
        );
        assert!(
            out.contains("says    \"checking layout\""),
            "say line rendered in detail card"
        );
    }

    #[test]
    fn sessions_panel_detail_shows_log_path_and_headless_for_a_headless_session() {
        let mut rec = session("s1", "/home/k/Aoide", "running", None);
        rec.log_path = Some("/home/k/Aoide/state/sessions/s1.log".into());
        let mut app = app_with(
            vec![Project {
                name: "aoide".into(),
                path: "/home/k/Aoide".into(),
                ..Default::default()
            }],
            vec![rec],
        );
        app.dag_sel = 1; // row 0 is the ◆ aoide group header; row 1 is the session
        let out = render_panel(&app, Panel::Session, 100, 30);
        assert!(
            out.contains("log     /home/k/Aoide/state/sessions/s1.log   started s1"),
            "log path line keeps started alongside the path: {out}"
        );
        assert!(
            out.contains("headless"),
            "dim headless marker on the header line: {out}"
        );
        assert!(
            !out.contains("window "),
            "no window line for a headless session: {out}"
        );
    }

    #[test]
    fn sessions_panel_detail_windowed_session_renders_unchanged() {
        let mut app = app_with(
            vec![Project {
                name: "aoide".into(),
                path: "/home/k/Aoide".into(),
                ..Default::default()
            }],
            vec![session("s1", "/home/k/Aoide", "running", None)],
        );
        app.dag_sel = 1; // row 0 is the ◆ aoide group header; row 1 is the session
        let out = render_panel(&app, Panel::Session, 100, 30);
        assert!(
            out.contains("window  0xs1   started s1"),
            "a windowed session's detail line is byte-identical to before: {out}"
        );
        assert!(
            !out.contains("headless"),
            "no headless marker for a windowed session: {out}"
        );
        assert!(
            !out.contains("log     "),
            "no log line for a windowed session: {out}"
        );
    }

    #[test]
    fn sessions_panel_shows_model_on_roster_row_and_detail_card_for_a_subagent() {
        let mut root = session("root", "/home/k/Aoide", "running", None);
        root.model = Some("claude-sonnet-5".into());
        let mut sub = session("kid", "/home/k/Aoide", "working", Some("root"));
        sub.kind = Some("subagent".into());
        sub.model = Some("claude-fable-5".into());
        let mut app = app_with(
            vec![Project {
                name: "aoide".into(),
                path: "/home/k/Aoide".into(),
                ..Default::default()
            }],
            vec![root, sub],
        );
        // Row 0 is the ◆ aoide group header; row 1 is `root`, row 2 is `kid`.
        app.dag_sel = 2;
        let out = render_panel(&app, Panel::Session, 100, 30);
        assert!(
            out.contains("⟐claude-sonnet-5"),
            "root agent's model tag on its roster row: {out}"
        );
        assert!(
            out.contains("⟐claude-fable-5"),
            "subagent's OWN model tag on its roster row: {out}"
        );
        assert!(
            out.contains("model   claude-fable-5"),
            "subagent's model line on the detail card: {out}"
        );
    }

    #[test]
    fn graph_panel_draws_the_model_tag_on_a_subagent_chip() {
        // Short ids + a short state + a one-char model, so the chip's
        // CHIP_MAX budget survives the display-grammar label (petnames
        // plan P3 — `<host>/<role>/<sessionId>` now eats into the SAME
        // budget the model tag used to have mostly to itself) on any
        // reasonably short box hostname. The point is the glyph+text ride
        // the chip at all, not exercising the truncation boundary itself.
        let root = session("r", "/home/k/Aoide", "idle", None);
        let mut sub = session("k", "/home/k/Aoide", "idle", Some("r"));
        sub.kind = Some("subagent".into());
        sub.model = Some("m".into());
        let app = app_with(
            vec![Project {
                name: "aoide".into(),
                path: "/home/k/Aoide".into(),
                ..Default::default()
            }],
            vec![root, sub],
        );
        let out = render_panel(&app, Panel::Graph, 120, 30);
        assert!(out.contains("⟐m"), "subagent chip carries its model tag: {out}");
    }

    #[test]
    fn projects_panel_lists_sorted_with_meter() {
        let app = app_with(
            vec![
                Project {
                    name: "zeta".into(),
                    path: "/z".into(),
                    ..Default::default()
                },
                Project {
                    name: "alpha".into(),
                    path: "/a".into(),
                    ..Default::default()
                },
            ],
            vec![],
        );
        let out = render_panel(&app, Panel::Projects, 90, 20);
        assert!(out.contains("PROJECTS"));
        let ai = out.find("alpha").unwrap();
        let zi = out.find("zeta").unwrap();
        assert!(ai < zi, "roster sorted by name");
        assert!(out.contains('░'), "ascii meter drawn");
    }

    #[test]
    fn log_panel_colours_and_shows_records() {
        let mut app = app_with(vec![], vec![]);
        app.log = vec![
            crate::app::LogLine {
                ts: 1,
                door: "cli".into(),
                class: "audit".into(),
                command: "session.prune".into(),
                status: "ok".into(),
                message: "staged".into(),
            },
            crate::app::LogLine {
                ts: 2,
                door: "cli".into(),
                class: "audit".into(),
                command: "graph.focus".into(),
                status: "error".into(),
                message: "gone".into(),
            },
        ];
        let out = render_panel(&app, Panel::Log, 100, 20);
        assert!(out.contains("session.prune") && out.contains("graph.focus"));
        assert!(out.contains("cli"), "door column visible");
    }

    #[test]
    fn help_overlay_stamps_over_the_frame() {
        let app = app_with(vec![], vec![]);
        let mut a = App::for_test(vec![], vec![], vec![]);
        a.help_open = true;
        let _ = &app;
        let backend = TestBackend::new(90, 34);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| draw(f, &a)).unwrap();
        let out = dump(term.backend().buffer());
        assert!(out.contains("aoide conductor — keys"), "overlay title present");
        assert!(out.contains("cycle panels"));
        assert!(out.contains("read-only tag"), "DAG tag legend documented");
        assert!(
            out.contains("tail the log if headless"),
            "Enter's headless branch is documented: {out}"
        );
        assert!(
            out.contains("close the log tail"),
            "the log-tail overlay's close keys are documented: {out}"
        );
    }

    /// A throwaway on-disk log the overlay tests point `App::open_tail` at —
    /// `LogTail::mtime` is private to `app.rs`, so a real (bounded) read via
    /// the public `App::open_tail` is the only way to populate `app.tail`
    /// from here. The `lines` field is public, so once opened the fixture
    /// overwrites it with canned content.
    fn app_with_tail(session_id: &str, lines: Vec<String>, tag: &str) -> App {
        app_with_tail_under(std::env::temp_dir(), session_id, lines, tag)
    }

    /// [`app_with_tail`], parameterised on the base directory the fixture's
    /// log file nests under — lets a test pin a DETERMINISTIC path depth
    /// (task #59's regression test, below) rather than relying on however
    /// deep the ambient `$TMPDIR` happens to be on whatever machine runs it.
    fn app_with_tail_under(base: std::path::PathBuf, session_id: &str, lines: Vec<String>, tag: &str) -> App {
        let dir = base.join(format!(
            "aoide-ui-tail-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s.log");
        std::fs::write(&path, "seed\n").unwrap();
        let mut rec = session(session_id, "/tmp", "running", None);
        rec.log_path = Some(path.to_string_lossy().into_owned());
        let mut app = App::for_test(vec![], vec![rec.clone()], vec![]);
        app.open_tail(&rec);
        if let Some(t) = app.tail.as_mut() {
            t.lines = lines;
        }
        app
    }

    #[test]
    fn log_tail_overlay_stamps_title_mirror_clause_path_and_content() {
        let app = app_with_tail("s1", vec!["line one".into(), "line two".into()], "content");
        let backend = TestBackend::new(90, 34);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| draw(f, &app)).unwrap();
        let out = dump(term.backend().buffer());
        assert!(
            out.contains("s1 — headless log"),
            "overlay title names the session: {out}"
        );
        assert!(
            out.contains("stripped mirror") && out.contains("not a terminal"),
            "the honesty-clause subtitle is painted: {out}"
        );
        assert!(out.contains(".log"), "the log path line is painted: {out}");
        assert!(out.contains("line two"), "tail content is painted: {out}");
    }

    #[test]
    fn log_tail_overlay_shows_none_yet_when_lines_are_empty() {
        let app = app_with_tail("s1", Vec::new(), "empty");
        let backend = TestBackend::new(90, 34);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| draw(f, &app)).unwrap();
        let out = dump(term.backend().buffer());
        assert!(out.contains("(none yet)"), "empty tail says so: {out}");
    }

    #[test]
    fn log_tail_overlay_title_survives_a_long_session_id_at_a_narrow_width() {
        // The point of this fixture is width, not id realism: a title far
        // longer than the frame it must be drawn into, at a width far
        // narrower than the title text — this must not panic (saturating
        // arithmetic throughout `draw_log_tail`/`centered`).
        let long_id = "s".repeat(200);
        let app = app_with_tail(&long_id, vec!["hi".into()], "long-id");
        let backend = TestBackend::new(12, 8);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| draw(f, &app)).unwrap();
    }

    #[test]
    fn log_tail_overlay_path_line_survives_a_deep_ancestor_tree() {
        // Regression pin (task #59): `draw_log_tail` used to paint
        // `tail.path.display()` UNBOUNDED with no wrap, so the terminal
        // buffer silently clipped the line at the overlay's inner width —
        // on a deep enough ancestor tree that clip landed BEFORE the
        // `.log` extension, so this exact assertion in the sibling test
        // above passed or failed purely on how deep the ambient `$TMPDIR`
        // happened to be that run (settled diagnosis: "TMPDIR
        // PATH-LENGTH-SENSITIVE"). The fix shortens the painted path to
        // its last two components (`theme::shorten_cwd`, the same rule
        // SESSION already applies to a cwd), which is bounded by
        // component count rather than by ancestor depth. This test pins
        // that fix with a deliberately deep, DETERMINISTIC prefix — two
        // 60-character directory names — so the deep-tree case is
        // exercised every run, not only on whichever machine happens to
        // hand out a long temp path.
        let deep_base = std::env::temp_dir().join("a".repeat(60)).join("b".repeat(60));
        let app = app_with_tail_under(deep_base.clone(), "s1", vec!["hi".into()], "deep");
        let backend = TestBackend::new(90, 34);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| draw(f, &app)).unwrap();
        let out = dump(term.backend().buffer());
        assert!(
            out.contains(".log"),
            "the log path line survives a deep ancestor tree: {out}"
        );
        let _ = std::fs::remove_dir_all(&deep_base);
    }

    // ── ROSTER panel (P-C4): fixed `session --hosts --json` fixture -> render ──

    /// A fixed `session --hosts --json` fixture, shaped exactly like
    /// `conduct/src/graph/who.rs::session_roster_with`'s real `Outcome.data`
    /// (this box online, one unreachable node with a stale-cache session,
    /// one never-pulled node) — the ONLY input `draw_roster` is allowed to
    /// read.
    fn roster_fixture() -> aoide_protocol::output::Outcome {
        let data = serde_json::json!({
            "host": "sakaki",
            "generatedAt": "2026-08-21T00:00:00Z",
            "nodes": [
                {
                    "name": "sakaki",
                    "isLocal": true,
                    "presence": "online",
                    "fetchedAt": null,
                    "error": null,
                    "sessions": [
                        {
                            "sessionId": "s1",
                            "label": "sakaki/root/brave-otter (…s1)",
                            "petname": "brave-otter",
                            "agent": "claude",
                            "state": "working",
                            "presence": "online",
                            "cwd": "/x",
                        },
                    ],
                },
                {
                    "name": "yomi-strix",
                    "isLocal": false,
                    "presence": "unreachable",
                    "fetchedAt": "2026-08-20T23:00:00Z",
                    "error": "HTTP 000",
                    "sessions": [
                        {
                            "sessionId": "s2",
                            "label": "yomi-strix/root/misty-comet (…s2)",
                            "petname": "misty-comet",
                            "agent": "claude",
                            "state": "idle",
                            "presence": "online",
                            "cwd": "/y",
                        },
                    ],
                },
                {
                    "name": "ghost",
                    "isLocal": false,
                    "presence": "never-pulled",
                    "fetchedAt": null,
                    "error": "could not reach the agent",
                    "sessions": [],
                },
            ],
        });
        aoide_protocol::output::Outcome::ok("session", "3 node(s), 2 session(s)").with_data(data)
    }

    #[test]
    fn roster_panel_renders_grouped_nodes_with_presence_glyphs_and_staleness() {
        let mut a = App::for_test(vec![], vec![], vec![]);
        a.panel = Panel::Roster;
        a.roster.outcome = Some(roster_fixture());

        let backend = TestBackend::new(100, 30);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| draw(f, &a)).unwrap();
        let out = dump(term.backend().buffer());

        assert!(out.contains("ROSTER"), "panel title: {out}");
        assert!(
            out.contains("● sakaki (this host)"),
            "local node: online glyph + (this host): {out}"
        );
        assert!(
            out.contains("◐ yomi-strix — unreachable (last seen 2026-08-20T23:00:00Z)"),
            "mesh node: unreachable glyph + staleness stamp: {out}"
        );
        assert!(
            out.contains("○ ghost — never pulled"),
            "mesh node: never-pulled glyph: {out}"
        );
        assert!(
            out.contains("brave-otter") && out.contains('♪'),
            "local session row + its working glyph: {out}"
        );
        assert!(
            out.contains("misty-comet"),
            "an unreachable node's last-known session still surfaces: {out}"
        );

        // Local box first, then nodes — the roster's own node order, never
        // re-sorted here.
        let local_pos = out.find("sakaki (this host)").unwrap();
        let node_pos = out.find("yomi-strix").unwrap();
        assert!(local_pos < node_pos, "local box renders before nodes: {out}");
    }

    #[test]
    fn roster_panel_shows_a_fetch_hint_when_never_fetched() {
        let mut a = App::for_test(vec![], vec![], vec![]);
        a.panel = Panel::Roster;
        // `a.roster.outcome` stays `None` — never fetched this run.

        let backend = TestBackend::new(80, 20);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| draw(f, &a)).unwrap();
        let out = dump(term.backend().buffer());

        assert!(
            out.contains("not yet fetched") && out.contains("press r"),
            "an empty cache tells the human how to get data: {out}"
        );
    }

    // ── PENDING panel (P-C5) ─────────────────────────────────────────────

    fn pending_fixture() -> aoide_protocol::output::Outcome {
        let data = serde_json::json!({
            "pending": [
                {
                    "id": "0", "sessionId": "s0", "text": "do the thing", "submit": true,
                    "queuedAt": "2026-08-21T00:00:00Z", "from": "sakaki/root/brave-otter (…snd)",
                    "state": "pending",
                },
                {
                    "id": "1", "sessionId": "s1", "text": "status?", "submit": false,
                    "queuedAt": "2026-08-21T00:05:00Z", "from": serde_json::Value::Null,
                    "state": "pending",
                },
                {
                    // The `is_malformed` shape `conduct/src/graph/pending.rs::entry_view`
                    // renders for a stale hand-edited entry: `sessionId`/`queuedAt` empty,
                    // `text` carrying the raw dumped value, `state: "malformed"`.
                    "id": "2", "sessionId": "", "text": "<malformed entry>", "submit": false,
                    "queuedAt": "", "from": serde_json::Value::Null,
                    "state": "malformed",
                },
            ],
        });
        aoide_protocol::output::Outcome::ok("session.pending.list", "3 pending").with_data(data)
    }

    #[test]
    fn pending_panel_renders_rows_with_selection_highlight() {
        let mut a = App::for_test(vec![], vec![], vec![]);
        a.panel = Panel::Pending;
        a.pending = Some(pending_fixture());
        a.pending_sel = 1;

        let backend = TestBackend::new(100, 20);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| draw(f, &a)).unwrap();
        let out = dump(term.backend().buffer());

        assert!(out.contains("PENDING"), "panel title: {out}");
        assert!(
            out.contains("[0] s0 ← do the thing [submit] (from sakaki/root/brave-otter (…snd))"),
            "first entry, full grammar: {out}"
        );
        assert!(
            out.contains("[1] s1 ← status?"),
            "second (selected) entry, no `from` tag since it queued anonymous: {out}"
        );
        assert!(
            out.contains("[2] ⚠") && out.contains("<malformed entry>"),
            "a malformed entry renders its warning marker, not silently: {out}"
        );
    }

    #[test]
    fn pending_panel_shows_the_empty_hint_when_the_queue_is_empty() {
        let mut a = App::for_test(vec![], vec![], vec![]);
        a.panel = Panel::Pending;
        a.pending = Some(
            aoide_protocol::output::Outcome::ok("session.pending.list", "0 pending")
                .with_data(serde_json::json!({ "pending": [] })),
        );

        let backend = TestBackend::new(80, 20);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| draw(f, &a)).unwrap();
        let out = dump(term.backend().buffer());

        assert!(
            out.contains("nothing held"),
            "an empty queue tells the human, not a bare blank pane: {out}"
        );
    }
}
