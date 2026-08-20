//! The ratatui view layer — top-level layout, the five panel widgets, the
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
//! Two of the five panels are the expansion this port carries: `DAG` (the
//! visual graph, drawn by [`crate::graphview`]) and `SESSIONS` (the
//! terminal roster, now split into a scrolling list + a live detail card with a
//! focus affordance). The other three — PROJECTS, LOG, STATUS — are ports of the
//! originals.

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

/// The status-line keymap hint per panel — Aoide cues only, the verbs this
/// frontend owns.
fn keymap_hint(panel: Panel) -> &'static str {
    match panel {
        Panel::Graph => {
            "j/k walk · g/G ends · Enter jump · p prune · e emit · Tab panel · ? help · q quit"
        }
        Panel::Sessions => {
            "j/k select · Enter jump/fold · h/l fold · L link · a add · d rm · p prune · e emit · ? help · q quit"
        }
        Panel::Projects => "j/k select · a add · d remove · Tab panel · ? help · q quit",
        Panel::Log => "Tab panel · ? help · q quit",
        Panel::Status => "Tab panel · ? help · q quit",
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
        Panel::Sessions => draw_sessions(f, inner, app),
        Panel::Projects => draw_projects(f, inner, app),
        Panel::Log => draw_log(f, inner, app),
        Panel::Status => draw_status_panel(f, inner, app),
    }
}

// ── [1] SESSIONS — the roster + a live detail card ──────────────────────────

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
    let stage = aoide_storage::fs::stage_dir();
    let sock = aoide_conduct::shellbridge::socket_path();
    let audit = aoide_protocol::default_audit_log();

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(format!(" stage dir   {}", stage.display())));
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
        &stage.join("livery.json"),
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

    let mut lines: Vec<Line> = vec![Line::from(tail.path.display().to_string()).style(theme::dim())];
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
        "  1 2 3 4 5         DAG / SESSIONS / PROJECTS / LOG / STATUS",
        "  j / k  ↓ / ↑      move selection",
        "",
        "  DAG (the visual graph)",
        "    j / k            walk nodes (preorder)",
        "    g / G            jump to first / last node",
        "    Enter            cue window · tail the log if headless",
        "    Esc / q          close the log tail (Enter also closes it)",
        "    p / e            prune done · emit graph.json",
        "    ◆ project  ● session   ⟨tag⟩ read-only tag",
        "",
        "  SESSIONS",
        "    Enter            cue window · tail the log if headless",
        "    Esc / q          close the log tail (Enter also closes it)",
        "    h / l            fold / unfold the group",
        "    L                link the session under a parent",
        "    a / d            add / remove a project anchor",
        "    p / e            prune done · emit the DAG",
        "    ♪ 𝄐 𝄁 𝄽 𝄂        working · awaiting · stopped · idle · done   ‣ fresh",
        "",
        "  PROJECTS: a add · d remove",
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
            }],
            vec![session("s1", "/home/k/Aoide", "running", None)],
        );
        let out = render_panel(&app, Panel::Sessions, 100, 30);
        assert!(out.contains("SESSIONS"), "panel title");
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
            }],
            vec![rec],
        );
        app.dag_sel = 1; // row 0 is the ◆ aoide group header; row 1 is the session
        let out = render_panel(&app, Panel::Sessions, 100, 30);
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
            }],
            vec![rec],
        );
        app.dag_sel = 1; // row 0 is the ◆ aoide group header; row 1 is the session
        let out = render_panel(&app, Panel::Sessions, 100, 30);
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
            }],
            vec![session("s1", "/home/k/Aoide", "running", None)],
        );
        app.dag_sel = 1; // row 0 is the ◆ aoide group header; row 1 is the session
        let out = render_panel(&app, Panel::Sessions, 100, 30);
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
            }],
            vec![root, sub],
        );
        // Row 0 is the ◆ aoide group header; row 1 is `root`, row 2 is `kid`.
        app.dag_sel = 2;
        let out = render_panel(&app, Panel::Sessions, 100, 30);
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
                },
                Project {
                    name: "alpha".into(),
                    path: "/a".into(),
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
                command: "graph.emit".into(),
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
        assert!(out.contains("graph.emit") && out.contains("graph.focus"));
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
        let dir = std::env::temp_dir().join(format!(
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
}
