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
//! Two of the seven panels are the expansion this port carries: `GRAPH` (the
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
use crate::theme;
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
    crate::board::draw(f, app);
}

pub(crate) fn draw_overlays(f: &mut Frame, app: &App) {
    let area = f.area();
    if app.help_open {
        draw_help(f, area, app);
    }
    if app.tail.is_some() {
        draw_log_tail(f, area, app);
    }
    if let Some(input) = &app.input {
        if let crate::app::InputKind::ProjectRemove { name } = &input.kind {
            let width = area.width.min(68);
            let height = area.height.min(10);
            let popup = Rect::new(
                area.x + (area.width - width) / 2,
                area.y + (area.height - height) / 2,
                width,
                height,
            );
            f.render_widget(Clear, popup);
            f.render_widget(
                Paragraph::new(format!("Unregister project `{name}`?\nProject files are kept.\n\nType the exact project name: {}▏\n\nEnter confirms matching name; Esc cancels", input.buffer))
                    .wrap(ratatui::widgets::Wrap { trim: false })
                    .style(theme::accent_style(&app.palette))
                    .block(Block::default().title(" Confirm project removal ").borders(Borders::ALL)),
                popup,
            );
        }
    }
}

// ── Chrome: header, tabs, status bar ────────────────────────────────────────

pub(crate) fn draw_status(f: &mut Frame, area: Rect, app: &App) {
    let hint = keymap_hint(app.panel);
    let msg = if let Some(input) = &app.input {
        format!("{}: {}▏", input.label, input.buffer)
    } else {
        app.status_message()
    };
    let left = format!(" {msg}");

    // The message carries errors and prompts; the hint is only a convenience,
    // so the message gets its own width first and the hint takes what's left
    // -- measured in display cells, never bytes (the hints carry `·`, two
    // bytes for one cell, which used to starve the message down to a stub).
    // A one-column gap is reserved between them so a hint that fills its
    // whole share of the width can never abut the message; the hint is what
    // gets clipped (or dropped entirely) when that gap can't fit.
    let msg_w = crate::board::cells(&left).min(area.width);
    let gap: u16 = 1;
    let hint_room = area.width.saturating_sub(msg_w).saturating_sub(gap);
    let hint_w = (crate::board::cells(hint) + 1).min(hint_room);
    let gap_w = area.width - msg_w - hint_w;
    let cols = Layout::horizontal([
        Constraint::Length(msg_w),
        Constraint::Length(gap_w),
        Constraint::Length(hint_w),
    ])
    .split(area);
    f.render_widget(
        Paragraph::new(Line::from(left)).style(theme::accent_style(&app.palette)),
        cols[0],
    );
    f.render_widget(
        Paragraph::new(Line::from(hint).style(theme::dim()).right_aligned()),
        cols[2],
    );
}

/// The status-line keymap hint per panel — Aoide cues only, the commands this
/// frontend owns.
fn keymap_hint(panel: Panel) -> &'static str {
    match panel {
        Panel::Home => "click to open · Ctrl-P projects · ? help · q quit",
        Panel::Mail => "↑/↓ letters · PgUp/PgDn read · r refresh · ? help",
        Panel::Graph => {
            "j/k child/parent · h/l sibling · a all/focus · Enter open · s letter · e menu · drag/wheel pan · Ctrl-wheel zoom · p prune"
        }
        Panel::Session|Panel::Terminals => {
            "j/k select · Enter jump/fold · h/l fold · L link · a add root · d rm · p prune · ? help · q quit"
        }
        Panel::Projects => "j/k select · a add root · d remove · Tab panel · ? help · q quit",
        Panel::Log => "Tab panel · ? help · q quit",
        Panel::Status => "Tab panel · ? help · q quit",
        Panel::Roster => {
            "j/k select · s compose · r refresh (auto ~15s while open) · Tab panel · ? help · q quit"
        }
        Panel::Pending => "j/k select · a approve · d deny · Tab panel · ? help · q quit",
    }
}

/// Single-line pane borders; the focused body receives the accent.
fn panel_block(title: &str, app: &App) -> Block<'static> {
    let accent = theme::accent(&app.palette);
    let mut title_style = Style::default().add_modifier(Modifier::BOLD);
    if !app.sidebar_focused {
        if let Some(c) = accent {
            title_style = title_style.fg(c);
        }
    }
    let mut border_style = Style::default();
    if !app.sidebar_focused {
        if let Some(c) = accent {
            border_style = border_style.fg(c).add_modifier(Modifier::BOLD);
        }
    }
    Block::new()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(border_style)
        .title(Span::styled(format!(" {title} "), title_style))
}

/// Ratatui applies this across the complete selected row, including trailing cells.
fn selection_style(app: &App) -> Style {
    if app.sidebar_focused {
        return theme::surface(&app.palette, 14).add_modifier(Modifier::BOLD);
    }
    Style::default()
        .bg(theme::accent(&app.palette).unwrap_or(Color::Cyan))
        .fg(theme::opt_color(app.palette.bg).unwrap_or(Color::Black))
        .add_modifier(Modifier::BOLD)
}

fn pad_column(text: &str, width: usize) -> String {
    format!(
        "{text}{}",
        " ".repeat(width.saturating_sub(Span::raw(text).width()))
    )
}

// ── Body dispatch ───────────────────────────────────────────────────────────

pub(crate) fn draw_body(f: &mut Frame, area: Rect, app: &App) {
    let block = panel_block(app.panel.title(), app);
    let inner = block.inner(area);
    f.render_widget(block, area);
    let (inner, actions) = crate::board::body_content(inner);
    crate::board::draw_actions(f, actions, app);
    match app.panel {
        Panel::Home => crate::board::draw_home(f, inner, app),
        Panel::Mail => crate::board::draw_mail(f, inner, app),
        Panel::Graph => graphview::render(f, inner, app),
        Panel::Session | Panel::Terminals if app.history_selected.is_some() => {
            crate::board::draw_history(f, inner, app)
        }
        Panel::Session | Panel::Terminals => draw_sessions(f, inner, app),
        Panel::Projects => draw_projects(f, inner, app),
        Panel::Log => crate::eventview::draw(f, inner, app),
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
        " ◆ project (h/l fold)  ♜ agent  ▣ terminal  ‣ fresh   ♪ working  𝄐 awaiting  𝄁 stopped  𝄽 idle  𝄂 done",
    )
    .style(theme::dim());
    f.render_widget(Paragraph::new(legend), parts[0]);

    // Roster: a stateful list so selection auto-scrolls.
    let items: Vec<ListItem> = rows.iter().map(|r| roster_item(r, app)).collect();
    let list = List::new(items).highlight_style(selection_style(app));
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
                Span::styled(
                    format!(
                        "{} ",
                        theme::mark(if crate::app::is_terminal(rec) {
                            theme::Mark::Terminal
                        } else {
                            theme::Mark::Agent
                        })
                    ),
                    theme::dim(),
                ),
                Span::raw(format!(
                    "{}  ",
                    rec.petname
                        .as_deref()
                        .or(rec.title.as_deref())
                        .unwrap_or(&rec.agent)
                )),
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
                spans.push(Span::styled(
                    format!("  {}{model}", theme::mark(theme::Mark::Model)),
                    ms,
                ));
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

    let name_width = projects
        .iter()
        .map(|p| Span::raw(&p.name).width())
        .max()
        .unwrap_or(0)
        .max(12);
    let parts = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).split(area);
    f.render_widget(
        Paragraph::new(
            Line::from(format!(
                "  {} sessions  path",
                pad_column("project", name_width)
            ))
            .style(theme::dim()),
        ),
        parts[0],
    );

    let merged = app.merged();
    let items: Vec<ListItem> = projects
        .iter()
        .map(|p| {
            let anchored = merged
                .iter()
                .filter(|s| {
                    graph::effective_project_for(s, &merged, &projects)
                        .map(|idx| projects[idx].name == p.name)
                        .unwrap_or(false)
                })
                .count();
            let bar = theme::ascii_bar(anchored, 6);
            let mut lines = vec![Line::from(format!(
                "◆ {} {bar} {:>2}  {}",
                pad_column(&p.name, name_width),
                anchored,
                p.path
            ))];
            for r in p.roots().into_iter().skip(1) {
                lines.push(
                    Line::from(format!(
                        "  {} {} {:>2}  {}",
                        " ".repeat(name_width),
                        " ".repeat(bar.chars().count()),
                        "",
                        r
                    ))
                    .style(theme::dim()),
                );
            }
            ListItem::new(lines)
        })
        .collect();

    let list = List::new(items).highlight_style(selection_style(app));
    let mut state = ListState::default();
    if app.input.is_none() {
        state.select(Some(app.proj_sel.min(projects.len().saturating_sub(1))));
    }
    f.render_stateful_widget(list, parts[1], &mut state);
}

// ── [3] LOG — the audit tail ────────────────────────────────────────────────

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
        " 🖧 host  ● online  ◐ unreachable  ○ never-pulled    ♪ working  𝄐 awaiting  𝄁 stopped  𝄽 idle  𝄂 done",
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
    let items: Vec<ListItem> = rows.iter().map(|r| roster_row_item(r, pal)).collect();
    let list = List::new(items).highlight_style(selection_style(app));
    let mut state = ListState::default();
    state.select(Some(app.roster_sel.min(rows.len().saturating_sub(1))));
    f.render_stateful_widget(list, parts[2], &mut state);
}

fn roster_row_item<'a>(row: &crate::app::RosterRow, pal: &crate::app::Palette) -> ListItem<'a> {
    match row {
        crate::app::RosterRow::NodeHeader {
            name,
            is_local,
            presence,
            fetched_at,
        } => {
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
        crate::app::RosterRow::Session {
            session: s,
            is_last,
        } => {
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

    let items: Vec<ListItem> = rows.iter().map(pending_row_item).collect();
    let list = List::new(items).highlight_style(selection_style(app));
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
        "  Tab / Shift-Tab   cycle views · Ctrl-P project tree",
        "  1 Home · 2 Mail · 3 Agents · 4 Terminals · 5 Mesh",
        "  6 Review · 7 Projects · 8 Graph · 9 Log · 0 Status",
        "  Mouse             click tabs, rows and actions; wheel scrolls",
        "  Arrows / j,k      select in the focused pane",
        "  Tree: h/l         fold/unfold · Enter open · Past is history",
        "  Home: n           create a project",
        "  Projects: a/r     add folder / resurrect project",
        "  Agents/Terminals: Enter cue window or tail the log if headless",
        "  Esc / q           close the log tail (Enter also closes it)",
        "  Graph: j/k        down/up a rank: child / parent",
        "  Graph: a          whole forest / the picked card's own graph",
        "  Graph: h/l        previous/next sibling · Enter focus · read-only tags",
        "  Graph: e/s        actions menu / write a letter",
        "  Graph: pan        Space or middle drag; wheel/Shift-wheel",
        "  Graph: zoom       Ctrl+wheel steps 50-150%, at the pointer",
        "  Graph: p          prune ended sessions",
        "  Mail: h/l         conversations / letters; j/k select",
        "  Mail: n/s/r       new letter / reply / refresh",
        "  Compose: Enter    newline after recipient · Ctrl-S send",
        "  Compose: Esc      discard draft; shortcuts become text",
        "  Mail / Log        PgUp/PgDn or wheel scrolls detail",
        "  Mesh: s/r         terminal input / refresh",
        "  Approvals: a/d    approve / deny conductor input (not mail)",
        "  ? / Esc           close help · q / Ctrl-C quit",
    ];
    let title = " aoide conductor — keys ";
    let box_w = help_box_width(help, title, area);
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

/// The help box's width: the widest of its lines and its title, measured in
/// display cells (`board::cells`, never `len()` -- a byte count disagrees
/// with cell width the moment a line carries a multi-byte glyph such as the
/// title's em dash), plus the border and the box's own padding.
fn help_box_width(help: &[&str], title: &str, area: Rect) -> u16 {
    let box_w = help
        .iter()
        .map(|l| crate::board::cells(l))
        .max()
        .unwrap_or(20)
        .max(crate::board::cells(title))
        + 4;
    box_w.min(area.width.saturating_sub(2))
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
            project: None,
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
            sources: None,
            petname: None,
            hook_ancestry: Vec::new(),
            headless: false,
            spawned: false,
            exempt: false,
            harness_session_id: None,
            resumed_from: None,
            native_role: None,
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
        a.graph.selected = app.graph.selected.clone();
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
        // Three ranks (project → root → kid) stand 3×CARD_H + 2×RANK_GAP =
        // 27 world rows tall, and the camera centres the default selection
        // (the topmost card) rather than top-aligning — so the pane itself
        // must be tall enough to pull the origin to 0 and still clear the
        // bottom-most card. 50 rows of graph content does that with room to
        // spare; the other 10 are this panel's header/nav/border/action
        // row/status-bar chrome.
        let out = render_panel(&app, Panel::Graph, 220, 60);
        assert!(out.contains("GRAPH"), "panel title rendered");
        assert!(
            out.contains("PROJECT") && out.contains("aoide"),
            "project node drawn"
        );
        // Session chips render the display grammar (petnames plan P3), not
        // the bare id — neither fixture session has a minted petname, so
        // each degrades to `<host>/<role>/<sessionId>`.
        let host = aoide_storage::display::local_host_name();
        assert!(
            out.contains(&format!("{host}/root/r")) && out.contains(&format!("{host}/child/k")),
            "session nodes drawn: {out}"
        );
        assert!(
            out.contains('├') || out.contains('└') || out.contains('─'),
            "box-drawing edges present"
        );
        assert!(out.contains("[x]"), "read-only tag chip drawn: {out}");
        assert!(
            out.contains("all/focus"),
            "status bar keymap hint carries the view toggle: {out}"
        );
        assert!(
            out.contains("prune"),
            "status bar keymap hint carries prune: {out}"
        );
    }

    #[test]
    fn graph_panel_title_is_the_graph_noun_not_dag() {
        let app = app_with(vec![], vec![]);
        let out = render_panel(&app, Panel::Graph, 100, 30);
        assert!(
            out.contains("GRAPH"),
            "panel title is the Graph noun: {out}"
        );
        assert!(!out.contains("DAG"), "panel title is not DAG: {out}");
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
        assert!(out.contains("AGENTS"), "panel title");
        assert!(
            out.contains("PROJECT") && out.contains("aoide"),
            "group header"
        );
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
            out.contains("⊚claude-sonnet-5"),
            "root agent's model tag on its roster row: {out}"
        );
        assert!(
            out.contains("⊚claude-fable-5"),
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
        // Same 3-rank project → root → subagent chain as
        // `graph_panel_draws_nodes_edges_and_tags`; see that test's comment
        // for the viewport arithmetic.
        let out = render_panel(&app, Panel::Graph, 220, 60);
        assert!(
            out.contains("claude · m"),
            "subagent chip carries its model tag: {out}"
        );
    }

    #[test]
    fn selected_project_highlight_fills_each_root_row_and_columns_align() {
        let mut app = app_with(
            vec![Project {
                name: "界wide-project-name".into(),
                path: "/primary".into(),
                roots: vec!["/extra".into()],
                ..Default::default()
            }],
            vec![],
        );
        app.sidebar_focused = false;
        app.palette.bg = Some(0);
        app.palette.accent = Some(6);
        let mut terminal = Terminal::new(TestBackend::new(80, 10)).unwrap();
        terminal
            .draw(|f| draw_projects(f, Rect::new(0, 0, 80, 10), &app))
            .unwrap();
        let buffer = terminal.backend().buffer();
        for y in [1, 2] {
            for x in [0, 40, 79] {
                assert_eq!(buffer[(x, y)].bg, Color::Indexed(6));
                assert_eq!(buffer[(x, y)].fg, Color::Indexed(0));
            }
        }
        let cell_column = |row: u16, symbol: &str| {
            (0..80)
                .find(|x| buffer[(*x, row)].symbol() == symbol)
                .unwrap()
        };
        assert_eq!(cell_column(1, "/"), cell_column(2, "/"));
        assert_eq!(cell_column(0, "p"), 2); // project heading
        assert_eq!(pad_column("界", 4), "界  ");
    }

    #[test]
    fn focused_pane_border_is_single_accent_and_inactive_selection_is_subdued() {
        let mut app = app_with(vec![], vec![]);
        app.sidebar_focused = false;
        app.palette.bg = Some(15);
        app.palette.fg = Some(0);
        app.palette.accent = Some(4);
        let mut terminal = Terminal::new(TestBackend::new(30, 5)).unwrap();
        terminal
            .draw(|f| f.render_widget(panel_block("Projects", &app), Rect::new(0, 0, 30, 5)))
            .unwrap();
        let buffer = terminal.backend().buffer();
        assert_eq!(buffer[(0, 0)].symbol(), "┌");
        assert_eq!(buffer[(0, 0)].fg, Color::Indexed(4));
        assert_eq!(buffer[(28, 4)].symbol(), "─");
        app.sidebar_focused = true;
        assert_ne!(selection_style(&app).bg, Some(Color::Indexed(4)));
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
    fn the_projects_panel_lists_every_root_under_its_project() {
        let app = app_with(
            vec![
                Project {
                    name: "aoide".into(),
                    path: "/a".into(),
                    roots: vec!["/second-root".into()],
                    ..Default::default()
                },
                Project {
                    name: "zeta".into(),
                    path: "/z".into(),
                    ..Default::default()
                },
            ],
            vec![],
        );
        let out = render_panel(&app, Panel::Projects, 90, 20);
        assert!(out.contains("/a"), "the primary root still renders: {out}");
        assert!(
            out.contains("/second-root"),
            "the extra root renders too: {out}"
        );
        let ai = out.find("aoide").unwrap();
        let zi = out.find("zeta").unwrap();
        assert!(ai < zi, "sort/meter for the neighbour still holds");
        assert!(out.contains('░'), "ascii meter drawn");
    }

    #[test]
    fn log_panel_colours_and_shows_records() {
        let mut app = app_with(vec![], vec![]);
        app.log = vec![
            crate::app::LogLine {
                raw: serde_json::json!({}),
                ts: 1,
                door: "cli".into(),
                class: "audit".into(),
                command: "session.prune".into(),
                status: "ok".into(),
                message: "staged".into(),
            },
            crate::app::LogLine {
                raw: serde_json::json!({}),
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
        assert!(
            out.contains("aoide conductor — keys"),
            "overlay title present"
        );
        assert!(out.contains("cycle views"));
        assert!(out.contains("read-only tag"), "Graph tag legend documented");
        assert!(
            out.contains("tail the log if headless"),
            "Enter's headless branch is documented: {out}"
        );
        assert!(
            out.contains("close the log tail"),
            "the log-tail overlay's close keys are documented: {out}"
        );
        assert!(
            out.contains("whole forest"),
            "Graph's `a` view toggle is documented: {out}"
        );
        assert!(
            out.contains("drag") && out.contains("wheel") && out.contains("50-150%"),
            "Graph's pan and zoom controls are documented: {out}"
        );
    }

    #[test]
    fn help_box_width_matches_its_widest_line_in_cells() {
        // Every help line here is shorter than the title, so the title's em
        // dash -- three bytes, one display cell -- is what decides the
        // width. Measuring it as bytes (26) rather than cells (24) would
        // widen the box by 2 columns; `help_box_width` must not do that.
        let help = ["short", "also short"];
        let title = " aoide conductor — keys ";
        let area = Rect::new(0, 0, 200, 50);
        let widest_cells = help
            .iter()
            .map(|l| crate::board::cells(l))
            .max()
            .unwrap()
            .max(crate::board::cells(title));
        assert_eq!(crate::board::cells(title), 24, "fixture assumption");
        assert_eq!(help_box_width(&help, title, area), widest_cells + 4);
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
    fn app_with_tail_under(
        base: std::path::PathBuf,
        session_id: &str,
        lines: Vec<String>,
        tag: &str,
    ) -> App {
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
        let deep_base = std::env::temp_dir()
            .join("a".repeat(60))
            .join("b".repeat(60));
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
        assert!(
            local_pos < node_pos,
            "local box renders before nodes: {out}"
        );
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

    /// The exact live repro: at 118 columns the Graph hint is 122 bytes but
    /// only 114 display cells (its eight `·` separators are two bytes each),
    /// so measuring it with `.len()` and reserving only four columns for the
    /// message cut "ready" down to "rea" with the hint's own text glued on
    /// right after. The message must survive intact.
    #[test]
    fn status_bar_keeps_the_message_intact_beside_a_long_hint() {
        let mut a = App::for_test(vec![], vec![], vec![]);
        a.panel = Panel::Graph;
        let backend = TestBackend::new(118, 1);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| draw_status(f, f.area(), &a)).unwrap();
        let out = dump(term.backend().buffer());
        assert!(
            out.contains(" ready"),
            "the message must not be clobbered by the hint: {out:?}"
        );
    }

    /// At a width too narrow for both, the message still wins and nothing
    /// panics -- the hint is the one that gets dropped or clipped.
    #[test]
    fn status_bar_keeps_the_message_at_a_narrow_width() {
        let mut a = App::for_test(vec![], vec![], vec![]);
        a.panel = Panel::Graph;
        let backend = TestBackend::new(40, 1);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| draw_status(f, f.area(), &a)).unwrap();
        let out = dump(term.backend().buffer());
        assert!(
            out.contains(" ready"),
            "the message still renders whole at a narrow width: {out:?}"
        );
    }

    /// The exact live repro, one step further: the prior fix stopped the
    /// hint from truncating the message but left zero columns between the
    /// two, so at 118 columns they rendered as the glued nonsense
    /// "readyj/k...". The message must survive AND a gap must separate it
    /// from the hint.
    #[test]
    fn status_bar_never_glues_the_message_to_the_hint_at_118_columns() {
        let mut a = App::for_test(vec![], vec![], vec![]);
        a.panel = Panel::Graph;
        let backend = TestBackend::new(118, 1);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| draw_status(f, f.area(), &a)).unwrap();
        let out = dump(term.backend().buffer());
        assert!(
            out.contains(" ready"),
            "the message must render intact: {out:?}"
        );
        assert!(
            !out.contains("readyj"),
            "the message and the hint's first word must not abut: {out:?}"
        );
        let after_message = out.find(" ready").unwrap() + " ready".len();
        assert_eq!(
            out.as_bytes().get(after_message),
            Some(&b' '),
            "a blank column separates the message from the hint: {out:?}"
        );
    }

    /// A width too narrow for the hint at all: the message still renders
    /// whole and nothing panics -- the hint is what disappears entirely.
    #[test]
    fn status_bar_keeps_the_message_at_a_very_narrow_width() {
        let mut a = App::for_test(vec![], vec![], vec![]);
        a.panel = Panel::Graph;
        let backend = TestBackend::new(30, 1);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| draw_status(f, f.area(), &a)).unwrap();
        let out = dump(term.backend().buffer());
        assert!(
            out.contains(" ready"),
            "the message still renders whole at a very narrow width: {out:?}"
        );
    }
}
