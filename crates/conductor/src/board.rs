//! Message-board chrome and shared drawing/hit geometry.
use crate::app::{App, Panel, SidebarRow};
use crate::theme;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

// Tab labels: fixed digit (the key), the panel's identity mark, the name.
pub const NAV: [(Panel, &str); 10] = [
    (Panel::Home, "1 ⌂ Home"),
    (Panel::Mail, "2 ✉ Mail"),
    (Panel::Session, "3 ♜ Agents"),
    (Panel::Terminals, "4 ▣ Terminals"),
    (Panel::Roster, "5 🖧 Mesh"),
    (Panel::Pending, "6 ⚑ Review"),
    (Panel::Projects, "7 ◆ Projects"),
    (Panel::Graph, "8 ∴ Graph"),
    (Panel::Log, "9 ≡ Log"),
    (Panel::Status, "0 ⚙ Status"),
];

/// Display width in cells — every hit region is sized by this, never by
/// byte length (a mark is three bytes for one cell).
pub fn cells(s: &str) -> u16 {
    ratatui::text::Line::from(s).width() as u16
}

pub struct Geometry {
    pub header: Rect,
    pub nav: Rect,
    pub tree: Rect,
    pub body: Rect,
    pub footer: Rect,
}
pub fn geometry(area: Rect, focused: bool) -> Geometry {
    let available = area.width.saturating_sub(2).max(1);
    let (mut used, mut nav_height) = (0, 1);
    for (_, label) in NAV {
        let width = cells(label) + 2;
        if used > 0 && used + width > available {
            nav_height += 1;
            used = 0;
        }
        used += width;
    }
    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(nav_height + 2),
        Constraint::Min(0),
        Constraint::Length(3),
    ])
    .split(area);
    let width = if area.width >= 80 {
        (area.width / 4).clamp(24, 34)
    } else if focused {
        area.width.min(30)
    } else {
        0
    };
    let cols = Layout::horizontal([Constraint::Length(width), Constraint::Min(0)]).split(rows[2]);
    Geometry {
        header: rows[0],
        nav: rows[1],
        tree: cols[0],
        body: cols[1],
        footer: rows[3],
    }
}
pub fn page_geometry(area: Rect, app: &App) -> Geometry {
    let mut g = geometry(area, app.sidebar_focused);
    if app.panel == Panel::Home {
        g.body = Rect::new(area.x, g.body.y, area.width, g.body.height);
        g.tree.width = 0;
    }
    g
}

pub fn nav_regions(area: Rect) -> Vec<(Rect, Panel, &'static str)> {
    let area = inner(area);
    let mut x = area.x;
    let mut y = area.y;
    NAV.iter()
        .filter_map(|&(panel, label)| {
            let w = cells(label) + 2;
            if x.saturating_add(w) > area.right() {
                x = area.x;
                y = y.saturating_add(1);
            }
            if y >= area.bottom() || w > area.width {
                return None;
            }
            let rect = Rect::new(x, y, w, 1);
            x += w;
            Some((rect, panel, label))
        })
        .collect()
}

pub fn inner(area: Rect) -> Rect {
    area.inner(ratatui::layout::Margin::new(1, 1))
}
pub fn body_content(area: Rect) -> (Rect, Rect) {
    let rows = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(area);
    (rows[0], rows[1])
}
pub fn action_regions(
    area: Rect,
    panel: Panel,
) -> Vec<(Rect, crossterm::event::KeyCode, &'static str)> {
    use crossterm::event::KeyCode;
    let labels: &[(char, &str)] = match panel {
        Panel::Graph => &[('s', "Write letter"), ('e', "Actions")],
        Panel::Projects => &[('a', "Add folder"), ('r', "Resurrect")],
        Panel::Session | Panel::Terminals => &[('\n', "Open / focus")],
        Panel::Roster => &[('s', "Terminal input"), ('r', "Refresh")],
        Panel::Pending => &[('a', "Approve"), ('d', "Deny")],
        Panel::Mail => &[
            ('n', "New letter"),
            ('s', "Reply"),
            ('a', "Reply all"),
            ('f', "Forward"),
            ('r', "Refresh"),
        ],
        _ => &[],
    };
    let mut x = area.x;
    labels
        .iter()
        .filter_map(|&(key, label)| {
            let w = cells(label) + 4;
            if x + w > area.right() {
                return None;
            }
            let r = Rect::new(x, area.y, w, 1);
            x += w;
            Some((
                r,
                if key == '\n' {
                    KeyCode::Enter
                } else {
                    KeyCode::Char(key)
                },
                label,
            ))
        })
        .collect()
}
pub fn draw_actions(f: &mut Frame, area: Rect, app: &App) {
    if app.panel == Panel::Graph {
        let columns = Layout::horizontal([Constraint::Length(30), Constraint::Min(0)]).split(area);
        for (r, _, label) in action_regions(columns[0], Panel::Graph) {
            f.render_widget(
                Paragraph::new(format!("[{label}]"))
                    .style(Style::default().fg(theme::role_color(&app.palette, theme::Role::Mail))),
                r,
            );
        }
        f.render_widget(
            Paragraph::new(format!(
                "Canvas {} | Ctrl-wheel zoom | Space+drag pan",
                crate::graphview::zoom_label(app)
            ))
            .style(Style::default().fg(theme::role_color(&app.palette, theme::Role::Terminal))),
            columns[1],
        );
        return;
    }
    if matches!(app.panel, Panel::Session | Panel::Terminals) && app.history_selected.is_some() {
        return;
    }
    for (r, _, label) in action_regions(area, app.panel) {
        f.render_widget(
            Paragraph::new(format!("[{label}] "))
                .style(Style::default().add_modifier(Modifier::BOLD)),
            r,
        );
    }
}
fn selected() -> Style {
    Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
}
fn frame(title: &str) -> Block<'_> {
    Block::default().borders(Borders::ALL).title(title)
}

pub fn draw(f: &mut Frame, app: &App) {
    let g = page_geometry(f.area(), app);
    let base = theme::surface(&app.palette, 0);
    f.render_widget(Block::default().style(base), f.area());
    f.render_widget(
        Block::default().style(theme::surface(&app.palette, 12)),
        g.header,
    );
    f.render_widget(
        Block::default()
            .borders(Borders::ALL)
            .style(theme::surface(&app.palette, 7)),
        g.nav,
    );
    f.render_widget(
        Block::default().style(theme::surface(&app.palette, 7)),
        g.footer,
    );
    f.render_widget(
        Paragraph::new(" 𝄞 CONDUCTOR").style(Style::default().add_modifier(Modifier::BOLD)),
        g.header,
    );
    for (r, p, label) in header_regions(g.header, app) {
        f.render_widget(
            Paragraph::new(label).style(theme::tab_style(
                &app.palette,
                panel_role(p),
                false,
                false,
            )),
            r,
        );
    }
    for (rect, panel, label) in nav_regions(g.nav) {
        let st = theme::tab_style(&app.palette, panel_role(panel), panel == app.panel, false);
        f.render_widget(Paragraph::new(format!(" {} ", label)).style(st), rect);
    }
    if g.tree.width > 0 {
        draw_tree(f, g.tree, app);
    }
    if app.panel == Panel::Home {
        draw_home(f, g.body, app);
    } else {
        crate::ui::draw_body(f, g.body, app);
    }
    divider(f, Rect::new(g.footer.x, g.footer.y, g.footer.width, 1), app);
    let rows = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(Rect::new(
        g.footer.x,
        g.footer.y + 1,
        g.footer.width,
        g.footer.height.saturating_sub(1),
    ));
    f.render_widget(
        Paragraph::new(
            " hjkl/arrows move · Ctrl-P tree · Tab views · right-click actions · ? help",
        ),
        rows[0],
    );
    f.render_widget(
        Block::default().style(theme::surface(&app.palette, 22)),
        rows[1],
    );
    crate::ui::draw_status(f, rows[1], app);
    crate::ui::draw_overlays(f, app);
    draw_mail_draft(f, app);
    draw_target_menu(f, app);
    draw_context_menu(f, app);
}

pub fn tree_offset(app: &App, height: u16) -> usize {
    let h = usize::from(height.max(1));
    app.sidebar_scroll
        .min(app.sidebar_sel)
        .max(app.sidebar_sel.saturating_sub(h - 1))
}

fn draw_tree(f: &mut Frame, area: Rect, app: &App) {
    let title = if app.sidebar_focused {
        " PROJECTS * "
    } else {
        " PROJECTS "
    };
    f.render_widget(
        frame(title).border_style(if app.sidebar_focused {
            theme::accent_style(&app.palette).add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        }),
        area,
    );
    f.render_widget(
        Block::default().style(theme::surface(&app.palette, 5)),
        inner(area),
    );
    let content = inner(area);
    let rows = app.sidebar_rows();
    if rows.is_empty() {
        f.render_widget(
            Paragraph::new("No projects yet.\nOpen Projects to add a folder.")
                .wrap(Wrap { trim: false }),
            content,
        );
        return;
    }
    for (n, row) in rows
        .iter()
        .enumerate()
        .skip(tree_offset(app, content.height))
        .take(content.height as usize)
    {
        let y = content.y + (n - tree_offset(app, content.height)) as u16;
        let label = match row {
            SidebarRow::Project { name, folded, .. } => {
                format!(
                    "{} {} {name}",
                    if *folded { "▸" } else { "▾" },
                    theme::mark(theme::Mark::Project)
                )
            }
            SidebarRow::Past {
                project,
                folded,
                count,
            } => format!(
                "{}{} {} Past sessions ({count})",
                if project == crate::app::UNANCHORED {
                    ""
                } else {
                    "  "
                },
                if *folded { "▸" } else { "▾" },
                theme::mark(theme::Mark::Past)
            ),
            SidebarRow::Session {
                label,
                past,
                depth,
                rec,
                ..
            } => format!(
                "{}{} {label}",
                " ".repeat((*depth).min(8) * 2),
                theme::mark(if *past {
                    theme::Mark::Past
                } else if crate::app::is_terminal(rec) {
                    theme::Mark::Terminal
                } else {
                    theme::Mark::Agent
                })
            ),
            SidebarRow::History { label, depth, .. } => format!(
                "{}{} {label}",
                " ".repeat((*depth).min(8) * 2),
                theme::mark(theme::Mark::Past)
            ),
            SidebarRow::Section {
                terminal,
                folded,
                count,
                ..
            } => format!(
                "  {} {} {} ({count})",
                if *folded { "▸" } else { "▾" },
                theme::mark(if *terminal {
                    theme::Mark::Terminal
                } else {
                    theme::Mark::Agent
                }),
                if *terminal { "Terminals" } else { "Agents" }
            ),
        };
        let role = match row {
            SidebarRow::Project { .. } => theme::Role::Project,
            SidebarRow::Session { rec, .. } => {
                if crate::app::is_terminal(rec) {
                    theme::Role::Terminal
                } else {
                    theme::Role::Agent
                }
            }
            SidebarRow::Section { terminal, .. } => {
                if *terminal {
                    theme::Role::Terminal
                } else {
                    theme::Role::Agent
                }
            }
            _ => theme::Role::Muted,
        };
        f.render_widget(
            Paragraph::new(label).style(if n == app.sidebar_sel {
                if app.sidebar_focused {
                    selected()
                } else {
                    theme::surface(&app.palette, 10).fg(theme::role_color(&app.palette, role))
                }
            } else {
                Style::default().fg(theme::role_color(&app.palette, role))
            }),
            Rect::new(content.x, y, content.width, 1),
        );
    }
    if app.history_error.is_some() && content.height > 0 {
        f.render_widget(
            Paragraph::new("History unavailable"),
            Rect::new(content.x, content.bottom() - 1, content.width, 1),
        );
    }
}

/// The Home column is LEFT-anchored inside the padded surface (never centered).
pub fn home_content(area: Rect) -> Rect {
    let width = area.width.saturating_sub(12).min(62);
    Rect::new(area.x + 6, area.y + 1, width, area.height.saturating_sub(3))
}

pub fn recent_projects(app: &App) -> Vec<&aoide_conduct::graph::Project> {
    let records = app.merged();
    let mut rows: Vec<_> = app.projects.iter().collect();
    let latest = |p: &aoide_conduct::graph::Project| {
        let live = records
            .iter()
            .filter(|r| {
                aoide_conduct::graph::effective_project_for(r, &records, &app.projects)
                    .is_some_and(|i| app.projects[i].name == p.name)
            })
            .map(|r| r.started_at.as_str())
            .max()
            .unwrap_or("");
        let past = app
            .history
            .iter()
            .filter(|h| h.project.as_deref() == Some(&p.name))
            .map(|h| h.ended_at.as_str())
            .max()
            .unwrap_or("");
        live.max(past).to_string()
    };
    rows.sort_by(|a, b| latest(b).cmp(&latest(a)).then(a.name.cmp(&b.name)));
    rows.truncate(5);
    rows
}

fn home_groups(area: Rect) -> Vec<(Rect, &'static str)> {
    let a = home_content(area);
    // logo (6 rows) + a three-row breath before the panels
    let y = a.y + 9;
    if a.width >= 58 {
        let w = (a.width - 2) / 2;
        vec![
            (
                Rect::new(a.x, y, w, a.bottom().saturating_sub(y).min(7)),
                " ◆ PROJECTS ",
            ),
            (
                Rect::new(
                    a.x + w + 2,
                    y,
                    a.width - w - 2,
                    a.bottom().saturating_sub(y).min(7),
                ),
                " ✉ COMMUNICATION ",
            ),
        ]
    } else {
        vec![
            (
                Rect::new(a.x, y, a.width, a.bottom().saturating_sub(y).min(4)),
                " ◆ PROJECTS ",
            ),
            (
                Rect::new(a.x, y + 4, a.width, a.bottom().saturating_sub(y + 4).min(5)),
                " ✉ COMMUNICATION ",
            ),
        ]
    }
}
fn home_menu(area: Rect) -> Vec<(Rect, char, &'static str)> {
    let groups = home_groups(area);
    let step = if home_content(area).width >= 58 { 2 } else { 1 };
    [
        (0, 0, 'n', "New project"),
        (0, 1, 'p', "Open project"),
        (1, 0, 'm', "Correspondence"),
        (1, 1, 'H', "Connected hosts"),
        (1, 2, 'L', "Activity log"),
    ]
    .into_iter()
    .filter_map(|(g, row, key, label)| {
        let r = inner(groups[g].0);
        let y = r.y + row * step;
        (y < r.bottom()).then_some((Rect::new(r.x, y, r.width, 1), key, label))
    })
    .collect()
}
fn recent_start(area: Rect) -> u16 {
    home_groups(area)
        .iter()
        .map(|(r, _)| r.bottom())
        .max()
        .unwrap_or(area.y)
        + 1
}
pub fn home_project_regions(area: Rect, app: &App) -> Vec<(Rect, String)> {
    let a = home_content(area);
    let start = recent_start(area) + 2;
    recent_projects(app)
        .iter()
        .enumerate()
        .filter_map(|(i, p)| {
            let y = start + i as u16 * 3;
            (y + 1 < a.bottom()).then_some((Rect::new(a.x, y, a.width, 2), p.name.clone()))
        })
        .collect()
}
pub fn home_actions(area: Rect) -> Vec<(Rect, Panel, &'static str)> {
    home_menu(area)
        .into_iter()
        .filter_map(|(r, k, l)| match k {
            'p' => Some((r, Panel::Projects, l)),
            'm' => Some((r, Panel::Mail, l)),
            'H' => Some((r, Panel::Roster, l)),
            'L' => Some((r, Panel::Log, l)),
            _ => None,
        })
        .collect()
}
pub fn home_hit(area: Rect, app: &App, x: u16, y: u16) -> Hit {
    let pos = ratatui::layout::Position::new(x, y);
    for (r, k, _) in home_menu(area) {
        if k == 'n' && r.contains(pos) {
            return Hit::NewProject;
        }
    }
    for (r, name) in home_project_regions(area, app) {
        if r.contains(pos) {
            return Hit::Project(name);
        }
    }
    for (r, p, _) in home_actions(area) {
        if r.contains(pos) {
            return Hit::Panel(p);
        }
    }
    Hit::None
}
fn abbreviated(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }
    if width < 4 {
        return text.chars().take(width).collect();
    }
    let tail: String = text
        .chars()
        .rev()
        .take(width - 2)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("… {tail}")
}
fn divider(f: &mut Frame, area: Rect, app: &App) {
    f.render_widget(
        Paragraph::new("─".repeat(area.width as usize)).style(theme::accent_style(&app.palette)),
        area,
    );
}

fn home_surface(area: Rect, app: &App) -> Rect {
    let content = home_content(area);
    let top = home_groups(area)
        .first()
        .map(|(r, _)| r.y)
        .unwrap_or(content.y);
    let bottom = home_project_regions(area, app)
        .last()
        .map(|(r, _)| r.bottom())
        .unwrap_or_else(|| recent_start(area) + 3);
    let left = content.x.saturating_sub(3).max(area.x + area.width.min(1));
    let right = (content.right() + 3).min(area.right().saturating_sub(1));
    let top = top.saturating_sub(1).max(area.y);
    let bottom = (bottom + 2).min(area.bottom().saturating_sub(1));
    Rect::new(
        left,
        top,
        right.saturating_sub(left),
        bottom.saturating_sub(top),
    )
}

pub fn draw_home(f: &mut Frame, area: Rect, app: &App) {
    let a = home_content(area);
    let logo = include_str!("../assets/logo.txt");
    let logo_width = logo
        .lines()
        .map(|line| Line::from(line).width())
        .max()
        .unwrap_or(0) as u16;
    let logo_width = logo_width.min(a.width);
    f.render_widget(
        Paragraph::new(logo).style(theme::accent_style(&app.palette)),
        Rect::new(
            a.x + (a.width - logo_width) / 2,
            a.y,
            logo_width,
            a.height.min(7),
        ),
    );
    f.render_widget(
        Block::default().style(theme::surface(&app.palette, 4)),
        home_surface(area, app),
    );
    let menu = home_menu(area);
    for (r, title) in home_groups(area) {
        f.render_widget(
            frame("")
                .title(
                    Line::from(title).style(Style::default().fg(theme::role_color(
                        &app.palette,
                        if title.contains("PROJECT") {
                            theme::Role::Project
                        } else {
                            theme::Role::Mail
                        },
                    ))),
                )
                .style(theme::surface(&app.palette, 4))
                .border_style(Style::default()),
            r,
        );
    }
    for (index, (r, k, label)) in menu.into_iter().enumerate() {
        f.render_widget(
            Block::default().style(if index == app.home_sel {
                selected()
            } else {
                theme::surface(&app.palette, 4)
            }),
            r,
        );
        let columns = Layout::horizontal([Constraint::Min(0), Constraint::Length(5)]).split(r);
        f.render_widget(
            Paragraph::new(label).style(Style::default().fg(theme::role_color(
                &app.palette,
                match k {
                    'n' | 'p' => theme::Role::Project,
                    'm' => theme::Role::Mail,
                    'H' => theme::Role::Success,
                    _ => theme::Role::Terminal,
                },
            ))),
            columns[0],
        );
        f.render_widget(
            Paragraph::new(format!("[{k}]")).style(theme::accent_style(&app.palette)),
            columns[1],
        );
    }
    let start = recent_start(area);
    if start < a.bottom() {
        f.render_widget(
            Paragraph::new("◌ RECENT PROJECTS ────────────────────────────────────────")
                .style(theme::accent_style(&app.palette)),
            Rect::new(a.x, start, a.width, 1),
        );
    }
    for (index, (r, name)) in home_project_regions(area, app).into_iter().enumerate() {
        if r.bottom() < a.bottom() {
            divider(f, Rect::new(r.x, r.bottom(), r.width, 1), app);
        }
        let path = app
            .projects
            .iter()
            .find(|p| p.name == name)
            .map(|p| p.path.as_str())
            .unwrap_or("");
        let label = format!("  {name}");
        let path = abbreviated(path, r.width.saturating_sub(4) as usize);
        f.render_widget(
            Paragraph::new(vec![
                Line::from(label).style(
                    Style::default()
                        .fg(theme::role_color(&app.palette, theme::Role::Project))
                        .add_modifier(Modifier::BOLD),
                ),
                Line::from(format!("  {path}")),
            ])
            .style(if app.home_sel == index + 5 {
                selected()
            } else {
                theme::surface(&app.palette, 4)
            }),
            r,
        );
    }
    if app.projects.is_empty() && start + 2 < a.bottom() {
        f.render_widget(
            Paragraph::new("No recent projects."),
            Rect::new(a.x, start + 2, a.width, 1),
        );
    }
}

pub fn draw_history(f: &mut Frame, area: Rect, app: &App) {
    if let Some(h) = &app.history_selected {
        let text=format!("PAST SESSION\n\n{}\nHarness: {}\nSession ID: {}\nNative ID: {}\nProject: {}\nDirectory: {}\nStarted: {}\nEnded: {}\n\nThis is a historical record. Selecting it does not restart a process.\nUse Projects → Resurrect for supported durable project sessions.",
            h.title.as_deref().or(h.petname.as_deref()).unwrap_or(&h.agent),h.agent,h.session_id,
            h.harness_session_id.as_deref().unwrap_or("not recorded"),h.project.as_deref().unwrap_or("inferred from directory / unassigned"),h.cwd,h.started_at,h.ended_at);
        f.render_widget(Paragraph::new(text).wrap(Wrap { trim: false }), area);
    }
}

pub fn conversation_parts(area: Rect) -> (Rect, Rect) {
    let p = if area.width >= 95 {
        Layout::horizontal([Constraint::Length(30), Constraint::Min(0)]).split(area)
    } else {
        Layout::vertical([Constraint::Length(5), Constraint::Min(0)]).split(area)
    };
    (p[0], p[1])
}
pub fn mail_parts(area: Rect) -> (Rect, Rect) {
    let rows = Layout::vertical([
        Constraint::Length((area.height / 3).clamp(3, 7)),
        Constraint::Min(0),
    ])
    .split(area);
    (rows[0], rows[1])
}

pub fn draw_mail(f: &mut Frame, area: Rect, app: &App) {
    let (rooms, content) = conversation_parts(area);
    f.render_widget(
        frame(if app.mail_room_focus {
            " CONVERSATIONS * "
        } else {
            " CONVERSATIONS "
        })
        .border_style(Style::default()),
        rooms,
    );
    let room_area = inner(rooms);
    let conversations = app.mail.conversations();
    let offset = app
        .mail_room_sel
        .saturating_sub(room_area.height.saturating_sub(1) as usize);
    for (i, c) in conversations
        .iter()
        .enumerate()
        .skip(offset)
        .take(room_area.height as usize)
    {
        let text = format!(
            "{} [{} people / {} copies]",
            c.label,
            c.participants.len(),
            c.letters.len()
        );
        f.render_widget(
            Paragraph::new(text).style(if i == app.mail_room_sel {
                if app.mail_room_focus && !app.sidebar_focused {
                    selected()
                } else {
                    theme::surface(&app.palette, 10)
                }
            } else {
                theme::surface(&app.palette, 5)
            }),
            Rect::new(
                room_area.x,
                room_area.y + (i - offset) as u16,
                room_area.width,
                1,
            ),
        );
    }
    let (list, detail) = mail_parts(content);
    let letters = app.mail_letters();
    let offset = app
        .mail_sel
        .saturating_sub(list.height.saturating_sub(1) as usize);
    for (i, m) in letters
        .iter()
        .enumerate()
        .skip(offset)
        .take(list.height as usize)
    {
        let summary = m.subject().unwrap_or_else(|| "(no subject)".into());
        let from = m.from_address.name.as_str();
        f.render_widget(
            Paragraph::new(format!("{from}: {summary}")).style(if i == app.mail_sel {
                if !app.mail_room_focus && !app.sidebar_focused {
                    selected()
                } else {
                    theme::surface(&app.palette, 10)
                }
            } else {
                theme::surface(&app.palette, if i % 2 == 0 { 2 } else { 5 })
            }),
            Rect::new(list.x, list.y + (i - offset) as u16, list.width, 1),
        );
    }
    let title = if app.mail.truncated {
        " LETTER / recent local archive "
    } else {
        " LETTER / local archive "
    };
    f.render_widget(frame(title).border_style(Style::default()), detail);
    let inside = inner(detail);
    if let Some(m) = letters.get(app.mail_sel) {
        let text = format!(
            "Subject: {}\nFrom: {}\nTo: {}\nCc: {}\n{} · #{}\n\n{}\n\nEnvelope delivered to: {}\nMessage ID: {}",
            m.subject().unwrap_or_else(||"(no subject)".into()), m.from, addresses(&m.to_recipients()), addresses(&m.cc_recipients()), m.minted_at, m.seq, m.body(), m.to, m.msgid
        );
        let text = if let Some(thread) = conversations.get(app.mail_room_sel) {
            format!(
                "{text}\nThread: {}\nSeen in thread: {}",
                thread
                    .thread_id
                    .as_deref()
                    .unwrap_or("legacy correspondence"),
                thread.participants.join(", ")
            )
        } else {
            text
        };
        f.render_widget(
            Paragraph::new(text)
                .wrap(Wrap { trim: false })
                .scroll((app.mail_scroll, 0)),
            inside,
        );
    } else {
        let text = app
            .mail
            .error
            .as_deref()
            .unwrap_or("No local letters. Browsing does not consume an agent inbox.");
        f.render_widget(Paragraph::new(text).wrap(Wrap { trim: false }), inside);
    }
    if let Some(error) = &app.mail.error {
        if inside.height > 0 {
            f.render_widget(
                Paragraph::new(error.as_str()),
                Rect::new(inside.x, inside.bottom() - 1, inside.width, 1),
            );
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Hit {
    Panel(Panel),
    Tree(usize),
    Row(usize),
    Key(crossterm::event::KeyCode),
    NewProject,
    Project(String),
    Conversation(usize),
    None,
}

pub fn hit(area: Rect, app: &App, x: u16, y: u16) -> Hit {
    let pos = ratatui::layout::Position::new(x, y);
    let g = page_geometry(area, app);
    for (r, p, _) in header_regions(g.header, app) {
        if r.contains(pos) {
            return Hit::Panel(p);
        }
    }
    for (r, p, _) in nav_regions(g.nav) {
        if r.contains(pos) {
            return Hit::Panel(p);
        }
    }
    let tree = inner(g.tree);
    if tree.contains(pos) {
        return Hit::Tree(tree_offset(app, tree.height) + (y - tree.y) as usize);
    }
    if app.panel == Panel::Home {
        return home_hit(g.body, app, x, y);
    }
    let (body, actions) = body_content(inner(g.body));
    if matches!(app.panel, Panel::Session | Panel::Terminals) && app.history_selected.is_some() {
        return Hit::None;
    }
    for (r, k, _) in action_regions(actions, app.panel) {
        if r.contains(pos) {
            return Hit::Key(k);
        }
    }
    if !body.contains(pos) {
        return Hit::None;
    }
    if app.panel == Panel::Graph {
        return crate::graphview::hit_node(body, app, x, y)
            .map(Hit::Row)
            .unwrap_or(Hit::None);
    }
    if app.panel == Panel::Home {
        for (r, p, _) in home_actions(body) {
            if r.contains(pos) {
                return Hit::Panel(p);
            }
        }
    }
    if app.panel == Panel::Mail {
        let (rooms, content) = conversation_parts(body);
        let room_area = inner(rooms);
        if room_area.contains(pos) {
            return Hit::Conversation(
                app.mail_room_sel
                    .saturating_sub(room_area.height.saturating_sub(1) as usize)
                    + (y - room_area.y) as usize,
            );
        }
        let (list, _) = mail_parts(content);
        if list.contains(pos) {
            return Hit::Row(
                app.mail_sel
                    .saturating_sub(list.height.saturating_sub(1) as usize)
                    + (y - list.y) as usize,
            );
        }
    }
    let (list, selected, heights) = match app.panel {
        Panel::Session | Panel::Terminals => {
            let p = Layout::vertical([
                Constraint::Length(1),
                Constraint::Min(3),
                Constraint::Length(9),
            ])
            .split(body);
            (p[1], app.dag_sel, vec![1; app.dag_rows().len()])
        }
        Panel::Roster => {
            let p = Layout::vertical([
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Min(3),
            ])
            .split(body);
            (p[2], app.roster_sel, vec![1; app.roster_flat_rows().len()])
        }
        Panel::Pending => {
            let p = Layout::vertical([Constraint::Length(1), Constraint::Min(3)]).split(body);
            (p[1], app.pending_sel, vec![1; app.pending_rows().len()])
        }
        Panel::Projects => {
            let p = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).split(body);
            let mut projects = app.projects.clone();
            projects.sort_by(|a, b| a.name.cmp(&b.name));
            (
                p[1],
                app.proj_sel,
                projects.iter().map(|p| p.roots().len().max(1)).collect(),
            )
        }
        Panel::Log => {
            let (list, _) = crate::eventview::parts(body);
            (inner(list), app.log_sel, vec![2; app.log.len()])
        }
        _ => return Hit::None,
    };
    if list.contains(pos) {
        let mut start = 0;
        let mut used: usize = heights.iter().take(selected + 1).sum();
        while used > list.height as usize && start < selected {
            used = used.saturating_sub(heights[start]);
            start += 1;
        }
        let mut line = 0;
        for (i, h) in heights.iter().enumerate().skip(start) {
            if (y - list.y) as usize >= line && ((y - list.y) as usize) < line + h {
                return Hit::Row(i);
            }
            line += h;
        }
    }
    Hit::None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn narrow_tree_is_explicit_and_navigation_fits() {
        let a = Rect::new(0, 0, 60, 24);
        assert_eq!(geometry(a, false).tree.width, 0);
        assert!(geometry(a, true).tree.width > 0);
        for (r, _, _) in nav_regions(geometry(a, false).nav) {
            assert!(r.right() <= 60);
        }
    }
    #[test]
    fn home_surface_pads_controls_and_preserves_logo_columns() {
        let app = App::for_test(vec![], vec![], vec![]);
        let area = Rect::new(0, 0, 100, 40);
        let surface = home_surface(area, &app);
        let content = home_content(area);
        assert_eq!(content.x - surface.x, 3);
        assert_eq!(surface.right() - content.right(), 3);
        assert!(surface.y < home_groups(area)[0].0.y);
        assert!(surface.bottom() > recent_start(area) + 2);
        let backend = ratatui::backend::TestBackend::new(100, 40);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw_home(frame, area, &app)).unwrap();
        let buffer = terminal.backend().buffer();
        let logo = include_str!("../assets/logo.txt");
        let width = logo
            .lines()
            .map(|line| Line::from(line).width())
            .max()
            .unwrap() as u16;
        let x = content.x + (content.width - width) / 2;
        for (row, line) in logo.lines().enumerate() {
            for (column, glyph) in line.chars().enumerate() {
                assert_eq!(
                    buffer[(x + column as u16, content.y + row as u16)].symbol(),
                    glyph.to_string()
                );
            }
        }
        let text = (0..40)
            .map(|y| {
                (0..100)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<String>();
        assert_eq!(text.matches("COMMUNICATION").count(), 1);
    }

    #[test]
    fn home_mouse_targets_match_visible_actions() {
        let a = App::for_test(vec![], vec![], vec![]);
        let area = Rect::new(0, 0, 120, 40);
        let body = page_geometry(area, &a).body;
        for (r, p, _) in home_actions(body) {
            assert_eq!(hit(area, &a, r.x, r.y), Hit::Panel(p));
        }
    }
}

fn addresses(items: &[aoide_storage::mail::Address]) -> String {
    if items.is_empty() {
        return "—".into();
    }
    items
        .iter()
        .map(|a| format!("{}/{}", a.node, a.name))
        .collect::<Vec<_>>()
        .join(", ")
}

pub struct ComposerGeometry {
    pub area: Rect,
    pub tree: Rect,
    pub to_picker: Rect,
    pub cc_picker: Rect,
    pub from: Rect,
    pub fields: Vec<(Rect, crate::app::MailField)>,
    pub original: Rect,
    pub send: Rect,
    pub cancel: Rect,
    pub hint: Rect,
}
pub fn composer_geometry(area: Rect) -> ComposerGeometry {
    use crate::app::MailField;
    let outer = area.inner(ratatui::layout::Margin::new(1, 1));
    let panels = if outer.width >= 45 {
        Layout::horizontal([
            Constraint::Length((outer.width / 3).clamp(16, 30)),
            Constraint::Min(0),
        ])
        .split(outer)
    } else {
        Layout::vertical([
            Constraint::Length((outer.height / 4).min(6)),
            Constraint::Min(0),
        ])
        .split(outer)
    };
    let left = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).split(panels[0]);
    let pickers =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).split(left[0]);
    let a = panels[1];
    let i = inner(a);
    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(2),
        Constraint::Length(2),
        Constraint::Length(2),
        Constraint::Length(3),
        Constraint::Min(1),
        Constraint::Length(1),
        Constraint::Length(2),
    ])
    .split(i);
    let actions = Layout::horizontal([
        Constraint::Length(20),
        Constraint::Length(18),
        Constraint::Min(0),
    ])
    .split(rows[6]);
    ComposerGeometry {
        area: a,
        tree: left[1],
        to_picker: pickers[0],
        cc_picker: pickers[1],
        from: rows[0],
        fields: vec![
            (rows[1], MailField::To),
            (rows[2], MailField::Cc),
            (rows[3], MailField::Subject),
            (rows[5], MailField::Body),
        ],
        original: rows[4],
        send: actions[0],
        cancel: actions[1],
        hint: rows[7],
    }
}
fn draw_mail_draft(f: &mut Frame, app: &App) {
    use crate::app::{MailField, MailMode};
    let Some(d) = &app.mail_draft else {
        return;
    };
    let g = composer_geometry(f.area());
    f.render_widget(ratatui::widgets::Clear, g.tree);
    draw_tree(f, g.tree, app);
    for (rect, field, label) in [
        (g.to_picker, MailField::To, "[+ To]"),
        (g.cc_picker, MailField::Cc, "[+ Cc]"),
    ] {
        f.render_widget(
            Paragraph::new(label).style(if d.recipient_field == field {
                Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
            } else {
                theme::surface(&app.palette, 7)
            }),
            rect,
        );
    }
    f.render_widget(ratatui::widgets::Clear, g.area);
    let title = match d.mode {
        MailMode::New => " NEW LETTER ",
        MailMode::Reply => " REPLY ",
        MailMode::ReplyAll => " REPLY ALL ",
        MailMode::Forward => " FORWARD ",
    };
    f.render_widget(
        frame(title)
            .style(theme::surface(&app.palette, 4))
            .border_style(if app.sidebar_focused {
                Style::default()
            } else {
                theme::accent_style(&app.palette)
            }),
        g.area,
    );
    f.render_widget(Paragraph::new(format!("From: {}  (you)", d.from)), g.from);
    for &(r, field) in &g.fields {
        let (label, value) = match field {
            MailField::To => ("To", &d.to),
            MailField::Cc => ("Cc", &d.cc),
            MailField::Subject => ("Subject", &d.subject),
            MailField::Body => ("Message", &d.body),
        };
        let active = field == d.focus && !app.sidebar_focused;
        let label = format!("{} {} ", if active { ">" } else { " " }, label);
        let block = Block::default()
            .borders(Borders::TOP)
            .title(label)
            .border_style(Style::default());
        let content = block.inner(r);
        f.render_widget(
            block.style(theme::surface(&app.palette, if active { 7 } else { 3 })),
            r,
        );
        let display = if value.is_empty() {
            match field {
                MailField::To => "node/mailbox, ...",
                MailField::Cc => "Optional copy recipients",
                MailField::Subject => "What is this letter about?",
                MailField::Body => "Write your message...",
            }
            .to_string()
        } else {
            value.clone()
        };
        if field == MailField::Body && d.submitted {
            f.render_widget(
                Paragraph::new(
                    d.error
                        .as_deref()
                        .unwrap_or("Inspect delivery results before sending another letter."),
                )
                .wrap(Wrap { trim: false }),
                content,
            );
            continue;
        }
        if value.is_empty() {
            f.render_widget(Paragraph::new(display), content);
        }
        let lines = field_lines(value, content.width);
        let cursor_row = lines
            .iter()
            .rposition(|(start, _)| *start <= d.cursor)
            .unwrap_or(0);
        let offset = if active {
            cursor_row.saturating_sub(content.height.saturating_sub(1) as usize)
        } else {
            0
        };
        for (row, &(start, end)) in lines
            .iter()
            .enumerate()
            .skip(offset)
            .take(content.height as usize)
        {
            if value.is_empty() {
                break;
            }
            f.render_widget(
                Paragraph::new(&value[start..end]),
                Rect::new(
                    content.x,
                    content.y + (row - offset) as u16,
                    content.width,
                    1,
                ),
            );
        }
        if active && content.width > 0 && content.height > 0 {
            let start = lines.get(cursor_row).map(|l| l.0).unwrap_or(0);
            let col =
                ratatui::text::Span::raw(&value[start..d.cursor.min(value.len())]).width() as u16;
            f.set_cursor_position((
                content.x + col.min(content.width - 1),
                content.y
                    + (cursor_row - offset).min(content.height.saturating_sub(1) as usize) as u16,
            ));
        }
    }
    let original = if let Some(m) = &d.original {
        format!(
            "Regarding: {}\nFrom {} · {}\n{}",
            m.subject().unwrap_or_else(|| "(no subject)".into()),
            m.from,
            m.minted_at,
            abbreviated(&m.body().replace('\n', " "), g.original.width as usize)
        )
    } else {
        "Recipients see To and Cc. Sending files or queues mail; it does not confirm reading."
            .into()
    };
    f.render_widget(
        Paragraph::new(original)
            .style(theme::surface(&app.palette, 5))
            .wrap(Wrap { trim: false }),
        g.original,
    );
    f.render_widget(
        Paragraph::new(if d.submitted {
            "[ Submitted ]"
        } else {
            "[> Send ^S]"
        })
        .style(theme::accent_style(&app.palette).add_modifier(Modifier::BOLD)),
        g.send,
    );
    f.render_widget(Paragraph::new("[x Cancel Esc]"), g.cancel);
    let hint=d.error.clone().unwrap_or_else(||"Tab / Shift-Tab fields | Ctrl-S send | Esc cancel\n+ To / + Cc selects where tree clicks add recipients".into());
    f.render_widget(Paragraph::new(hint).wrap(Wrap { trim: false }), g.hint);
}
pub fn target_menu_area(area: Rect, x: u16, y: u16, count: usize) -> Rect {
    let w = area.width.min(62);
    let h = area.height.min(count as u16 + 2);
    Rect::new(
        x.min(area.right().saturating_sub(w)),
        y.min(area.bottom().saturating_sub(h)),
        w,
        h,
    )
}
fn draw_target_menu(f: &mut Frame, app: &App) {
    let Some((x, y, choices, index)) = &app.mail_target_menu else {
        return;
    };
    let a = target_menu_area(f.area(), *x, *y, choices.len());
    f.render_widget(ratatui::widgets::Clear, a);
    f.render_widget(
        frame(" WRITE LETTER TO · Esc close ").style(theme::surface(&app.palette, 4)),
        a,
    );
    let offset = index.saturating_sub(inner(a).height.saturating_sub(1) as usize);
    for (i, (label, address)) in choices
        .iter()
        .enumerate()
        .skip(offset)
        .take(inner(a).height as usize)
    {
        let r = Rect::new(
            a.x + 1,
            a.y + 1 + (i - offset) as u16,
            a.width.saturating_sub(2),
            1,
        );
        f.render_widget(
            Paragraph::new(format!("{label} · {address}")).style(if i == *index {
                selected()
            } else {
                Style::default()
            }),
            r,
        );
    }
}

pub fn field_lines(text: &str, width: u16) -> Vec<(usize, usize)> {
    let width = usize::from(width.max(1));
    let mut rows = Vec::new();
    let mut start = 0;
    let mut used = 0;
    for (i, c) in text.char_indices() {
        if c == '\n' {
            rows.push((start, i));
            start = i + 1;
            used = 0;
            continue;
        }
        let w = ratatui::text::Span::raw(c.to_string()).width();
        if used + w > width {
            rows.push((start, i));
            start = i;
            used = 0;
        }
        used += w;
    }
    rows.push((start, text.len()));
    rows
}
pub fn field_click(
    d: &crate::app::MailDraft,
    field: crate::app::MailField,
    rect: Rect,
    x: u16,
    y: u16,
) -> usize {
    let content = Block::default().borders(Borders::TOP).inner(rect);
    let text = d.field(field);
    let rows = field_lines(text, content.width);
    let selected = rows
        .iter()
        .rposition(|(start, _)| *start <= d.cursor)
        .unwrap_or(0);
    let offset = if field == d.focus {
        selected.saturating_sub(content.height.saturating_sub(1) as usize)
    } else {
        0
    };
    let row = (y.saturating_sub(content.y) as usize + offset).min(rows.len() - 1);
    let (start, end) = rows[row];
    let mut col = 0;
    for (i, c) in text[start..end].char_indices() {
        let w = ratatui::text::Span::raw(c.to_string()).width();
        if col + w > x.saturating_sub(content.x) as usize {
            return start + i;
        }
        col += w;
    }
    end
}

fn draw_context_menu(f: &mut Frame, app: &App) {
    let Some(m) = &app.context_menu else {
        return;
    };
    let area = target_menu_area(f.area(), m.x, m.y, m.actions.len());
    f.render_widget(ratatui::widgets::Clear, area);
    f.render_widget(
        frame(&format!(" {} ", m.title)).style(theme::surface(&app.palette, 5)),
        area,
    );
    let inside = inner(area);
    let offset = m
        .selected
        .saturating_sub(inside.height.saturating_sub(1) as usize);
    for (i, action) in m
        .actions
        .iter()
        .enumerate()
        .skip(offset)
        .take(inside.height as usize)
    {
        let symbol = match action {
            crate::app::ContextAction::Details => "?",
            crate::app::ContextAction::WriteLetter => "@",
            crate::app::ContextAction::Open => ">",
            crate::app::ContextAction::AssignProject => "#",
            crate::app::ContextAction::Resurrect => "^",
            crate::app::ContextAction::AddFolder => "+",
        };
        f.render_widget(
            Paragraph::new(format!(" {symbol} {}", action.label())).style(if i == m.selected {
                selected()
            } else {
                Style::default()
            }),
            Rect::new(inside.x, inside.y + (i - offset) as u16, inside.width, 1),
        );
    }
}

pub fn panel_role(panel: Panel) -> theme::Role {
    match panel {
        Panel::Home | Panel::Projects => theme::Role::Project,
        Panel::Session | Panel::Graph => theme::Role::Agent,
        Panel::Terminals => theme::Role::Terminal,
        Panel::Mail => theme::Role::Mail,
        Panel::Pending => theme::Role::Warning,
        Panel::Roster => theme::Role::Success,
        Panel::Log | Panel::Status => theme::Role::Muted,
    }
}
/// The three count buttons sit on the RIGHT edge of the header, each led by
/// its identity mark; `𝄞 CONDUCTOR` keeps the left.
pub fn header_regions(area: Rect, app: &App) -> Vec<(Rect, Panel, String)> {
    let records = app.merged();
    let buttons = [
        (
            Panel::Projects,
            format!(
                "[{} {} Projects]",
                theme::mark(theme::Mark::Project),
                app.projects.len()
            ),
        ),
        (
            Panel::Session,
            format!(
                "[{} {} Agents]",
                theme::mark(theme::Mark::Agent),
                records
                    .iter()
                    .filter(|r| !crate::app::is_terminal(r) && !crate::app::is_done(&r.state))
                    .count()
            ),
        ),
        (
            Panel::Terminals,
            format!(
                "[{} {} Terminals]",
                theme::mark(theme::Mark::Terminal),
                records
                    .iter()
                    .filter(|r| crate::app::is_terminal(r) && !crate::app::is_done(&r.state))
                    .count()
            ),
        ),
    ];
    let total: u16 = buttons.iter().map(|(_, l)| cells(l) + 1).sum();
    let left = area.x + 15;
    let mut x = area.right().saturating_sub(total).max(left);
    buttons
        .into_iter()
        .filter_map(|(p, label)| {
            let width = cells(&label);
            let r = Rect::new(x, area.y, width, 1);
            x += width + 1;
            (r.right() <= area.right()).then_some((r, p, label))
        })
        .collect()
}
