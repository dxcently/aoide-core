//! `aoide conductor` — the interactive terminal frontend over the trunk.
//!
//! One rule governs this whole module: the conductor is a FRONTEND, never a
//! second implementation. Every action is `dispatch::dispatch(Invocation {
//! door: Door::Cli, .. })` — so the single audit log records conductor
//! actions exactly like a typed command, and the two-doors-one-schema
//! contract holds. Reads
//! reuse the pure graph functions ([`aoide_conduct::graph::build_graph`],
//! [`aoide_conduct::graph::merged_sessions`], `anchor_for`) and load the stage files
//! directly. Nothing here parses or re-derives a command; the views only
//! compose calls and paint results.
//!
//! ── The ratatui port ────────────────────────────────────────────────────────
//! The renderer is [ratatui.rs](https://ratatui.rs) over the crossterm backend —
//! the rig's standard for every Aoide TUI. ratatui owns the double buffer and
//! the frame diff (what the old hand-rolled differential renderer did by hand);
//! we keep the loop, the event feed, and the live-state polling:
//!   * [`app::App`] is the core — live state (projects/sessions/hooks loaded
//!     from the stage tree), the audit tail, panel + node selection, and the
//!     last [`Outcome`](aoide_protocol::output::Outcome) from a dispatched action. It
//!     draws nothing.
//!   * [`ui`] is the view layer — pure `draw(frame, area, &App)` functions built
//!     from ratatui widgets. Given the same state they paint the same buffer, so
//!     every panel is testable with a `TestBackend` (no tty).
//!   * [`graphview`] lays out and draws the visual graph; [`theme`] carries the
//!     palette → `Style`, the glyph vocabulary, and the small pure formatters.
//!
//! The seven panels: GRAPH (the visual graph), SESSION (the terminal roster),
//! PROJECTS, LOG, STATUS, ROSTER (presence — this box plus every registered
//! node, messaging/presence plan P-C4; selection + compose P-C5), PENDING
//! (held `graph send`/A2A entries, approve/deny, P-C5). The event stream is
//! still the audit log (the LOG panel tails it); live state is still
//! stage-file mtimes, polled each tick (~500 ms via the crossterm poll
//! timeout). There is no watcher, no async runtime — one thread, one loop
//! for everything except ROSTER's own dispatch: `session --hosts` performs
//! LIVE network probes, so its throttled (~15s) fetch runs on its own background
//! `std::thread` and reports back over a channel the tick polls without
//! blocking (see `app`'s "ROSTER" section) — the one deliberate exception to
//! "one thread". PENDING's `graph pending list` is a local file read, so it
//! refreshes synchronously on the tick instead (`app`'s "PENDING" section).
//!
//! Terminal restoration is belt-and-braces: [`TermGuard`]'s `Drop` leaves the
//! alternate screen and disables raw mode, and a panic hook does the same before
//! the default hook prints — so no exit path (clean quit, `?`, or a panic deep
//! in a view) can leave the tty wedged.
//!
//! ── Try it without a live desktop ──────────────────────────────────────────
//! The whole thing honours `$AOIDE_STAGE_DIR` and `$AOIDE_AUDIT_LOG`, so a
//! throwaway tempdir is a full test rig. Seed one and launch:
//!
//! ```sh
//! export AOIDE_STAGE_DIR=$(mktemp -d) AOIDE_AUDIT_LOG=$AOIDE_STAGE_DIR/log
//! pkgs/aoide/tests/fixtures/seed.sh "$AOIDE_STAGE_DIR"
//! aoide conductor  # 1-7/Tab switch panels, j/k select, ? help, q quit
//! ```

pub mod app;
pub mod board;
pub mod commands;
pub mod eventview;
pub mod graphview;
pub mod logtail;
pub mod mailview;
pub mod scene;
pub mod theme;
pub mod ui;

use crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, KeyboardEnhancementFlags, MouseButton,
    MouseEvent, MouseEventKind, PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io::{self, Stdout};
use std::time::Duration;

use app::{App, DispatchFn, Panel};

/// How long each `event::poll` waits before we tick: the mtime-poll cadence.
const TICK: Duration = Duration::from_millis(500);

/// RAII terminal restoration. Constructing it enters raw mode + the alternate
/// screen; dropping it (clean quit OR unwind) leaves both. Paired with the panic
/// hook below, no exit path leaves the terminal in raw/alt state.
struct TermGuard;

impl TermGuard {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut out = io::stdout();
        execute!(
            out,
            EnterAlternateScreen,
            EnableMouseCapture,
            EnableBracketedPaste,
            PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::REPORT_EVENT_TYPES)
        )?;
        Ok(TermGuard)
    }
}

impl Drop for TermGuard {
    fn drop(&mut self) {
        // Best-effort on every step: a failed leave must not mask the reason we
        // are exiting, so errors are swallowed (the process is going down).
        let mut out = io::stdout();
        let _ = execute!(
            out,
            DisableBracketedPaste,
            PopKeyboardEnhancementFlags,
            DisableMouseCapture,
            LeaveAlternateScreen
        );
        let _ = disable_raw_mode();
    }
}

/// Install a panic hook that restores the terminal BEFORE the default hook
/// prints — otherwise the backtrace lands on the alternate screen and vanishes
/// when we leave it. Chains the previous hook.
fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let mut out = io::stdout();
        let _ = execute!(
            out,
            DisableBracketedPaste,
            PopKeyboardEnhancementFlags,
            DisableMouseCapture,
            LeaveAlternateScreen
        );
        let _ = disable_raw_mode();
        prev(info);
    }));
}

/// Run the interactive conductor to completion. Returns `Ok(())` on a clean quit.
///
/// The dispatch that records the launch has already run (lib.rs); here we set up
/// the terminal, build the app from the stage tree, and drive the loop.
///
/// `dispatch` is the real dispatcher, injected by the caller (`lib.rs` passes
/// `dispatch::dispatch`) — see [`app::DispatchFn`]'s doc comment for why the
/// conductor takes this in rather than reaching for the trunk's dispatcher
/// itself.
pub fn run(dispatch: DispatchFn) -> io::Result<()> {
    install_panic_hook();
    let _guard = TermGuard::enter()?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal: Terminal<CrosstermBackend<Stdout>> = Terminal::new(backend)?;

    let mut app = App::load(dispatch);
    event_loop(&mut terminal, &mut app)
    // `_guard` drops here (or on `?`/panic): terminal restored.
}

fn event_loop(terminal: &mut Terminal<CrosstermBackend<Stdout>>, app: &mut App) -> io::Result<()> {
    loop {
        // ratatui diffs against its previous buffer, so an unchanged frame is a
        // near no-op write — we can redraw every iteration and stay correct.
        terminal.draw(|f| ui::draw(f, app))?;

        if event::poll(TICK)? {
            match event::read()? {
                Event::Key(key)
                    if key.kind == KeyEventKind::Release && key.code == KeyCode::Char(' ') =>
                {
                    app.graph.pan_mode = false;
                    app.graph.drag = None;
                }
                // A press/repeat that `handle_key` reports as a quit ends the
                // loop. The guard short-circuits, so `handle_key` (which mutates
                // `app`) runs only for a real press, never a key release.
                Event::Key(key) if key.kind != KeyEventKind::Release && handle_key(app, key) => {
                    return Ok(())
                }
                Event::Paste(text) => handle_paste(app, &text),
                Event::Mouse(mouse) => handle_mouse(app, terminal.size()?.into(), mouse),
                // Every other event (release, resize, paste, …) needs no work:
                // the next `draw` reads the new size and repaints.
                _ => {}
            }
        } else {
            // Tick: reload any stage file / audit line that changed on disk.
            app.poll_refresh();
        }
    }
}

/// Handle one key. Returns `true` when the user asked to quit.
///
/// Global keys (quit, panel switch, help) are handled here; everything else is
/// forwarded to the active panel via [`App::handle_key`], which is where the
/// dispatch-backed actions live.
fn handle_key(app: &mut App, key: KeyEvent) -> bool {
    // Ctrl-C always quits, even mid-overlay.
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return true;
    }

    if app.context_menu.is_some() {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => app.context_menu = None,
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some(m) = &mut app.context_menu {
                    m.selected = m.selected.saturating_sub(1);
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(m) = &mut app.context_menu {
                    m.selected = (m.selected + 1).min(m.actions.len().saturating_sub(1));
                }
            }
            KeyCode::Enter => {
                let i = app.context_menu.as_ref().unwrap().selected;
                app.run_context_action(i);
            }
            _ => {}
        }
        return false;
    }
    if app.mail_target_menu.is_some() {
        match key.code {
            KeyCode::Esc => app.mail_target_menu = None,
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some((_, _, _, i)) = &mut app.mail_target_menu {
                    *i = i.saturating_sub(1);
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some((_, _, choices, i)) = &mut app.mail_target_menu {
                    *i = (*i + 1).min(choices.len().saturating_sub(1));
                }
            }
            KeyCode::Enter => {
                if let Some((_, _, choices, i)) = app.mail_target_menu.take() {
                    if let Some((_, address)) = choices.get(i) {
                        app.open_mail_to(address.clone());
                    }
                }
            }
            _ => {}
        }
        return false;
    }
    // The help overlay swallows keys until dismissed (pi-style modal overlay).
    if app.help_open {
        match key.code {
            KeyCode::Char('?') | KeyCode::Esc | KeyCode::Char('q') => app.help_open = false,
            _ => {}
        }
        return false;
    }

    // The log-tail overlay is the same modal shape: swallow everything until
    // dismissed. Enter joins Esc/`q` here (unlike help's `?`) since Enter is
    // what opened it — closing on the same key that opens it is the least
    // surprising round trip.
    if app.tail.is_some() {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => app.close_tail(),
            _ => {}
        }
        return false;
    }

    // If a panel has an inline input open (e.g. projects "add"), it consumes
    // text/enter/esc itself — don't let global keys steal them.
    if app.mail_draft.is_some()
        && key.code == KeyCode::Char('p')
        && key.modifiers.contains(KeyModifiers::CONTROL)
    {
        app.sidebar_focused = !app.sidebar_focused;
        return false;
    }
    if app.mail_draft.is_some() && app.sidebar_focused {
        if key.code == KeyCode::Tab || key.code == KeyCode::Esc {
            app.sidebar_focused = false;
            return false;
        }
        if key.code == KeyCode::Enter {
            add_tree_recipient(app, app.sidebar_sel);
            return false;
        }
        if matches!(
            key.code,
            KeyCode::Up | KeyCode::Down | KeyCode::Left | KeyCode::Right | KeyCode::Char('h'|'j'|'k'|'l')
        ) {
            app.handle_sidebar_key(key);
            return false;
        }
        app.sidebar_focused = false;
    }
    if app.input_active() {
        app.handle_key(key);
        return false;
    }
    if key.code == KeyCode::Esc {
        app.sidebar_focused = false;
        app.mail_room_focus = false;
        app.graph.pan_mode = false;
        app.graph.drag = None;
        return false;
    }
    if app.panel == Panel::Home {
        let count = 5 + board::recent_projects(app).len();
        match key.code {
            KeyCode::Char('j' | 'l') | KeyCode::Down | KeyCode::Right => {
                app.home_sel = (app.home_sel + 1).min(count - 1);
                return false;
            }
            KeyCode::Char('k' | 'h') | KeyCode::Up | KeyCode::Left => {
                app.home_sel = app.home_sel.saturating_sub(1);
                return false;
            }
            KeyCode::Home | KeyCode::Char('g') => {
                app.home_sel = 0;
                return false;
            }
            KeyCode::End | KeyCode::Char('G') => {
                app.home_sel = count - 1;
                return false;
            }
            KeyCode::Enter => {
                if app.home_sel < 5 {
                    return handle_key(
                        app,
                        KeyEvent::from(KeyCode::Char(['n', 'p', 'm', 'H', 'L'][app.home_sel])),
                    );
                }
                if let Some(name) = board::recent_projects(app)
                    .get(app.home_sel - 5)
                    .map(|p| p.name.clone())
                {
                    app.select_panel(Panel::Projects);
                    app.sidebar_focused = false;
                    if let Some(i) = app::sorted_project_names(&app.projects)
                        .iter()
                        .position(|n| n == &name)
                    {
                        app.proj_sel = i;
                    }
                }
                return false;
            }
            _ => {}
        }
    }
    if key.code == KeyCode::Char('e')
        && matches!(
            app.panel,
            Panel::Graph | Panel::Session | Panel::Terminals | Panel::Projects
        )
    {
        let hit = if app.sidebar_focused {
            board::Hit::Tree(app.sidebar_sel)
        } else {
            board::Hit::Row(match app.panel {
                Panel::Graph => graphview::selected_index(app),
                Panel::Projects => app.proj_sel,
                _ => app.dag_sel,
            })
        };
        open_context_hit(app, hit, 2, 4);
        return false;
    }
    if !app.sidebar_focused
        && matches!(app.panel, Panel::Session | Panel::Terminals)
        && matches!(key.code, KeyCode::Left | KeyCode::Right)
    {
        app.handle_key(KeyEvent::from(KeyCode::Char(
            if key.code == KeyCode::Left { 'h' } else { 'l' },
        )));
        return false;
    }
    if app.panel == Panel::Graph && !app.sidebar_focused {
        if key.code == KeyCode::Char(' ') {
            if key.kind != KeyEventKind::Repeat {
                app.graph.pan_mode = !app.graph.pan_mode;
            }
            return false;
        }
        if key.code == KeyCode::Esc {
            app.graph.pan_mode = false;
            app.graph.drag = None;
            return false;
        }
    }

    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('p') {
        if app.panel == Panel::Home {
            app.select_panel(Panel::Projects);
            app.sidebar_focused = true;
            return false;
        }
        app.sidebar_focused = !app.sidebar_focused;
        return false;
    }
    let navigation = matches!(
        key.code,
        KeyCode::Tab | KeyCode::BackTab | KeyCode::Char('0'..='9')
    );
    if navigation {
        app.sidebar_focused = false;
    }
    if app.panel != Panel::Home
        && app.sidebar_focused
        && !navigation
        && !matches!(key.code, KeyCode::Char('q' | '?'))
    {
        if key.code == KeyCode::Char('s') {
            open_tree_mail_menu(app, app.sidebar_sel, 2, 4);
        } else {
            app.handle_sidebar_key(key);
        }
        return false;
    }

    if app.panel == Panel::Graph && key.code == KeyCode::Char('s') {
        if let Some(id) = graphview::selected_session_id(app) {
            open_graph_letter(app, &id);
        }
        return false;
    }
    match key.code {
        KeyCode::Char('q') => return true,
        KeyCode::Char('?') => app.help_open = true,
        KeyCode::Tab => app.next_panel(),
        KeyCode::BackTab => app.prev_panel(),
        KeyCode::Char(c @ '0'..='9') => {
            let index = if c == '0' { 9 } else { (c as u8 - b'1') as usize };
            app.select_panel(board::NAV[index].0);
        }
        KeyCode::Char('n') if app.panel == Panel::Home => {
            app.select_panel(Panel::Projects);
            app.handle_key(KeyEvent::from(KeyCode::Char('a')));
        }
        KeyCode::Char('p') if app.panel == Panel::Home => {
            app.sidebar_focused = false;
            app.select_panel(Panel::Projects);
        }
        KeyCode::Char('m') if app.panel == Panel::Home => {
            app.sidebar_focused = false;
            app.select_panel(Panel::Mail);
        }
        KeyCode::Char('H') if app.panel == Panel::Home => {
            app.sidebar_focused = false;
            app.select_panel(Panel::Roster);
        }
        KeyCode::Char('L') if app.panel == Panel::Home => {
            app.sidebar_focused = false;
            app.select_panel(Panel::Log);
        }
        _ => app.handle_key(key),
    }
    false
}

fn handle_paste(app: &mut App, text: &str) {
    if let Some(d) = &mut app.mail_draft {
        if d.submitted {
            return;
        }
        let text = text.replace("\r\n", "\n").replace('\r', "\n");
        let text: String = text
            .chars()
            .filter(|c| {
                !c.is_control() || (*c == '\n' && d.focus == app::MailField::Body) || *c == '\t'
            })
            .collect();
        let target = match d.focus {
            app::MailField::To => &mut d.to,
            app::MailField::Cc => &mut d.cc,
            app::MailField::Subject => &mut d.subject,
            app::MailField::Body => &mut d.body,
        };
        target.insert_str(d.cursor, &text);
        d.cursor += text.len();
    } else if let Some(input) = &mut app.input {
        input.buffer.extend(
            text.chars()
                .map(|c| {
                    if c == '\n' || c == '\r' || c == '\t' {
                        ' '
                    } else {
                        c
                    }
                })
                .filter(|c| !c.is_control()),
        );
    }
}

fn handle_mouse(app: &mut App, area: ratatui::layout::Rect, mouse: MouseEvent) {
    if let Some(m) = &mut app.context_menu {
        let rect = board::target_menu_area(area, m.x, m.y, m.actions.len());
        if mouse.kind == MouseEventKind::ScrollUp {
            m.selected = m.selected.saturating_sub(1);
            return;
        }
        if mouse.kind == MouseEventKind::ScrollDown {
            m.selected = (m.selected + 1).min(m.actions.len().saturating_sub(1));
            return;
        }
        if mouse.kind == MouseEventKind::Down(MouseButton::Left) {
            let inner = board::inner(rect);
            let point = ratatui::layout::Position::new(mouse.column, mouse.row);
            if inner.contains(point) {
                let offset = m
                    .selected
                    .saturating_sub(inner.height.saturating_sub(1) as usize);
                let index = offset + (mouse.row - inner.y) as usize;
                app.run_context_action(index);
            } else {
                app.context_menu = None;
            }
        } else if mouse.kind == MouseEventKind::Down(MouseButton::Right) {
            app.context_menu = None;
        }
        return;
    }
    if app.help_open || app.tail.is_some() {
        if mouse.kind == MouseEventKind::Down(MouseButton::Right) {
            app.help_open = false;
            app.close_tail();
        }
        return;
    }
    if app.mail_draft.is_some() {
        let g = board::composer_geometry(area);
        let point = ratatui::layout::Position::new(mouse.column, mouse.row);
        if g.tree.contains(point) {
            app.sidebar_focused = true;
            if mouse.kind == MouseEventKind::Down(MouseButton::Left)
                && board::inner(g.tree).contains(point)
            {
                let index = board::tree_offset(app, board::inner(g.tree).height)
                    + (mouse.row - board::inner(g.tree).y) as usize;
                if let Some(row) = app.sidebar_rows().get(index).cloned() {
                    app.sidebar_sel = index;
                    match row {
                        app::SidebarRow::Session {
                            rec, past: false, ..
                        } if !app::is_terminal(&rec) && !app::is_done(&rec.state) => {
                            if let Some(p) = rec.petname {
                                app.add_mail_recipient(&format!("self/{p}"));
                            }
                        }
                        app::SidebarRow::Project { folded, .. }
                        | app::SidebarRow::Section { folded, .. }
                        | app::SidebarRow::Past { folded, .. } => {
                            app.handle_sidebar_key(KeyEvent::from(if folded {
                                KeyCode::Right
                            } else {
                                KeyCode::Left
                            }))
                        }
                        _ => {}
                    }
                }
            } else if matches!(
                mouse.kind,
                MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
            ) {
                app.handle_sidebar_key(KeyEvent::from(if mouse.kind == MouseEventKind::ScrollUp {
                    KeyCode::Up
                } else {
                    KeyCode::Down
                }));
            }
            return;
        }
        if mouse.kind == MouseEventKind::Down(MouseButton::Left) && g.to_picker.contains(point) {
            app.focus_mail_field(app::MailField::To);
            return;
        }
        if mouse.kind == MouseEventKind::Down(MouseButton::Left) && g.cc_picker.contains(point) {
            app.focus_mail_field(app::MailField::Cc);
            return;
        }
        if mouse.kind == MouseEventKind::Down(MouseButton::Left) {
            let g = board::composer_geometry(area);
            let point = ratatui::layout::Position::new(mouse.column, mouse.row);
            if g.send.contains(point) {
                app.send_mail_draft();
            } else if g.cancel.contains(point) {
                app.mail_draft = None;
            } else {
                for (r, field) in g.fields {
                    if r.contains(point) {
                        let cursor = board::field_click(
                            app.mail_draft.as_ref().unwrap(),
                            field,
                            r,
                            mouse.column,
                            mouse.row,
                        );
                        app.focus_mail_field(field);
                        if let Some(d) = &mut app.mail_draft {
                            d.cursor = cursor;
                        }
                        break;
                    }
                }
            }
        }
        return;
    }
    if let Some((x, y, choices, index)) = &mut app.mail_target_menu {
        let rect = board::target_menu_area(area, *x, *y, choices.len());
        if matches!(
            mouse.kind,
            MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
        ) {
            *index = if mouse.kind == MouseEventKind::ScrollUp {
                index.saturating_sub(1)
            } else {
                (*index + 1).min(choices.len().saturating_sub(1))
            };
            return;
        }
        if mouse.kind == MouseEventKind::Down(MouseButton::Left) {
            let point = ratatui::layout::Position::new(mouse.column, mouse.row);
            let address = if board::inner(rect).contains(point) {
                choices
                    .get(
                        index.saturating_sub(board::inner(rect).height.saturating_sub(1) as usize)
                            + (mouse.row - rect.y - 1) as usize,
                    )
                    .map(|(_, a)| a.clone())
            } else {
                None
            };
            app.mail_target_menu = None;
            if let Some(a) = address {
                app.open_mail_to(a);
            }
        } else if mouse.kind == MouseEventKind::Down(MouseButton::Right) {
            app.mail_target_menu = None;
        }
        return;
    }
    if app.input_active() {
        return;
    }
    let g = board::page_geometry(area, app);
    let point = ratatui::layout::Position::new(mouse.column, mouse.row);
    if app.panel == Panel::Graph {
        let (canvas, _) = board::body_content(board::inner(g.body));
        match mouse.kind {
            MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
                if canvas.contains(point) && mouse.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                graphview::zoom_at(
                    app,
                    canvas,
                    (mouse.column, mouse.row),
                    if mouse.kind == MouseEventKind::ScrollUp {
                        1
                    } else {
                        -1
                    },
                );
                app.sidebar_focused = false;
                return;
            }
            MouseEventKind::Down(button)
                if canvas.contains(point)
                    && (button == MouseButton::Middle
                        || (button == MouseButton::Left && app.graph.pan_mode)) =>
            {
                let (x, y) = graphview::graph_origin(app, canvas);
                app.graph.drag = Some((mouse.column, mouse.row, x, y));
                app.sidebar_focused = false;
                return;
            }
            // Right-click hit-tests the same camera-transformed card geometry
            // the left click above and render itself use, so the menu opens
            // on the card under the pointer rather than a row counted from
            // the top of the pane. A miss opens nothing.
            MouseEventKind::Down(MouseButton::Right) if canvas.contains(point) => {
                if let Some(i) = graphview::hit_node(canvas, app, mouse.column, mouse.row) {
                    open_context_hit(app, board::Hit::Row(i), mouse.column, mouse.row);
                }
                return;
            }
            MouseEventKind::Drag(_) if app.graph.drag.is_some() => {
                let (sx, sy, ox, oy) = app.graph.drag.unwrap();
                let (w, h) = graphview::graph_extent(app);
                let x = (ox + sx as i32 - mouse.column as i32).max(0);
                let y = (oy + sy as i32 - mouse.row as i32).max(0);
                app.graph.camera.pan = Some((
                    x.min((w - canvas.width as i32).max(0)),
                    y.min((h - canvas.height as i32).max(0)),
                ));
                return;
            }
            MouseEventKind::Up(_) => {
                app.graph.drag = None;
                return;
            }
            MouseEventKind::ScrollUp
            | MouseEventKind::ScrollDown
            | MouseEventKind::ScrollLeft
            | MouseEventKind::ScrollRight
                if canvas.contains(point) =>
            {
                let (mut x, mut y) = graphview::graph_origin(app, canvas);
                let (w, h) = graphview::graph_extent(app);
                let horizontal = mouse.modifiers.contains(KeyModifiers::SHIFT)
                    || matches!(
                        mouse.kind,
                        MouseEventKind::ScrollLeft | MouseEventKind::ScrollRight
                    );
                let forward = matches!(
                    mouse.kind,
                    MouseEventKind::ScrollDown | MouseEventKind::ScrollRight
                );
                let n = if horizontal { &mut x } else { &mut y };
                *n = if forward { *n + 3 } else { *n - 3 };
                app.graph.camera.pan = Some((
                    x.clamp(0, (w - canvas.width as i32).max(0)),
                    y.clamp(0, (h - canvas.height as i32).max(0)),
                ));
                return;
            }
            _ => {}
        }
    }
    if mouse.kind == MouseEventKind::Down(MouseButton::Right) {
        open_context_hit(
            app,
            board::hit(area, app, mouse.column, mouse.row),
            mouse.column,
            mouse.row,
        );
        return;
    }
    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            match board::hit(area, app, mouse.column, mouse.row) {
                board::Hit::Panel(p) => {
                    app.sidebar_focused = false;
                    app.select_panel(p);
                }
                board::Hit::Tree(i) => {
                    app.sidebar_focused = true;
                    if i < app.sidebar_rows().len() {
                        app.sidebar_sel = i;
                        if matches!(app.sidebar_rows()[i], app::SidebarRow::Project { .. })
                            && mouse.column <= g.tree.x + 3
                        {
                            let folded = matches!(
                                app.sidebar_rows()[i],
                                app::SidebarRow::Project { folded: true, .. }
                            );
                            app.handle_sidebar_key(KeyEvent::from(if folded {
                                KeyCode::Right
                            } else {
                                KeyCode::Left
                            }));
                        } else if matches!(
                            app.sidebar_rows()[i],
                            app::SidebarRow::Past { .. } | app::SidebarRow::Section { .. }
                        ) {
                            app.handle_sidebar_key(KeyEvent::from(KeyCode::Enter));
                        } else {
                            app.sidebar_activate(i);
                        }
                    }
                }
                board::Hit::Row(i) => {
                    app.sidebar_focused = false;
                    match app.panel {
                        Panel::Mail if i < app.mail_letters().len() => {
                            app.mail_sel = i;
                            app.mail_scroll = 0;
                            app.mail_room_focus = false;
                        }
                        Panel::Session | Panel::Terminals if i < app.dag_rows().len() => {
                            app.dag_sel = i
                        }
                        Panel::Projects if i < app.projects.len() => app.proj_sel = i,
                        Panel::Roster if i < app.roster_flat_rows().len() => app.roster_sel = i,
                        Panel::Pending if i < app.pending_rows().len() => app.pending_sel = i,
                        Panel::Log if i < app.log.len() => {
                            app.log_sel = i;
                            app.log_scroll = 0;
                        }
                        Panel::Graph => graphview::select_index(app, i),
                        _ => {}
                    }
                }
                board::Hit::Key(k) => {
                    app.sidebar_focused = false;
                    handle_key(app, KeyEvent::from(k));
                }
                board::Hit::Conversation(i) => {
                    app.sidebar_focused = false;
                    app.select_mail_room(i);
                    app.mail_room_focus = true;
                }
                board::Hit::NewProject => {
                    app.sidebar_focused = false;
                    app.select_panel(Panel::Projects);
                    app.handle_key(KeyEvent::from(KeyCode::Char('a')));
                }
                board::Hit::Project(name) => {
                    app.sidebar_focused = false;
                    app.select_panel(Panel::Projects);
                    if let Some(i) = app::sorted_project_names(&app.projects)
                        .iter()
                        .position(|n| n == &name)
                    {
                        app.proj_sel = i;
                    }
                }
                board::Hit::None => {
                    if g.body.contains(point) {
                        app.sidebar_focused = false;
                    }
                }
            }
        }
        MouseEventKind::ScrollUp | MouseEventKind::ScrollDown => {
            let down = mouse.kind == MouseEventKind::ScrollDown;
            if g.tree.contains(point) {
                app.handle_sidebar_key(KeyEvent::from(if down {
                    KeyCode::Down
                } else {
                    KeyCode::Up
                }));
            } else if g.body.contains(point) {
                if app.panel == Panel::Mail {
                    let (content, _) = board::body_content(board::inner(g.body));
                    let (rooms, timeline) = board::conversation_parts(content);
                    if rooms.contains(point) {
                        app.mail_room_focus = true;
                        app.handle_key(KeyEvent::from(if down {
                            KeyCode::Down
                        } else {
                            KeyCode::Up
                        }));
                        return;
                    }
                    app.mail_room_focus = false;
                    let (_, detail) = board::mail_parts(timeline);
                    if detail.contains(point) {
                        app.mail_scroll = if down {
                            app.mail_scroll.saturating_add(3)
                        } else {
                            app.mail_scroll.saturating_sub(3)
                        };
                        return;
                    }
                }
                if app.panel == Panel::Log {
                    let (content, _) = board::body_content(board::inner(g.body));
                    let (_, detail) = eventview::parts(content);
                    if detail.contains(point) {
                        app.handle_key(KeyEvent::from(if down {
                            KeyCode::PageDown
                        } else {
                            KeyCode::PageUp
                        }));
                        return;
                    }
                }
                app.handle_key(KeyEvent::from(if down {
                    KeyCode::Down
                } else {
                    KeyCode::Up
                }));
            }
        }
        _ => {}
    }
}

fn open_context_hit(app: &mut App, hit: board::Hit, x: u16, y: u16) {
    match hit {
        board::Hit::Tree(i) => {
            app.sidebar_sel = i;
            app.sidebar_focused = true;
            match app.sidebar_rows().get(i).cloned() {
                Some(app::SidebarRow::Session { rec, .. }) => {
                    app.open_context_for_session(rec, x, y)
                }
                Some(app::SidebarRow::History { entry, .. }) => {
                    app.open_context_for_history(entry, x, y)
                }
                Some(app::SidebarRow::Project { name, .. })
                | Some(app::SidebarRow::Section { project: name, .. })
                | Some(app::SidebarRow::Past { project: name, .. }) => {
                    app.open_context_for_project(name, x, y)
                }
                _ => {}
            }
        }
        board::Hit::Row(i) if app.panel == Panel::Graph => {
            // Resolve the node `i` names BEFORE selecting it: selecting a card
            // outside the current selection's bridged component re-forms the
            // Focus visible list (the synthetic unanchored root drops out
            // once a real session anchors it), so looking `i` up again
            // afterward can name a different card than the one hit.
            let node = graphview::node_order(app).get(i).cloned();
            graphview::select_index(app, i);
            app.sidebar_focused = false;
            if let Some(node) = node {
                if let Some(id) = &node.session_id {
                    if let Some(rec) = app.merged().into_iter().find(|r| &r.session_id == id) {
                        app.open_context_for_session(rec, x, y);
                    }
                } else if node.kind == graphview::NodeKind::Project {
                    app.open_context_for_project(node.label.clone(), x, y);
                }
            }
        }
        board::Hit::Row(i) if matches!(app.panel, Panel::Session | Panel::Terminals) => {
            if let Some(h) = app.history_selected.clone() {
                app.open_context_for_history(h, x, y);
            } else {
                match app.dag_rows().get(i).cloned() {
                    Some(app::DagRow::Session { rec, .. }) => {
                        app.open_context_for_session(rec, x, y)
                    }
                    Some(app::DagRow::Group { name, .. }) => {
                        app.open_context_for_project(name, x, y)
                    }
                    _ => {}
                }
            }
        }
        board::Hit::Row(i) if app.panel == Panel::Projects => {
            if let Some(name) = app::sorted_project_names(&app.projects).get(i) {
                app.open_context_for_project(name.clone(), x, y);
            }
        }
        board::Hit::Project(name) => app.open_context_for_project(name, x, y),
        _ => {}
    }
}

fn add_tree_recipient(app: &mut App, index: usize) {
    if let Some(app::SidebarRow::Session {
        rec, past: false, ..
    }) = app.sidebar_rows().get(index)
    {
        if !app::is_terminal(rec) && !app::is_done(&rec.state) {
            if let Some(p) = &rec.petname {
                app.add_mail_recipient(&format!("self/{p}"));
            }
        }
    }
}

fn open_graph_letter(app: &mut App, id: &str) {
    let rec = app.merged().into_iter().find(|r| r.session_id == id);
    if let Some(rec) = rec.filter(|r| !app::is_terminal(r) && !app::is_done(&r.state)) {
        if let Some(p) = rec.petname {
            app.open_mail_to(format!("{}/{p}", aoide_storage::display::local_host_name()));
            return;
        }
    }
    app.last_outcome = Some(aoide_protocol::output::Outcome::usage(
        "mail.compose",
        "Select a live agent card with a mailbox.",
    ));
}

fn open_project_mail_menu(app: &mut App, name: String, x: u16, y: u16) {
    let records = app.merged();
    let choices = records
        .iter()
        .filter(|r| !app::is_terminal(r) && !app::is_done(&r.state))
        .filter(|r| {
            aoide_conduct::graph::effective_project_for(r, &records, &app.projects)
                .map(|i| app.projects[i].name.as_str())
                .unwrap_or(app::UNANCHORED)
                == name
        })
        .filter_map(|r| {
            r.petname.as_ref().map(|p| {
                (
                    r.title.clone().unwrap_or_else(|| r.agent.clone()),
                    format!("{}/{p}", aoide_storage::display::local_host_name()),
                )
            })
        })
        .collect::<Vec<_>>();
    if !choices.is_empty() {
        app.mail_target_menu = Some((x, y, choices, 0));
    } else {
        app.last_outcome = Some(aoide_protocol::output::Outcome::usage(
            "mail.compose",
            "No live agents with a mailbox are recorded in this project.",
        ));
    }
}
fn open_tree_mail_menu(app: &mut App, index: usize, x: u16, y: u16) {
    match app.sidebar_rows().get(index) {
        Some(app::SidebarRow::Session {
            rec, past: false, ..
        }) if !app::is_terminal(rec) => {
            if let Some(p) = &rec.petname {
                app.mail_target_menu = Some((
                    x,
                    y,
                    vec![(
                        rec.title.clone().unwrap_or_else(|| rec.agent.clone()),
                        format!("{}/{p}", aoide_storage::display::local_host_name()),
                    )],
                    0,
                ));
            }
        }
        Some(app::SidebarRow::Project { name, .. })
        | Some(app::SidebarRow::Section { project: name, .. }) => {
            open_project_mail_menu(app, name.clone(), x, y)
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aoide_conduct::graph::SessionRecord;

    #[test]
    fn sidebar_focus_does_not_dispatch_body_actions_and_tabs_release_focus() {
        let mut app = App::for_test(vec![], vec![], vec![]);
        app.panel = Panel::Projects;
        app.sidebar_focused = true;
        handle_key(&mut app, KeyEvent::from(KeyCode::Char('a')));
        assert!(app.input.is_none());
        handle_key(&mut app, KeyEvent::from(KeyCode::Tab));
        assert!(!app.sidebar_focused);
    }

    #[test]
    fn mouse_navigation_and_mail_selection_are_non_dispatching() {
        let mut app = App::for_test(vec![], vec![], vec![]);
        let area = ratatui::layout::Rect::new(0, 0, 120, 40);
        let (r, _, _) = board::nav_regions(board::geometry(area, true).nav)
            .into_iter()
            .find(|(_, p, _)| *p == Panel::Projects)
            .unwrap();
        handle_mouse(
            &mut app,
            area,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: r.x,
                row: r.y,
                modifiers: KeyModifiers::NONE,
            },
        );
        assert_eq!(app.panel, Panel::Projects);
        assert!(!app.sidebar_focused);
        assert!(app.last_outcome.is_none());
    }

    #[test]
    fn mail_composer_enter_adds_newline_instead_of_sending() {
        let mut app = App::for_test(vec![], vec![], vec![]);
        app.panel = Panel::Mail;
        app.sidebar_focused = false;
        handle_key(&mut app, KeyEvent::from(KeyCode::Char('n')));
        for c in "self/test".chars() {
            handle_key(&mut app, KeyEvent::from(KeyCode::Char(c)));
        }
        app.focus_mail_field(app::MailField::Body);
        handle_key(&mut app, KeyEvent::from(KeyCode::Char('a')));
        handle_key(&mut app, KeyEvent::from(KeyCode::Enter));
        assert_eq!(app.mail_draft.as_ref().unwrap().body, "a\n");
        assert!(app.last_outcome.is_none());
    }

    #[test]
    fn composer_mouse_and_paste_edit_without_dispatch() {
        let mut app = App::for_test(vec![], vec![], vec![]);
        app.open_mail_to("self/reviewer".into());
        let area = ratatui::layout::Rect::new(0, 0, 90, 30);
        let g = board::composer_geometry(area);
        let rect = g
            .fields
            .iter()
            .find(|(_, f)| *f == app::MailField::Subject)
            .unwrap()
            .0;
        handle_mouse(
            &mut app,
            area,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: rect.x,
                row: rect.y + 1,
                modifiers: KeyModifiers::NONE,
            },
        );
        assert_eq!(
            app.mail_draft.as_ref().unwrap().focus,
            app::MailField::Subject
        );
        handle_paste(&mut app, "Review\u{13} changes");
        assert_eq!(app.mail_draft.as_ref().unwrap().subject, "Review changes");
        assert!(app.last_outcome.is_none());
        let body = g
            .fields
            .iter()
            .find(|(_, f)| *f == app::MailField::Body)
            .unwrap()
            .0;
        handle_mouse(
            &mut app,
            area,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: body.x,
                row: body.y + 1,
                modifiers: KeyModifiers::NONE,
            },
        );
        handle_paste(&mut app, "αβ\r\nsecond line");
        assert_eq!(app.mail_draft.as_ref().unwrap().body, "αβ\nsecond line");
        handle_mouse(
            &mut app,
            area,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: body.x + 1,
                row: body.y + 1,
                modifiers: KeyModifiers::NONE,
            },
        );
        handle_key(&mut app, KeyEvent::from(KeyCode::Char('!')));
        assert_eq!(app.mail_draft.as_ref().unwrap().body, "α!β\nsecond line");
    }

    #[test]
    fn recipient_menu_click_prefills_but_does_not_send() {
        let mut app = App::for_test(vec![], vec![], vec![]);
        app.mail_target_menu = Some((
            4,
            4,
            vec![("Review worker".into(), "self/quiet-fern".into())],
            0,
        ));
        handle_mouse(
            &mut app,
            ratatui::layout::Rect::new(0, 0, 90, 30),
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: 5,
                row: 5,
                modifiers: KeyModifiers::NONE,
            },
        );
        assert!(app.mail_target_menu.is_none());
        assert!(app.mail_draft.as_ref().unwrap().to.ends_with("/quiet-fern"));
        assert!(app.last_outcome.is_none());
    }

    #[test]
    fn composer_render_has_headers_and_fits_small_terminals() {
        let mut app = App::for_test(vec![], vec![], vec![]);
        app.open_mail_to("self/reviewer".into());
        for (w, h) in [(90, 30), (40, 18), (10, 5)] {
            let mut terminal =
                ratatui::Terminal::new(ratatui::backend::TestBackend::new(w, h)).unwrap();
            terminal.draw(|f| board::draw(f, &app)).unwrap();
            if w == 90 {
                let text = terminal
                    .backend()
                    .buffer()
                    .content
                    .iter()
                    .map(|c| c.symbol())
                    .collect::<String>();
                for label in ["From:", "To", "Cc", "Subject", "Message", "Send", "Cancel"] {
                    assert!(text.contains(label), "missing {label}");
                }
            }
        }
    }

    #[test]
    fn ctrl_wheel_zooms_only_inside_graph_canvas() {
        let mut app = App::for_test(vec![], vec![], vec![]);
        app.panel = Panel::Graph;
        let area = ratatui::layout::Rect::new(0, 0, 120, 40);
        let g = board::page_geometry(area, &app);
        let (canvas, _) = board::body_content(board::inner(g.body));
        let event = MouseEvent {
            kind: MouseEventKind::ScrollUp,
            column: canvas.x + 1,
            row: canvas.y + 1,
            modifiers: KeyModifiers::CONTROL,
        };
        handle_mouse(&mut app, area, event);
        assert_eq!(app.graph.camera.zoom, 1);
        handle_mouse(
            &mut app,
            area,
            MouseEvent {
                kind: MouseEventKind::ScrollDown,
                column: canvas.x + 1,
                row: canvas.y + 1,
                ..event
            },
        );
        assert_eq!(app.graph.camera.zoom, 0);
        handle_mouse(
            &mut app,
            area,
            MouseEvent {
                column: 0,
                row: 0,
                ..event
            },
        );
        assert_eq!(app.graph.camera.zoom, 0);
        assert!(app.last_outcome.is_none());
    }

    /// The all/focus switch means the same thing by key and by click, and the
    /// scene's own state — not a render — is what either one moves.
    #[test]
    fn all_and_focus_toggle_the_same_way_by_key_and_by_click() {
        let session = |id: &str, cwd: &str| SessionRecord {
            session_id: id.into(),
            agent: "claude".into(),
            cwd: cwd.into(),
            state: "working".into(),
            ..Default::default()
        };
        let project = |name: &str, path: &str| aoide_conduct::graph::Project {
            name: name.into(),
            path: path.into(),
            ..Default::default()
        };
        let mut app = App::for_test(
            vec![project("one", "/one"), project("two", "/two")],
            vec![session("a", "/one"), session("b", "/two")],
            vec![],
        );
        app.panel = Panel::Graph;
        app.sidebar_focused = false;
        app.sync_graph_scene();

        // Focus is the default and draws only the picked project's own forest.
        assert_eq!(app.graph.view, crate::scene::View::Focus);
        let focused = graphview::node_order(&app).len();
        let whole = graphview::build_model(&app).nodes.len();
        assert!(focused < whole, "{focused} of {whole} nodes in focus");

        handle_key(&mut app, KeyEvent::from(KeyCode::Char('a')));
        assert_eq!(app.graph.view, crate::scene::View::All);
        assert_eq!(graphview::node_order(&app).len(), whole);

        // The action control carries the same key, so the click routes through
        // the identical handler rather than a parallel path.
        let area = ratatui::layout::Rect::new(0, 0, 120, 40);
        let g = board::page_geometry(area, &app);
        let (_, actions) = board::body_content(board::inner(g.body));
        let (rect, key, label) = board::action_regions(actions, Panel::Graph)
            .into_iter()
            .next()
            .expect("the graph panel exposes its view control");
        assert_eq!((key, label), (KeyCode::Char('a'), "All / focus"));
        handle_mouse(
            &mut app,
            area,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: rect.x + 1,
                row: rect.y,
                modifiers: KeyModifiers::NONE,
            },
        );
        assert_eq!(app.graph.view, crate::scene::View::Focus);
        assert_eq!(graphview::node_order(&app).len(), focused);
        assert!(
            app.last_outcome.is_none(),
            "a view choice dispatches nothing"
        );
    }

    /// A click on a card selects exactly the card the camera painted there —
    /// the scene's selection is an id, so the keyboard agrees immediately.
    #[test]
    fn a_click_on_a_card_selects_the_same_node_the_keyboard_would() {
        let mut app = App::for_test(
            vec![],
            vec![
                SessionRecord {
                    session_id: "parent".into(),
                    agent: "claude".into(),
                    cwd: "/x".into(),
                    state: "working".into(),
                    ..Default::default()
                },
                SessionRecord {
                    session_id: "child".into(),
                    agent: "claude".into(),
                    cwd: "/x".into(),
                    state: "idle".into(),
                    parent_session_id: Some("parent".into()),
                    ..Default::default()
                },
            ],
            vec![],
        );
        app.panel = Panel::Graph;
        app.sidebar_focused = false;
        app.sync_graph_scene();
        graphview::select_index(&mut app, 0);

        let area = ratatui::layout::Rect::new(0, 0, 120, 40);
        let g = board::page_geometry(area, &app);
        let (canvas, _) = board::body_content(board::inner(g.body));
        // Walk the canvas for the first cell that hits a card other than the
        // selected one, then click it.
        let target = (canvas.y..canvas.bottom())
            .flat_map(|y| (canvas.x..canvas.right()).map(move |x| (x, y)))
            .find(|&(x, y)| graphview::hit_node(canvas, &app, x, y).is_some_and(|i| i != 0))
            .expect("a second card is on screen");
        let expected = graphview::hit_node(canvas, &app, target.0, target.1).unwrap();
        let expected_id = graphview::node_order(&app)[expected].id.clone();
        handle_mouse(
            &mut app,
            area,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: target.0,
                row: target.1,
                modifiers: KeyModifiers::NONE,
            },
        );
        // The id is what moved — under Focus the visible list re-forms around
        // the newly picked card, so an index would name a different node.
        assert_eq!(app.graph.selected, expected_id);
        assert_eq!(
            graphview::node_order(&app)[graphview::selected_index(&app)].id,
            expected_id
        );
        assert!(!app.sidebar_focused);
        assert!(app.last_outcome.is_none());
    }

    /// A right-click opens the actions menu for the card under the pointer,
    /// not a row counted from the top of the pane -- the same camera-hit-test
    /// the left click above uses, and the menu anchors at the click itself.
    #[test]
    fn a_right_click_on_a_card_opens_its_own_context_menu() {
        let mut app = App::for_test(
            vec![],
            vec![
                SessionRecord {
                    session_id: "parent".into(),
                    agent: "claude".into(),
                    cwd: "/x".into(),
                    state: "working".into(),
                    ..Default::default()
                },
                SessionRecord {
                    session_id: "child".into(),
                    agent: "claude".into(),
                    cwd: "/x".into(),
                    state: "idle".into(),
                    parent_session_id: Some("parent".into()),
                    ..Default::default()
                },
            ],
            vec![],
        );
        app.panel = Panel::Graph;
        app.sidebar_focused = true;
        app.sync_graph_scene();
        graphview::select_index(&mut app, 0);

        let area = ratatui::layout::Rect::new(0, 0, 120, 40);
        let g = board::page_geometry(area, &app);
        let (canvas, _) = board::body_content(board::inner(g.body));
        let target = (canvas.y..canvas.bottom())
            .flat_map(|y| (canvas.x..canvas.right()).map(move |x| (x, y)))
            .find(|&(x, y)| graphview::hit_node(canvas, &app, x, y).is_some_and(|i| i != 0))
            .expect("a second card is on screen");
        let expected = graphview::hit_node(canvas, &app, target.0, target.1).unwrap();
        let expected_id = graphview::node_order(&app)[expected].id.clone();
        let expected_session = graphview::node_order(&app)[expected]
            .session_id
            .clone()
            .expect("the second card is a session");

        handle_mouse(
            &mut app,
            area,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Right),
                column: target.0,
                row: target.1,
                modifiers: KeyModifiers::NONE,
            },
        );

        assert_eq!(
            app.graph.selected, expected_id,
            "the click selects the card it hit"
        );
        assert!(!app.sidebar_focused);
        let menu = app
            .context_menu
            .as_ref()
            .expect("a menu opened on the hit card");
        assert_eq!((menu.x, menu.y), target, "the menu anchors at the click");
        match &menu.target {
            app::ContextTarget::Session(rec) => assert_eq!(rec.session_id, expected_session),
            other => panic!("expected the clicked session, got {other:?}"),
        }
    }

    /// A right-click that misses every card opens nothing, rather than
    /// resolving to an unrelated row.
    #[test]
    fn a_right_click_on_empty_canvas_opens_no_menu() {
        let mut app = App::for_test(
            vec![],
            vec![SessionRecord {
                session_id: "solo".into(),
                agent: "claude".into(),
                cwd: "/x".into(),
                state: "working".into(),
                ..Default::default()
            }],
            vec![],
        );
        app.panel = Panel::Graph;
        app.sync_graph_scene();

        let area = ratatui::layout::Rect::new(0, 0, 120, 40);
        let g = board::page_geometry(area, &app);
        let (canvas, _) = board::body_content(board::inner(g.body));
        let empty = (canvas.y..canvas.bottom())
            .flat_map(|y| (canvas.x..canvas.right()).map(move |x| (x, y)))
            .find(|&(x, y)| graphview::hit_node(canvas, &app, x, y).is_none())
            .expect("the padded canvas has room past the one card");

        handle_mouse(
            &mut app,
            area,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Right),
                column: empty.0,
                row: empty.1,
                modifiers: KeyModifiers::NONE,
            },
        );

        assert!(app.context_menu.is_none());
    }

    #[test]
    fn numbers_and_tab_follow_visible_navigation() {
        let mut app = App::for_test(vec![], vec![], vec![]);
        for (index, digit) in "1234567890".chars().enumerate() {
            handle_key(&mut app, KeyEvent::from(KeyCode::Char(digit)));
            assert_eq!(app.panel, board::NAV[index].0);
            handle_key(&mut app, KeyEvent::from(KeyCode::Tab));
            assert_eq!(app.panel, board::NAV[(index + 1) % board::NAV.len()].0);
        }
    }

    #[test]
    fn composer_captures_global_shortcuts_and_tabs_without_quitting() {
        let mut app = App::for_test(vec![], vec![], vec![]);
        app.panel = Panel::Mail;
        app.open_mail_to("self/reviewer".into());
        app.focus_mail_field(app::MailField::Body);
        for c in "q?n018".chars() {
            assert!(!handle_key(&mut app, KeyEvent::from(KeyCode::Char(c))));
        }
        assert_eq!(app.mail_draft.as_ref().unwrap().body, "q?n018");
        assert!(!handle_key(&mut app, KeyEvent::from(KeyCode::Tab)));
        assert_eq!(app.mail_draft.as_ref().unwrap().focus, app::MailField::To);
        assert_eq!(app.panel, Panel::Mail);
        assert!(!app.help_open);
        assert!(app.input.is_none());
        assert!(app.last_outcome.is_none());
    }

    #[test]
    fn tree_adds_to_selected_recipient_field_without_replacing_draft() {
        let rec=SessionRecord{session_id:"recipient".into(),agent:"claude".into(),petname:Some("quiet-fern".into()),state:"working".into(),..Default::default()};
        let mut app=App::for_test(vec![],vec![rec],vec![]);app.open_mail_to("self/first".into());
        app.focus_mail_field(app::MailField::Cc);app.focus_mail_field(app::MailField::Body);
        handle_paste(&mut app,"keep this text");
        let area=ratatui::layout::Rect::new(0,0,100,40);let g=board::composer_geometry(area);
        let row=app.sidebar_rows().iter().position(|r|matches!(r,app::SidebarRow::Session{rec,..}if rec.session_id=="recipient")).unwrap();
        let click=MouseEvent{kind:MouseEventKind::Down(MouseButton::Left),column:g.tree.x+3,row:g.tree.y+1+row as u16,modifiers:KeyModifiers::NONE};
        handle_mouse(&mut app,area,click);handle_mouse(&mut app,area,click);
        let d=app.mail_draft.as_ref().unwrap();assert_eq!(d.to,"self/first");assert!(d.cc.ends_with("/quiet-fern"));assert_eq!(d.cc.split(',').count(),1);assert_eq!(d.body,"keep this text");assert!(app.last_outcome.is_none());assert!(!app.sidebar_focused);
    }
    #[test]
    fn vim_home_arrows_and_escape_respect_focus() {
        let mut app=App::for_test(vec![aoide_conduct::graph::Project{name:"demo".into(),path:"/demo".into(),..Default::default()}],vec![],vec![]);app.panel=Panel::Home;
        handle_key(&mut app,KeyEvent::from(KeyCode::Char('j')));assert_eq!(app.home_sel,1);
        handle_key(&mut app,KeyEvent::from(KeyCode::Down));assert_eq!(app.home_sel,2);
        handle_key(&mut app,KeyEvent::from(KeyCode::Enter));assert_eq!(app.panel,Panel::Mail);
        app.sidebar_focused=true;handle_key(&mut app,KeyEvent::from(KeyCode::Esc));assert!(!app.sidebar_focused);
        app.open_context_for_project("demo".into(),2,2);
        handle_key(&mut app,KeyEvent::from(KeyCode::Char('j')));assert_eq!(app.context_menu.as_ref().unwrap().selected,1);
        handle_key(&mut app,KeyEvent::from(KeyCode::Esc));assert!(app.context_menu.is_none());assert!(app.last_outcome.is_none());
    }

    #[test]
    fn composer_ctrl_p_toggles_both_directions_and_escape_returns_to_form() {
        let mut app=App::for_test(vec![],vec![],vec![]);app.open_mail_to("self/test".into());
        let toggle=KeyEvent::new(KeyCode::Char('p'),KeyModifiers::CONTROL);
        handle_key(&mut app,toggle);assert!(app.sidebar_focused);
        handle_key(&mut app,KeyEvent::from(KeyCode::Char('j')));assert!(app.sidebar_focused);assert_eq!(app.mail_draft.as_ref().unwrap().subject,"");
        handle_key(&mut app,toggle);assert!(!app.sidebar_focused);
        handle_key(&mut app,toggle);handle_key(&mut app,KeyEvent::from(KeyCode::Esc));assert!(!app.sidebar_focused);assert!(app.mail_draft.is_some());
    }

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aoide-conductor-lib-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A headless session fixture: `log_path` stamped, the marker
    /// `App::cue_session` branches on.
    fn headless_session(path: &std::path::Path) -> SessionRecord {
        SessionRecord {
            session_id: "s1".into(),
            enduring_agent_id: None,
            project: None,
            agent: "claude".into(),
            window_address: String::new(),
            cwd: "/tmp".into(),
            state: "running".into(),
            started_at: "s1".into(),
            parent_session_id: None,
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
            log_path: Some(path.to_string_lossy().into_owned()),
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
            extra: serde_json::Map::new(),
        }
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::from(code)
    }

    /// The tail overlay is the same modal shape as `help_open` (block right
    /// after it, ~lib.rs:172): Esc, `q`, and Enter (the key that opened it)
    /// all close it, and none of them fall through to quit.
    #[test]
    fn the_tail_overlay_closes_on_esc_q_or_enter() {
        let dir = tmp_dir("close-keys");
        let log = dir.join("s1.log");
        std::fs::write(&log, "hi\n").unwrap();
        let rec = headless_session(&log);

        for close_key in [KeyCode::Esc, KeyCode::Char('q'), KeyCode::Enter] {
            let mut app = App::for_test(Vec::new(), vec![rec.clone()], Vec::new());
            app.open_tail(&rec);
            assert!(app.tail.is_some());

            let quit = handle_key(&mut app, key(close_key));

            assert!(!quit, "closing the tail must not quit the conductor");
            assert!(app.tail.is_none(), "{close_key:?} must close the tail");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every other key is swallowed outright — it must neither close the
    /// overlay nor leak through to the global keymap (panel switches, quit).
    #[test]
    fn an_unrelated_key_is_swallowed_while_the_tail_is_open() {
        let dir = tmp_dir("swallow");
        let log = dir.join("s1.log");
        std::fs::write(&log, "hi\n").unwrap();
        let rec = headless_session(&log);

        let mut app = App::for_test(Vec::new(), vec![rec.clone()], Vec::new());
        app.open_tail(&rec);
        let panel_before = app.panel;

        let quit = handle_key(&mut app, key(KeyCode::Char('j')));

        assert!(!quit);
        assert!(
            app.tail.is_some(),
            "an unrelated key must not close the tail"
        );
        assert_eq!(
            app.panel, panel_before,
            "global keys must not leak through the modal"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Ctrl-C's "always quits" rule (checked before either modal block) must
    /// still win while the tail overlay is open.
    #[test]
    fn ctrl_c_still_quits_with_the_tail_open() {
        let dir = tmp_dir("ctrl-c");
        let log = dir.join("s1.log");
        std::fs::write(&log, "hi\n").unwrap();
        let rec = headless_session(&log);

        let mut app = App::for_test(Vec::new(), vec![rec.clone()], Vec::new());
        app.open_tail(&rec);

        let mut ev = key(KeyCode::Char('c'));
        ev.modifiers = KeyModifiers::CONTROL;
        let quit = handle_key(&mut app, ev);

        assert!(quit, "Ctrl-C must quit even mid-overlay");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
