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
//!   * [`graphview`] lays out and draws the visual DAG; [`theme`] carries the
//!     palette → `Style`, the glyph vocabulary, and the small pure formatters.
//!
//! The seven panels: DAG (the visual graph), SESSION (the terminal roster),
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
pub mod commands;
pub mod graphview;
pub mod logtail;
pub mod theme;
pub mod ui;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
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
        execute!(out, EnterAlternateScreen)?;
        Ok(TermGuard)
    }
}

impl Drop for TermGuard {
    fn drop(&mut self) {
        // Best-effort on every step: a failed leave must not mask the reason we
        // are exiting, so errors are swallowed (the process is going down).
        let mut out = io::stdout();
        let _ = execute!(out, LeaveAlternateScreen);
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
        let _ = execute!(out, LeaveAlternateScreen);
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
                // A press/repeat that `handle_key` reports as a quit ends the
                // loop. The guard short-circuits, so `handle_key` (which mutates
                // `app`) runs only for a real press, never a key release.
                Event::Key(key) if key.kind != KeyEventKind::Release && handle_key(app, key) => {
                    return Ok(())
                }
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
    if app.input_active() {
        app.handle_key(key);
        return false;
    }

    match key.code {
        KeyCode::Char('q') => return true,
        KeyCode::Char('?') => app.help_open = true,
        KeyCode::Tab => app.next_panel(),
        KeyCode::BackTab => app.prev_panel(),
        KeyCode::Char('1') => app.select_panel(Panel::Graph),
        KeyCode::Char('2') => app.select_panel(Panel::Session),
        KeyCode::Char('3') => app.select_panel(Panel::Projects),
        KeyCode::Char('4') => app.select_panel(Panel::Log),
        KeyCode::Char('5') => app.select_panel(Panel::Status),
        KeyCode::Char('6') => app.select_panel(Panel::Roster),
        KeyCode::Char('7') => app.select_panel(Panel::Pending),
        _ => app.handle_key(key),
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use aoide_conduct::graph::SessionRecord;

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
        assert!(app.tail.is_some(), "an unrelated key must not close the tail");
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
