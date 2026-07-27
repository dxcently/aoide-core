//! `aoide baton` — the conductor's interactive terminal frontend over the trunk.
//!
//! One rule governs this whole module: the baton is a FRONTEND, never a second
//! implementation. Every action is `dispatch::dispatch(Invocation { door:
//! Door::Cli, .. })` — so the single audit log records baton actions exactly
//! like a typed command, and the two-doors-one-schema contract holds. Reads reuse
//! the pure graph functions ([`crate::graph::render`], [`build_graph`],
//! [`merged_sessions`]) and load the stage files directly. Nothing here parses
//! or re-derives a command; the panels only compose calls and paint results.
//!
//! The shape is pi's frontend/core split rendered in a terminal:
//!   * [`app::App`] is the core — live state (projects/sessions/hooks loaded
//!     from the stage tree), the audit tail, panel selection, and the last
//!     [`Outcome`](crate::output::Outcome) from a dispatched action. It owns no
//!     drawing.
//!   * [`render`] is the compositor — a hand-rolled DIFFERENTIAL renderer
//!     (keep the last frame, repaint only from the first changed line down),
//!     wrapping each frame in synchronized-output so a resize never tears.
//!   * [`components`]/[`panels`] are pure: `Component::render(width) ->
//!     Vec<String>`. Given the same state they return the same lines, so every
//!     panel is unit-testable without a terminal.
//!
//! The event stream is the audit log (pi's flat event feed): the LOG panel
//! tails it. Live state is stage-file mtimes, polled each tick (~500 ms via the
//! crossterm poll timeout); a changed mtime reloads that file. There is no
//! watcher, no async runtime — one thread, one loop.
//!
//! Terminal restoration is belt-and-braces: [`TermGuard`]'s `Drop` leaves the
//! alternate screen and disables raw mode, and a panic hook does the same
//! before printing the panic — so no exit path (clean quit, `?`, or a panic
//! deep in a panel) can leave the tty wedged.
//!
//! ── Try it without a live desktop ──────────────────────────────────────────
//! The whole thing honours `$AOIDE_STAGE_DIR` and `$AOIDE_AUDIT_LOG`, so a
//! throwaway tempdir is a full test rig. Seed one and launch:
//!
//! ```sh
//! export AOIDE_STAGE_DIR=$(mktemp -d) AOIDE_AUDIT_LOG=$AOIDE_STAGE_DIR/log
//! pkgs/aoide/tests/fixtures/seed.sh "$AOIDE_STAGE_DIR"
//! aoide baton      # 1-4/Tab switch panels, j/k select, ? help, q quit
//! ```

pub mod app;
pub mod components;
pub mod panels;
pub mod render;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::{cursor, execute};
use std::io::{self, Write};
use std::time::Duration;

use app::{App, Panel};

/// How long each `event::poll` waits before we tick: the mtime-poll cadence.
const TICK: Duration = Duration::from_millis(500);

/// RAII terminal restoration. Constructing it enters raw mode + the alternate
/// screen; dropping it (clean quit OR unwind) leaves both. Paired with the
/// panic hook below, no exit path leaves the terminal in raw/alt state.
struct TermGuard;

impl TermGuard {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut out = io::stdout();
        execute!(out, EnterAlternateScreen, cursor::Hide)?;
        Ok(TermGuard)
    }
}

impl Drop for TermGuard {
    fn drop(&mut self) {
        // Best-effort on every field: a failed leave must not mask the reason we
        // are exiting, so errors are swallowed here (the process is going down).
        let mut out = io::stdout();
        let _ = execute!(out, cursor::Show, LeaveAlternateScreen);
        let _ = disable_raw_mode();
        let _ = out.flush();
    }
}

/// Install a panic hook that restores the terminal BEFORE the default hook
/// prints the panic message — otherwise the backtrace lands on the alternate
/// screen and vanishes when we leave it. Chains the previous hook.
fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let mut out = io::stdout();
        let _ = execute!(out, cursor::Show, LeaveAlternateScreen);
        let _ = disable_raw_mode();
        let _ = out.flush();
        prev(info);
    }));
}

/// Run the interactive baton to completion. Returns `Ok(())` on a clean quit.
///
/// The dispatch that records the launch has already run (lib.rs); here we set
/// up the terminal, build the app from the stage tree, and drive the loop.
pub fn run() -> io::Result<()> {
    install_panic_hook();
    let _guard = TermGuard::enter()?;

    let mut app = App::load();
    let mut renderer = render::Renderer::new();
    let mut out = io::stdout();

    // First paint: force a full frame so the whole screen is ours.
    let (mut cols, mut rows) = crossterm::terminal::size().unwrap_or((80, 24));
    renderer.paint(&mut out, &app.frame(cols, rows), true)?;

    loop {
        // Poll for a key with the tick timeout; a timeout is our "tick" — check
        // the stage-file mtimes and the audit tail for changes.
        let dirty_state = if event::poll(TICK)? {
            match event::read()? {
                Event::Key(key) => {
                    if handle_key(&mut app, key) {
                        return Ok(()); // quit requested
                    }
                    true
                }
                Event::Resize(w, h) => {
                    cols = w;
                    rows = h;
                    // A resize invalidates the diff base: force a full repaint.
                    renderer.paint(&mut out, &app.frame(cols, rows), true)?;
                    false
                }
                _ => false,
            }
        } else {
            // Tick: reload any stage file / audit line that changed on disk.
            app.poll_refresh()
        };

        if dirty_state {
            renderer.paint(&mut out, &app.frame(cols, rows), false)?;
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
        KeyCode::Char('1') => app.select_panel(Panel::Dag),
        KeyCode::Char('2') => app.select_panel(Panel::Projects),
        KeyCode::Char('3') => app.select_panel(Panel::Log),
        KeyCode::Char('4') => app.select_panel(Panel::Status),
        _ => app.handle_key(key),
    }
    false
}
