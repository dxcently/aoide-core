# aoide-conductor

`aoide conductor` — the interactive terminal frontend over the trunk: a
ratatui/crossterm TUI with five panels (DAG, SESSIONS, PROJECTS, LOG,
STATUS). Core, never `lyra` — pure Rust, no system-closure weight, and
conducting orchestration is Aoide's core identity (root `AGENTS.md`).

## Named seams (what it exposes)

- `app::App` — live state (projects/sessions/hooks from the stage tree),
  audit tail, panel/node selection, the last dispatched `Outcome`. Draws
  nothing.
- `ui` — pure `draw(frame, area, &App)` view functions per panel, testable
  with a `TestBackend`.
- `graphview` — DAG layout + drawing.
- `theme` — palette → `Style`, glyph vocabulary, small pure formatters.
- `logtail` — the log-tail overlay for headless-session detail.
- `commands` — this crate's one CLI verb, `conductor`.

## What it consumes

`aoide-protocol`, `aoide-conduct` (`build_graph`/`merged_sessions`/
`anchor_for` — reused, never re-derived), `aoide-storage`. Reads stage files
directly for live state; does not depend on `aoide-server`.

## How it composes

Only `cli` depends on it — `conductor` never ships in `lyra`. **The one
rule**: it is a FRONTEND, never a second implementation. Every action
dispatches through `dispatch::dispatch(Invocation { door: Door::Cli, .. })`
via a dependency-injected `DispatchFn` (Phase 6a's DI seam) so the single
audit log records conductor actions exactly like a typed command — nothing
here parses or re-derives a command.
