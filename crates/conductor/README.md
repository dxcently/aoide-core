# aoide-conductor

`aoide conductor` — the interactive terminal frontend over the trunk: a
ratatui/crossterm TUI with six panels (DAG, SESSIONS, PROJECTS, LOG,
STATUS, ROSTER). Core, never `lyra` — pure Rust, no system-closure weight,
and conducting orchestration is Aoide's core identity (root `AGENTS.md`).

## Named seams (what it exposes)

- `app::App` — live state (projects/sessions/hooks from the stage tree),
  audit tail, panel/node selection, the last dispatched `Outcome`, the
  ROSTER panel's throttled `who` cache. Draws nothing.
- `ui` — pure `draw(frame, area, &App)` view functions per panel, testable
  with a `TestBackend`.
- `graphview` — DAG layout + drawing.
- `theme` — palette → `Style`, glyph vocabulary, small pure formatters.
- `logtail` — the log-tail overlay for headless-session detail.
- `commands` — this crate's one CLI verb, `conductor`.

## ROSTER: presence over this box + every registered peer (P-C4)

Read-only. Rows are `who --json`'s `Outcome.data`, dispatched through the
same injected `DispatchFn` as every other action — never re-derived —
parsed into `App::roster_nodes()` (local box first, then peers, exactly
`who`'s own order). Node glyphs (`●`/`◐`/`○` — online/unreachable/
never-pulled) match `who`'s own Unicode-roster vocabulary
(`conduct/src/graph/who.rs`'s private `glyph` helper — same three glyphs,
independently drawn here since that helper isn't public); session glyphs
reuse the conductor's existing musical-note set
(`theme::state_glyph`) since `who` classifies sessions off the identical
state vocabulary the SESSIONS panel already reads.

`who` performs a LIVE network probe of every registered peer (~2s/peer,
parallel) on every invocation, so this pane throttles: it re-dispatches at
most every ~15s while VISIBLE, never on every ~500ms tick. Switching into
the pane with a stale cache fires one immediate fetch; `r` forces one
regardless of the throttle window. The dispatch itself runs on its own
`std::thread` (mirroring `who`'s own internal `probe_peers` pattern) and
reports back over an `mpsc` channel the tick loop polls without blocking —
the one dispatch in this crate that does not go through the synchronous
`App::dispatch` (which every mutating action uses), because `who` never
mutates anything and its live probes would otherwise freeze the tick loop
for the probe's duration.

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
