# aoide-conductor

`aoide conductor` — the interactive terminal frontend over the trunk: a
ratatui/crossterm TUI with seven panels (DAG, SESSION, PROJECTS, LOG,
STATUS, ROSTER, PENDING). Core, never `lyra` — pure Rust, no system-closure
weight, and conducting orchestration is Aoide's core identity (root
`AGENTS.md`).

## Named seams (what it exposes)

- `app::App` — live state (projects/sessions/hooks from the CONDUCTING stage
  tree, `state/stage/`), audit tail, panel/node selection, the last
  dispatched `Outcome`, the ROSTER panel's throttled `who` cache, the
  PENDING panel's `session pending list` cache. Draws nothing. `App::stage`
  (`state/stage/`, core) and `App::rice_stage` (`song/stage/`, `livery.json`
  only, for the STATUS panel's palette) are two DIFFERENT roots
  (command-defrag lane S1, 2026-08-27) — they coincide only under an
  `$AOIDE_STAGE_DIR` override (every test here sets one), diverging on the
  default production layout.
- `ui` — pure `draw(frame, area, &App)` view functions per panel, testable
  with a `TestBackend`.
- `graphview` — DAG layout + drawing.
- `theme` — palette → `Style`, glyph vocabulary, small pure formatters.
- `logtail` — the log-tail overlay for headless-session detail.
- `commands` — this crate's one CLI command, `conductor`.

## ROSTER: presence over this box + every registered peer (P-C4; selection + compose P-C5)

Rows are `who --json`'s `Outcome.data`, dispatched through the same
injected `DispatchFn` as every other action — never re-derived — parsed
into `App::roster_nodes()` (local box first, then peers, exactly `who`'s
own order), then flattened into `App::roster_flat_rows()` for selection
(one `Vec` is the single source of truth for both render and key handling,
the same shape `App::dag_rows()` uses over the DAG). Node glyphs
(`●`/`◐`/`○` — online/unreachable/never-pulled) match `who`'s own
Unicode-roster vocabulary (`conduct/src/graph/who.rs`'s private `glyph`
helper — same three glyphs, independently drawn here since that helper
isn't public); session glyphs reuse the conductor's existing musical-note
set (`theme::state_glyph`) since `who` classifies sessions off the
identical state vocabulary the SESSION panel already reads.

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

`j`/`k` walk the flattened rows; `s` on a selected SESSION row (P-C5) opens
the existing inline `Input` line editor, pre-labeled with that row's own
display-grammar label, and on submit dispatches `send --to <target>
--yes -- <text>` through `App::dispatch_with_flags` — the same single
dispatch seam, just with flags. `--yes` is a documented no-op for a REMOTE
target (`conduct/src/graph/send.rs::deliver_remote` folds that note
straight into the `Outcome` message, so `App::status_message` surfaces it
same as any other dispatch, no special-casing needed here).

## PENDING: held `send` / A2A entries, approve/deny (P-C5)

Rows are `session pending list --json`'s `Outcome.data`, dispatched through
the same injected `DispatchFn`, parsed into `App::pending_rows()` — never
re-derived: the malformed-entry detection and display-grammar rendering
stay in `conduct::graph::pending`. Unlike ROSTER's `who`, `session pending
list` is a local file read (no network), so there is no throttle and no
background thread: `App::refresh_pending` runs synchronously, called from
`reload_all` (which fires after every dispatch) and from the tick loop
while the pane is visible.

`j`/`k` walk the rows; `a`/`d` approve/deny the selected one. **The
invariant**: `session pending list`'s `id` is the entry's ARRAY POSITION, not
a stable id (`conduct/src/graph/pending.rs`'s module doc) — resolving one
entry shifts every id after it. `App::dispatch` already re-lists via
`reload_all` -> `refresh_pending` synchronously before the next paint, so a
second a/d keypress in the same visit always resolves the row actually on
screen, never a stale index.

## PROJECTS: register/remove/resurrect (P-D8 adds `r`)

Rows are `App::projects` (the live-loaded `projects.json`, already read for
the DAG panel's own anchoring), sorted by name (`sorted_project_names`) for
a stable, deterministic row order independent of file-write order. `j`/`k`
walk the rows; `a` opens the same inline `Input` line editor ROSTER's
compose flow uses to `project add <path>`; `d` dispatches `project
remove <name>` for the row under the cursor; `r` (P-D8,
`docs/architecture/AOIDED.md`'s "L5") dispatches `resurrect --project
<name>` through `App::dispatch_with_flags` — the SAME single dispatch seam
every other action uses, just with the project name riding as a flag
rather than a positional arg (`resurrect` takes no positional args
at all). `r` is unclaimed on this panel (it binds only `j`/`k`/`a`/`d`
otherwise); the ROSTER panel's own `r` = force-refresh is a different
handler, different panel, so the two never collide. All three actions are
no-ops with the cursor on an empty list.

## What it consumes

`aoide-protocol`, `aoide-conduct` (`build_graph`/`merged_sessions`/
`anchor_for` — reused, never re-derived), `aoide-storage`. Reads stage files
directly for live state (`aoide_storage::fs::conducting_stage_dir` for
projects/sessions/hooks/graph, `stage_dir` for `livery.json` — see
`app::App`'s own seam note above); does not depend on `aoide-server`.

## How it composes

Only `cli` depends on it — `conductor` never ships in `lyra`. **The one
rule**: it is a FRONTEND, never a second implementation. Every action
dispatches through `dispatch::dispatch(Invocation { door: Door::Cli, .. })`
via a dependency-injected `DispatchFn` (Phase 6a's DI seam) so the single
audit log records conductor actions exactly like a typed command — nothing
here parses or re-derives a command.
