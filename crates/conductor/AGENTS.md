# AGENTS.md — aoide-conductor

## Invariants

- **Frontend only — never a second implementation.** Every action the TUI
  performs is `dispatch::dispatch(Invocation { door: Door::Cli, .. })`
  through the injected `DispatchFn`. Adding logic here that computes an
  outcome instead of dispatching for one breaks the "three doors, one
  schema" contract — the conductor would drift from what the CLI/MCP/A2A
  doors do.
- **The DI seam is one-way.** `App` takes a `DispatchFn` fn-pointer
  parameter rather than calling a trunk's assembled registry directly — this
  crate must never depend on `cli` (or `lyra`) to get one; the app crate
  supplies it at construction.
- **`ui` stays pure.** `draw(frame, area, &App)` functions take `&App` and
  paint; they never mutate state or dispatch — that discipline is what
  makes every panel `TestBackend`-testable.
- **Terminal restoration is belt-and-braces.** Any new exit path (a new
  keybind, a new panic site) must still route through `TermGuard`'s `Drop`
  or the panic hook — never leave the tty in raw/alternate-screen mode.
- **Core, never lyra.** No dependency here may pull in wayland/image/song —
  that would contradict "conducting is core identity, painting is lyra's."
- **Two stage roots, never merged (command-defrag S1, 2026-08-27).**
  `App::stage` (`aoide_storage::fs::conducting_stage_dir`, `state/stage/`)
  is for projects/sessions/hooks/graph; `App::rice_stage`
  (`aoide_storage::fs::stage_dir`, `song/stage/`) is for `livery.json` only
  (the STATUS panel's palette). A new panel that reads a CONDUCTING file
  uses `App::stage`; one that reads rice/paint state uses `App::rice_stage`.
  They resolve to the SAME directory only under an `$AOIDE_STAGE_DIR`
  override (every test here sets one) — don't collapse them back to one
  `dir` variable "for simplicity," that reintroduces the coupling the
  storage-crate split exists to remove.
- **A keybind is scoped to its own panel's `handle_*_key` handler — a
  letter used on one panel is free to mean something else on another
  (P-D8: `r` = resurrect on PROJECTS, `r` = force-refresh on ROSTER, two
  different handlers, never a collision).** Don't chase "one global keymap"
  consistency across panels; check only the ONE handler a new binding
  lands in for a clash, and note in the handler's own comment which other
  panel reuses the same letter and why that's still safe.

## Extension points

- **A new panel** adds a `ui` draw function + a `graphview`/`theme` helper
  as needed, wired into `app::App`'s panel enum.
- **A new dispatched action** is a normal `Invocation` built and passed to
  the injected `DispatchFn` — never a bespoke code path.
- **A new project-scoped action** (PROJECTS panel: `a`/`d`/`r` today) reads
  the focused row via `sorted_project_names(&self.projects).get(self.
  proj_sel)`, the same resolution every existing binding in
  `handle_projects_key` uses — never a second way to find "the project
  under the cursor."
- **A project spans several roots** (`Project::roots()`, path first). A
  PROJECTS row stays ONE selectable multi-line `ListItem` per project no
  matter how many roots it has — `proj_sel` indexes projects, so a new root
  is a new line inside the existing item, never a new row. The SESSION
  panel's DAG group header deliberately shows only a project's first root
  (D6 of the multi-root-projects lane) — extra roots are the PROJECTS
  panel's job alone; do not duplicate them into the DAG header, which has
  no row for them in `dag_rows`.

## Docs update required in the same commit

- This `README.md` when a panel, seam, or the DI contract changes.
- `pkgs/aoide/crates/AGENTS.md` for cross-crate invariants — not restated
  here.
