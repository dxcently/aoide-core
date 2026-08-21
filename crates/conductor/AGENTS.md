# AGENTS.md — aoide-conductor

## Invariants

- **Frontend only — never a second implementation.** Every action the TUI
  performs is `dispatch::dispatch(Invocation { door: Door::Cli, .. })`
  through the injected `DispatchFn`. Adding logic here that computes an
  outcome instead of dispatching for one breaks the "two doors, one schema"
  contract — the conductor would drift from what the CLI/MCP doors do.
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

## Extension points

- **A new panel** adds a `ui` draw function + a `graphview`/`theme` helper
  as needed, wired into `app::App`'s panel enum.
- **A new dispatched action** is a normal `Invocation` built and passed to
  the injected `DispatchFn` — never a bespoke code path.

## Docs update required in the same commit

- This `README.md` when a panel, seam, or the DI contract changes.
- `pkgs/aoide/crates/AGENTS.md` for cross-crate invariants — not restated
  here.
