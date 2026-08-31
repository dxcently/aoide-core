# aoide-upkeep

Mechanical integrity, the WORKING-tree half. `nix flake check` polices the
committed tree; this crate polices whatever that structurally can't see —
gitignored or merely-uncommitted state (`result`, `state/`, a stray file at
repo root, an untracked `.nix` file no flake check was ever handed). Two
faces of the same charter: `aoide soundcheck`, a human/agent-invoked report,
and the check lane (`checklane`), the same gap wired into the agent LOOP
itself via `aoide session hook`'s SessionStart/Stop events. Report-only,
forever — neither ever moves, deletes, formats, or repairs anything.

## Named seams (what it exposes)

- `scan` — the individual checks `soundcheck` runs.
- `commands` — this crate's CLI command, `soundcheck` (registration +
  finding-report format).
- `checklane` — `on_session_start`/`on_stop`/`on_prompt_submit`, the three
  hook-fired entry points `aoide-conduct`'s `session hook` calls; runs the
  operator-configured verify command (`aoide_storage::config::Upkeep::
  verify_command`) plus an untracked-`.nix` scan, and reports only what's new
  since the last call for the same session id. `on_stop` never returns a
  note directly — Stop's own stdout never reaches the model — it persists
  the rendered delta as a PENDING note that `on_prompt_submit` (or a settled
  `on_session_start`) drains at the next event that does.

## What it consumes

`aoide-protocol`, `aoide-storage`, `aoide-test-support` (dev-dependency).

## How it composes

`cli` depends on it for `soundcheck`; `conduct` depends on it for
`checklane`, called from the hook door — the one place outside `cli` that
reaches into this crate, since the check lane's TRIGGER is a session-hook
event, not a CLI invocation. Its own crate rather than a stretch of
`aoide-storage`'s "durable session data" charter — repo hygiene is a
distinct concern (one-package-one-charter,
`docs/architecture/PACKAGE-LAYOUT.md`).
