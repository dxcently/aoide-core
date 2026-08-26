# aoide-upkeep

Mechanical integrity, the WORKING-tree half. `nix flake check` polices the
committed tree; this crate's one command, `aoide soundcheck`, polices whatever
that structurally can't see — gitignored or merely-uncommitted state
(`result`, `state/`, a stray file at repo root). Report-only, forever — it
never moves, deletes, formats, or repairs anything.

## Named seams (what it exposes)

- `scan` — the individual checks `soundcheck` runs.
- `commands` — this crate's one CLI command, `soundcheck` (registration +
  finding-report format).

## What it consumes

`aoide-protocol`, `aoide-storage`, `aoide-test-support` (dev-dependency).

## How it composes

Only `cli` depends on it. Its own crate rather than a stretch of
`aoide-storage`'s "durable session data" charter — repo hygiene is a
distinct concern (one-package-one-charter,
`docs/architecture/PACKAGE-LAYOUT.md`).
