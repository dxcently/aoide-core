# aoide-conduct

Aoide's session core: the PTY multiplexer (`aoide conduct`), the session DAG
(`aoide graph`), Claude-Code hook plumbing, and liveness reaping. Makes
every terminal a tracked, conductable session (root `AGENTS.md`, "Conducting
— aoide's headline"). Core, never `lyra` — headless-safe by construction.

## Named seams (what it exposes)

- `graph` — the session DAG: build/merge/send/spawn/wrap, `normalize_addr`
  (widened to `pub` at P-A1 so `screen` could reach it without duplicating
  it), `SessionRecord`/`SessionsFile`/`load_stage`/`write_stage`.
- `reap` — liveness reaping (`aoide graph reap`), sweeping sessions a
  `SIGKILL`'d terminal could never mark `done`.
- `shellbridge`, `herald` — files only; their CLI verbs (registry lines)
  moved to `lyra` at P-A2, but both stay resident here (see charter smudge
  below).
- `commands` — this crate's CLI verbs: `graph *` (15 paths), `conduct`,
  `hooks install`.

## What it consumes

`aoide-protocol`, `aoide-storage`, `aoide-client` (for the planned `who`
presence verb's peer-pull transport — workstream C2, not yet implemented;
see `client`'s own README for why that edge stays).

## How it composes

`screen`, `server`, `conductor`, `cli`, and `lyra` all depend on it.
**Charter smudge**: `shellbridge.rs`/`herald.rs` stay as FILES here even
though their CLI verbs moved to `lyra` — `permit.rs` publishes summons
through `herald`, and `conductor/ui.rs` reads the socket path `shellbridge`
owns, so both are entangled with core
(`docs/architecture/PACKAGE-LAYOUT.md`, "Charter exceptions").
