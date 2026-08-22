# aoide-conduct

Aoide's session core: the PTY multiplexer (`aoide conduct`), the session DAG
(`aoide graph`), Claude-Code hook plumbing, and liveness reaping. Makes
every terminal a tracked, conductable session (root `AGENTS.md`, "Conducting
— aoide's headline"). Core, never `lyra` — headless-safe by construction.

## Named seams (what it exposes)

- `graph` — the session DAG: build/merge/send/spawn/wrap, `normalize_addr`
  (widened to `pub` at P-A1 so `screen` could reach it without duplicating
  it), `SessionRecord`/`SessionsFile`/`load_stage`/`write_stage`. `graph
  send` gained `--to <target>` (messaging plan P-C3, mutually exclusive
  with `--id`): resolves via `aoide_storage::addr::resolve` against local
  sessions + registered peers — a LOCAL match re-drives the exact `--id`
  path unchanged, a REMOTE match (`peer/<query>`, resolved against that
  peer's CACHED graph, never a live pull) delivers over A2A `message/send`
  instead, gated entirely on the RECEIVING peer's side (this door's own
  `--yes`/pending/autogate machinery is a local-socket concept and does not
  apply to a remote delivery).
- `reap` — liveness reaping (`aoide graph reap`), sweeping sessions a
  `SIGKILL`'d terminal could never mark `done`.
- `shellbridge`, `herald` — files only; their CLI verbs (registry lines)
  moved to `lyra` at P-A2, but both stay resident here (see charter smudge
  below).
- `commands` — this crate's CLI verbs: `graph *` (15 paths), `conduct`,
  `hooks install`, `who`.
- `who` — `aoide who [filter] [--json] [--all]` (`graph/who.rs`): live
  presence over this box's own sessions plus every registered peer,
  probed in parallel on each invocation (messaging workstream C2). A
  PROJECTION, never a store — it never writes `state/peer-cache/`;
  `build_graph`'s own fold (`doc.rs`) owns that file.

## What it consumes

`aoide-protocol`, `aoide-storage`, `aoide-client` (`who`'s live per-peer
probe calls `aoide_client::commands::pull_peer_live` — the peer-pull
transport `peer pull` itself uses, workstream C2; `graph send --to`'s
remote branch calls `aoide_client::commands::send_message_to_peer`,
workstream C3; see `client`'s own README for why that edge stays).

## How it composes

`screen`, `server`, `conductor`, `cli`, and `lyra` all depend on it.
**Charter smudge**: `shellbridge.rs`/`herald.rs` stay as FILES here even
though their CLI verbs moved to `lyra` — `permit.rs` publishes summons
through `herald`, and `conductor/ui.rs` reads the socket path `shellbridge`
owns, so both are entangled with core
(`docs/architecture/PACKAGE-LAYOUT.md`, "Charter exceptions").
