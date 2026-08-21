# aoide-storage

Durable session data + memory persistence: stage-file record shapes, atomic
stage I/O, session/hook upsert ops, the client-side A2A agent roster, the
staging/declarative mode marker, and the peer-federation registry + pull
cache (CONTRACTS.md §7). File-first by decision — no embedded database yet
(`docs/architecture/PACKAGE-LAYOUT.md`, "storage backend" open question).

## Named seams (what it exposes)

- `records`/`fs`/`stage` — the stage-file record shapes and atomic
  read/write I/O every stage consumer (this crate's own `commands`, `conduct`,
  `song`, `conductor`) goes through instead of touching JSON on disk directly.
- `session` — pure session/hook upsert operations.
- `a2a_store` — the client-side A2A agent roster.
- `peer_store` — the peer-federation registry + pull cache (CONTRACTS.md §7).
- `mode` — the staging/declarative mode marker, read by `shellbridge`
  (which stays in `conduct`, see that crate's charter-smudge note).
- `takes` — the per-draft take store behind `rice back`/`rice take`.
- `petname`/`display` — the adjective-noun petname mint and its
  render-time-only display grammar.
- `addr` — the pure address resolver (messaging/presence plan, P-C1),
  inverting `display::session_label`'s grammar to turn a typed query back
  into a local session id or a deferred `peer/<rest>` remote query. Zero
  I/O, agnostic of any call site — planned callers are `aoide who` (C2) and
  `graph send --to` (C3), neither wired in yet.
- `commands` — this crate's one CLI verb, `usage` (local token/cost rollup).

## What it consumes

`aoide-protocol` only (plus `aoide-test-support` as a dev-dependency). It is
the second-lowest crate in the DAG — everything that persists state sits
above it.

## How it composes

`client`, `conduct`, `server`, `song`, `conductor`, and both app crates
depend on it for durable state. **Charter smudge**: `takes` and `mode` live
here rather than in a paint-adjacent crate — zero dependency weight, and
`mode` is read by `shellbridge`, which itself stays core-crate-resident in
`conduct` (see `docs/architecture/PACKAGE-LAYOUT.md`, "Charter exceptions").
