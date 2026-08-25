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
  `Peer` carries two independent, opposite-direction credential fields:
  `tokenFile` (inbound — what a peer presents TO US, read from a local
  file) and `bearerSecret` (outbound — what WE present TO a peer, a
  secrets-broker secret NAME resolved fresh at request time by
  `aoide-client`, task #84). Both are optional and independently settable
  via `peer add`; neither implies the other. `hub` (P-D5,
  `docs/architecture/AOIDED.md`) marks AT MOST ONE registered peer as the
  standing orchestrator address resolution falls back to — additive,
  `#[serde(default)]`, omitted from the wire when `false`
  (`SessionRecord::headless`'s precedent, `records.rs`). `set_hub`/
  `clear_hub` hold the "at most one" and idempotence invariants; nothing
  else writes the field directly.
- `mode` — the staging/declarative mode marker, read by `shellbridge`
  (which stays in `conduct`, see that crate's charter-smudge note).
- `ledger` — the durable, append-only session HISTORY (`state/
  session-ledger.jsonl`, under `fs::state_dir` — real disk, never tmpfs;
  P-D8, `docs/architecture/AOIDED.md`'s "L5"). `sessions.json` is the live
  roster; this is what survives its pruning. One `LedgerEntry` line per
  session, written at the exact moment it leaves the roster (`aoide-conduct`
  owns the single shared call site both `session end` and `reap` route
  through — never two independently-written appenders); every field
  serializes unconditionally, unlike `records::SessionRecord`'s additive
  optional fields, since a ledger line is a closed historical shape, not a
  growing live record. `append_ledger_entry`/`read_ledger` are the only
  I/O; a malformed line is skipped on read rather than failing the file.
  `records::Project.autoResume` and `records::SessionRecord.resumedFrom`
  (both additive/v0-safe, `skip_serializing_if`) are this same phase's
  other two wire-shape additions — the daemon's boot-time auto-resume flag
  and the mark a resurrected session's own record carries.
- `takes` — the per-draft take store behind `rice back`/`rice take`.
- `petname`/`display` — the adjective-noun petname mint and its
  render-time-only display grammar.
- `addr` — the pure address resolver (messaging/presence plan, P-C1),
  inverting `display::session_label`'s grammar to turn a typed query back
  into a local session id or a deferred `peer/<rest>` remote query. Zero
  I/O, agnostic of any call site — `aoide who` (`aoide-conduct::graph::who`,
  C2) and `graph send --to` (`aoide-conduct::graph::send`, C3) both call
  `resolve` directly. `resolve_with_hub` (P-D5) composes it with the hub
  preference (`peer_store::Peer.hub`): a hub-designated peer is offered as
  one last, least-specific `Remote` candidate only on `resolve`'s own
  `NotFound` — every earlier precedence tier is untouched. As of P-D5 it is
  a tested library function only; `graph send --to`'s live call site still
  calls plain `resolve` (the same "land the function, wire a caller later"
  order this module's own tier-5 `peer/<rest>` grammar went through).
- `inbox` — the durable per-host message store (messaging plan P-C6,
  `state/inbox.json`, CONTRACTS.md §4): every message that lands in a local
  session, filed by `conduct`'s `deliver_local` success path — the ONE
  writer that covers a direct `graph send`, a `--to` local resolve, a
  `pending approve` re-drive, AND the A2A server's `do_inject` (which
  reaches `deliver_local` through the same `session_send` door). Capped at
  200, oldest-drop, atomic writes (`herald::LEDGER_CAP`'s fold-and-cap
  precedent). `context` is an opaque `serde_json::Value` passthrough
  reserved for a future Mneme (memory-manager) integration — v0 never reads
  it.
- `commands` — this crate's CLI verbs: `usage` (local token/cost rollup) and
  `inbox list|read|clear` (the store above's CLI surface).

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
