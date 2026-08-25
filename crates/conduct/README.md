# aoide-conduct

Aoide's session core: the PTY multiplexer (`aoide conduct`), the session DAG
(`aoide graph`), Claude-Code hook plumbing, and liveness reaping. Makes
every terminal a tracked, conductable session (root `AGENTS.md`, "Conducting
— aoide's headline"). Core, never `lyra` — headless-safe by construction.

## Named seams (what it exposes)

- `graph` — the session DAG: build/merge/send/spawn/wrap, `normalize_addr`
  (widened to `pub` at P-A1 so `screen` could reach it without duplicating
  it), `SessionRecord`/`SessionsFile`/`load_stage`/`write_stage`. `--id`
  accepts a bare session id OR the exact `session:<id>` form `graph view
  --json` emits for a node id (a known prefix stripped before matching,
  same discipline `graph focus`/`focus_session` already used) — `graph
  view`'s own emitted contract is unchanged, only what `--id`/`--to` accept
  as input widened; an id with any OTHER prefix still errors as unknown,
  unchanged. `graph send` gained `--to <target>` (messaging plan P-C3, mutually exclusive
  with `--id`): resolves via `aoide_storage::addr::resolve` (itself
  `session:`-prefix-tolerant on its exact-id tier) against local
  sessions + registered peers — a LOCAL match re-drives the exact `--id`
  path unchanged, a REMOTE match (`peer/<query>`, resolved against that
  peer's CACHED graph, never a live pull) delivers over A2A `message/send`
  instead, gated entirely on the RECEIVING peer's side (this door's own
  `--yes`/pending/autogate machinery is a local-socket concept and does not
  apply to a remote delivery). `send::deliver_local`'s success path is ONE
  of exactly TWO seams that file a delivered message into
  `aoide_storage::inbox` (messaging plan P-C6, `state/inbox.json`) — every
  route that lands a message into an ALREADY-REGISTERED session (direct
  `--id`, `--to` local, `pending approve`'s re-drive, AND `aoide-server`'s
  A2A `do_inject`, which reaches this same function through `session_send`)
  is covered by that one call. The OTHER seam lives in `aoide-server`
  itself (`spawn_inject_prompt`, `a2a.rs`): a brand-new A2A-spawned
  session's first turn is typed before that session has a `SessionRecord`
  at all, so it can't reach `deliver_local` and files itself instead — see
  `aoide_storage::inbox`'s module doc for the full two-writer reasoning.
- `reap` — liveness reaping (`aoide graph reap`), sweeping sessions a
  `SIGKILL`'d terminal could never mark `done`.
- `graph/window.rs` — window discovery/backfill/listener PLUS the
  automatic-parenting seam (task #89, corrected in review round 2):
  `is_windowless_wrap` (a conducted record is windowless when `headless` is
  set OR its own `windowAddress` is empty — `headless` overrides a stray
  address) backs `windowless_by_lineage`, which checks a session's OWN
  record first before walking its parent chain, so a nested headless
  `conduct`/`spawn` never pid-ancestry-walks to its enclosing terminal's
  window — neither for itself nor for its descendants. `stamp_headless`
  (`session_store.rs`) is the one writer of the permanent `headless` marker,
  called from `graph/conduct.rs::session_conduct` right after registration;
  that same call site gates its window-discovery call on `!headless`, so a
  headless wrap never even attempts discovery. `ancestry_parent`/
  `resolve_registration_parent` (the `--parent` flag > `/proc` ancestry ↔
  `hookAncestry` > `AOIDE_SESSION_ID` env precedence `wrap`/`conduct`/`spawn`
  registration resolve their parent through). `session_store::lineage_of`
  (ancestors + descendants) is the matching widened carve-out for the
  same-window registration-time eviction, reused by `reap.rs`'s dedup pass
  as defense in depth. See AGENTS.md's invariants for the full reasoning
  and every site that must agree: the discovery gate, the listener
  self-check, and the four historical backfill call sites.
- `shellbridge`, `herald` — files only; their CLI verbs (registry lines)
  moved to `lyra` at P-A2, but both stay resident here (see charter smudge
  below).
- `commands` — this crate's CLI verbs: `graph *` (15 paths), `conduct`,
  `hooks install`, `who`.
- `who` — `aoide who [filter] [--json] [--all]` (`graph/who.rs`): live
  presence over this box's own sessions plus every registered peer,
  probed in parallel on each invocation (messaging workstream C2). A
  PROJECTION, never a store — it never writes `state/peer-cache/`;
  `build_graph`'s own fold (`doc.rs`) owns that file. `glyph` (the
  online/unreachable/never-pulled node-presence map) is `pub`, re-exported
  at `graph::glyph` — the conductor's ROSTER panel (P-C4) is its second
  consumer, reusing it rather than redrawing its own copy.

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
