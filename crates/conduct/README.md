# aoide-conduct

Aoide's session core: the PTY multiplexer (`aoide conduct`), the session DAG
(`aoide graph`), Claude-Code hook plumbing, and liveness reaping. Makes
every terminal a tracked, conductable session (root `AGENTS.md`, "Conducting
— aoide's headline"). Core, never `lyra` — headless-safe by construction.

## Named seams (what it exposes)

- **Graph residency (P-D6, `docs/architecture/AOIDED.md`'s "L4")**: the
  session-write family — `graph session start/phase/end`, `graph session
  hook`, and `graph reap` (below) — each try `aoide_client::daemon::
  daemon_dispatch(inv)` FIRST and fall back to their pre-existing direct
  stage-write path byte-identically on `None`. The daemon executes the
  SAME registered handler code (its `dispatch` fn IS `cli::dispatch::
  dispatch`) — no logic forks, no daemon-specific policy anywhere in this
  crate. `session_hook` smuggles its already-read stdin payload through
  the routed `Invocation`'s `flags` map under an internal-only key
  (`STDIN_PAYLOAD_FLAG`) rather than growing the daemon wire a stdin
  channel — the daemon-side handler reads that flag first and never
  touches its own stdin.
- `graph/spawn.rs` — `graph spawn [--windowed] [--carry]` (P-D7,
  `docs/architecture/AOIDED.md`'s "L5"): the child is always `aoide conduct
  -- <agent cmd>`, built by the ONE shared `build_conduct_args` (`--headless`
  aside) — headless by default (detaches, re-execs this same binary), or,
  under `--windowed`, execs a real terminal named by `$AOIDE_TERMINAL` (env
  only) that runs the identical conducted command, so registration, the
  control socket, and the parent-autogate lane come for free either way.
  `build_terminal_argv` parses the template (whitespace split, a `{cmd}`
  placeholder token spliced in as separate argv slots when bare, or POSIX
  single-quote-joined into ONE slot when the token is quote-wrapped —
  `foot sh -c '{cmd}'`) — pure, unit-tested, never a real terminal spawned in
  a test. Taught errors, no process ever touched: no `$AOIDE_TERMINAL` set,
  or neither `$WAYLAND_DISPLAY` nor `$DISPLAY` present (a headless host,
  steered back to plain `graph spawn`). `--carry` (P-C3, durable-sessions
  plan) marks the spawned id in `state/carry.json` once — and only once —
  the registration wait actually succeeds; an id that never registers has no
  live session behind it, so nothing is marked.
- `graph/send.rs`'s `graph session hook` stamps `SessionRecord.
  harness_session_id` (P-D7) from the raw hook payload's own `session_id`
  on every event that carries one, mapped-to-an-action or not — see
  `CONTRACTS.md`'s `sessions.json` entry for the full field contract.
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
  apply to a remote delivery). A `--to` query that resolves against neither
  a local session nor any peer/prefix form falls through to a registered
  **hub peer** (P-D5's `peer hub`, wired here at P-D6 —
  `aoide_storage::addr::resolve_with_hub`, given the one peer with
  `hub: true` if any) instead of erroring `not-found` — the ONE routing
  consumer of the hub preference in this crate; `who.rs`'s own listing
  filter deliberately keeps the plain, hub-blind `addr::resolve`. `send::deliver_local`'s success path is ONE
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
- **The carry mark (P-C2/P-C3, durable-sessions plan):** `graph/carry.rs`'s
  `session_carry` (`graph session carry on|off [--self | --id <id>]`) is the
  command over `aoide_storage::carry`'s store (`state/carry.json`) — a
  session id marked DURABLE, so a project's whole carried set can later be
  resurrected together. Unlike every other `graph session *` handler in this
  crate, it takes no stage lock and does not route through `daemon_dispatch`:
  `carry.json` is not a `song/stage/` file, so it sits entirely outside the
  L4 dual-writer surface. `--id` targets any session id, live or not — no
  roster lookup gates the write, which is what makes the mark flippable
  post-mortem off a bare ledger id; bare and `--self` both resolve the
  target from `$AOIDE_SESSION_ID`. Two more sites touch the same store:
  `graph spawn --carry` marks at birth (above), and `graph/resurrect.rs`'s
  `resurrect_one` moves the mark from an old, carried ledger id onto its
  freshly spawned replacement — new id added, old id dropped, in ONE
  `save_carry` call, only when the spawn actually reached `Status::Ok` and
  only when the old id was carried to begin with. The new id is added
  BEFORE the old one is dropped in the shared in-memory vector, so a crash
  between that edit and the write leaves the OLD id carried (retryable)
  rather than neither (silent loss) — the same bias a failed spawn gets
  deliberately, by never touching the store at all.
- `reap` — liveness reaping (`aoide graph reap`), sweeping sessions a
  `SIGKILL`'d terminal could never mark `done`. `reap_and_announce` (the
  registered CLI handler) routes through `daemon_dispatch` first like every
  other session-write command above; the toast-free `reap` underneath is what
  every in-crate caller and unit test calls directly, and what the
  daemon's own tick runs internally on its ~12s cadence — the systemd timer
  becomes a redundant backstop once a daemon is resident, never a second
  liveness mechanism.
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
- `shellbridge`, `herald` — files only; their CLI commands (registry lines)
  moved to `lyra` at P-A2, but both stay resident here (see charter smudge
  below).
- `commands` — this crate's CLI commands: `graph *` (22 paths, including
  `graph resurrect`, P-D8, and `graph session carry`, P-C2), `conduct`,
  `hooks install`, `who`.
- **The durable session ledger + resurrect (P-D8, `docs/architecture/
  AOIDED.md`'s "L5"):** `graph/doc.rs::ledger_session_exit` is the ONE
  shared call both `session_store.rs::do_session_end_inner` (a clean
  `graph session end`) and `reap.rs::reap_inner` (every id its `reaped` set
  collects) route through to append one `aoide_storage::ledger::
  LedgerEntry` line at the exact instant a session leaves the roster —
  never two independently-written appenders, so a given session
  contributes exactly one ledger line regardless of which path retired it.
  `graph/resurrect.rs::session_resurrect` (`graph resurrect --project
  <name> [--all | --id <ledgerSessionId>]`) reads that ledger, anchors
  entries to a project by the SAME `anchor_for` longest-prefix rule `graph
  emit` uses, filters to harnesses with a verified `AgentProfile.
  resume_args` (`aoide_protocol::agents` — a harness with none is skipped
  with a taught message naming it, never a guessed invocation), and spawns
  each survivor via the windowed path (`graph/spawn.rs`, P-D7) with the
  harness's own resume argv and `--cwd` set to the ledger entry's own cwd.
  A resurrected session is ALWAYS a fresh `sessionId` — ids are never
  recycled — and gets stamped `resumedFrom` (`session_store.rs::
  stamp_resumed_from`) naming the ledger entry it continues; `build_graph`
  projects that as an additive `resumed` edge beside `spawned`/`anchors`.
  Never a hard `Outcome::error` over a per-candidate spawn failure (a
  headless host's taught "no `$AOIDE_TERMINAL`" error, for one) — every
  outcome folds into `resurrected`/`skipped`/`failed` and the command
  itself stays `Ok`, which is what lets the daemon's own boot-time
  auto-resume trigger (`aoide-server`'s `daemon.rs`) call this exact
  command core in-process without ever risking its own tick on a
  headless box.
- **Session origin (P-P3, `docs/architecture/PAIRING.md` decision 7):**
  `session_store.rs::stamp_origin` stamps `SessionRecord.origin` —
  `"peer:<name>"` for a session `aoide-server`'s A2A door spawned on
  behalf of an identified, paired peer — right after `do_session_start`,
  same seam `stamp_headless` uses. `graph/conduct.rs::session_conduct`
  reads it off the `AOIDE_SESSION_ORIGIN` env var `aoide-server`'s
  `a2a::do_spawn` sets on the child it launches; a locally-launched
  `conduct` (a plain terminal, `graph spawn`, etc.) never has that env var
  set, so `origin` stays absent. No `graph.json` projection (like
  `headless`/`hookAncestry`, consumed internally, not rendered) —
  `doc.rs::ledger_session_exit` is the ONE place it surfaces, projected
  verbatim into the durable session ledger's own `origin` field. `origin`
  is attribution, not authentication: any same-uid process can set
  `AOIDE_SESSION_ORIGIN` before running `aoide conduct` and forge
  `"peer:X"` with no door involved, the same ordinary spoofable
  same-user process state `--from`/`AOIDE_SESSION_ID` already are — nothing
  may ever gate on it without upgrading it to an authenticated channel
  first (task #63's lane).
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
workstream C3; every session-write handler calls `aoide_client::daemon::
daemon_dispatch`, P-D6; see `client`'s own README for why that edge stays).

## How it composes

`screen`, `server`, `conductor`, `cli`, and `lyra` all depend on it.
**Charter smudge**: `shellbridge.rs`/`herald.rs` stay as FILES here even
though their CLI commands moved to `lyra` — `permit.rs` publishes summons
through `herald`, and `conductor/ui.rs` reads the socket path `shellbridge`
owns, so both are entangled with core
(`docs/architecture/PACKAGE-LAYOUT.md`, "Charter exceptions").
