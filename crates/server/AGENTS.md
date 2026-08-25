# AGENTS.md — aoide-server

## Invariants

- **Inbound/serve only.** This crate is the SERVER half of every door.
  Outbound client behavior (A2A client, adapters) belongs in `aoide-client`,
  never here — even a "just this once" helper reverses the direction the
  split is built to keep.
- **Never reach for a crate-global registry.** `mcp::serve_stdio` and
  `a2a::serve` take `Registry`/dispatcher as PARAMETERS because the
  assembled registry only exists in an app crate (`cli`/`lyra`). Adding a
  `server → cli` (or `→ lyra`) dependency to shortcut this is exactly the
  inversion Phase 4c's DI seam exists to prevent.
- **Untrusted input stops here.** Every door-facing parse/validate boundary
  in this crate is the last line before dispatch; don't push validation
  downstream into `conduct`/`storage` handlers that assume a trusted caller.
- **The daemon door's own accept loop (`daemon::serve_daemon`/
  `accept_loop`) is thread-per-connection via the FALLIBLE
  `thread::Builder::spawn`, never the panicking `thread::spawn`** — a
  refused OS thread creation drops just the one connection instead of
  unwinding the whole accept loop, plus a short backoff on an accept
  error. This is `aoide_secrets::broker::serve`'s own accept-loop
  discipline, reused here BY CONVENTION (this crate cannot depend on
  `aoide-secrets`'s private `serve` fn) rather than `a2a::serve`'s plain
  `thread::spawn` — don't copy `a2a.rs`'s precedent onto a new socket-based
  door; copy `daemon.rs`'s instead.
- **`producers::SecretsMirror` never depends on `aoide-secrets`'s wire or
  record TYPES for PARSING, even though this crate already carries an
  `aoide-secrets` dependency it freely uses for the broker's socket/events
  PATH (`aoide_secrets::socket::socket_path`/`events_path` — plain,
  wire-type-free `PathBuf` resolvers; `daemon::run_loop` calls them
  directly, the "no cross-crate copying" convention
  (`pkgs/aoide/crates/AGENTS.md`) working as intended, not a boundary to
  route around).** `mirror_secrets_line` parses each feed line as a bare
  `serde_json::Value` and copies exactly the four named fields
  (`id`/`secret`/`consumer`/`timeoutSecs`) it recognizes — never the
  parsed object wholesale, and never through a shared typed struct. This
  is what makes "an unknown field never rides the mirror" a STRUCTURAL
  property instead of a discipline a future edit could quietly break by
  switching to a shared type; don't "simplify" this producer by importing
  `aoide_secrets::watch`'s own event type — the path functions are fine to
  reuse, the record SHAPE never is.
- **Every tick-driven producer (`producers::SecretsMirror::tick`,
  `producers::HandEditWatcher::sweep`, `events::poll_once`) stays a
  bounded, non-blocking, non-sleeping call — the loop/signal-handling
  wrapper around it lives ONE layer up** (`daemon::run_loop`'s tick,
  `events::tail`'s `SIGINT` loop). This is what lets every one of their
  tests call the bounded function directly with a deadline-poll or a plain
  synchronous assertion, never a fixed sleep or a real signal sent into
  the shared test binary — don't fold a `thread::sleep`/signal check into
  one of the bounded functions "to save a caller the loop."
- **`daemon::handle_conn`'s `dispatch` op (P-D4) adds no daemon-specific
  policy, and never will.** Every per-verb door check that already runs
  over MCP/A2A (a CLI-only admin verb's refusal, a gated command's
  `gated: true`, `mcp.serve`/`a2a.serve`'s non-Cli metadata replies) runs
  IDENTICALLY over this door, because the injected `dispatch` fn IS
  `cli::dispatch::dispatch` — the same function, the same registry, the
  same `inv.door` branches. Don't add a daemon-specific allowlist or
  permission table here "for symmetry with MCP's tool list" —
  `docs/architecture/AOIDED.md`'s "L2" section names a daemon-door
  allowlist a review-blocking violation; a new per-verb policy need is
  proved by a failing test against the EXISTING handler's `inv.door`
  branch, never by a new table in this crate.
- **`producers::HandEditWatcher` is ONE shared `Arc<Mutex<..>>` instance
  (`daemon::SharedHandEditWatcher`), not tick-private (task #92).** A
  dispatched session verb writes stage files on `handle_conn`'s own
  connection thread, never the tick thread, so `daemon::run_loop` hands the
  SAME watcher instance to `accept_loop`/`handle_conn` it ticks itself;
  `daemon::rebaseline_stage_roster` re-baselines the WHOLE roster after
  every completed `dispatch` op, unconditionally — never a per-verb "which
  files did this write" table (the same drift trap the door-policy
  invariant above already forbids). Don't reintroduce a tick-private
  `HandEditWatcher::new(..)` inside `run_loop`'s loop body or inside
  `accept_loop`/`handle_conn` — a second instance means two baselines that
  can each independently go stale against the other's writes, reopening
  task #92 by a different door.
- **Request-line reads on the daemon socket go through
  `daemon::read_capped_line` (a hand-rolled `fill_buf`/`consume` loop),
  never `BufReader::read_line` (P-D4, closing a P-D2-flagged gap).**
  `read_line` only checks a size cap AFTER a `\n` (or EOF) finally
  arrives — a client that streams past the cap with no trailing newline
  could grow that connection's own buffer for as long as it kept sending.
  `read_capped_line` checks the accumulated length on EVERY buffer fill
  instead, so an over-cap, newline-less stream is disconnected the
  instant it crosses the cap. A future op or connection type reading more
  request lines off this same socket reuses `read_capped_line`, never a
  second hand-rolled read loop.
- **The tick's own reconcile/reap (P-D6) keep NO separate in-memory
  roster.** `reconcile_graph_projection` and `run_internal_reap` both
  re-read the stage files fresh on every call, the same as any other
  dispatch would — this is deliberate, not a missing optimization: since
  "no logic forks" already means a routed dispatch does a plain
  read-modify-write against disk with no daemon-side cache, the tick has
  nothing else to compare against either, and "fold in the newest
  out-of-band write" falls straight out of "the file on disk is the single
  source of truth at every instant." Don't introduce a persistent
  `HashMap<SessionId, SessionRecord>` cache here "for performance" — it
  would reintroduce exactly the two-writer divergence this design avoids.
- **This crate's own `env_lock()` (`lib.rs`)'s first call in a test binary
  also floors `$AOIDE_STAGE_DIR` at a fresh private tempdir, unless a test
  already set one (P-D6 safety net).** `daemon::run_loop`'s tick now
  WRITES through `aoide_conduct::graph::emit`/`aoide_conduct::reap::
  reap_and_announce`; a `run_loop` test spawns that tick loop on a
  background thread it deliberately never joins (so the test itself can
  return once its own assertion holds), so that thread keeps ticking for
  the rest of the test BINARY's life — without this floor it would
  eventually read `$AOIDE_STAGE_DIR` as unset (once whichever test set it
  restores its own prior value) and start reading/writing the REAL
  `~/Aoide/song/stage/*` on this box. Every test that wants its own
  isolated tempdir still calls `env_lock()` first (existing convention)
  and restores what it captured on exit, same as `aoide-conduct`'s sibling
  `$AOIDE_DAEMON_SOCKET` floor (see that crate's own `AGENTS.md`) — don't
  remove or weaken either without re-reading why it exists. **A second
  floor (P-D8, same reasoning, one env var over) does the identical thing
  for `$AOIDE_STATE_DIR`:** `daemon::run_loop`'s entry now also calls
  `run_boot_auto_resume` once, which reads/writes a marker under
  `aoide_storage::fs::state_dir()` — the SAME un-joined background thread
  makes that call too, so without this floor it would eventually touch the
  real `~/Aoide/state/auto-resume-boot-epoch` on this box.
- **`daemon::run_boot_auto_resume` fires exactly ONCE per `run_loop` call,
  strictly BEFORE the tick loop — never move it inside the loop (P-D8).**
  It is a boot-time trigger, not a tick-cadence one: the guard
  (`daemon::epoch_already_fired`, a pure predicate deliberately factored
  out so it is unit-testable without `/proc/stat`) exists specifically to
  make a `Restart=on-failure` restart within the same boot a no-op, which
  only holds if the call happens once at entry, not once per tick. Don't
  fold it into the tick loop "for consistency with reap" — that would
  re-fire it every `REAP_EVERY_TICKS` and defeat the whole guard.

## Extension points

- **A new serve-side verb** (`daemon`, `shellbridge` registration, `a2a
  serve`, `events tail`) adds a `cmd!`/`register` entry in `commands.rs`,
  wired into the owning app crate's `commands::all()` — core-only today
  (`daemon`/`a2a serve`/`events tail` are core identity, per root
  `AGENTS.md`).
- **A new door type** (beyond CLI/MCP/A2A) gets its own `serve_*` function
  here, taking `Registry`/dispatcher the same injected way.
- **A new daemon tick producer** (P-D3's `SecretsMirror`/`HandEditWatcher`
  are the first two) is a plain struct in `producers.rs` with its own
  bounded `tick`/`sweep` method, constructed once in `daemon::run_loop`
  before its tick loop and called once per iteration — never a producer
  that spawns its OWN thread or sleeps internally (previous invariant).

## Docs update required in the same commit

- This `README.md` when a new module or serve-side verb is added.
- `CONTRACTS.md §6` when an A2A/MCP wire shape changes.
- `CONTRACTS.md §3`'s "Daemon wire" subsection when the daemon socket's own
  wire shape changes (`ping`/`subscribe`/`dispatch`).
- `pkgs/aoide/crates/AGENTS.md` for cross-crate invariants — not restated
  here.
