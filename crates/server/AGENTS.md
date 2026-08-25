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
