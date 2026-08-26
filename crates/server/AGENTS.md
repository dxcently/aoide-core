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
  policy, and never will.** Every per-command door check that already runs
  over MCP/A2A (a CLI-only admin command's refusal, a gated command's
  `gated: true`, `mcp.serve`/`a2a.serve`'s non-Cli metadata replies) runs
  IDENTICALLY over this door, because the injected `dispatch` fn IS
  `cli::dispatch::dispatch` — the same function, the same registry, the
  same `inv.door` branches. Don't add a daemon-specific allowlist or
  permission table here "for symmetry with MCP's tool list" —
  `docs/architecture/AOIDED.md`'s "L2" section names a daemon-door
  allowlist a review-blocking violation; a new per-command policy need is
  proved by a failing test against the EXISTING handler's `inv.door`
  branch, never by a new table in this crate.
- **`producers::HandEditWatcher` is ONE shared `Arc<Mutex<..>>` instance
  (`daemon::SharedHandEditWatcher`), not tick-private (task #92).** A
  dispatched session command writes stage files on `handle_conn`'s own
  connection thread, never the tick thread, so `daemon::run_loop` hands the
  SAME watcher instance to `accept_loop`/`handle_conn` it ticks itself;
  `daemon::rebaseline_stage_roster` re-baselines the WHOLE roster after
  every completed `dispatch` op, unconditionally — never a per-command "which
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

- **`pair_request`/`pair_reveal`/`pair_approve_callback` (P-P2) are
  deliberately UNGATED by `read_ok`/
  bearer verification, and this is not an oversight to "fix."** The
  pairing ceremony's entire purpose is establishing a credential where
  none exists yet — gating any of the three on an existing credential
  would be circular. What keeps this safe: a parked/revealed/approved
  request grants NOTHING by itself (no `allows`, no spawn/bearer gate,
  P-P3's lane untouched), every field is validated BEFORE anything is
  parked or resolved (`valid_pubkey_hex`/`valid_nonce_hex`/
  `valid_commit_hex`/`valid_peer_name`/`valid_callback_url`), the
  commitment check (`aoide_storage::pairing::reveal_inbound`) binds a
  reveal to its own earlier request with no signature needed yet
  (an active MITM cannot force a shared SAS by choosing its own values
  after seeing the real ones), and the SAS
  confirmation (`aoide_storage::pairing::derive_sas`) is the actual
  human-verified gate — it lives in the CLIENT's `peer pair approve`
  prompt (BOTH times it fires — once on each end), not in this door. Don't add a bearer check to any of the three
  handlers "for consistency with `message/send`" — that would break the
  bootstrap the whole ceremony exists to solve.
- **`pair_approve_callback` never writes a peer record on either a
  match or a mismatch — it only ever moves an
  OUTBOUND entry's `state`.** On a pubkey match it calls
  `aoide_storage::pairing::mark_outbound_awaiting_confirm`, which
  transitions `AwaitingApproval` → `AwaitingConfirm` and nothing else; the
  requester's own peer record commits later, entirely inside
  `aoide-client`, gated behind that instance's own operator running `peer
  pair approve <id>` a second time. On a pubkey mismatch the outbound
  entry is left completely UNTOUCHED (still `AwaitingApproval`, never
  re-parked, never dropped) — a mismatch could be a transient
  data-integrity hiccup, not necessarily an attack, and leaving the entry
  exactly where it was lets a legitimate retry just try the callback
  again with no state to reconcile. Don't reintroduce a peer-store write
  in this function, and don't drop/re-park the entry on a mismatch — both
  would commit or destroy state no human on this end confirmed.
- **`message_send`'s Spawn arm gates on `spawn_admitted`, which requires a
  resolved, paired, spawn-allowed peer identified via its OWN PER-REQUEST
  SIGNATURE — never a bare token, and never the address rung (P-P3
  decision 6, narrowed again by P-P4, `docs/architecture/PAIRING.md`'s
  wire-authentication section, CONTRACTS.md §6).** `handle_connection`
  calls `verify_signed_request` exactly once per connection, strictly
  before either dispatch path, and threads its result down as
  `signed_peer_name: Option<&str>` through `route`/`stream_task`/
  `RequestCtx` into `message_send`. When `Some(name)`, `message_send`
  resolves EXCLUSIVELY against that name (`PeerRung::Signature`) — no
  fallback to `aoide_storage::peer_store::resolve_peer`'s addr/token
  ladder even on a registry-lookup miss, since a request
  `verify_signed_request` already proved came from a specific peer must
  never be silently re-resolved as if it came from whoever's address or
  token happens to match instead. Only when the request carries no
  signature headers at all does `resolve_peer` run its own two-rung
  ladder (a presented token against a peer's own `token_file` first —
  `PeerRung::Token` — else the TCP origin against that peer's `url` —
  `PeerRung::Addr`). `spawn_admitted` accepts ONLY a `PeerRung::Signature`
  resolution, deferring the peer-side check to `peer_may_spawn(peer)`
  (`verified && allows.contains("spawn")`) only in that case — neither the
  address rung nor the (now-insufficient) token rung reaches `do_spawn`
  any more. Both unsigned rungs still resolve a peer identity fine for
  every OTHER purpose (Inject's `from` attribution, autogate) — they are
  excluded from Spawn specifically, since neither one is cryptographically
  bound to the one request presenting it: a bare source-address match
  carries no possession proof at all, and a bare shared-secret token is
  replayable and identical across every request the true peer or an
  impersonator ever sends. `spawn_refusal` gives a SHAPE-SPECIFIC message
  for the code `-32006` still returns uniformly: a genuinely paired peer
  resolved via the Token rung is told its aoide is too old to sign
  requests (upgrade the caller, don't re-pair); a Signature-resolved peer
  whose `allows` lacks `spawn` is told the exact `peer allow` fix; every
  other shape gets the original "pair first, then allow" message, now
  naming the signature requirement too. The door-wide bearer that gates
  every OTHER arm (read commands, the uniform-response guard, Inject's
  `effective_origin` coupling) is not consulted here at all. Signing
  itself never touches this crate — `aoide_storage::wire_auth` holds the
  canonical-string/verify logic, `aoide-client` holds the signer; this
  crate is verify-only, consistent with "inbound/serve only" above. No
  test in this file drives `do_spawn`'s real OS-level process spawn (an
  established precedent, `spawn_inject_prompts_success_branch_
  files_the_opening_turn_into_the_inbox`'s own doc comment) — the gate
  itself is proven via the pure `peer_may_spawn`/`spawn_admitted`/
  `spawn_refusal` predicates, `verify_signed_request`'s own dedicated test
  section, and `message_send`'s REFUSAL branches only. **P-P5b's own
  `peer_spawn_signed_and_allowed_is_admitted_up_to_the_do_spawn_boundary`
  holds the SAME line**: it drives a REAL ed25519 signature (via
  `aoide_client::wire::build_message_send_body`, the dev-dependency edge)
  through the REAL `verify_signed_request` → `spawn_admitted`, proving
  admission all the way to (never through) the `do_spawn` call — the
  refusal-side sibling (`peer_spawn_revoked_is_refused_...`) IS safe to
  drive through the real `message_send` because a refusal never reaches
  `do_spawn`. Don't "complete" the admitted-side test by calling
  `message_send`/`do_spawn` themselves — that would be exactly the real
  process spawn this precedent exists to avoid inside a `cargo test`
  binary (`std::env::current_exe()` there is the TEST binary, not a real
  `aoide`).
  `verify_signed_request`'s canonical string now reads `&req.method` (the
  request's own OBSERVED method), not a hardcoded `"POST"` literal (P-P5b,
  closing a P-P4 review finding) — a genuine behavior no-op today (every
  signed request is a POST), but the "binds method" claim above is now
  structurally true, not merely coincidentally true.
- **`do_inject`'s `from` attribution (P-P3 decision 7) is scoped to the
  QUEUED path only — never an immediately-delivered payload's bytes.**
  `session_send`'s own `from` mechanism also prefixes DELIVERED text
  (`provenance_prefix`, "from `<sender>`: "), so stamping a resolved
  peer's identity unconditionally would change what an already-autogated
  peer's delivered message looks like — a regression
  `autogated_peer_delivers_despite_being_non_loopback` pins against.
  `message_send`'s Inject arm computes `from` as `None` whenever
  `deliver_now` is `true`, `Some("peer:<name>")` only when it's `false`
  (queuing). Don't lift that `!deliver_now` guard without re-reading why
  it's there.
- **`NONCE_CACHE` (P-P4) is process-local, in-memory, and deliberately NOT
  a `HashSet` — a bounded `VecDeque<(peer, nonce)>` capped at
  `NONCE_CACHE_CAP` with FIFO eviction, so it never needs a second
  data structure to know which entry is oldest.** It lives in THIS crate
  (`a2a.rs`), not `aoide-storage::wire_auth` — the module doc there states
  why: it is the one piece of P-P4 state with no durable file behind it at
  all, so it belongs beside its only consumer
  (`verify_signed_request`), the same "ephemeral runtime state stays where
  it's used" reasoning that already keeps `producers.rs`'s tick state out
  of `aoide-storage`. `verify_signed_request` records a nonce ONLY after
  every cheaper check (including the signature itself) already passed —
  don't move the `nonce_is_replay` call earlier "to fail faster"; a forged
  or garbage nonce must never consume a cache slot. `handle_connection`
  calls `verify_signed_request` exactly ONCE per connection, strictly
  before both the streaming and the plain-JSON-RPC dispatch branches —
  don't duplicate that call inside `route`/`stream_task`/`handle_jsonrpc`;
  they only ever receive the already-computed `signed_peer_name`.

## Extension points

- **A new serve-side command** (`daemon`, `shellbridge` registration, `a2a
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

- This `README.md` when a new module or serve-side command is added.
- `CONTRACTS.md §6` when an A2A/MCP wire shape changes.
- `CONTRACTS.md §3`'s "Daemon wire" subsection when the daemon socket's own
  wire shape changes (`ping`/`subscribe`/`dispatch`).
- `pkgs/aoide/crates/AGENTS.md` for cross-crate invariants — not restated
  here.
