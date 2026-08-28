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
- **`daemon::accept_loop` refuses a CROSS-uid connection before it ever
  reaches `handle_conn` (LANE IDENTITY P-ID3, G8).** `cross_uid_gate` is a
  pure decision fn (`Option<PeerCred>` in, `Option<String>` refusal reason
  out) mirroring `aoide_secrets::broker::admin_gate`'s exact shape — reuse
  that mirroring for any FUTURE socket-based door in this crate rather than
  inventing a fourth wording. Reads `aoide_secrets::peercred::peer_cred`
  (already `pub`, already a dependency — do not reach into
  `aoide-conduct::graph::identity` for its OWN `pub(crate)`-only
  `peer_cred`, which is unreachable across the crate boundary anyway; do
  not vendor a THIRD `SO_PEERCRED` reader here). **This is a CROSS-uid
  floor only** — it does not, and is not meant to, stop a same-uid process
  from dispatching a request over this socket; every legitimate connector
  (the CLI's `daemon_dispatch` proxy, a hook, the conductor) already shares
  the daemon's own uid under OQ1-A.
- **`invocation_from_dispatch_request` stamps an absent `from` flag
  explicit-empty (LANE IDENTITY P-ID3, G8's attribution half) — never
  leaves it absent.** `send`'s own `resolve_sender` falls back to
  `AOIDE_SESSION_ID` off the CALLING process's env whenever `--from` is
  absent; a `dispatch`ed invocation runs its handler INSIDE this daemon
  process, so that fallback would read `aoided`'s own ambient env, not the
  connecting client's (which never crosses this socket at all). Stamping
  `--from ""` on an absent flag is `resolve_sender`'s own documented
  "explicit no attribution" form — it SKIPS the env fallback outright,
  the same mechanism `a2a::do_inject` uses for the identical leak (G9). Do
  not "fix" this by clearing `AOIDE_SESSION_ID` out of the daemon's own
  process env instead: this crate is thread-per-connection
  (`accept_loop`'s own doc above), and mutating global env from a
  connection-handling thread races every OTHER concurrent connection's own
  env reads — the flags-map stamp is per-request and touches no shared
  state. **This does NOT close the GATE** (`aoide_conduct::graph::
  send::real_attested_sender`, untouched by this phase, out of its scope
  fence) — it walks `std::process::id()`'s own `/proc` ancestry, which for
  a dispatched `send` is `aoided`'s own ancestry, not the connecting
  client's; in production (`init -> systemd -> aoided`) that never resolves
  a live sealed session, so a dispatched `send` with no `--yes`/autogate
  already fails closed to `pending` — not because this fix re-derives the
  real caller's identity, but because the daemon's own ancestry is
  architecturally incapable of impersonating one.
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
- **`daemon::seal_keypair` mints exactly ONE keypair per process, in a
  `OnceLock`, and it must NEVER be written to disk (LANE IDENTITY P-ID1,
  OQ1-A).** This is the daemon's own in-memory seal-signing key, deliberately
  a DIFFERENT keypair from `state/identity/`'s on-disk peer-wire key — a
  same-uid attacker can read that on-disk file, so a seal signed with it
  would not be secret against the exact adversary this lane's thesis names.
  Don't "simplify" by reusing `identity::load_or_mint`'s key here, and
  don't add any code path that persists `seal_keypair`'s bytes anywhere —
  its whole secrecy claim is "this process is still alive, and `ptrace`
  against it is blocked" (Yama `ptrace_scope>=1`), which a disk copy would
  destroy outright.
- **`daemon::seal_freshly_registered_session` mints/stamps a seal ONLY for
  a successful `session start` dispatch whose record already carries a
  `pid`, and it is NOT a security gate.** No gate anywhere reads
  `SessionRecord.seal` yet (P-ID2 adds the first verify-on-accept caller) —
  don't make this function's success/failure affect the dispatch reply, and
  don't wire a door/socket decision on `seal`'s presence without first
  reading the LANE IDENTITY plan section (P-ID2/P-ID4's own scope). The pid
  it mints over is the record's OWN `pid` field, not yet a peercred-verified
  connecting pid — stated as scaffolding in its own doc comment, not to be
  quietly upgraded into a security claim by a future edit that forgets the
  boundary.
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
  WRITES through `aoide_conduct::graph::restage_graph`/`aoide_conduct::reap::
  reap_and_announce`; a `run_loop` test spawns that tick loop on a
  background thread it deliberately never joins (so the test itself can
  return once its own assertion holds), so that thread keeps ticking for
  the rest of the test BINARY's life — without this floor it would
  eventually read `$AOIDE_STAGE_DIR` as unset (once whichever test set it
  restores its own prior value) and start reading/writing the REAL
  `~/Aoide/state/stage/*` on this box. Every test that wants its own
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
- **`run_boot_auto_resume`'s per-project loop carries no liveness check of
  its own (P-C4, durable-sessions plan).** It used to skip a whole project
  when ANY non-`done` session anchored to it; that was wrong for a
  multi-session undying set, since one live terminal would suppress
  reviving the rest. The skip moved into `aoide_conduct::graph::
  session_resurrect`'s own bare-mode selection, per candidate — this loop
  now just calls it unconditionally for every `autoResume` project. Don't
  put a project-wide `has_live`-shaped check back here; if a project's
  entire undying set is already alive, `session_resurrect` itself resolves
  to the empty-set `Outcome::ok` no-op.

- **`pair_request`/`pair_reveal` (P-P2) are deliberately UNGATED by
  `read_ok`/bearer verification, and this is not an oversight to "fix."**
  The pairing ceremony's entire purpose is establishing a credential where
  none exists yet — gating either on an existing credential would be
  circular. What keeps this safe: a parked/revealed/approved request
  grants NOTHING by itself (no `allows`, no spawn/bearer gate, P-P3's lane
  untouched), every field is validated BEFORE anything is parked or
  resolved (`valid_pubkey_hex`/`valid_nonce_hex`/`valid_commit_hex`/
  `valid_peer_name`/`valid_peer_url`), the commitment check
  (`aoide_storage::pairing::reveal_inbound`) binds a reveal to its own
  earlier request with no signature needed yet (an active MITM cannot
  force a shared SAS by choosing its own values after seeing the real
  ones), and the SAS confirmation (`aoide_storage::pairing::derive_sas`) is
  the actual human-verified gate — it lives in the CLIENT's `peer pair
  approve` prompt (BOTH times it fires — once on each end), not in this
  door. Don't add a bearer check to either handler "for consistency with
  `message/send`" — that would break the bootstrap the whole ceremony
  exists to solve. `pair_poll` (Design A, task #119, REPLACES the old
  `aoide/pairApprove` reverse callback) is DIFFERENT: it is
  self-authenticating (its own doc has the mechanism) rather than
  door-level-gated, and this is the correct posture for it too — see the
  next bullet.
- **`pair_poll` verifies its OWN signature inline against the parked
  entry's stored `pubkey_hex` — never through `verify_signed_request`
  (P-P4), and never writes a peer record.** No verified `Peer` record
  exists on the approver's side until the very id being polled is
  approved, so P-P4's header scheme (which requires one) cannot gate this
  method — `pair_poll` decodes `{id, timestampIso, nonceHex,
  signatureHex}` from its OWN params and calls
  `aoide_storage::wire_auth::verify_signature_hex` directly against
  `InboundPairingRequest.pubkey_hex`. It reads
  [`InboundPairingRequest::approved`] and returns it, never mutates it —
  `mark_inbound_approved` (called from `aoide-client::commands::approve_inbound`,
  not from any wire handler) is the ONLY thing that ever sets that flag,
  purely locally, no wire call. Every non-approved/unverified/unknown
  outcome returns the IDENTICAL `{"status":"pending"}` (the
  existing-oracle discipline, `pair_poll`'s own doc) — don't add a
  distinct error code for "unknown id" or "bad signature" here; that
  would let an outsider learn something a legitimate not-yet-approved
  poller couldn't.
  `aoide-client::commands::approve_outbound` is what checks a released
  pubkey against what THIS instance learned at request time
  (`mark_outbound_awaiting_confirm`'s own `Mismatch` handling, entirely
  client-side now) — don't reintroduce that check here; this handler has
  no basis to know what the REQUESTER already learned.
- **`emit_pairing_event` (P-P5) fires ONLY from an Ok arm, never from a
  mismatch or unknown-id arm, and its `payload` carries fields BY NAME
  ONLY.** Two call sites today (`pair_request`'s `pair-parked`,
  `pair_reveal`'s `pair-revealed`) — `pair_poll` (Design A, task #119)
  deliberately does NOT call this: a poll arriving and being answered
  isn't a state change on the approver's side worth surfacing (it already
  knows it approved; it did so itself, locally), and the requester's own
  side never transitions asynchronously anymore either, only synchronously
  inside `approve_outbound`'s own poll-then-mark call — there is no longer
  a `pair-awaiting-confirm` kind. Add a call site the same way if a future
  milestone genuinely needs one — never widen the payload builder to pass
  a parsed struct wholesale, and never add `sas`/`pubkey*`/`nonce*`/
  `commit*` to the by-name list; a watcher re-derives the SAS locally from
  `aoide_storage::pairing::list_inbound`/`list_outbound`; this feed line is
  a trigger only. `a2a serve` opens
  its own `FeedWriter` onto `aoided`'s events file rather than routing
  through the daemon process (they're separate processes) — don't thread
  a socket call through here to "unify" the two writers; the cap-truncate
  race that creates is already accepted (module doc, CONTRACTS.md §6).
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
- **`message_send`'s Inject arm feeds `should_deliver_now` through
  `origin_for_inject` first (P-S6, CONTRACTS.md §6's "Peer authentication
  today" standing paragraph) — a VERIFIED signature strips
  `PeerOrigin::Loopback`'s automatic auto-deliver pass, whatever the
  connection's own address looks like, UNLESS that peer's own signature
  rung is itself autogate-marked.** An ssh `-L` forward (or any other
  loopback-terminating proxy) delivers a tunneled peer's packets from its
  own end's sshd, so `classify_origin` sees loopback for a tunneled request
  exactly like a genuinely local caller — `origin_for_inject(origin,
  signed_peer_name.is_some() && !sig_autogate)` closes that gap by coercing
  the origin fed to `should_deliver_now` to `PeerOrigin::Unknown` for a
  signed, NON-autogate peer (reusing that variant's existing fail-safe arm,
  the same move `effective_origin` already makes for an invalid door-wide
  token — no fourth `PeerOrigin` kind). **The `!sig_autogate` guard is not
  optional plumbing — `should_deliver_now(PeerOrigin::Unknown, _)` ignores
  `autogate_match` entirely (unconditional `false`, see that function's own
  match arm and `uniform_response_guard_never_fires_for_a_per_peer_
  autogated_token`'s doc comment for the existing pin), so coercing an
  autogate-marked signed peer's origin to `Unknown` would make it
  UN-deliverable, the opposite of the restoration this phase owes.** An
  UNSIGNED request is completely untouched: `origin_for_inject` is the
  identity function when its `signed` argument is `false`, so a genuinely
  local caller's loopback trust is exactly as before this phase. The
  like-for-like half: `autogate_match` folds in a THIRD signal,
  `sig_autogate` — `resolved_peer` matched via `PeerRung::Signature` whose
  own `Peer.autogate` is `true` — alongside the existing
  `ip_autogate`/`token_autogate`, computed AFTER `resolved_peer` now (moved
  down from before it) so this fold can read it; an operator who already
  marked a peer auto-deliver keeps that behavior once it starts signing,
  riding the ordinary Loopback/Remote arms (which DO consult
  `autogate_match`) instead of the coercion. Don't gate this on
  `token_configured`/`TokenState` — that's `effective_origin`'s own,
  separate question (an invalid DOOR-WIDE bearer); this narrowing fires on
  `signed_peer_name`/`sig_autogate` alone, unconditionally. Tests:
  `signed_inject_from_a_non_autogate_peer_on_a_loopback_connection_is_held_pending`
  is the actual regression pin (the exact hole a tunnel would otherwise
  open); `signed_inject_from_an_autogate_peer_on_a_loopback_connection_still_auto_delivers`
  is the restoration; `origin_for_inject_is_the_identity_function_when_unsigned`
  and `origin_for_inject_downgrades_loopback_once_the_request_is_signed`
  pin the pure predicate directly.
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
- **`do_inject` stamps the `from` flag EXPLICIT-EMPTY when its own `from`
  parameter is `None` (LANE IDENTITY P-ID3, G9) — never leaves the flag
  absent.** `session_send`'s `resolve_sender` falls back to
  `AOIDE_SESSION_ID` off the CALLING process's env whenever `--from` is
  absent, and `do_inject` calls `session_send` DIRECTLY, in-process — the
  "calling process" for a remote A2A inject is `aoide a2a serve` itself, a
  long-lived process whose own ambient env has nothing to do with whichever
  remote peer just sent the message. `from.unwrap_or_default()` (an empty
  `String` when `None`) is `resolve_sender`'s own documented "explicit no
  attribution" form (`--from ""`) — it skips the env fallback outright,
  rather than merely overwriting whatever the env currently holds, so this
  holds regardless of what `a2a serve`'s own env carries at any given
  moment. Don't revert to a bare `if let Some(f) = from { flags.insert(...)
  }` "for symmetry with reading `from`" — that shape is exactly what let
  the daemon's own ambient `AOIDE_SESSION_ID` leak into an unattributed
  inject's pending record before this fix
  (`an_unattributed_inject_never_falls_back_to_this_processs_own_ambient_session_id`
  is the regression pin). This closes only the ATTRIBUTION leak, not the
  GATE — `real_attested_sender` still walks `a2a serve`'s own `/proc`
  ancestry for `do_inject`'s in-process `session_send` call, same posture
  `aoided`'s dispatch-socket `send` holds (`accept_loop`'s own invariant
  above); it already fails closed in practice because `restore_delivery`
  and `do_inject` both only reach the gate with `--yes` already forced or
  the ancestry never resolving a live session.
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
- **`a2a::self_url(bind, port)` is the ONE formula the AgentCard's `url`
  field and `route`'s own `aoide/graphSummary` handling call — never a
  second inline `format!("http://{bind}:{port}/")` (P-P6).** Before this
  phase the two independently carried the same literal that merely
  happened to agree (the exact shape the `HTTP_METHOD` precedent already
  warns against, `client/AGENTS.md`). A future change to how the door
  URL is derived (a public-hostname override, a reverse-proxy prefix, …)
  touches this one function and every caller inherits it. The discovery
  advertisement is deliberately NOT a caller — it carries no door URL at
  all (task #120: rendezvous, not authentication;
  `aoide_storage::advertise`'s module doc), and must never regrow one.
- **`discovery::spawn_advertiser` is called from EXACTLY one place —
  `a2a::serve`, before the accept loop starts (P-P6 + task #120).** It is
  never called from `handle_connection`, a per-request path, or anywhere
  else — one thread per `a2a serve` process, for that process's whole
  lifetime, mirroring how `--bind`/`--port` are resolved once at launch
  and held unchanged. Whether a tick SENDS is `resolve_discovery_
  advertise`'s launch-time force OR'd with the runtime switch
  (`aoide_storage::advertise::enabled`), read INSIDE the thread each tick
  — keep the read per-tick, so `aoide peer advertise on|off` lands
  without a restart, and don't gate a SECOND call site on the same
  env/flag "for redundancy": a duplicate advertiser thread would just
  double the send rate and complicate the "both off means silence"
  proof.

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
