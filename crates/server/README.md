# aoide-server

`aoided` and the door serve-loops: A2A JSON-RPC/HTTP/SSE, MCP-over-stdio,
listeners, sessions, snapshots, the audit sink. Untrusted input stops here —
the inbound half of the two-door contract (the outbound half is
`aoide-client`).

## Named seams (what it exposes)

- `daemon` — the `aoided` daemon. `run` is the one-shot policy self-check
  `aoide daemon` still runs. `run_loop`/`serve_daemon` (P-D2,
  `docs/architecture/AOIDED.md`) are the RESIDENT daemon `bin/aoided.rs`
  execs: bind the control socket
  (`$AOIDE_DAEMON_SOCKET`, else `$XDG_RUNTIME_DIR/aoide/aoided.sock`,
  `daemon::socket_path`), spawn a thread-per-connection accept loop
  (fallible `Builder::spawn`, accept-error backoff — the secrets broker's
  own accept-loop discipline, reused by convention), then tick forever
  (~1s; P-D3's two producers, below). Newline-delimited JSON, the secrets
  wire framing verbatim, request lines read via `read_capped_line`'s
  `fill_buf`/`consume` loop (P-D4 — the byte cap is checked on every buffer
  fill, not only after a `\n` arrives, closing the P-D2-flagged gap where a
  newline-less stream could grow one connection's buffer unbounded). Three
  ops: `ping` (liveness), `subscribe` (follow the daemon's own events feed
  — `$AOIDE_DAEMON_EVENTS`, else a sibling of the socket,
  `daemon::events_path` — filtered by an explicit `classes` array,
  default-deny), and `dispatch` (P-D4, the fourth door) — builds an
  `Invocation { path, args, flags, door: Door::Daemon }` LITERALLY from the
  wire's `path`/`args`/`flags` and runs it through the injected `dispatch`
  fn, replying with one `{"outcome": <the full Outcome envelope>}` line.
  Door policy is not reimplemented here: every command's own `inv.door`
  branch (a CLI-only admin command's refusal, a gated command's `gated: true`,
  `mcp.serve`/`a2a.serve`'s non-Cli metadata reply) runs exactly as it
  already does over MCP/A2A, since the injected fn IS
  `cli::dispatch::dispatch` — no daemon-specific allowlist exists or is
  planned (`docs/architecture/AOIDED.md`'s "L2" section). `registry` still
  rides along the DI seam unused — no op resolves a dotted tool name
  against it the way MCP's `tools/call` does.
- `producers` (P-D3, `docs/architecture/AOIDED.md`'s "L1" section) — the
  daemon tick's two producers, both constructed once at `run_loop` startup
  and ticked every iteration. `SecretsMirror` tails the secrets broker's
  OWN events feed, its location resolved via `aoide_secrets::socket::
  socket_path`/`events_path` (`daemon::run_loop`'s own construction site —
  plain, wire-type-free `PathBuf` resolvers, reused rather than re-derived;
  this crate's `aoide-secrets` dependency also covers the A2A door's
  inbound bearer resolve). The mirror IS deliberately kept off that
  crate's wire/record TYPES for parsing, so "never copy an unknown field"
  is structural — `mirror_secrets_line` reads a bare `serde_json::Value`
  and copies exactly four named fields, `id`/`secret`/`consumer`/
  `timeoutSecs`, for one of the five recognized outcomes,
  `released`/`parked`/`completed`/`dismissed`/`expired`) and re-publishes
  each as a `class:"secret",source:"secrets-mirror"` record on the
  daemon's own feed. `HandEditWatcher` stat-sweeps a fixed six-file roster
  (`daemon::stage_roster`: `sessions.json`/`hooks.json`/`projects.json`/
  `graph.json` from `aoide-storage`, `pending.json`/`herald.json` from
  `aoide-conduct`) each tick and fires a `class:"audit",kind:"hand-edit"`
  event for any file whose `(mtime, len)` no longer matches its baseline
  (the #69 hand-edit watcher) — detection and narration only, this daemon
  never reverts a hand edit. `note_own_write` is the seam P-D6's own
  tick-reconcile/reap writes (below) fold into so they are never reported
  back as a hand edit. **The watcher itself is a single `Arc<Mutex<
  HandEditWatcher>>` (task #92), shared between the tick thread and
  `handle_conn`'s connection threads** — not tick-private: a dispatched
  session command (`graph session start/end`/etc., `{"op":"dispatch"}`) writes
  stage files on ITS OWN connection thread, not the tick's, so
  `rebaseline_stage_roster` re-baselines the WHOLE roster after every
  completed dispatch (roster-wide, not a per-command "which files did this
  write" table) before that connection's reply goes out — closing the
  window where the daemon's own routed write got reported back to itself as
  a hand edit one tick later.
- **Graph residency (P-D6, `docs/architecture/AOIDED.md`'s "L4")** —
  `run_loop`'s tick, after narrating the hand-edit sweep above, does two
  more things every iteration: `reconcile_graph_projection(changed_files)`
  re-derives `song/stage/graph.json` (via `aoide_conduct::graph::restage_graph`,
  the same function every project/session mutation site already calls — the
  `graph emit` CLI command was retired in favor of `graph prune` — no forked
  logic) whenever `sessions.json`/`hooks.json` is among the
  files the sweep just reported changed, so an out-of-band write (the
  direct-fallback CLI path, or a hand edit) is folded into the projection
  on the very next tick rather than waiting for the next dispatch to touch
  it; `run_internal_reap` calls the SAME `aoide_conduct::reap::
  reap_and_announce` `graph reap` always runs, every `REAP_EVERY_TICKS`
  (12) ticks (~12s, matching the systemd timer's own cadence), re-baselining
  `HandEditWatcher` via `note_own_write` for whatever it touched so its own
  sweep is never mistaken for a hand edit next tick. Neither producer keeps
  a separate in-memory roster — every dispatch (routed or internal) reads
  the stage files fresh, so "fold in the newest write" falls directly out
  of "the file on disk is the single source of truth at every instant";
  `daemon::handle_conn`'s `dispatch` op is also how a REMOTE `graph
  session start/phase/end/hook`/`graph reap` call actually executes once
  routed here — `internal_invocation` builds the same shape of
  `Invocation { door: Door::Daemon, .. }` for the tick's own internal
  calls, so the tick's writes and a routed client's writes go through
  literally the same code.
- **Boot-time auto-resume trigger (P-D8, `docs/architecture/AOIDED.md`'s
  "L5"/"Open knobs")** — `daemon::run_boot_auto_resume`, called exactly
  ONCE at `run_loop`'s entry, before the tick loop starts (never from
  inside it). Boot-epoch guarded: `epoch_already_fired` (a pure predicate,
  unit-testable with no `/proc/stat` involved) compares a one-line marker
  file under `state_dir` (`daemon::auto_resume_marker_path`) against
  `aoide_conduct::reap::boot_epoch()` — reused directly rather than
  re-derived, that function's own doc names this exact caller — so a
  `Restart=on-failure` restart within the SAME boot is a no-op, and only a
  real reboot (a changed epoch) reopens the guard. On a fresh boot, for
  EVERY `autoResume` project (`projects.json`, P-D8) — unconditionally, no
  liveness check here — calls `aoide_conduct::graph::session_resurrect`
  in-process (`Door::Daemon`) — the identical command core `graph resurrect
  --project` runs over the CLI, the same in-process-call pattern
  `run_internal_reap` already uses for `graph reap`. Liveness lives one
  layer down: `session_resurrect`'s own bare-mode selection
  (`carried_selection`, durable-sessions plan P-C4) drops any carried id
  already alive in `sessions.json` per candidate before spawning anything,
  so a project where every carried session is already live resolves to the
  empty-set `Outcome::ok` no-op rather than being skipped wholesale — a
  per-project skip here would have suppressed reviving a multi-session
  carried set's other, actually-dead members over one live terminal. That
  function never hard-errors on a per-candidate spawn failure either; a
  headless host's taught "no `$AOIDE_TERMINAL`" error is only
  `eprintln!`'d here, never propagated — the tick/loop itself is never at
  risk.
- `events` — `tail`, the blocking loop behind `aoide events tail` (P-D3):
  follows the daemon's own events feed with a `Follower` and prints every
  line whose `class` passes an (optional, comma-separated) filter, `--json`
  verbatim or narrated otherwise. `poll_once` is the bounded, non-blocking
  core a test drives directly; `tail` is the thin `SIGINT`-handling wrapper
  around it, mirroring `aoide_secrets::watch`'s own tail-loop shape.
- `mcp` — `serve_stdio`, the MCP stdio server.
- `a2a` — the serve half of A2A (JSON-RPC/HTTP/SSE); the client half stays
  in `aoide-client`. Two `message/send` arms, two different relationships to
  the inbox (messaging plan P-C6, `state/inbox.json`): `do_inject` (Inject,
  an EXISTING session) delivers through `aoide_conduct::graph::session_send`
  — the same door `graph send` uses — which is where a delivered message
  gets filed; `do_inject` itself files no entry of its own, since its
  Invocation can only ever reach `session_send`'s LOCAL branch (see
  `do_inject`'s doc comment). `do_spawn` (Spawn, a BRAND-NEW session) types
  the opening turn via `spawn_inject_prompt`, which files ITS OWN entry
  right after the write — a spawned session has no `SessionRecord` yet at
  that moment, so it cannot reach `session_send` at all (see
  `spawn_inject_prompt`'s doc comment for the race that rules it out).
  These are the only two inbox-filing call sites in the whole tree.
  **Inbound bearer verification (task #84)** resolves the door's expected
  `Authorization: Bearer` token through `aoide-secrets`'s broker rather
  than only reading a static token file: `--bearer-secret <name>` (or
  `AOIDE_A2A_BEARER_SECRET`) names a secret, resolved FRESH on every
  connection via `aoide_secrets::client::resolve_bounded` as consumer
  `a2a-door`, with a short (~2s) timeout so a misconfigured `requireTotp`
  secret refuses immediately instead of parking the door open. Unset
  stays the pre-existing token-file behavior exactly; set takes
  precedence over `--token-file`. A broker-unreachable or denied resolve
  fails CLOSED — the connection is refused the same way a wrong bearer
  is, never held open and never treated as "unconfigured." The resolved
  value is never cached, logged, or placed in any audit line — see
  `CONTRACTS.md`'s "Secrets wire"/§6 sections for the wire contract and
  the resolve-consumer honesty note.
  **The pairing ceremony's three methods (P-P2,
  CONTRACTS.md §6's "Pairing wire" subsection)** — `pair_request`
  (`aoide/pairRequest`), `pair_reveal` (`aoide/pairReveal`), and
  `pair_approve_callback` (`aoide/pairApprove`) — join this same JSON-RPC
  dispatch table, deliberately UNGATED by `read_ok`/bearer verification:
  the ceremony's whole point is establishing a credential where none
  exists yet, so gating any of the three on one would be circular. None
  grants anything beyond a `pubkey`/`verified` peer record, and that
  record commits only on BOTH ends' own separate human confirmation — the
  default `allows` (`["read","spawn"]`) is stamped by
  `aoide_storage::peer_store::upsert_paired_peer` itself, the moment a peer
  first becomes verified (P-P3, PAIRING.md decision 5), never by these three
  methods directly. `pair_request`
  validates every field (64-hex pubkey, 64-hex commitment, a
  `valid_peer_name` name, a non-empty `://`-bearing url) before calling
  `aoide_storage::pairing::park_inbound` — malformed input never reaches
  the parked-state file, and a park past the configured cap is refused
  with a distinct `-32000`. `pair_reveal` is the ceremony's
  third message: it checks a POSTed nonce against the parked entry's
  earlier commitment (`aoide_storage::pairing::reveal_inbound`) — a match
  stores the nonce so a SAS becomes derivable; a mismatch DROPS the parked
  entry outright and answers the distinct `-32002` (unlike the
  approve callback's mismatch handling below, a bad reveal is exactly the
  shape a MITM's forced retry would take, so it is not treated as a
  recoverable hiccup — the reveal is unauthenticated, so a third party
  who obtains a live pending id can destroy that one ceremony attempt
  with a bogus reveal: an accepted denial-of-one-attempt, never an
  impersonation, and the operators simply re-run the ceremony).
  `pair_approve_callback` looks up the matching
  outbound entry by id and, on a pubkey match, only TRANSITIONS its state
  (`aoide_storage::pairing::mark_outbound_awaiting_confirm`,
  `AwaitingApproval` → `AwaitingConfirm`) — it commits no peer record on
  either a match or a mismatch; a mismatch leaves the entry
  untouched (never re-parked, never dropped) so a legitimate retry after a
  transient hiccup isn't permanently broken. The requester's own peer
  record commits later, entirely inside `aoide-client`, once that
  instance's own operator confirms the SAS a second time. All three audit
  via the existing `Door::A2a` audit sink (`a2a.pairRequest`/
  `a2a.pairReveal`/`a2a.pairApprove`), same as every other A2A method.
  **The Spawn arm's gate (P-P3, narrowed again by P-P4, PAIRING.md
  decision 6 + the wire-authentication section)** —
  `message_send`'s `SendAction::Spawn` arm no longer consults
  `token_authorized` (the door-wide bearer, 2026-08-19's own amendment) at
  all: it requires `spawn_admitted`, which accepts ONLY a
  `PeerRung::Signature` resolution to a peer that is BOTH `verified` and
  carries `"spawn"` in `allows` (`peer_may_spawn`, pure and directly
  unit-tested against `Peer` fixtures — no test in this file drives
  `do_spawn`'s real OS-level process spawn, same house rule every other
  Spawn-arm test already follows). That resolution comes from
  `verify_signed_request` (P-P4) — called once per connection in
  `handle_connection`, before any dispatch — which authenticates a
  request's `X-Aoide-Peer`/`X-Aoide-Timestamp`/`X-Aoide-Nonce`/
  `X-Aoide-Signature` headers against the named peer's stored public key
  (CONTRACTS.md §6's P-P4 amendment has the full canonical-string/header
  shape and pinned vectors) and threads the proven name down as
  `signed_peer_name`; when present, `message_send` resolves EXCLUSIVELY
  against it, never falling back to `aoide_storage::peer_store::
  resolve_peer`'s own two-rung ladder (a peer's own `token_file` —
  `PeerRung::Token` — else the TCP origin against a peer's `url` —
  `PeerRung::Addr`, the SAME identification the door's
  `is_autogated_peer_addr`/`is_autogated_peer_token` already fold, just
  unfiltered by `autogate` and narrowed to one named peer) even on a
  registry-lookup miss. Neither the `Addr` nor the (now-insufficient)
  `Token` resolution reaches Spawn any more — a bare TCP-source-IP-vs-`url`
  match carries no possession proof, and a bare shared-secret token is
  replayable and identical across every request the true peer or an
  impersonator ever sends; both rungs still resolve a peer identity for
  attribution/origin-stamping purposes below, just never for Spawn. A
  caller resolved via `Token` to a genuinely paired peer gets a taught
  `-32006` telling it plainly to sign requests (its aoide is too old, or
  is failing to sign); a `Signature`-resolved peer missing the `spawn`
  capability gets the exact `peer allow` fix; every other shape gets the
  original "pair first, then allow" message. The resolved peer's name also
  threads two ways past the gate: `do_spawn` sets
  `AOIDE_SESSION_ORIGIN=peer:<name>` on the child it launches (read by
  `aoide-conduct`'s `session_conduct`, which stamps
  `SessionRecord.origin`), and the Inject arm's own `resolved_peer` (a
  SEPARATE, ungated identity lookup — attribution, never a gate) rides
  `do_inject`'s existing `--from` flag onto a QUEUED `pending.json` entry
  only (an immediately-delivered payload's bytes stay untouched, so an
  already-autogated peer's delivery is byte-identical to before this
  phase).
- `discovery` — the discovery beacon's ADVERTISE half (P-P6,
  `docs/architecture/PAIRING.md`'s "Discovery (advertise-but-locked)"
  section, CONTRACTS.md §6's "Discovery beacon" subsection). `a2a::serve`
  calls `spawn_advertiser` exactly once, at launch, ONLY when
  `a2a::resolve_discovery_advertise` (`--discovery-advertise`/
  `AOIDE_DISCOVERY_ADVERTISE`, mirroring `resolve_bind_port`'s own
  precedence) says on — off by default, no thread, no socket, no identity
  file touched at all otherwise. Each tick (~30s, jittered) binds a fresh
  ephemeral UDP socket, sends one `aoide_storage::beacon` line to the
  fixed multicast group+port, and drops the socket — fire-and-forget, no
  connection state held between ticks. Fallible spawn
  (`thread::Builder::spawn`, `daemon.rs`'s discipline, not `a2a.rs`'s own
  plain `thread::spawn` for connection handlers — that one is reserved for
  a NEW socket-based door, not a background worker thread) — a refused OS
  thread costs discovery only, never the door. The RECEIVE half
  (`peer discover`/`peer invite`'s multicast sweep) lives in
  `aoide-client::discover` instead; this crate stays inbound/serve-only.
- `commands` — this crate's CLI commands: `daemon`, `shellbridge` (registration
  only — the files stay in `conduct`), `a2a serve`, `events tail` (P-D3,
  appended newest — CLI-only, the same door-policy shape `a2a serve`/
  `aoide_secrets::commands::handle_secrets_watch` already hold for a
  foreground/blocking command).

## What it consumes

`aoide-protocol`, `aoide-storage`, `aoide-conduct`, `aoide-secrets` (task
#84 — the A2A door's inbound bearer resolve, `aoide_secrets::client::
resolve_bounded`, reused rather than a second wire client written here).
`aoide-client` is a dev-dependency only (one round-trip test) — production
code never calls into the outbound client from here.

## How it composes

Sits above `conduct` (reads/writes session state via `do_inject`/`do_spawn`/
`tasks/get`) and `storage`. **The registry-parameter seam**: `mcp::serve_stdio`
and `a2a::serve` take the assembled `Registry` and dispatcher as parameters
rather than reaching for a crate-global singleton — that singleton doesn't
exist until the app crate (`cli`/`lyra`) assembles it, and `server → cli`
would invert the dependency direction the whole split exists to forbid.
