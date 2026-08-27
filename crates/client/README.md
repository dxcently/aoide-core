# aoide-client

Aoide's outbound door: the A2A client-side wire builders/parsers and the
melete neutral-event adapter. Drives external agents and talks to `aoided`;
never the inbound/serve half (that's `aoide-server`).

## Named seams (what it exposes)

- `daemon` — the fourth door's outbound half (P-D6, `docs/architecture/
  AOIDED.md`'s "L4 — graph residency"): `daemon_dispatch(&Invocation) ->
  Option<Outcome>` tries the resident `aoided`'s `{"op":"dispatch"}` wire
  (`socket_path()` re-derives `$AOIDE_DAEMON_SOCKET` →
  `$XDG_RUNTIME_DIR/aoide/aoided.sock`, the identical convention
  `aoide_server::daemon::socket_path` resolves — re-derived rather than
  imported, since this crate sits BELOW `aoide-server` in the DAG) with a
  bounded connect (`connect_bounded`, a background-thread-plus-channel
  race, ~100ms). `None` means "nothing usable answered" — the caller's own
  pre-existing direct stage-write path runs unchanged; any OTHER failure
  once a connection exists becomes `Some(Outcome::error(...))` instead of a
  silent fallback, since a daemon that answered but broke is a real bug
  worth surfacing. `inv.door == Door::Daemon` short-circuits to `None`
  immediately — the reentrancy guard that stops a handler running INSIDE
  the daemon (because a remote caller's request just landed) from trying
  to connect to itself.
- `wire` — client-side A2A JSON-RPC message builders
  (`build_message_send_body` and `resolve_card_url`).
- `adapter` — the melete neutral-event adapter (consumes events, stays
  agnostic of any one downstream agent's shape).
- `peer` — peer-federation client half (CONTRACTS.md §7), joined at P-P2 by
  the pairing ceremony's own wire builders/parsers:
  `build_pair_request_body`/`parse_pair_request_response` (the requester's
  `aoide/pairRequest` call, carrying a `commitHex`, never a
  `nonceHex`), `build_pair_reveal_body`/
  `check_pair_reveal_response` (the requester's immediately-following
  `aoide/pairReveal` call), and `build_pair_approve_body`/
  `check_pair_approve_response` (the approver's `aoide/pairApprove`
  callback) — pure JSON-RPC envelope builders/parsers only, same split as
  the graphSummary pair above them; the server-side handlers
  (`pair_request`/`pair_reveal`/`pair_approve_callback`) live in
  `aoide-server::a2a`, never duplicated here.
- `discover` — the discovery beacon's LISTEN half (P-P6,
  `docs/architecture/PAIRING.md`'s "Discovery (advertise-but-locked)"
  section): `run_sweep(secs)` joins `aoide_storage::beacon::GROUP`/`PORT`,
  listens for a bounded window, validates every line heard
  (`aoide_storage::beacon::parse_and_validate`), and folds survivors into a
  `SweepResult` deduped by fingerprint, freshest wins (`fold_heard`, pure,
  unit-tested with no socket at all — the same pure-fold/impure-socket
  split `aoide-server::a2a`'s own `route`/`handle_connection` holds). Each
  `Heard` carries the packet's `src_addr` alongside its `beacon` (P-S1) —
  the beacon's own `url` is what the advertiser CLAIMS (useless for a
  loopback-bound door, since it always reads `http://127.0.0.1:<port>/`
  regardless of who hears it); `src_addr` is what this process actually
  OBSERVED the packet arrive from. `Beacon` itself is CONTRACTS-pinned wire
  shape and never gains this field — `src_addr` lives only on `Heard`,
  local-only and unpinned. `invite_dial_url(beacon_url, src_addr)` composes
  `peer invite`'s ceremony dial target from that observation: it swaps only
  the host, preserving scheme/port/path verbatim from `beacon_url` (the
  path preservation matters — `sign_headers_for_peer` signs over the path,
  never the host), and refuses a non-`http`/`https` scheme or a malformed
  authority. `is_self_target(beacon_fpr, own_fpr, dial_url, own_urls)` is
  the self-invite guard: true when the heard fingerprint is this instance's
  own, or when the composed dial target is loopback or matches one of this
  instance's own known urls. `resolve_invite_target(heard, name)` is the
  same shape one layer up: `peer invite`'s zero/one/many-match resolution
  against an already-swept result, also pure, and returns the whole `Heard`
  so `src_addr` reaches `peer invite` for free. This crate's send-side
  counterpart (`a2a serve`'s own advertise thread) lives in
  `aoide-server::discovery` instead — sending is the door-owning process's
  own job; listening is this crate's outbound-facing action, the same
  "outbound only" charter every other module here holds.
- `tunnel` (P-S3, ssh-transport lane) — the ssh child, and the only place
  in this workspace that ever spawns one. `open_or_reuse(session_id, key,
  via, remote_host, remote_port) -> Result<u16, String>` loads any record
  already on file for `(session_id, key)` (`aoide_storage::tunnel::load`);
  a record whose pid is alive AND whose local port answers a bounded probe
  is reused as-is (no second `ssh`). Anything else is stale — a dead pid,
  or a live process whose forward nothing answers on — and the record is
  about to be REPLACED by a freshly opened one at the same `(session_id,
  key)`, on a freshly reserved local port (the
  `TcpListener::bind("127.0.0.1:0")` read-back-drop idiom
  `cli/tests/peer_connectivity.rs::free_port` already established); a
  live-but-dead-port OLD pid is killed first (`kill_if_still_our_ssh`, the
  same guard `close` uses below) — review finding, P-S3 — since once its
  record is overwritten nothing could ever find that pid again (`close`/
  the reaper only ever act on a pid loaded FROM a record). The spawned
  `ssh -N -T -o BatchMode=yes …` (stdin/stdout/stderr all `null`) is polled
  (`TcpStream::connect`) until its forward answers or a bounded deadline
  elapses (default 8s, `AOIDE_TUNNEL_OPEN_TIMEOUT` overrides, the same
  unparsable-or-zero-falls-back-to-default shape
  `aoide_storage::pairing::pairing_timeout_secs` holds) — and the poll loop
  also watches the child's own exit (`Child::try_wait`) so a doomed forward
  (missing `authorized_keys`, a refused/unreachable host) fails in well
  under a second instead of sitting out the whole deadline, which is the
  entire reason `ExitOnForwardFailure=yes` is on the argv. Any failure past
  that point — the deadline, an early exit, or the record failing to save
  even after a healthy answering spawn — kills and reaps the child, removes
  any record, and surfaces a taught error naming the ssh target and the
  one-time manual `authorized_keys` step; aoide never writes that file for
  anyone. `close(session_id, key)` SIGTERMs the recorded pid and removes
  the record, idempotent on a record already gone; before signaling
  anything it checks `/proc/<pid>/cmdline` actually names `ssh` carrying
  this exact `-L` spec (`looks_like_our_ssh`, wrapped as
  `kill_if_still_our_ssh`, shared with the stale-reopen path above) — a pid
  an earlier `aoide` invocation recorded may have been recycled by the OS
  to an unrelated process by the time anything acts on it, and a pid alone
  is never enough to justify a signal. Once a kill IS justified,
  `terminate_pid` reaps with a real `waitpid(pid, WNOHANG)` poll before
  ever falling back to a `/proc` poll — required whenever `open` and
  `close` (or a stale reopen) share a process, since that pid genuinely IS
  this process's own child and nothing else will ever collect it; `ECHILD`
  (the ordinary cross-invocation case) falls back to the `/proc` poll, same
  as always. `close_all_for_session(session_id)` closes every tunnel
  recorded for that session, best-effort across all of them. The actual
  spawn is an injected closure internally (the same `Arc<dyn Fn(...)>`
  shape `aoide_conduct::graph::who::PullFn` holds for its own live-probe
  seam, re-derived rather than imported) so every reuse/stale/timeout/
  early-exit/reap branch is unit-tested with a fake spawn (an innocuous
  real `sleep`/`sh` child, never `ssh` — one fake overrides its own
  `argv[0]` to `"ssh"`, `CommandExt::arg0`, purely so `looks_like_our_ssh`
  can be exercised against a genuine, killable process) — the one
  `#[ignore]`'d real-ssh proof lives at `cli/tests/tunnel_ssh.rs` instead,
  the same "real bytes, not a mock, but sandboxed-build-unsafe" shape
  `peer_connectivity.rs` already holds.
- **Dial resolution (P-S4, ssh-transport lane)** — the tunnel seam every
  outbound POST resolves through BEFORE it ever reaches `commands::
  post_json` (`aoide-client`'s one HTTP transport, unchanged by this
  phase). `resolve_dial_url(logical_url, via, tunnel_key)` is the funnel:
  `via: None` returns `logical_url` byte-for-byte (the "off = unchanged"
  guarantee, pinned per call site); `via: Some` opens/reuses `tunnel::
  open_or_reuse` and rewrites the authority to `127.0.0.1:<local port>`
  via `aoide_storage::tunnel::dial_url`, which preserves the PATH
  verbatim — the reason `sign_headers_for_peer`'s canonical string (signed
  over `peer_store::url_path(&peer.url)`, computed independently and
  never touching the dial url) still verifies on the far end.
  `post_json_to_peer(peer, …)` resolves `peer.via` (keyed by `peer.name`);
  `post_json_via(logical_url, via, tunnel_key, …)` is the same funnel for
  the three ceremony dials that have no `Peer` record yet
  (`aoide/pairRequest`/`pairReveal` in `run_pair_request`,
  `aoide/pairApprove` in `approve_inbound`) — keyed by the ceremony's own
  local nickname. `spawn_on_peer_via(peer, text, via_override)` is
  `spawn_on_peer`'s own body plus an explicit override that beats
  `peer.via` (`peer spawn --via`); `spawn_on_peer` itself stays a thin
  `via_override: None` wrapper so `aoide-conduct`'s existing call site
  needs no change. `--via` (`ssh://[user@]host[:port]`,
  `aoide_storage::tunnel::parse_via`) is a FLAG on `peer.add`/
  `peer.invite`/`peer.pair.request`/`peer.spawn` — never a new command
  path — parsed by the shared `parse_via_flag` (absent is `None`,
  malformed is a usage error, the same `parse_secs_flag` stance).
  **`peer add`'s AgentCard verification (its ONE network call) dials
  through `resolve_dial_url` too when `--via` is given** — the review
  finding this needed fixing for: the exact scenario `--via` exists for (a
  loopback-bound door reachable only through the tunnel) used to fail
  verification, before the peer was ever registered, making the flag dead
  weight on `add`. The fetch target is the REWRITTEN url (its path —
  `/.well-known/agent-card.json` — preserved verbatim by the same funnel);
  the recorded `Peer.url` stays the LOGICAL url either way. No signing is
  involved (a card fetch is a plain GET), so there is no canonical-string
  path to keep in sync here, unlike the signed peer calls this funnel also
  serves.
  The session id a tunnel opens under (`tunnel_session_id`) is
  `AOIDE_SESSION_ID` when a conducted session set it, else a
  process-scoped `pid-<pid>` fallback (K3). This crate only resolves and
  passes that key through — it never closes a tunnel itself, on purpose:
  `pull_peer_live`/`send_message_to_peer`/`spawn_on_peer` are called from
  `aoide-conduct` command handlers this crate cannot wrap, and a partial
  close covering only the client-owned handlers would make the same
  function behave inconsistently by caller. The real lifecycle lives one
  crate up, in `aoide-conduct`, and differs by key shape: a session-keyed
  tunnel is closed on its session's own clean exit
  (`aoide_client::tunnel::close_all_for_session`, called from
  `graph::session_store::do_session_end`'s fast path) and, for a session
  that never gets to run that exit, by `reap::sweep_orphan_tunnels`'s
  backstop; a pid-scoped tunnel has no session lifecycle to hook a fast
  path into at all — its one-shot CLI process has already exited by the
  time any reap pass runs, so the SAME sweep collects it through its
  ordinary dead-pid arm. Both key shapes converge on one sweep; neither is
  a special case of it.
  Every tunneled request reaches the far door as `PeerOrigin::Loopback`
  (`aoide-server::a2a::classify_origin`), which carries an unconditional
  delivery free pass for an UNSIGNED request. `aoide-server::a2a` narrows
  that free pass for a request carrying a verified per-request signature
  (`origin_for_inject`, CONTRACTS.md §6) — a signed caller is a remote peer
  by construction and never rides Loopback's trust, so tunneled delivery is
  safe against a real, non-autogate peer, not merely possible.
- `commands` — this crate's CLI commands:
  `peer add/remove/pull/status/hub/allow/spawn/discover/invite`,
  `peer pair request/pending/approve/reject` (P-P2, CONTRACTS.md §6/§7 —
  `handle_peer_allow` (`peer allow <name> <cap> on|off`, P-P3, `docs/
  architecture/PAIRING.md` decision 5) is a thin wire around
  `aoide_storage::peer_store::set_peer_allow` — idempotent, refuses an
  unknown peer or an unknown capability with distinct taught errors, no
  network call (this instance's own `state/peers.json` is authoritative
  for its own `allows` grants) —
  `confirm_sas`/`default_self_url` are this group's own local helpers:
  `confirm_sas` (like `confirm_spawn` below) is a thin wrapper around
  `aoide_protocol::pick::confirm` (ONBOARD.md's prompt substrate section,
  P-I1) rather than a hand-rolled stdin read — `inquire::Confirm` on a tty,
  the identical `y/N` stdin read otherwise; the question text is unchanged,
  `confirm` owns the `[y/N]` decoration now). `handle_peer_pair_request` sends
  the commitment and its reveal as two sequential POSTs in one invocation
  before ever computing a SAS. `handle_peer_pair_approve`
  dispatches by direction: on an INBOUND entry (`approve_inbound`) it
  refuses an unrevealed one outright, then delivers the `aoide/pairApprove`
  callback to the requester BEFORE writing any local peer record — an
  unreachable requester must leave BOTH ends unpaired, never just the
  approver's; on an OUTBOUND entry (`approve_outbound`, reached only once
  the approver's own callback already transitioned it to
  `awaiting-confirm`) it makes no wire call at all and commits THIS
  instance's own record directly on confirmation (decision 4's
  mutual confirmation, on both ends). `handle_peer_pair_reject` tries
  the inbound queue then the outbound queue, aborting an outbound entry at
  any stage — the ceremony's abort command.
  **`run_pair_request(cmd, url, name, self_url, dial_via, record_via)`
  (P-P6, `dial_via`/`record_via` added P-S4) is `handle_peer_pair_request`'s
  own body, extracted so `peer invite` reaches it too — reused, never
  copied.** `handle_peer_pair_request` still owns every bit of
  `<url>`/`--name`/`--self-url`/`--via` parsing and the `valid_peer_name`
  check (a CLI-typed name needs it); `handle_peer_invite` calls straight
  into `run_pair_request` with a `url`/`name` already lifted off an
  already-validated, already-confirmed discovery beacon, needing no second
  name check. `dial_via`/`record_via` are deliberately separate: `dial_via`
  is what the ceremony's OWN two POSTs tunnel through — `None` unless an
  explicit `--via` was given, so a plain ceremony still dials directly
  (P-S1's `invite_dial_url` already resolves a working LAN target; forcing
  every pairing through ssh by default was not asked for). `record_via` is
  the string parked onto `OutboundPairingRequest.via` for LATER commit
  (`approve_outbound`) onto the peer record this ceremony creates —
  `handle_peer_invite` defaults it to K1's src_addr-derived
  `default_via(&hit.src_addr, "")` even when `dial_via` is `None`, so the
  resulting peer still gets an automatic transport marker for its own
  FUTURE calls. `handle_peer_discover`/`handle_peer_invite` (`peer
  discover [--secs N]`/`peer invite <name> [--secs N] [--yes]`) are thin
  wrappers around `discover::run_sweep`/`discover::resolve_invite_target`
  above — `confirm_invite` is this pair's own local helper, still the
  original hand-rolled `y/N` stdin read `confirm_sas`/`confirm_spawn` used
  to share before their P-I1 retrofit onto `aoide_protocol::pick::confirm`
  above — out of that phase's own scope, not an oversight; it now shows
  both the beacon's advertised `url` and its observed `src_addr` side by
  side, so an operator sees the substitution before it happens.
  `handle_peer_invite` composes its ceremony dial target with
  `discover::invite_dial_url(hit.beacon.url, hit.src_addr)` rather than
  dialing `hit.beacon.url` verbatim, and refuses before dialing anything
  when `discover::is_self_target` says the resolved target is this
  instance's own door (P-S1) — `peer discover`'s own JSON `heard` rows
  gain a `srcAddr` field alongside `url` for the same reason.
  `adapter melete` (`peer hub
  <name> [--clear]`, P-D5, designates at most one registered peer as the
  hub `aoide_storage::addr::resolve_with_hub` prefers as a last-resort
  remote target — `peer_store::set_hub`/`clear_hub` hold the invariants,
  this handler just reports which of set/moved/cleared/no-op happened);
  also exposes two
  non-command functions that are the `conduct → client` edge's crossing
  points: `pull_peer_live` (`who`'s live per-peer probe, read-only) and
  `send_message_to_peer` (`send --to <peer>/<query>`'s delivery,
  workstream C3 — POSTs `message/send` with an explicit `contextId` naming
  the resolved remote session). **Outbound bearer presentation (task
  #84)**: `peer add --bearer-secret <name>` records a per-peer
  `Peer.bearerSecret` (`aoide-storage`'s `peer_store`); every outbound
  peer POST (`pull_one_peer`, `pull_peer_live`, `send_message_to_peer`)
  resolves it FRESH through `aoide_secrets::client::resolve_bounded` as
  consumer `a2a-client` and presents it as `Authorization: Bearer <value>`
  — absent (the default) still sends no bearer at all, today's exact
  behavior. The token never touches curl's argv (readable via
  `/proc/<pid>/cmdline`): `post_json` routes it through curl's `-H @-`
  (header read from stdin) instead of a literal `-H "Authorization: ..."`
  argument, moving the (non-sensitive) request body to a short-lived
  `ScratchBodyFile` only on the bearer-present path. A broker-unreachable
  or denied resolve errors out with a taught message naming the secret
  and the broker socket, rather than silently sending no bearer.
  **Outbound signed-request headers (P-P4,
  `docs/architecture/PAIRING.md`'s wire-authentication section,
  CONTRACTS.md §6's own amendment)**: `sign_headers_for_peer` is the ONE
  production caller that builds the four `X-Aoide-*` headers — for a
  `peer.verified` target it loads this instance's own P-P1 identity
  (`aoide_storage::identity::load_or_mint`), mints a nonce
  (`aoide_storage::pairing::random_hex(16)`, the same mint the pairing
  ceremony already uses), signs
  `aoide_storage::wire_auth::canonical_string(HTTP_METHOD,
  aoide_storage::peer_store::url_path(&peer.url), timestamp, nonce, body)`
  with `aoide_storage::wire_auth::sign_hex`, and sends `X-Aoide-Peer` as
  `peer.name` (this instance's own local registry name for the
  counterpart — the pairing ceremony's single shared `name` value makes it
  identical to what the counterpart's own registry resolves back to this
  instance). `HTTP_METHOD` (P-P5b, closing a P-P4 review finding) is the
  ONE named constant `post_json`'s own `-X` argument reads too — before
  this fix the two carried independent `"POST"` literals that merely
  happened to agree; now there is exactly one value to drift from. An
  unverified/unpaired peer gets an empty header list — byte-identical to
  the pre-P-P4 transport. Wired into all four real peer-POST call sites
  (`pull_one_peer`, `pull_peer_live`, `send_message_to_peer`,
  `handle_peer_spawn` — P-P5b, the FIRST of the four to ever sign a
  `contextId`-less, spawn-shaped body); the pairing ceremony's own three
  wire calls stay unauthenticated by design and always pass an empty
  slice. `post_json` threads `extra_headers` as plain `-H "<name>:
  <value>"` curl argv literals in EITHER the bearer or no-bearer branch —
  unlike the bearer token, nothing in a signature header is a secret worth
  hiding from `/proc/<pid>/cmdline`.
- **`spawn_on_peer(peer, text) -> Result<Value, String>`** is the wire-level
  seam for a spawn-shaped `message/send` — builds
  `crate::wire::build_message_send_body(text, messageId, None)` (`contextId`
  omitted, `<text>` riding as the prompt `aoide-server::a2a::do_spawn` types
  into the newly spawned session's first turn), signs it via
  `sign_headers_for_peer` above, and posts it. Mirrors
  `send_message_to_peer`/`pull_peer_live`'s own `Result`-not-`Outcome`
  shape (the caller builds its own `Outcome`/audit line). Two callers:
  **`handle_peer_spawn` (P-P5b, `peer spawn <name> [--yes] -- <text…>`)**
  makes PAIRING.md's spawn gate reachable from the CLI — gates LOCALLY on
  exactly one question (is `name` a registered, `verified` peer at all — an
  unsigned request could never satisfy the remote's `PeerRung::Signature`
  -only requirement regardless), refusing with a taught error naming `peer
  pair request`, then confirms (`--yes` skips only this LOCAL `y`/`N`
  prompt, `confirm_spawn`, mirroring `confirm_sas`'s idiom) before calling
  `spawn_on_peer` and shaping the `Outcome`. **`aoide-conduct`'s manifest
  remote-summon path** (U4, command-defrag lane U — `graph::resurrect::
  summon_remote`, the `conduct` → `client` edge documented in `conduct`'s
  own `Cargo.toml`) calls `spawn_on_peer` directly, no confirm: a manifest
  spec is itself the operator's standing declaration. Either way, every
  OTHER refusal (`allows` lacking `spawn`, an unsigned-but-paired caller,
  clock skew, an unreachable peer) is the remote door's — or the
  transport's — own call, surfaced verbatim as `spawn_on_peer`'s `Err`;
  neither caller re-derives or second-guesses it.

## What it consumes

`aoide-protocol` and `aoide-storage` (the peer registry and pull cache
persist through `storage`), and `aoide-secrets` (task #84 — outbound
per-peer bearer resolve, `aoide_secrets::client::resolve_bounded`, reused
rather than a second wire client written here).

## How it composes

`conduct`, `screen`, `server` (dev-dependency only, for one round-trip
test), and `cli` depend on it. **The `conduct → client` edge is intentional,
not technical debt**: `conduct`'s `who` presence command (workstream C2,
landed) calls this crate's `commands::pull_peer_live` for its live
per-peer probe, `send --to`'s remote branch (workstream C3, landed)
calls `commands::send_message_to_peer` to deliver, and (P-D6) every
session-write handler (`session start/phase/end/hook`, `session reap`)
calls `daemon::daemon_dispatch` first — the edge stays even though the
original reason (`screen/send.rs`) moved out to the `screen` crate at P-A1
(`docs/architecture/PACKAGE-LAYOUT.md`, "Verified facts").
