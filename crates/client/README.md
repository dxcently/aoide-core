# aoide-client

Aoide's outbound door: the A2A client-side wire builders/parsers and the
melete neutral-event adapter. Drives external agents and talks to `aoided`;
never the inbound/serve half (that's `aoide-server`).

## Named seams (what it exposes)

- `context` implements `aoide context --id <session>`: local CLI requests
  daemon-owned, read-only persona/memory retrieval through the optional
  portable `context` config. The CLI requires aoided; MCP/A2A are refused.
  Its CLI reply wait is bounded at 120 seconds for the sequential 15-second
  HTTP requests and cleanup; timeout is incomplete, never retried. Other
  daemon dispatch callers retain their two-second bound.
  Configure the named `tokenEnv` in **aoided's environment**: caller secrets
  are not forwarded in an invocation. Missing bindings, mappings, credentials,
  or note references fail explicitly. No cache, prompt insertion, or write.
  `mcp_client::McpSession` performs initialize/initialized and carries the
  negotiated protocol version and optional MCP session ID through every
  request. `commands::request_json_with_headers` keeps bounded response headers
  alongside the body through the existing curl runner; credentials and MCP
  session headers use stdin, never argv. Melete's existing commands retain
  their stateless behavior. Assigned MCP sessions receive a bounded DELETE
  after retrieval (and after a failed initialization); cleanup failure does
  not replace the primary result. `sessionCleanup` reports closed, unsupported
  (HTTP 405), failed, or not-applicable for a stateless server.
  Each requested `.md` path must appear exactly in `list_notes` before
  `read_note`. Returned notes include content, SHA-256, requested reference,
  and retrieval time. These are sequential reads with no server revision:
  Mneme may alias-resolve a path changed between listing and reading, so
  coordinated writers must keep references stable during retrieval. A later
  failure returns a nonzero outcome with `complete=false` and any earlier
  fetched notes explicitly separated from errors.

- `daemon` — the fourth door's outbound half (P-D6, `docs/architecture/
  AOIDED.md`'s "L4 — graph residency"): `daemon_dispatch(&Invocation) ->
  Option<Outcome>` tries the resident `aoided`'s `{"op":"dispatch"}` wire
  (`socket_path()` resolves `$AOIDE_DAEMON_SOCKET` →
  `$XDG_RUNTIME_DIR/aoide/aoided.sock`, the identical convention
  `aoide_server::daemon::socket_path` resolves — this crate sits BELOW
  `aoide-server` in the DAG, so it is never imported from there; as of
  LANE IDENTITY P-ID4 the derivation's body, the bounded connect
  (`connect_bounded`, a background-thread-plus-channel race, ~100ms), and
  the `daemon_seal_pubkey_hex` ping fetch all live in
  `aoide_storage::attest`, with this module's public seams delegating —
  the secrets broker's origin gate needs the same fetch and cannot depend
  on this crate). `None` means "nothing usable answered" — the caller's own
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
- `mcp_client` (M2, task #14) — the Melete MCP client: `melete
  status|graph|call`. Not the same thing as `adapter`'s melete consumer
  above — `adapter` consumes aoide's OWN outbound neutral event stream
  INTO melete; `mcp_client` is the reverse direction, aoide calling OUT to
  Melete's own MCP connector (Melete's stated "only machine surface").
  Speaks MCP (JSON-RPC 2.0 over HTTP POST — `initialize`/`tools/list`/
  `tools/call`) over `commands::post_json` (widened `pub(crate)` for this),
  the SAME curl transport `node` already uses — zero new Cargo dependency,
  TLS comes free with curl. `melete status` runs `initialize` and reports
  reachability plus `serverInfo`/`protocolVersion`; `melete graph` calls
  the `graph_view` tool and writes the snapshot to `state/melete-graph.json`
  (`aoide_storage::fs::state_dir()` — never a hardcoded path); `melete call
  <tool> [--args <json>]` is a generic gated `tools/call` passthrough
  (`job_status`/`run_code_task`/`schedule_*`/`stop_run`/`steer_run`/…) —
  deliberately no per-tool commands, so a change to Melete's own tool list
  never needs a matching aoide release. The connector's endpoint/token ride
  `AOIDE_MELETE_URL`/`AOIDE_MELETE_TOKEN` (env-only, read fresh per call,
  the token never touching argv or disk) rather than `node_store` — Melete
  is a third-party MCP service, never an aoide node, so the AgentCard-
  verified/signed federation shape doesn't fit; unconfigured is a
  structured, taught `Outcome::error` naming both vars, never an invented
  credential. All three commands are `Door::Cli`-only, matching
  `aoide-secrets`' own blanket stance for its whole command family: every
  call sends a live bearer token outward and `call` can trigger real,
  possibly cost-incurring action, so the family is refused over MCP/A2A/
  Daemon wholesale rather than gating only the consequential command.
  A response is read defensively off a raw `Value` (never forced through
  `aoide_protocol::wire::mcp`'s server-side result structs) and, failing a
  plain-JSON parse, as an SSE-framed (`data: `-line) body — Melete is
  assumed to be a streamable-HTTP MCP server, so either shape must parse.
- `node` — node-federation client half (CONTRACTS.md §7), joined at P-P2 by
  the pairing ceremony's own wire builders/parsers:
  `build_pair_request_body`/`parse_pair_request_response` (the requester's
  `aoide/pairRequest` call, carrying a `commitHex`, never a `nonceHex` —
  and, task #131, an OPTIONAL `selfVia` beside `self_url`: the requester's
  own self-asserted reach-back hop claim, same trust class as `self_url`,
  omitted outright rather than sent `null` when the caller has none, so an
  old approver — which never looks for the field — sees exactly the shape
  it always has), `build_pair_reveal_body`/
  `check_pair_reveal_response` (the requester's immediately-following
  `aoide/pairReveal` call), and `build_pair_poll_body`/
  `parse_pair_poll_response` (the requester's `aoide/pairPoll` call —
  Design A, task #119, REPLACES the old `aoide/pairApprove` reverse
  callback: the requester polls the approver's door over the SAME forward
  dial the request/reveal already used, rather than the approver ever
  dialing back) — pure JSON-RPC envelope builders/parsers only, same split
  as the graphSummary pair above them; the server-side handlers
  (`pair_request`/`pair_reveal`/`pair_poll`) live in `aoide-server::a2a`,
  never duplicated here.
- `discover` — the discovery advertisement's LISTEN half (P-P6 + task
  #120, `docs/architecture/PAIRING.md`'s "Discovery
  (advertise-but-locked)" section): `run_sweep(secs)` binds
  `0.0.0.0:aoide_storage::advertise::PORT` (a plain bind hears the
  broadcast — no group join, no interface pinning, no capability
  probing), listens for a bounded window, validates every line heard
  (`aoide_storage::advertise::parse_and_validate`), and folds survivors
  into a `SweepResult` deduped by (name, source), freshest wins, BOUNDED
  at `MAX_HEARD` distinct entries (a flood past the cap counts as
  dropped) — `fold_heard`, pure, unit-tested with no socket at all, the
  same pure-fold/impure-socket split `aoide-server::a2a`'s own
  `route`/`handle_connection` holds. Each `Heard` carries the packet's
  `src_addr` alongside its `advertisement` (P-S1) — the advertisement's
  `host`/`user` are what the advertiser CLAIMS; `src_addr` is what this
  process actually OBSERVED the packet arrive from, and the address
  anything downstream dials. `Advertisement` itself is CONTRACTS-pinned
  wire shape and never gains this field — `src_addr` lives only on
  `Heard`, local-only and unpinned. `is_self_target(heard, own_name)` is
  the self-invite guard: true when the heard name is this instance's own
  or the datagram came from loopback (a broadcast always loops back to
  its own sender). Known gap: a serve advertising under a custom
  `--node-name` flag escapes the name arm (`own_name` here derives from
  env/hostname only) and the self-heard broadcast arrives on the
  physical interface, so such a self-invite proceeds — confusion, not
  compromise; the SAS ceremony backstops it. `resolve_invite_target(heard, name)` is the same
  shape one layer up: `pair`'s hostname arm's zero/one/many-match
  resolution against an already-swept result, also pure, and returns the
  whole `Heard` so `src_addr` reaches that arm for free. Three consumers
  drive `run_sweep`: `handle_node_discover`, `pair_via_hostname`, and
  `aoide-conduct::graph`'s `node list` (task #120 P2 — one ~2s sweep
  merged into the mesh roster's advertising marks and `◆` candidate
  rows; `is_self_target` is its self-row guard too), all read-only,
  never a second sweep implementation. This crate's
  send-side counterpart (`a2a serve`'s own advertise thread) lives in
  `aoide-server::discovery` instead — sending is the door-owning process's
  own job; listening is this crate's outbound-facing action, the same
  "outbound only" charter every other module here holds.
- `tunnel` (P-S3, ssh-transport lane) — the ssh child, and the only place
  in this workspace that ever spawns one. `open_or_reuse(session_id, key,
  via, remote_host, remote_port) -> Result<u16, String>` loads any record
  already on file for `(session_id, key)` (`aoide_storage::tunnel::load`);
  a record whose pid is alive AND whose local port answers a bounded probe
  is reused as-is (no second `ssh`). Anything else is stale — a dead pid,
  or a live process whose forward nothing answers on — and its OLD pid is
  killed first (`kill_if_still_our_ssh`, the same guard `close` uses below,
  P-S3): once confirmed gone, the record is REPLACED by a freshly opened
  one at the same `(session_id, key)`, on a freshly reserved local port
  (the `TcpListener::bind("127.0.0.1:0")` read-back-drop idiom
  `cli/tests/node_connectivity.rs::free_port` already established). A live,
  still-ours OLD pid that SURVIVES that bounded kill instead REFUSES the
  reopen with a taught error rather than being overwritten — opening a
  second forward to the same target while the first is untracked would
  strand it, since once its record is overwritten nothing could ever find
  that pid again (`close`/the reaper only ever act on a pid loaded FROM a
  record); the caller's own later retry, or the reaper's backstop, clears
  it once the old child finally exits. The spawned
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
  the record ONLY once that pid is confirmed gone, idempotent on a record
  already gone; before signaling anything it checks `/proc/<pid>/cmdline`
  actually names `ssh` carrying this exact `-L` spec (`looks_like_our_ssh`,
  wrapped as `kill_if_still_our_ssh`, shared with the stale-reopen path
  above) — a pid an earlier `aoide` invocation recorded may have been
  recycled by the OS to an unrelated process by the time anything acts on
  it, and a pid alone is never enough to justify a signal.
  `kill_if_still_our_ssh` returns whether the pid is now safe to forget
  (never alive, never ours, or ours and confirmed dead) versus still alive
  and still ours — `#[must_use]`, since every caller (`close`, the
  stale-reopen path above, and `aoide-conduct::reap::sweep_orphan_tunnels`)
  must gate a record's removal or replacement on it, never discard it. A
  stubborn/hung child that survives `terminate_pid`'s bounded
  `SIGTERM`+wait keeps its record on disk instead of losing it, so the
  reaper's backstop re-gathers the SAME record as a candidate on every
  later sweep pass and retries the kill, until it is finally confirmed
  dead — never a one-attempt affair. Once a kill IS justified, `terminate_pid` reaps
  with a real `waitpid(pid, WNOHANG)` poll before ever falling back to a
  `/proc` poll — required whenever `open` and `close` (or a stale reopen)
  share a process, since that pid genuinely IS this process's own child and
  nothing else will ever collect it; `ECHILD` (the ordinary
  cross-invocation case) falls back to the `/proc` poll, same as always.
  `close_all_for_session(session_id)` closes every tunnel recorded for that
  session, best-effort across all of them. The actual
  spawn is an injected closure internally (the same `Arc<dyn Fn(...)>`
  shape `aoide_conduct::graph::who::PullFn` holds for its own live-probe
  seam, re-derived rather than imported) so every reuse/stale/timeout/
  early-exit/reap branch is unit-tested with a fake spawn (an innocuous
  real `sleep`/`bash` child, never `ssh` — one fake overrides its own
  `argv[0]` to `"ssh"`, `CommandExt::arg0`, purely so `looks_like_our_ssh`
  can be exercised against a genuine, killable process; the `bash` fixture
  runs an all-builtin `-c "while :; do :; done"` rather than shelling out
  to `sleep`, so a shell that would otherwise replace itself via an
  exec-tail-call for a single external command — observed breaking
  `argv[0]` preservation in the nix build sandbox's check phase, though
  not in the dev shell — never gets the chance) — the one
  `#[ignore]`'d real-ssh proof lives at `cli/tests/tunnel_ssh.rs` instead,
  the same "real bytes, not a mock, but sandboxed-build-unsafe" shape
  `node_connectivity.rs` already holds.
- **Response byte cap (#114)** — `run_curl_with_timeout` is the ONE curl
  spawn point every fetch in this crate funnels through (`post_json`'s node
  POSTs, `node add`'s AgentCard GET, `mcp_client`'s Melete calls); before
  this fix it buffered a response of ANY size via `wait_with_output`
  before ever looking at it. `MAX_RESPONSE_BYTES` (20 MiB — 10x the
  investigated legitimate ceiling: `node pull`'s `aoide/graphSummary`
  response, which tops out in the low single-digit megabytes even for a
  very large multi-host graph, since `title`/`say` fields are already
  truncated before they reach a graph document) is enforced TWICE: curl's
  own `--max-filesize` refuses before download when a response declares an
  over-cap `Content-Length` up front, and — since that flag does not bind
  a chunked-Transfer-Encoding response, which carries no such upfront
  length — the bytes actually read off curl's stdout pipe are ALSO capped
  in the read loop itself, killing the child the moment the running total
  crosses the limit rather than waiting for it to finish. An over-cap
  response refuses with a taught error naming the cap; every existing
  caller's own node/url context still wraps it, unchanged.
- **Dial resolution (P-S4, ssh-transport lane)** — the tunnel seam every
  outbound POST resolves through BEFORE it ever reaches `commands::
  post_json` (`aoide-client`'s one HTTP transport, unchanged by this
  phase). `resolve_dial_url(logical_url, via, tunnel_key)` is the funnel:
  `via: None` returns `logical_url` byte-for-byte (the "off = unchanged"
  guarantee, pinned per call site); `via: Some` opens/reuses `tunnel::
  open_or_reuse` and rewrites the authority to `127.0.0.1:<local port>`
  via `aoide_storage::tunnel::dial_url`, which preserves the PATH
  verbatim — the reason `sign_headers_for_node`'s canonical string (signed
  over `node_store::url_path(&node.url)`, computed independently and
  never touching the dial url) still verifies on the far end.
  `post_json_to_node(node, …)` resolves `node.via` (keyed by `node.name`);
  `post_json_via(logical_url, via, tunnel_key, …)` is the same funnel for
  the ceremony dials that have no `Node` record yet
  (`aoide/pairRequest`/`pairReveal` in `run_pair_request`,
  `aoide/pairPoll` in `approve_outbound` — Design A, task #119, keyed off
  `entry.via` when the outbound entry recorded one) — keyed by the
  ceremony's own local nickname. `spawn_on_node_via(node, text, via_override)` is
  `spawn_on_node`'s own body plus an explicit override that beats
  `node.via` (`node spawn --via`); `spawn_on_node` itself stays a thin
  `via_override: None` wrapper so `aoide-conduct`'s existing call site
  needs no change. `--via` (`ssh://[user@]host[:port]`,
  `aoide_storage::tunnel::parse_via`) is a FLAG on `node.add`/
  `pair`/`node.spawn` — never a new command
  path — parsed by the shared `parse_via_flag` (absent is `None`,
  malformed is a usage error, the same `parse_secs_flag` stance).
  **`node add`'s AgentCard verification (its ONE network call) dials
  through `resolve_dial_url` too when `--via` is given** — the review
  finding this needed fixing for: the exact scenario `--via` exists for (a
  loopback-bound door reachable only through the tunnel) used to fail
  verification, before the node was ever registered, making the flag dead
  weight on `add`. The fetch target is the REWRITTEN url (its path —
  `/.well-known/agent-card.json` — preserved verbatim by the same funnel);
  the recorded `Node.url` stays the LOGICAL url either way. No signing is
  involved (a card fetch is a plain GET), so there is no canonical-string
  path to keep in sync here, unlike the signed node calls this funnel also
  serves. **`node add --no-verify` skips this fetch entirely** — for a node
  that serves no AgentCard at all (a plain A2A client endpoint, e.g. an
  inbound-only harness that never stood up the discovery surface this GET
  expects). The node is recorded exactly as the verified path records it:
  `verified` was already hardcoded `false` on this path regardless of the
  fetch (a card fetch is reachability, never identity — that only ever
  comes from `aoide pair`), so skipping it changes nothing about what gets
  written, only whether the GET runs first.
  The session id a tunnel opens under (`tunnel_session_id`) is
  `AOIDE_SESSION_ID` when a conducted session set it, else a
  process-scoped `pid-<pid>` fallback (K3). This crate only resolves and
  passes that key through — it never closes a tunnel itself, on purpose:
  `pull_node_live`/`send_message_to_node`/`spawn_on_node` are called from
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
  Every tunneled request reaches the far door as `ConnOrigin::Loopback`
  (`aoide-server::a2a::classify_origin`), which carries an unconditional
  delivery free pass for an UNSIGNED request. `aoide-server::a2a` narrows
  that free pass for a request carrying a verified per-request signature
  (`origin_for_inject`, CONTRACTS.md §6) — a signed caller is a remote node
  by construction and never rides Loopback's trust, so tunneled delivery is
  safe against a real, non-autogate node, not merely possible.
  **`mail_wire`'s drain (P-M2) is the one deliberate exception to "this
  crate never closes a tunnel itself."** A rarely-contacted outbox target
  should not accumulate a standing forward just because a background daemon
  tick happened to touch it once — `drain_node` closes its own tunnel
  unconditionally before returning, on every path, via a Drop guard
  (`TunnelTeardownGuard`) rather than the session/pid lifecycle above. This
  is safe specifically because a drain's dial is one-shot and self-contained
  (unlike `pull_node_live`/`send_message_to_node`/`spawn_on_node`, which are
  called from long-lived `aoide-conduct` handlers this crate cannot wrap) —
  don't generalize this exception to any other caller in this module.
- `mesh` (task #135 P4/P5) — `aoide mesh` and `aoide mesh pair`, the read
  and the converge over a declared `[mesh.<name>]`
  (`aoide_storage::config::Mesh`, validated but not a `config
  set`-reachable key — see `crates/storage/AGENTS.md`'s extension points).
  Own module, own `register` (the `mcp_client::register_melete` precedent —
  a self-contained file, own handler, own tests, appended last into
  `commands::all()`).

  **The read.** `aoide mesh` compares the declaration against the live node
  registry (`aoide_storage::node_store::load_nodes`) and reports where they
  diverge. The compare itself, `drift`, is pure — no I/O, no clock, no env
  — so every ruling (which class a mismatch falls into, that `allows`
  divergence is never one of them, that an undeclared node is reported, not
  accused) is a plain unit test; `handle_mesh` is the only impure edge,
  resolving `config::load()`/`node_store::load_nodes()`/`display::
  local_host_name()` and handing the results in. Writes nothing — a report
  over two read-only sources, never a third place either could drift from.
  Drift is never itself a command failure: every class is surfaced in the
  message and `data.report`, whatever it finds. The one exception is the
  read — a config that fails to load returns `Outcome::error`
  (`data.reason`, no `data.report`), same as any other command whose config
  read fails.

  **The converge.** `aoide mesh pair [<mesh>]` runs that SAME `drift` — no
  second comparison exists anywhere in the tree — and `plan` selects the
  `missing` and `unverified` rows, in declared-name order. Each goes
  through `commands::run_pair_request` and nothing else: the ordinary
  two-POST ceremony, the ordinary park, the ordinary blocking wait, dialed
  at `http://127.0.0.1:<default_a2a_port()>/` through the declared hop
  (`resolve_dial_url` discards a logical url's host whenever a `via` is
  set, so the loopback url is both correct and the record shape a paired
  node already carries). Zero ceremony logic lives in this module. A
  `via-mismatch` comes back `skipped` — a converge NEVER modifies an
  existing verified node — which is what makes a second run all-`skipped`.
  What the converge adds over N typed `aoide pair`s is the selection, ONE
  pre-flight confirm for the whole run (`--yes` skips it, exactly as it
  skips `pair`'s sweep proceed-prompt; the far operators still type codes),
  the mesh's declared `grant` handed through as `PairFinish::grant`, and
  one report in one vocabulary: completed / parked / UNREACHABLE / skipped.
  `classify` folds each node's envelope plus what `pairing::list_outbound`
  says about it afterward — never a `data.reason` string — so `UNREACHABLE`
  is exactly "nothing committed and nothing parked" and structurally
  carries no resumable id.
- `mail_wire` (P-M2, `docs/architecture/MAIL.md`) — the outbox drain: the
  ONE place a spooled mail envelope actually dials out.
  `aoide_storage::outbox` owns the spool as pure file CRUD with no network;
  this module owns the wire half. `drain_node(node_name)` is called from
  three places that all converge here so there is exactly one dial
  implementation: the daemon's periodic tick (`aoide-server::daemon` via
  `aoide_conduct::mail_bridge`, a thin passthrough that exists only because
  `aoide-server` must not carry a hard `aoide-client` dependency in
  production while `aoide-conduct` already does), a door's own best-effort
  drain of the node it just heard from (`aoide-server::a2a::mail_deposit`,
  same bridge), and `mail send`'s own one-shot attempt right after it
  writes the outbox entry (`handle_mail_send` in `commands`, below — spec
  item 8: the write is the report, delivery is the spool's job).
  `attempt_deposit` builds and sends one `aoide/mailDeposit` POST,
  mirroring `spawn_on_node_via`'s exact shape (resolve bearer, sign, POST,
  parse, check `error`) with no `--via` override — a drain only ever dials
  `node.via` as recorded. Its `DepositAttempt` has three arms:
  `Delivered{status}` (a result whose `status` is `"accepted"` or
  `"duplicate"`), `Refused(reason)` (the far end's own policy call, e.g.
  `-32010` lacks-message as a JSON-RPC `error` for an ADMISSION refusal,
  or a result whose `status` is `"refused"` for an OUTCOME one, e.g.
  `bad-msgid`/`unverified-origin` — MAIL.md §Wire's admission/outcome
  split means the two travel differently on the wire but collapse into
  this one arm here, since a drain only ever needs "not currently
  deliverable," never which shape carried that news; the link is fine
  either way, this ONE entry isn't), and `TransportFailed(reason)` (no
  response at all — the LINK is the suspect). `drain_node`'s loop walks every
  non-refused entry oldest first, stopping outright on the first
  `TransportFailed` (hammering the rest of the queue against a dead link
  gains nothing) but continuing past a `Refused` (that one entry is the
  problem, not the link). A receipt's own successful deposit — accepted OR
  duplicate, either way the far end has it now — IS its confirmation
  (ruling 4: no separate ack-of-an-ack), so `drain_node` removes it
  outright; an ordinary letter waits for a REAL ack instead, only having
  its `tries`/`last_try_at`/`last_outcome` bookkeeping updated. **Two
  locks, never nested** (mirrors `aoide_storage::outbox`'s own module
  doc): `drain_node` takes `.bsy` via `try_take_link_lock` — non-blocking,
  per-node, held across the whole function, safe to span network I/O — and
  leaves every individual `outbox::*` call as its own short,
  independently-locked operation around the POST, never holding the STAGE
  lock across the POST itself (spec item 9: network I/O never happens
  under the stage lock). `Ok(())` covers every ordinary non-error path —
  nothing registered under `node_name`, `.bsy` already held by a
  concurrent drain (ruling 3: skipped, never queued), a held-off link, an
  empty spool, or a completed pass regardless of outcome mix; `Err` is
  reserved for a genuine local I/O failure, never for "the remote node was
  unreachable," which is an ordinary outcome recorded in entry/link state
  instead of surfaced as an error to the caller. **A drain tears its own
  tunnel down before returning, unconditionally, on every path (ruling
  10)** — `TunnelTeardownGuard` is a Drop guard mirroring
  `commands::ScratchBodyFile`'s pattern; see the `tunnel` bullet above for
  why this is the one deliberate exception to that module's "never closes
  a tunnel itself" default, and why it doesn't generalize to any other
  caller.
- `commands` — this crate's CLI commands:
  `node add/remove/pull/status/hub/allow/spawn/discover`,
  `aoide pair` + `pair.reject`/`pair.watch` (P-P2, P-PV2, task #135 P3',
  CONTRACTS.md §6/§7 — **`register_mail`'s eight commands (`mail
  send/read/show/mark/rm/outbox/outbox.rm`, P-M1/P-M2, `docs/architecture/
  MAIL.md`) moved here from `aoide-storage` at P-M2, because
  `handle_mail_send`'s non-self branch now dials out and only this crate
  may hold that dial:** `handle_mail_send` mints and spools an outbound
  letter through `aoide_storage::mail`/`outbox` exactly as before, then —
  new at P-M2, for a non-self `to` — makes ONE best-effort call into
  `mail_wire::drain_node` before returning; the spool's own success (the
  WRITE) is the `Outcome`, never gated on what that dial did (spec item 8;
  the periodic daemon tick and the door's own post-heard drain are what
  actually guarantee delivery, this call is purely a latency shortcut).
  What the dial found IS surfaced, though: `data.delivery` is filled in
  after the drain attempt by `delivery_projection`, the same read-only
  join of an outbox entry with its node's `read_link_state` that
  `handle_mail_outbox` uses — see "Status and the nodelist view" in
  `docs/architecture/MAIL.md` for the status vocabulary. A post-spool read
  that itself fails degrades `delivery` to `queued`/"status unavailable"
  without ever touching the spool's own `Ok`. Its node-branch gate
  is deliberately shallow — it requires `verified` off `node_store::
  load_nodes()` and nothing more, the SAME "the client checks reachability
  of a record, never a granular capability" precedent `handle_node_spawn`
  already sets; whether this node actually GRANTS `message` is exclusively
  the remote door's own call (`node_may_message`), surfaced back as an
  ordinary taught JSON-RPC refusal if it says no, never pre-empted locally.
  **The `self` branch forwards the doorbell instead of ringing it**
  (P-M5a-2: this crate sits below `aoide-conduct` in the crate graph and
  cannot call `aoide_conduct::graph::ring` directly) — after `file_letter`
  succeeds, `handle_mail_send` builds a `mail ring --for <name> [--from
  <reader>]` `Invocation` and runs it through `daemon::daemon_dispatch`,
  the SAME forwarding mechanism every other daemon-first write already
  uses. No daemon reachable (or `inv.door == Door::Daemon`, which
  `daemon_dispatch` always answers `None` for) reports the outcome's own
  `ring` field as the literal string `"no-daemon"`, never an error — the
  letter is filed and the latch stays armed for the next trigger either
  way, so a self-send's own status never depends on ring's success.
  `handle_mail_outbox` (`mail outbox [node]`) is the spool's own read-only
  status view — an optional node arg narrows to one, otherwise every node
  `outbox::nodes_with_outbox` reports — rendering each `list_entries` row's
  msgid/to/tries/lastTryAt/lastOutcome/refused plus the same `delivery`
  projection `mail send` fills in (one `read_link_state` per node, joined
  onto each of that node's entries, never copied into per-entry state);
  "outbox empty" when there is nothing waiting anywhere. This command
  never dials — it is the read side of the projection, not a drain.
  `handle_mail_outbox_rm` (`mail outbox rm
  <msgid>`) is an exact-msgid removal, NOT the mailbase `mail rm`'s
  age-based prune — it walks `nodes_with_outbox` and calls
  `outbox::remove_entry(node, msgid)` on each until one actually held that
  msgid, erroring `not-found` if none did; neither command touches the
  mailbase (`aoide_storage::mail`) at all —
  `handle_node_allow` (`node allow <name> <cap> on|off`, P-P3, `docs/
  architecture/PAIRING.md` decision 5) is a thin wire around
  `aoide_storage::node_store::set_node_allow` — idempotent, refuses an
  unknown node or an unknown capability with distinct taught errors, no
  network call (this instance's own `state/nodes.json` is authoritative
  for its own `allows` grants) —
  `poll_outbound_once`/`commit_outbound` are the requester's half as TWO
  named seams (task #135 P2), with `approve_outbound` reduced to calling
  each once and `wait_and_commit` — `aoide pair`'s own blocking tail —
  calling the poll on a `PAIR_POLL_CADENCE` until the approver releases.
  `PairFinish` carries what `aoide pair` does after parking (`--wait`,
  `--yes`, `--allow`); `PairFinish::detached()` is the pre-P2 shape and
  what every test drives so none of them sit on a poll. `--wait 0` is the
  documented escape for a scripted caller that cannot sit on a human, and a
  timeout returns Ok with the request still parked — targeting the same
  id again finishes it later, which is also what makes Ctrl-C safe. The deadline is
  MONOTONIC (`Instant`, never `now_iso_utc`): a wall-clock deadline is
  defeated outright by an NTP step or a suspend/resume during the wait, which
  would leave the loop polling past the bound the command promised. The wall
  clock is still read inside the loop, where entry expiry needs it.
  `--allow` beside `--wait 0` is refused rather than accepted-and-dropped —
  that path returns before anything commits, and a grant is never persisted
  on a parked entry. `poll_outbound_once` is the ONE implementation of the
  `aoide/pairPoll` round trip and of the SAS/transcript binding that refuses
  a substituted reveal; its `PollOutcome::Pending` is the only arm a caller
  may retry, every other being terminal, so a `--wait` loop cannot hammer an
  unreachable box or a refused reveal. A second copy of that loop anywhere is
  the design error the split exists to prevent — a blocking `aoide pair` and
  `mesh pair` both consume these rather than reimplementing them.
  `resolve_grant`/`parse_allow_flag`/`grant_note` are the grant seam both
  commit directions share (task #135 P1): what a FIRST verification stamps
  is `config.toml`'s `[pairing] defaultGrant` (`["read"]` by default), or
  the `--allow read,spawn` typed on that one `aoide pair` — parsed by
  `aoide_storage::config::parse_value` over `NODE_CAPABILITIES`, the same
  validator and the same closed vocabulary `config set` uses, never a second
  list. Comma-separated, not a repeated flag, because `Invocation::flags` is
  a map and a second `--allow` would silently overwrite the first. A config
  that does not load REFUSES the commit instead of falling back, and the
  refusal happens BEFORE the code gate so nobody types a code this side will
  decline to commit. `grant_note` exists because a `--allow` on a RE-pairing
  legitimately does nothing (`upsert_paired_node` never re-grants), and that
  must not be silent —
  `default_self_url`/`default_self_via` are this group's own local helpers
  (their own doc comments in `commands.rs` state what each derives and how
  `--self-url`/`--self-via` override them). `pair_via_url`/`pair_via_hostname`
  (the SMART TARGET dispatch of a NEW request's two arms, P-PV2)
  both bottom out in `run_pair_request`, which sends
  the commitment and its reveal as two sequential POSTs in one invocation
  before ever computing a SAS. `approve_inbound_leg`/`resume_outbound_leg`
  (task #135 P3' — the two legs `pair_continue_or_request` routes a
  matched target to, replacing the old single `handle_node_pair_approve`)
  dispatch by direction (Design A, task #119 — REPLACES the old
  `aoide/pairApprove` reverse callback): on an INBOUND entry
  (`approve_inbound_leg` → `approve_inbound`) it refuses an unrevealed one outright, then gates on
  the TYPED pairing code (task #120 P3, `CodeGate` — the operator types
  the code as read off the REQUESTER's screen, compared against the
  locally derived SAS via the pure `code_matches`; the prompt never echoes
  the SAS; a mismatch persists one cumulative try through
  `aoide_storage::pairing::record_inbound_code_try`, and the third
  mismatch auto-denies via `auto_deny_inbound` — the same clean removal
  reject performs, audited as `auto-deny-on-code-mismatch`; `--code
  NNN-NNN` is the scripted spelling, and `--yes` maps to the taught
  refusal, never a bypass), then commits a
  local node record and marks the entry approved PURELY LOCALLY — no wire
  call at all, so an unreachable/loopback-only requester never blocks the
  approver's own half. **The commit's `url`/`via` depend on the parked
  entry's `self_via` (task #131).** Present — the requester claimed a
  reach-back hop on the wire (`InboundPairingRequest::self_via`, carried
  through from `aoide/pairRequest`'s own `selfVia`) — the commit records
  `url: http://127.0.0.1:<port>/` (loopback-as-seen-from-the-far-side; the
  requester's own door is reachable only through the very tunnel that
  delivered this request, so `entry.url`'s requester-observed HOST is
  never directly dialable) where `<port>` is `port_from_url(&entry.url)`
  — the REQUESTER's own door port, parsed off their own `self_url`
  (review finding: the first pass of this fix wrongly defaulted to THIS
  box's own `AOIDE_A2A_PORT`, which names nothing about the requester;
  `port_from_url` only ever falls back to `default_a2a_port()` when
  `entry.url` itself carries no parseable port) — and `via` set to the
  claim itself, via `set_node_via` in the SAME write as `upsert_paired_node`
  (the sibling-writer shape `approve_outbound`'s own equivalent call,
  below, already holds). Absent — an old requester, or one with nothing to
  claim — the commit is exactly what it always was: `entry.url` verbatim,
  `via` left unset. On an OUTBOUND entry (`resume_outbound_leg` →
  `approve_outbound`) it POLLS
  `aoide/pairPoll` first (over the SAME forward dial `request` already
  used — `entry.via` if one was recorded) and, once the poll comes back
  approved, gates on a SECOND, DIFFERENT typed code (the mutual-code
  redesign, R1) — `derive_reply_sas`, the approver's own reply code, read
  off the APPROVER's screen and relayed back out-of-band, never the code
  this instance already showed at request time (that would just be typing
  its own output back at itself) — through the identical `CodeGate`/
  `MAX_CODE_TRIES` machinery the inbound leg already holds: a mismatch
  persists one cumulative try through
  `aoide_storage::pairing::record_outbound_code_try`, and the third
  mismatch auto-aborts via `auto_abort_outbound`, audited as
  `auto-abort-on-code-mismatch`; `--code NNN-NNN` is the scripted spelling,
  `--yes` maps to the same taught refusal as inbound, never a bypass —
  then commits THIS instance's own record (decision 4's mutual
  confirmation, on both ends, unchanged, now over two DISTINCT codes
  rather than one shared one). `approve_outbound` takes the SAME `CodeGate`
  enum `approve_inbound` does now (was `skip_confirm: bool`, P-P5) —
  `pair_watch`'s popup arm (below) passes `CodeGate::Code` on BOTH legs
  (R1 supersedes P-PV3's own outbound confirm dialog; that reversal's own
  reasoning lives in `pair_watch`'s module doc, not repeated here).
  `handle_pair_reject` tries
  the inbound queue then the outbound queue by id OR by a name matching
  exactly one pending request, aborting an outbound entry at
  any stage — the ceremony's abort command; `reject_by_id(cmd, id)` (P-P5)
  is its shared body, extracted so `pair_watch`'s popup arm can reject by
  id alone, with no `Invocation` to construct for a dialog button.
  `handle_pair_watch` (`aoide pair watch [--popup] [--json]`, P-P5,
  CONTRACTS.md §6) is the launch-record handler for `pair_watch::run`
  (below) — the SAME "gate the door and the flag combo here, run the
  blocking loop from `cli`'s own `special` hook" split `handle_events_tail`/
  `handle_secrets_watch` already hold, registered as `pair.watch` in
  `register_pair`.
  **`pair_watch` (P-P5, a NEW module, CONTRACTS.md §6's "Pairing events
  feed" subsection)** is the pairing ceremony's own watcher: `parse_pair_line`
  reads the `class: "gate"`/`source: "a2a-door"` milestones
  `aoide_server::a2a::emit_pairing_event` writes (`pair-parked`/
  `pair-revealed` live; `pair-awaiting-confirm` dormant since task #119
  retired the callback that emitted it, parsed only for old lines) off
  aoided's OWN events feed —
  the SAME file `events tail` already follows, since `a2a serve` appends
  onto it directly; `reconcile` re-derives every pending request straight
  from `aoide_storage::pairing::list_inbound`/`list_outbound` (the
  AUTHORITY — the feed line is only ever a trigger to re-check them,
  mirroring `aoide_secrets::watch`'s identical "tail is a trigger" stance
  for its own feed), using the EXACT SAS arg order per direction
  `approve_inbound`/`approve_outbound` above already use — bare `aoide pair`
  itself carries no SAS at all, P-PV2; `actionable` decides
  whether a `Pending` is worth surfacing (an inbound entry once revealed
  and only while still `awaiting-approval` — approval leaves the entry
  PARKED for the requester's own `pairPoll`, so a revealed SAS alone
  would re-raise the code dialog every tick for a request this operator
  already answered; an outbound entry once `awaiting-confirm`); `run` is the blocking
  tail/reconcile loop (`aoide_secrets::watch::wait_for_follower`'s exact
  retry-until-exists shape, a 30s reconcile safety tick). **`--popup`
  (F6, upgraded P-PV3/task #132: TWO dialog shapes, one per pairing
  direction, never a single bare yes/no)** refuses up front when NEITHER
  `lyra` nor `zenity` resolves (`resolve_lyra_bin`, the SAME three-tier
  check `aoide_secrets::watch::resolve_lyra_bin` runs, repeated here since
  neither crate may depend on the other); past that, `popup_tick` replaces
  the plain narrate-only reconcile with: pick the next `Pending` that
  `eligible_for_dialog` admits — `actionable`, un-ignored, and no LIVE
  blocking `aoide pair` holding that id's pid marker (`PairActiveMarker`,
  the RAII guard `wait_and_commit` acquires; `marker_suppresses` is the
  pure half, a dead pid's marker is stale and cleaned up) — skip while
  the screen is locked (F8, `aoide_protocol::dialog::is_locked`), show
  its dialog and leave it up until the OPERATOR acts (R2: no timeout, no
  self-close — `should_cancel_dialog` closes it only for an interrupt,
  the request resolving elsewhere, or a live blocking marker appearing),
  and act on `decide`'s mapping. `run`'s loop also drives
  `poll_pending_outbound` on `OUTBOUND_POLL_INTERVAL` (60s):
  `poll_outbound_once` on every entry `needs_outbound_poll` admits
  (`awaiting-approval` only) — the ONLY way a detached request's confirm
  dialog ever becomes actionable, and never from the 200ms tick. **ONE
  dialog shape on BOTH directions now (the mutual-code redesign, R1 —
  this reverses P-PV3's own outbound CONFIRM dialog; `pair_watch`'s
  module doc has the theater-argument reasoning for why that reversal
  doesn't repeat P-PV3's original mistake): `run_ask_dialog`** — `lyra
  pair ask` (the SAME six-box entry surface `lyra secrets ask` renders)
  when `resolve_lyra_bin` found one, falling back to `zenity --entry` on a
  `lyra` `SpawnError`/`DialogFailure` for that one attempt
  (`aoide_secrets::watch::run_ask_dialog`'s own fallback shape, reused
  unchanged), `--no-markup` load-bearing on the zenity path for the same
  Pango-corruption reasoning `aoide_secrets::watch::spawn_zenity_entry`
  already carries. Exit 0 hands back the TYPED code, gated through
  `commit_approval` — `CodeGate::Code` on EITHER arm, inbound against
  `derive_sas`, outbound against `derive_reply_sas` — the SAME comparison
  and `MAX_CODE_TRIES` auto-deny/auto-abort machinery the CLI tty/`--code`
  paths already hold, byte-identical. Both arms share: the `REJECT_LABEL`
  extra button/dismiss control → `reject_by_id`; a bare Cancel →
  session-only `ignored`; a spawn/infra failure on BOTH binaries →
  backoff, NEVER `ignored`, the same "a broken binary doesn't silently
  stop offering the request" stance `aoide_secrets::watch::popup_loop`
  already holds. `dialog_title`/`dialog_context` are pure and read ONLY
  from a `Pending` `reconcile` already produced — never a `PairEvent`'s
  own feed-sourced fields; `dialog_context` is the only per-direction
  wording left to build (`dialog_code`, whose only job was showing an
  outbound confirm's plain code, is GONE along with the dialog it
  belonged to). The entry dialog itself still carries no code-display
  line on either direction; an inbound APPROVAL's reply code (the
  approver's own, `derive_reply_sas`) is instead handed onward three
  ways, in order: `notify_reply_code` fires a best-effort desktop
  notification (`notify-send` as bare argv — the untrusted node name
  rides as an argument, never a shell string — skipped under `--json`),
  `show_reply_code` raises the stay-open display dialog (`lyra pair
  show`: code large, Copy + Done, no reject; `zenity --info` fallback),
  and `popup_tick` prints the same code on its outcome line. The
  operator relays that code to the requester, who types it into their
  own still-pending prompt to finish the ceremony.
  **`run_pair_request(cmd, url, name, self_url, self_via, dial_via,
  record_via)` (P-P6, `dial_via`/`record_via` added P-S4, `self_via` added
  P-PV1/task #131) is `pair_via_url`'s own body, extracted so
  `pair_via_hostname` reaches it too — reused, never copied.**
  `pair_via_url` still owns every bit of
  `<url>`/`--name`/`--self-url`/`--self-via`/`--via` parsing and the
  `valid_node_name` check (a CLI-typed name needs it); `pair_via_hostname`
  calls straight into `run_pair_request` with a `name` already lifted off
  an already-validated, already-confirmed discovery advertisement, needing
  no second name check, and a `url` composed from the OBSERVED
  source address on the house door port (`default_a2a_port` —
  `AOIDE_A2A_PORT` or 8710; the advertisement carries no door URL, task
  #120) — that composition, plus the `dial_via`/`record_via` derivation
  below, lives in `resolve_pair_vias(hit, via_flag)` (pure, unit-tested
  with no dial), called from `pair_with_heard(cmd, hit, via_flag,
  self_via_flag)`, the settled-target tail `pair_via_hostname` and bare
  `pair`'s picker (below) both call so neither ever forks the ceremony.
  `handle_pair(inv)` is the ONE registered entry point (task #135 P3', the
  User's locked spec: "the command set can just be `aoide pair`") — with
  no target it calls `pair_overview` (below); with a target, SMART TARGET
  dispatch on the first positional arg (`"://"` present → `pair_via_url`,
  else → `pair_continue_or_request`, which checks the pending queues
  before ever falling to `pair_via_hostname`), refusing a second
  positional outright rather than reading only the first — never a second
  command path; `node invite`/`node pair request` died outright at
  P-PV2, and `node pair`/`node pair approve`/`node pair reject`/
  `node pair watch`/`node pending` died outright at task #135 P3' — hard
  cutover, no aliases either time.
  `dial_via`/`record_via` are related but distinct: `record_via` is
  UNCONDITIONAL — the advertisement's observed address plus its claimed
  login, string-rendered via `default_via`, even when that login is empty
  — parked onto `OutboundPairingRequest.via` for LATER commit
  (`approve_outbound`) onto the node record this ceremony creates, so that
  node has an automatic transport marker for its own FUTURE calls.
  `dial_via` (task #131 — previously `None` unless an explicit `--via` was
  given, forcing every plain ceremony to dial directly) now rides the SAME
  derived default too, UNLESS the advertisement carried no ssh claim at
  all (empty login), in which case there is nothing to tunnel through and
  the dial stays direct: against a door that binds loopback-only, the
  observed address is never directly dialable, so the ceremony's own two
  POSTs need the tunnel exactly as much as the record does. An explicit
  `--via` beats both defaults outright, for both halves, unchanged.
  `self_via` (task #131) is this instance's OWN reach-back hop claim —
  `default_self_via(toward)` (`ssh://<local login>@<local outbound address
  routed toward `toward`>`, reusing `crate::tunnel::local_login`'s
  `$USER`/`$LOGNAME` chain for the login half, `None` when neither env var
  is set) or an explicit `--self-via`, carried on the wire beside
  `self_url` ([`crate::node::build_pair_request_body`] below) so the
  approver — which can only ever OBSERVE this request arriving over the
  tunnel, i.e. loopback — has something to record a working `via` from at
  ITS OWN `aoide pair` commit time (`approve_inbound_leg` →
  `approve_inbound`, below).
  **The HOST half is deliberately NOT `aoide_storage::display::
  local_host_name`'s claimed hostname (review finding, task #131) — a live
  LAN check found hostnames resolving only through the router's DHCP-DNS,
  exactly the fragility K1's own "never a claimed host" rule (`Node.via`)
  exists to avoid.** `outbound_ip_toward(toward)` opens a UDP socket,
  `connect`s it to `toward` (no packet sent — `connect` on a UDP socket
  only resolves a route) and reads back the LOCAL address the kernel chose
  — on an ordinary LAN, the address the node can actually reach this box
  at — falling back to the claimed hostname only when that lookup itself
  fails. `toward` is the address actually being dialed: `pair_with_heard`
  passes `hit.src_addr` (the observed source, already the real target);
  `pair_via_url` passes `via`'s own host when dialing through
  a tunnel (the ssh target, not the logical `url`, which the tunnel may
  make unreachable directly), else the `url`'s own host.
  `handle_node_discover`/`pair_via_hostname` (`node
  discover [--secs N]`/`aoide pair <name> [--secs N] [--yes]`) are thin
  wrappers around `discover::run_sweep`/`discover::resolve_invite_target`
  above — `confirm_invite` is this pair's own local helper, still the
  original hand-rolled `y/N` stdin read this family's OTHER confirms
  (`confirm_spawn`) shared before their P-I1 retrofit onto
  `aoide_protocol::pick::confirm` above — out of that phase's own scope,
  not an oversight; it shows both
  the advertisement's claimed ssh hop and its observed `src_addr` side
  by side, so an operator sees claim and observation before anything
  dials. `pair_via_hostname` refuses before dialing anything when
  `discover::is_self_target` says the resolved target is this instance's
  own advertisement — `node discover`'s own JSON `heard` rows carry
  `srcAddr` alongside the claimed fields for the same reason.
  `handle_node_advertise` (`node advertise on|off`, task #120) flips
  `aoide_storage::advertise::set_enabled` — idempotent, reports changed
  vs already-so; the emitting `a2a serve` reads the switch every tick,
  so the message names the ~40s pickup and that nothing emits without a
  running `a2a serve`.
  `pair_overview` (task #120 P3, called from `handle_pair` when no target
  is given, registered as bare `pair` in `register_pair`) is the friendly
  interactive entry: CLI-door + real-tty only (`pick::interactive`, the
  same gate bare `session` holds; non-tty/non-CLI/`--json` fall to
  `pending_listing` — the JSON-friendly machine face the old `node
  pending` folded into at task #135 P3'), one bounded ~2s sweep
  (`PAIR_SWEEP_SECS`), self-advertisements filtered via `is_self_target`,
  then `pick::choose` over ONE menu spanning both pending requests (pick
  one to approve or resume, via `approve_inbound_leg`/
  `resume_outbound_leg`) and the sweep's candidates (pick one to request
  — the pick IS the proceed-confirmation, so no second `confirm_invite`
  y/N rides on top) and goes straight through `pair_with_heard`; hearing
  nothing and nothing pending teaches `node advertise on` and the manual
  `aoide pair <url>` path.
  `adapter melete` (`node hub
  <name> [--clear]`, P-D5, designates at most one registered node as the
  hub `aoide_storage::addr::resolve_with_hub` prefers as a last-resort
  remote target — `node_store::set_hub`/`clear_hub` hold the invariants,
  this handler just reports which of set/moved/cleared/no-op happened);
  also exposes two
  non-command functions that are the `conduct → client` edge's crossing
  points: `pull_node_live` (the roster core's live per-node probe, reached
  via bare `session`/`--hosts` — read-only) and
  `send_message_to_node` (`send --to <node>/<query>`'s delivery,
  workstream C3 — POSTs `message/send` with an explicit `contextId` naming
  the resolved remote session). **Outbound bearer presentation (task
  #84)**: `node add --bearer-secret <name>` records a per-node
  `Node.bearerSecret` (`aoide-storage`'s `node_store`); every outbound
  node POST (`pull_one_node`, `pull_node_live`, `send_message_to_node`)
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
  CONTRACTS.md §6's own amendment)**: `sign_headers_for_node` is the ONE
  production caller that builds the four `X-Aoide-*` headers — for a
  `node.verified` target it loads this instance's own P-P1 identity
  (`aoide_storage::identity::load_or_mint`), mints a nonce
  (`aoide_storage::pairing::random_hex(16)`, the same mint the pairing
  ceremony already uses), signs
  `aoide_storage::wire_auth::canonical_string(HTTP_METHOD,
  aoide_storage::node_store::url_path(&node.url), timestamp, nonce, body)`
  with `aoide_storage::wire_auth::sign_hex`, and sends `X-Aoide-Node` as
  this instance's own SELF name (`aoide_storage::display::
  local_host_name()`, the same value the pairing wire's `pairRequest.name`
  sends — never `node.name`, this side's local nickname for the
  counterpart). The header is attribution only (#63 P-ID5): the far end
  resolves the caller BY the stored pubkey that verifies the signature,
  audits any claimed-vs-resolved name mismatch as attribution drift, and
  uses the claimed name solely as the exact-name tiebreak among its own
  records sharing this instance's key. `HTTP_METHOD` (P-P5b, closing a P-P4 review finding) is the
  ONE named constant `post_json`'s own `-X` argument reads too — before
  this fix the two carried independent `"POST"` literals that merely
  happened to agree; now there is exactly one value to drift from. An
  unverified/unpaired node gets an empty header list — byte-identical to
  the pre-P-P4 transport. Wired into all four real node-POST call sites
  (`pull_one_node`, `pull_node_live`, `send_message_to_node`,
  `handle_node_spawn` — P-P5b, the FIRST of the four to ever sign a
  `contextId`-less, spawn-shaped body); the pairing ceremony's own three
  wire calls stay unauthenticated by design and always pass an empty
  slice. `post_json` threads `extra_headers` as plain `-H "<name>:
  <value>"` curl argv literals in EITHER the bearer or no-bearer branch —
  unlike the bearer token, nothing in a signature header is a secret worth
  hiding from `/proc/<pid>/cmdline`.
- **`spawn_on_node(node, text) -> Result<Value, String>`** is the wire-level
  seam for a spawn-shaped `message/send` — builds
  `crate::wire::build_message_send_body(text, messageId, None)` (`contextId`
  omitted, `<text>` riding as the prompt `aoide-server::a2a::do_spawn` types
  into the newly spawned session's first turn), signs it via
  `sign_headers_for_node` above, and posts it. Mirrors
  `send_message_to_node`/`pull_node_live`'s own `Result`-not-`Outcome`
  shape (the caller builds its own `Outcome`/audit line). Two callers:
  **`handle_node_spawn` (P-P5b, `node spawn <name> [--yes] -- <text…>`)**
  makes PAIRING.md's spawn gate reachable from the CLI — gates LOCALLY on
  exactly one question (is `name` a registered, `verified` node at all — an
  unsigned request could never satisfy the remote's `NodeRung::Signature`
  -only requirement regardless), refusing with a taught error naming `node
  pair`, then confirms (`--yes` skips only this LOCAL `y`/`N`
  prompt, `confirm_spawn`, mirroring `confirm_invite`'s idiom) before calling
  `spawn_on_node` and shaping the `Outcome`. **`aoide-conduct`'s manifest
  remote-summon path** (U4, command-defrag lane U — `graph::resurrect::
  summon_remote`, the `conduct` → `client` edge documented in `conduct`'s
  own `Cargo.toml`) calls `spawn_on_node` directly, no confirm: a manifest
  spec is itself the operator's standing declaration. Either way, every
  OTHER refusal (`allows` lacking `spawn`, an unsigned-but-paired caller,
  clock skew, an unreachable node) is the remote door's — or the
  transport's — own call, surfaced verbatim as `spawn_on_node`'s `Err`;
  neither caller re-derives or second-guesses it.

## What it consumes

`aoide-protocol` and `aoide-storage` (the node registry and pull cache
persist through `storage`), and `aoide-secrets` (task #84 — outbound
per-node bearer resolve, `aoide_secrets::client::resolve_bounded`, reused
rather than a second wire client written here).

## How it composes

`conduct`, `screen`, `server` (dev-dependency only, for one round-trip
test), and `cli` depend on it. **The `conduct → client` edge is intentional,
not technical debt**: `conduct`'s roster core (workstream C2, landed;
reached via bare `session`/`--hosts` — the standalone `who` command it
originally backed is retired, session-surface redesign, command-defrag lane
X, 2026-08-28) calls this crate's `commands::pull_node_live` for its live
per-node probe, `send --to`'s remote branch (workstream C3, landed)
calls `commands::send_message_to_node` to deliver, and (P-D6) every
session-write handler (`session start/phase/end/hook`, `session reap`)
calls `daemon::daemon_dispatch` first — the edge stays even though the
original reason (`screen/send.rs`) moved out to the `screen` crate at P-A1
(`docs/architecture/PACKAGE-LAYOUT.md`, "Verified facts").
