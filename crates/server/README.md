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
  session command (`session start/end`/etc., `{"op":"dispatch"}`) writes
  stage files on ITS OWN connection thread, not the tick's, so
  `rebaseline_stage_roster` re-baselines the WHOLE roster after every
  completed dispatch (roster-wide, not a per-command "which files did this
  write" table) before that connection's reply goes out — closing the
  window where the daemon's own routed write got reported back to itself as
  a hand edit one tick later.
- **Graph residency (P-D6, `docs/architecture/AOIDED.md`'s "L4")** —
  `run_loop`'s tick, after narrating the hand-edit sweep above, does two
  more things every iteration: `reconcile_graph_projection(changed_files)`
  re-derives `state/stage/graph.json` (via `aoide_conduct::graph::restage_graph`,
  the same function every project/session mutation site already calls — the
  `graph emit` CLI command was retired in favor of the resync now spelled `session prune` — no forked
  logic) whenever `sessions.json`/`hooks.json` is among the
  files the sweep just reported changed, so an out-of-band write (the
  direct-fallback CLI path, or a hand edit) is folded into the projection
  on the very next tick rather than waiting for the next dispatch to touch
  it; `run_internal_reap` calls the SAME `aoide_conduct::reap::
  reap_and_announce` `session reap` always runs, every `REAP_EVERY_TICKS`
  (12) ticks (~12s, matching the systemd timer's own cadence), re-baselining
  `HandEditWatcher` via `note_own_write` for whatever it touched so its own
  sweep is never mistaken for a hand edit next tick. Neither producer keeps
  a separate in-memory roster — every dispatch (routed or internal) reads
  the stage files fresh, so "fold in the newest write" falls directly out
  of "the file on disk is the single source of truth at every instant";
  `daemon::handle_conn`'s `dispatch` op is also how a REMOTE `graph
  session start/phase/end/hook`/`session reap` call actually executes once
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
  in-process (`Door::Daemon`) — the identical command core `resurrect
  --project` runs over the CLI, the same in-process-call pattern
  `run_internal_reap` already uses for `session reap`. Liveness lives one
  layer down: `session_resurrect`'s own bare-mode selection
  (`undying_selection`, durable-sessions plan P-C4) drops any undying id
  already alive in `sessions.json` per candidate before spawning anything,
  so a project where every undying session is already live resolves to the
  empty-set `Outcome::ok` no-op rather than being skipped wholesale — a
  per-project skip here would have suppressed reviving a multi-session
  undying set's other, actually-dead members over one live terminal. That
  function never hard-errors on a per-candidate spawn failure either; a
  headless host's taught "no `$AOIDE_TERMINAL`" error is only
  `eprintln!`'d here, never propagated — the tick/loop itself is never at
  risk.
- **The sealed session credential (LANE IDENTITY P-ID1, `docs/architecture/
  CONTRACTS.md` §4's `seal` field) — scaffolding, no gate consumes it
  yet.** `daemon::seal_keypair` mints this daemon PROCESS's own ed25519
  keypair exactly once (`aoide_storage::identity::mint_ephemeral`, held in
  a module-level `OnceLock`) and NEVER writes it to disk — under OQ1-A
  (the plan file's User-answered threat-model question) the seal's
  secrecy rests on process liveness plus Yama `ptrace_scope`, not file
  permissions, since a same-uid attacker can read any file the operator
  owns, including `state/identity/`'s own on-disk node-wire key.
  `daemon::mint_seal(session_id, pid, origin_class)` builds a
  `SealedIdentity` (reading `pid_starttime` via `aoide_conduct::
  graph::pid_starttime`, no second `/proc` parse) and signs it under that
  key (`aoide_storage::sealed_id::mint_seal`). `handle_conn`'s `dispatch`
  op calls `daemon::seal_freshly_registered_session` right after a
  successful `session start` dispatch: if the just-written record already
  carries a `pid` (today, only `session_conduct`'s own direct
  registration does — the bare wire path does not), it mints a seal and
  stamps it via `aoide_conduct::graph::stamp_seal`. **This is honest
  scaffolding, not a security boundary**: the pid sealed over is
  whatever the record already carries, not yet a peercred-verified
  CONNECTING pid, and nothing anywhere reads `seal` back to gate a
  decision. See CONTRACTS.md §4's `seal` paragraph and `aoide-storage`'s
  own README for the full mechanism.
- **The dispatch socket's own accept gets a cross-uid floor, and two
  attribution leaks close (LANE IDENTITY P-ID3).** `daemon::accept_loop`
  reads `aoide_secrets::peercred::peer_cred` on every accepted connection
  and refuses one whose peer uid doesn't match this daemon's own euid,
  fail-closed on an unidentified peer — the same `admin_gate` shape the
  secrets broker already holds, restated here for this THIRD socket
  (`daemon::cross_uid_gate`, `shellbridge::cross_uid_gate` in
  `aoide-conduct`). Cross-uid only: every legitimate connector already
  shares the daemon's own uid under OQ1-A. Separately,
  `invocation_from_dispatch_request` stamps an absent `from` flag
  explicit-empty so a `send` handler running INSIDE this process (a
  dispatched request runs its handler on the daemon's own thread) never
  falls back to reading the DAEMON's own ambient `AOIDE_SESSION_ID` as if
  it were the connecting client's attribution (G8); `a2a::do_inject` does
  the identical stamp for a remote inject, so it never picks up `aoide a2a
  serve`'s own ambient env either (G9). Neither closes the GATE itself
  (`aoide_conduct::graph::send::real_attested_sender`, out of this phase's
  scope fence) — see `aoide-conduct`'s own README/AGENTS for the honest
  accounting of what that leaves open.
- `events` — `tail`, the blocking loop behind `aoide events tail` (P-D3):
  follows the daemon's own events feed with a `Follower` and prints every
  line whose `class` passes an (optional, comma-separated) filter, `--json`
  verbatim or narrated otherwise. `poll_once` is the bounded, non-blocking
  core a test drives directly; `tail` is the thin `SIGINT`-handling wrapper
  around it, mirroring `aoide_secrets::watch`'s own tail-loop shape.
- `mcp` — `serve_stdio`, the MCP stdio server. `initialize` answers
  unconditionally with `capabilities.experimental["claude/channel"]` and
  `instructions` (P-M5c-2, `docs/architecture/CLAUDE-CHANNEL-PROOF.md`,
  CONTRACTS.md §3's "MCP door" subsection). When `AOIDE_SESSION_ID` is set
  and non-empty, `serve_stdio` unlink-then-binds
  `aoide_conduct::graph::channel_socket_path(<that id>)`, spawns one
  listener thread for the lifetime of the MCP subprocess, and unlinks the
  socket on return — no record, no command, the socket's own presence is
  the whole registration (house rule 7). Each line received on that socket
  becomes one `notifications/claude/channel` push, `{"content": <the
  line>, "meta": {"mailbox": <name>}}` when the line names a mailbox
  (`{}` otherwise — meta keys stay bare identifiers, never hyphenated).
  Stdout is one `Arc<Mutex<_>>` writer shared between the request loop and
  the listener thread, so a pushed notification and a `tools/call` reply
  can never interleave on the wire.
- `a2a` — the serve half of A2A (JSON-RPC/HTTP/SSE); the client half stays
  in `aoide-client`. Two `message/send` arms, two different relationships to
  the mailbase (messaging plan P-M1, `state/mail/base.jsonl`): `do_inject`
  (Inject, an EXISTING session) delivers through
  `aoide_conduct::graph::session_send` — the same door `send` uses —
  which is where a delivered message gets filed as a receipt
  (`mail::file_receipt`); `do_inject` itself files no entry of its own,
  since its Invocation can only ever reach `session_send`'s LOCAL branch
  (see `do_inject`'s doc comment). `do_spawn` (Spawn, a BRAND-NEW session)
  types the opening turn via `spawn_inject_prompt`, which files ITS OWN
  receipt right after the write — a spawned session has no `SessionRecord`
  yet at that moment, so it cannot reach `session_send` at all (see
  `spawn_inject_prompt`'s doc comment for the race that rules it out).
  These were the only two mailbase-filing call sites until P-M2 added a
  third, unrelated to either: `mail_deposit`'s own call into
  `aoide_storage::mail::deposit` (below), which files a letter or receipt
  arriving over the wire from a peer node — never a locally-typed or
  locally-delivered message, so it shares no code path with `do_inject`/
  `do_spawn` above.
  **`do_spawn`'s bounded liveness check (task #103)** gives the just-
  launched wrapper process (`aoide conduct`) a short window (400ms) to
  prove it's still alive via `Child::try_wait()` before acking `submitted`
  — a wrapper whose own exec of the configured agent fails (a missing
  `spawnAgent` binary on this unit's PATH) exits inside that window and
  gets a taught JSON-RPC error instead, closing the gap where a caller was
  handed a session id for a spawn that had already failed.
  **The spawned child's environment and cwd are sanitized, never trusted
  from the daemon's own ambient env.** `spawn_child_command` explicitly
  `.env_remove()`s both `AOIDE_SESSION_ORIGIN` (P-ID0/G16/G5 — an
  unauthenticated origin claim) and `AOIDE_SESSION_ID`: the `aoide-a2a`
  unit's own environment can carry the OPERATOR's live terminal session id,
  inherited from whatever shell the unit itself descends from, and without
  this removal a freshly-spawned child would adopt it as its
  `parentSessionId` via `window.rs`'s ambient-parent fallback — a spawned
  agent parented under an unrelated human terminal. A real `aoide conduct`
  launched from an agent's own shell is untouched by this: it inherits
  whatever ITS OWN wrap exported, the ordinary local-inheritance path;
  only this door's spawn clears the ambient value first. The child's
  working directory follows the same distrust: `resolve_spawn_cwd` reads
  `--spawn-cwd` then `AOIDE_A2A_SPAWN_CWD` (mirroring
  `resolve_spawn_agent`'s own precedence, resolved once at `a2a serve`
  launch), but `do_spawn` only ever calls `current_dir` on a value
  `resolve_bounded_spawn_cwd` has matched byte-identically against a
  REGISTERED project root (`Project::roots()`, loaded off
  `aoide_storage::stage::projects_path()` the same way session state is
  loaded off its own stage file) that still exists as a directory on disk.
  Anything else — unregistered, relative, a root that no longer exists —
  is ignored, the spawn inherits the daemon's own cwd exactly as before,
  and the reject is audited exactly once (`Door::A2a`, `EventClass::Audit`,
  `"a2a.message/send"`, `"skipped"`) so a misconfigured value degrades
  quietly instead of ever placing a spawn in an arbitrary directory.
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
  **The pairing ceremony's three methods (P-P2, Design A/task #119,
  CONTRACTS.md §6's "Pairing wire" subsection)** — `pair_request`
  (`aoide/pairRequest`), `pair_reveal` (`aoide/pairReveal`), and `pair_poll`
  (`aoide/pairPoll` — REPLACES the old `aoide/pairApprove` reverse
  callback) — join this same JSON-RPC dispatch table. `pair_request`/
  `pair_reveal` stay deliberately UNGATED by `read_ok`/bearer verification:
  the ceremony's whole point is establishing a credential where none
  exists yet, so gating either on one would be circular. `pair_poll` is
  self-authenticating instead (below) — neither door-gated nor fully open.
  None grants anything beyond a `pubkey`/`verified` node record, and that
  record commits only on BOTH ends' own separate human confirmation — the
  `allows` set is stamped by `aoide_storage::node_store::upsert_paired_node`
  itself, the moment a node first becomes verified (P-P3, PAIRING.md
  decision 5), from the grant the CLI half resolved (`[pairing] defaultGrant`
  or `--allow`) — never by these methods directly, and never off the wire. `pair_request`
  validates every field (64-hex pubkey, 64-hex commitment, a
  `valid_node_name` name, a non-empty `://`-bearing url) before calling
  `aoide_storage::pairing::park_inbound` — malformed input never reaches
  the parked-state file, and a park past the configured cap is refused
  with a distinct `-32000`. It also reads the OPTIONAL `selfVia` param
  (task #131 — the requester's own self-asserted reach-back hop claim,
  for the case where the requester's own door is loopback-only and this
  request is arriving over ITS tunnel, so nothing about the connection
  itself can answer "how do I dial the requester back") with no
  validation of its own: absent, wrong type, or empty all collapse to
  `None` alike, since the field is never load-bearing enough to refuse a
  pairing request over — only to enrich the eventual `aoide pair`
  commit when present. `pair_reveal` is the ceremony's
  third message: it checks a POSTed nonce against the parked entry's
  earlier commitment (`aoide_storage::pairing::reveal_inbound`) — a match
  stores the nonce so a SAS becomes derivable; a mismatch DROPS the parked
  entry outright and answers the distinct `-32002` (a bad reveal is exactly
  the shape a MITM's forced retry would take, so it is not treated as a
  recoverable hiccup — the reveal is unauthenticated, so a third party
  who obtains a live pending id can destroy that one ceremony attempt
  with a bogus reveal: an accepted denial-of-one-attempt, never an
  impersonation, and the operators simply re-run the ceremony).
  `pair_poll` is the REQUESTER's own follow-up, POSTed to the APPROVER's
  door over the SAME forward dial `pair_request`/`pair_reveal` already
  used — it carries a SELF-CONTAINED signature (`{id, timestampIso,
  nonceHex, signatureHex}`, verified inline against the parked entry's own
  `pubkey_hex` via `aoide_storage::wire_auth::verify_signature_hex`, never
  through P-P4's `verify_signed_request` — no `Node` record exists yet for
  that to key off) and NEVER writes a node record. It only READS
  `InboundPairingRequest::approved` (set PURELY LOCALLY, from
  `aoide-client::commands::approve_inbound`, never from a wire handler) and
  returns `{"status":"pending"}` uniformly for an unknown id, a
  wrongly-signed poll, or a genuinely-not-yet-approved one — never a
  distinct code that would let an outsider learn which case they hit
  (the existing-oracle discipline, mirroring `message/send`'s own
  `contextId` amendment above). Only a verified, approved poll gets
  `{"status":"approved","pubkeyHex":"<B's own pubkey>"}`. The requester's
  own node record commits later, entirely inside `aoide-client`, once that
  instance's own operator polls and confirms the SAS. All three audit
  via the existing `Door::A2a` audit sink (`a2a.pairRequest`/
  `a2a.pairReveal`/`a2a.pairPoll`), same as every other A2A method —
  `pair_poll` audits only its successful release, never a routine
  "still pending" poll.
  **The pairing events feed (P-P5, CONTRACTS.md §6's "Pairing events feed"
  subsection)** — `emit_pairing_event`, called from the Ok arms of
  `pair_request` (`pair-parked`) and `pair_reveal` (`pair-revealed`) only;
  `pair_poll` never calls it (Design A retired the third kind,
  `pair-awaiting-confirm` — that section's own doc has the reasoning),
  never from a mismatch or unknown-id arm either. `a2a serve` is a separate
  process from `aoided`, so
  it opens its OWN `aoide_protocol::feed::FeedWriter` onto the SAME
  `crate::daemon::events_path`/`EVENTS_CAP_BYTES`-capped feed file `aoided`
  already writes through — two independent writers sharing one
  truncate-in-place file, so a cap-truncate race at the 1 MiB boundary can
  lose a line; accepted, because this feed is ephemeral cues and the audit
  log above (already written at all three call sites) is the durable
  record. Every emitted record is `class: "gate"`, `source: "a2a-door"`,
  and a `payload` carrying `id`/`name`/`originAddr`/`url`/`direction` BY
  NAME ONLY — never a SAS, pubkey, nonce, or commitment; a watcher
  re-derives the SAS locally from `aoide_storage::pairing::list_inbound`/
  `list_outbound`, so this line is only ever a trigger, never trusted
  data. Best-effort throughout (`FeedWriter::append`'s own posture) — an
  unwritable events path never fails the ceremony.
  **The Spawn arm's gate (P-P3, narrowed again by P-P4, PAIRING.md
  decision 6 + the wire-authentication section)** —
  `message_send`'s `SendAction::Spawn` arm no longer consults
  `token_authorized` (the door-wide bearer, 2026-08-19's own amendment) at
  all: it requires `spawn_admitted`, which accepts ONLY a
  `NodeRung::Signature` resolution to a node that is BOTH `verified` and
  carries `"spawn"` in `allows` (`node_may_spawn`, pure and directly
  unit-tested against `Node` fixtures — no test in this file drives
  `do_spawn`'s real OS-level process spawn, same house rule every other
  Spawn-arm test already follows). That resolution comes from
  `verify_signed_request` (P-P4) — called once per connection in
  `handle_connection`, before any dispatch — which resolves the caller BY
  KEY (#63 P-ID5): the request's `X-Aoide-Timestamp`/`X-Aoide-Nonce`/
  `X-Aoide-Signature` headers are verified by trying the signature against
  every verified node's stored public key, and the record whose key
  verifies IS the caller; `X-Aoide-Node` is attribution only — a
  claimed-vs-resolved mismatch audits as attribution drift, and its one
  identity-adjacent role is the exact-name tiebreak among verified records
  sharing the verifying pubkey (CONTRACTS.md §6's P-P4 amendment has the
  full canonical-string/header shape, check order, collision semantics,
  and pinned vectors). The KEY-RESOLVED name threads down as
  `signed_node_name`; when present, `message_send` resolves EXCLUSIVELY
  against it, never falling back to `aoide_storage::node_store::
  resolve_node`'s own two-rung ladder (a node's own `token_file` —
  `NodeRung::Token` — else the TCP origin against a node's `url` —
  `NodeRung::Addr`, the SAME identification the door's
  `is_autogated_node_addr`/`is_autogated_node_token` already fold, just
  unfiltered by `autogate` and narrowed to one named node) even on a
  registry-lookup miss. Neither the `Addr` nor the (now-insufficient)
  `Token` resolution reaches Spawn any more — a bare TCP-source-IP-vs-`url`
  match carries no possession proof, and a bare shared-secret token is
  replayable and identical across every request the true node or an
  impersonator ever sends; both rungs still resolve a node identity for
  attribution/origin-stamping purposes below, just never for Spawn. A
  caller resolved via `Token` to a genuinely paired node gets a taught
  `-32006` telling it plainly to sign requests (its aoide is too old, or
  is failing to sign); a `Signature`-resolved node missing the `spawn`
  capability gets the exact `node allow` fix; every other shape gets the
  original "pair first, then allow" message. The resolved node's name also
  threads two ways past the gate: `do_spawn` calls `stamp_spawn_origin`
  (LANE IDENTITY P-ID0, G16/G5, review round 1) to stamp
  `SessionRecord.origin = "node:<name>"` DIRECTLY on the just-spawned record
  once it registers — this door is the ONLY place a `node:*` value may
  originate, not the child's own env, since any same-uid process can set an
  env var on itself before invoking `aoide conduct` directly
  (`aoide-conduct`'s `session_conduct` refuses exactly that shape from its
  env read, and a third path, `graph/resurrect.rs::origin_to_carry`,
  refuses it again when reading a revived session's own ledger entry back —
  `state/session-ledger.jsonl` is unsealed, so a same-uid process could
  otherwise forge the shape there too). `stamp_spawn_origin` polls for the
  record's registration on the same best-effort budget
  `spawn_inject_prompt` uses (~3s); a disclosed behavior change from the
  pre-P-ID0 synchronous env write — a child that registers slower than that
  window now loses its stamp, logged by name (`eprintln`) rather than
  silently, and the poll never retries unboundedly past it. Neither of
  these closes the FILE: a hand-crafted `sessions.json`/ledger line is
  still a readable, unflagged string on disk — sealing that is P-ID1/P-ID2,
  still open. The Inject arm's own `resolved_node` (a SEPARATE, ungated
  identity lookup — attribution, never a gate) rides `do_inject`'s existing
  `--from` flag onto a QUEUED `pending.json` entry only (an
  immediately-delivered payload's bytes stay untouched, so an
  already-autogated node's delivery is byte-identical to before this
  phase).
  **`aoide/mailDeposit` (P-M2, `docs/architecture/MAIL.md`, CONTRACTS.md
  §6's new subsection) is the SECOND capability-gated method, after
  Spawn, and the first one not gated on `spawn`.** `mail_deposit` resolves
  the caller the identical KEY-RESOLVED way Spawn does (`ctx.
  signed_node_name` against the registry), then requires
  `deposit_admitted` — `node_may_message` (`verified &&
  allows.contains("message")`), mirroring `node_may_spawn` one capability
  over, with no historical Addr/Token rung to migrate off since `message`
  was introduced signature-only from the start. A refusal is `-32010` — a
  NEW code, distinct from both `-32006` (Spawn's own) and `-32007`
  (`verify_signed_request`'s own incomplete-headers/signature-mismatch
  code) — in one of two shapes: paired-but-not-allowed (told the exact
  `node allow <name> message on` fix) or anything else (told to pair, then
  allow). Past the gate, the envelope's own content is entirely
  `aoide_storage::mail::deposit`'s job — recomputing `msgid`, verifying the
  ORIGIN signature (the two-lookup identity model: hop via
  `signed_node_name`, origin via the one key on record for
  `header.from.node`), deduping, and filing. `mail_deposit` self-audits
  UNCONDITIONALLY under `a2a.aoide/mailDeposit`, at both the admission
  refusal and the deposit outcome — mirroring `pair_request`'s "audit
  every call" shape rather than `message_send`'s narrower one, since a
  deposit never passes through `cli/src/dispatch.rs`'s own per-command
  audit and this is the only place a flood becomes visible. A filed
  **letter** mints an ack back to the origin, spools it, and best-effort
  drains that node once through the SAME `aoide_conduct::mail_bridge::
  drain_node` the daemon's own periodic tick uses — one drain
  implementation; `aoide-server` never dials out on its own account. It
  never rings the doorbell itself (P-M5a-2c: the resident daemon is the
  policy and audit boundary for every ring, so this door files and acks
  and stops there) — a remotely-deposited letter arms its readers
  exactly like a locally-filed one, but is rung only by the next
  daemon-side trigger for that name (a reader's Stop hook, a local
  filing, `mail ring` by hand), until a later slice (P-M5b-2) gives this
  door its own forward path to the daemon. A filed
  **receipt** never rings — it is not arming mail (`aoide_storage::mail`'s
  own `arms` predicate) — and instead retires the local outbox entry it
  confirms via `aoide_storage::outbox::retire_by_ack` (spec item 7 — a pure
  lookup keyed on the receipt's own verified origin and acked msgid, so a
  forged or stale ack simply retires nothing). A **duplicate** re-sends the ack only
  when the original filing was a letter, and is a silent no-op otherwise,
  so an ack is never itself acked. Every `outbox` call here runs strictly
  AFTER `mail::deposit` has already released its own lock — `mail` and
  `outbox` share the identical non-reentrant stage-lock primitive, so
  nesting one inside the other would deadlock a process against itself.
- `discovery` — the discovery advertisement's SEND half (P-P6 + task
  #120, `docs/architecture/PAIRING.md`'s "Discovery
  (advertise-but-locked)" section, CONTRACTS.md §6's "Discovery
  advertisement" subsection). `a2a::serve` calls `spawn_advertiser`
  exactly once, at launch — the thread always exists, but a tick only
  SENDS when `a2a::resolve_discovery_advertise`'s launch-time force
  (`--discovery-advertise`/`AOIDE_DISCOVERY_ADVERTISE`, mirroring
  `resolve_bind_port`'s own precedence) OR the runtime switch
  (`aoide_storage::advertise::enabled`, flipped by `aoide node advertise
  on|off`, read fresh every tick) says on — both off by default: silent
  ticks, no socket, nothing on the wire. A sending tick (~30s, jittered)
  binds a fresh ephemeral UDP socket with `SO_BROADCAST`, sends one
  `aoide_storage::advertise` line (name + ssh hop claim ONLY — no door
  URL, no key, no identity file touched) to the fixed
  broadcast-address+port, and drops the socket — fire-and-forget, no
  connection state held between ticks. Fallible spawn
  (`thread::Builder::spawn`, `daemon.rs`'s discipline, not `a2a.rs`'s own
  plain `thread::spawn` for connection handlers — that one is reserved for
  a NEW socket-based door, not a background worker thread) — a refused OS
  thread costs discovery only, never the door. The RECEIVE half
  (`node discover`/`aoide pair`'s hostname-target sweep) lives in
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
