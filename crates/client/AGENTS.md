# AGENTS.md — aoide-client

## Invariants

- **Outbound only.** This crate is the CLIENT half of A2A — node
  registration/messaging, the pairing ceremony's CLI half, the melete
  adapter. The serve/listen half lives in `aoide-server` and must never
  migrate here.
- **The `conduct → client` edge is load-bearing, not a smell.** `conduct`'s
  presence projection (the roster core, workstream C2, landed — reached via
  bare `session`/`--hosts`; the standalone `who` command it originally
  backed is retired, session-surface redesign, command-defrag lane X,
  2026-08-28) calls this crate's
  `commands::pull_node_live` for its live per-node probe. Don't "heal" it
  by inverting the dependency or duplicating the transport in `conduct` —
  see `docs/architecture/PACKAGE-LAYOUT.md`'s "Verified facts" note on this
  exact edge.
- **`build_message_send_body` hardcodes `context_id: None` today.** A caller
  adding cross-host context threading extends the function's parameters
  rather than working around it — the server side already routes a
  `context_id` when given one.
- **`sign_headers_for_node` (P-P4) is the ONE production call site that
  ever builds the `X-Aoide-*` signature headers — every real node-POST
  function threads `post_json`'s `extra_headers` through it, never
  hand-rolls a header set inline.** It returns `vec![]` for an
  unverified/unpaired node, never a partial or malformed header set —
  `verify_signed_request` (`aoide-server`) refuses a request carrying SOME
  but not all four headers, so a future edit that adds a header
  conditionally (e.g. "only send `X-Aoide-Nonce` if X") would silently
  turn every affected outbound request into a hard refusal on the far
  end. `aoide/pairRequest`/`aoide/pairReveal` always pass an empty header
  slice — they are unauthenticated by protocol design (see the P-P2
  ceremony invariants below), not merely "not yet wired." `aoide/pairPoll`
  (Design A, task #119, REPLACES the old `aoide/pairApprove` reverse
  callback) carries a signature too, but never through this function — no
  `Node` record exists yet at poll time for its `node.verified` check to
  key off, so `build_signed_pair_poll_body` (`commands.rs`) signs directly
  against the requester's own identity instead, a SEPARATE self-contained
  scheme (see that function's own doc for why P-P4's header scheme can't
  bootstrap this).
- **`HTTP_METHOD` (P-P5b, closing a P-P4 review finding) is the ONE named
  constant `post_json`'s `-X` argument AND `sign_headers_for_node`'s
  `canonical_string` call both read — never re-introduce a second
  hardcoded `"POST"` literal at either site.** Before this fix the two
  carried independent literals that merely happened to agree; if this
  crate ever sends a non-POST request, thread the real method through
  `HTTP_METHOD`'s call sites instead of adding a third guess.
- **`spawn_on_node` is the ONE place that builds and sends a spawn-shaped
  `message/send` — never re-implement it at a second call site.** Extracted
  (U4, command-defrag lane U) from `handle_node_spawn` so `aoide-conduct`'s
  manifest remote-summon path (`graph::resurrect::summon_remote`) could
  reuse the exact same signed wire call rather than shelling out to the
  `aoide` CLI or hand-rolling a second `post_json`/`sign_headers_for_node`
  pairing. It is the FIRST production seam to sign a `contextId`-less
  (spawn-shaped) body via `sign_headers_for_node`. `handle_node_spawn`
  (P-P5b, `node spawn`) gates LOCALLY on exactly one question before
  calling it — is the named node a registered, `verified` entry at all —
  and NOTHING else; `summon_remote` gates on the SAME question (plus
  "is there anything to summon with" — its own concern, no wire involved)
  before calling it too. Every refusal shape beyond "unknown/unpaired node"
  (`allows` lacking `spawn`, an unsigned-but-paired caller, clock skew, an
  unreachable node) belongs to the REMOTE door's own gate
  (`aoide-server::a2a::spawn_admitted`/`spawn_refusal`) or the transport —
  surfaced verbatim as `spawn_on_node`'s `Err`, never re-derived or
  duplicated at either call site. Don't add a second local check for any of
  those; the local refusal exists ONLY to save an obviously-doomed round
  trip (an unsigned request can never resolve `NodeRung::Signature`), never
  to second-guess the door's own authority (PAIRING.md decision 6).
- **Forwarded event text from `adapter` is untrusted data**, same as root
  `AGENTS.md` house rule 4 — an adapter never lets forwarded text execute as
  a command.
- **`mcp_client`'s `AOIDE_MELETE_URL`/`AOIDE_MELETE_TOKEN` are a deliberate
  choice, not an oversight — don't "fix" them onto `node_store` (M2, task
  #14).** `aoide_storage::node_store::Node` (url + `bearer_secret`,
  resolved through the secrets broker) models AOIDE-TO-AOIDE federation —
  AgentCard-verified, signed, per-node `allows` — over aoide's OWN wire
  protocol; Melete is a third-party claude.ai service speaking plain MCP,
  never an aoide node, so that shape doesn't fit. The `usage` command's `live`
  block (`aoide_storage::commands::fetch_live_usage`) is the closer
  precedent — a single, external, bearer-authenticated endpoint — but its
  token rides a LOCAL FILE Claude Code itself already maintains; aoide has
  no equivalent on-disk source for a Melete url/token, and inventing one
  is explicitly out of scope for M2. Both env vars are read FRESH on every
  call (never cached) and unconfigured is a structured `Outcome::error`
  naming both var names — never a silent degrade, never an invented
  credential. The eventual live wiring (most likely a secrets-broker-
  resolved secret, mirroring `node add --bearer-secret`) is a KNOWN future
  step, not something to backfill speculatively here.
- **Every `melete` command is `Door::Cli`-only, not just `melete call` (M2,
  task #14) — match `aoide-secrets`' BLANKET family gate, not its
  per-command one.** `aoide-secrets` gates its entire command family
  `Door::Cli`-only (`require_cli`, called from nearly every one of its
  handlers, including read-only ones like `secrets pending`) because its
  whole surface touches secret material; `melete`'s whole surface sends a
  live bearer token outward and can trigger real action, the same risk
  class, so `handle_melete_status`/`handle_melete_graph` gate identically
  to `handle_melete_call`, not just the one that obviously mutates. A new
  `melete` command gates the same way by default; carving out an exception
  needs the same justification `aoide-secrets` would need for one of its
  own.
- **`mcp_client::call` reads a Melete response defensively off a raw
  `Value` — never forces it through `aoide_protocol::wire::mcp`'s
  `InitializeResult`/`ToolCallResult` structs.** Those describe AOIDE's
  own guarantees as an MCP *server* (e.g. "always exactly one text content
  block") — promises Melete never made this client. `parse_response_body`
  parses plain JSON first, then defensively as an SSE-framed (`data: `-
  line) body per streamable-HTTP MCP; `extract_result` reads `result`/
  `error` off the parsed `Value` with `.get()`, never a strict
  deserialize. A future edit that "cleans this up" by typing the response
  strictly would turn an unexpected-but-valid Melete reply shape into a
  hard parse failure instead of the taught error the untyped path
  produces today.
- **`mcp_client` makes exactly ONE POST per command — no `initialize`-then-
  session-id handshake is threaded into `graph`/`call` (M2, task #14).**
  Documented as an ASSUMPTION (this crate's module doc), not a proven
  wire fact — Melete's connector is treated as a stateless-per-request
  bearer-token API, the minimal shape the three commands need. If a live
  integration later proves Melete requires a real MCP session
  (`Mcp-Session-Id` carried from `initialize` into subsequent calls),
  thread it through `mcp_client::call` centrally — every command already
  funnels through that one function — rather than adding a per-command
  workaround.
- **`daemon::daemon_dispatch` is outbound too, not an exception to "outbound
  only."** It is the CLIENT side of the fourth door (P-D6): a routed
  handler in `conduct`/`server` calling OUT to the resident `aoided`'s
  socket, never anything that listens. `daemon::socket_path` resolves
  `aoide_server::daemon::socket_path`'s exact convention without importing
  it from there — this crate sits BELOW `aoide-server` in the DAG (`server`
  depends on `conduct`, which depends on this crate), so an import would
  invert it. As of LANE IDENTITY P-ID4 the derivation (plus
  `connect_bounded` and the `daemon_seal_pubkey_hex` ping fetch) lives in
  `aoide_storage::attest` with this module delegating — edit the body
  there; a change to the daemon socket's resolution rule updates that body
  AND `aoide-server`'s bind-side copy in the same commit.
- **`daemon_dispatch` returning `None` is not the same as an error, and the
  distinction is load-bearing.** `None` means "nothing usable answered" —
  dead socket, refused connect, or `inv.door == Door::Daemon` (the
  reentrancy guard: a handler already running INSIDE the daemon must take
  its direct path, never try to connect to itself) — and the caller's own
  pre-existing direct path must run unchanged. Once a connection is
  actually made, every other failure becomes `Some(Outcome::error(...))`
  instead, since a daemon that answered but broke is a real anomaly, not
  something to paper over with a fallback that would mask a daemon-side
  bug. Don't collapse that second case into `None` "to keep the fallback
  path simple" — it hides real daemon failures as ordinary "no daemon
  running."

- **`handle_node_pair_approve` dispatches by DIRECTION — inbound first,
  outbound second (P-P2) — and Design A (task #119) put the ONE wire call
  on the OUTBOUND half, never the inbound one; before this phase it was the
  reverse.** `approve_inbound` (this instance is the APPROVER) is now
  PURELY LOCAL: it commits its own `pubkey`/`verified` node record, then
  marks the parked entry `approved` (`aoide_storage::pairing::mark_inbound_approved`)
  and leaves it PARKED for the requester's own poll to find — no wire call
  at all, so an unreachable or loopback-only requester never blocks this
  half.
- **`approve_inbound`'s commit maps `entry.self_via` to `{url, via}` — get
  this backwards and every loopback-only requester's node record comes out
  undialable (task #131).** Present, the commit is `url:
  http://127.0.0.1:<port>/` (never `entry.url` — the requester-observed
  door, undialable through the very tunnel that delivered this request)
  and `via: entry.self_via` via `set_node_via` in the SAME write as
  `upsert_paired_node`, mirroring the sibling-writer shape
  `approve_outbound`'s own `entry.via` commit already holds just below it.
  **`<port>` is `port_from_url(&entry.url)` — the REQUESTER's own door
  port. Never `default_a2a_port()` outright (review finding: the first
  pass read THIS box's own `AOIDE_A2A_PORT`, which has no relation to the
  requester's door at all)** — `port_from_url` is only ever a fallback for
  the rare case `entry.url` carries no parseable port. Absent (no
  `self_via` claim), both stay exactly what `upsert_paired_node` alone
  already produces: `entry.url` verbatim, `via` untouched (never call
  `set_node_via` with `None` here — that would WIPE a via a previous
  pairing recorded, the same "untouched unless this call names a change"
  stance `approve_outbound`'s own `Some`-gated call already holds).
  `approve_outbound` (this instance is the REQUESTER) is the one that
  now makes a wire call, when its entry is still `AwaitingApproval`: it
  POSTs a SIGNED `aoide/pairPoll` to the approver's door (over the SAME
  forward dial `run_pair_request` already used — `entry.via` if one
  was recorded), and ONLY on an `approved` response does it call
  `mark_outbound_awaiting_confirm` (rejecting a released pubkey that
  doesn't match what this instance learned at request time — the
  SAS/transcript binding, unchanged from before) and fall through to
  confirm-then-commit via `upsert_paired_node`. Never re-introduce a
  reverse callback here — the WHOLE POINT of Design A is that nothing ever
  needs to dial IN to the requester. `approve_inbound` also refuses outright
  (`"awaiting-reveal"`) on an entry whose `requester_nonce_hex` is still
  `None` — the commitment hasn't been revealed yet, so there
  is no SAS to confirm. The SAS itself is ALWAYS re-derived from this
  instance's own identity plus the parked entry's stored fields
  (`aoide_storage::pairing::derive_sas`) on EITHER path — never trusted
  from anything the wire carries, since the entire point of the ceremony
  is a code neither side can spoof to the other.
- **`run_pair_request` sends the commitment and the reveal as TWO
  sequential POSTs inside ONE invocation (P-P2) — never split
  across two separate CLI calls.** It mints its own nonce locally, POSTs
  `build_pair_request_body` carrying only `derive_commit(pubkey, nonce)`
  (the nonce itself never rides that first message), then immediately
  POSTs `build_pair_reveal_body(id, nonce)` to the SAME door before ever
  computing or printing a SAS — a reveal that fails (unreachable,
  HTTP error, or the node refusing with a commitment mismatch) fails the
  whole `aoide pair` call (either arm — `pair_via_url`/`pair_via_hostname`,
  P-PV2, both call this one core); nothing is parked as a usable outbound
  entry with an unrevealed commitment on this side, since this side chose
  the nonce and always has it.
- **`handle_node_pair_reject` tries the inbound queue, THEN the outbound
  queue — never just one (P-P2).** An outbound entry at EITHER
  `OutboundState` aborts cleanly on reject; this is the ceremony's only
  abort command, so collapsing this back to inbound-only would leave a
  requester with no way to cancel a pairing it no longer wants.
- **Neither approve half reads `&Invocation` — `approve_outbound` and
  `approve_inbound` take the SAME `CodeGate` enum now (task #120 P3; the
  mutual-code redesign, R1, unified them — `approve_outbound` used to take
  a bare `skip_confirm: bool`, P-P5).** Don't reach for
  `inv.flag_present(..)` inside either function; the ONLY callers that
  read flags are `pair_finish_from`/`outbound_gate_from`, which resolve
  them into the parameter for `approve_inbound_leg`/`resume_outbound_leg`
  to pass on. A caller with no `Invocation` at all (`pair_watch`'s popup
  arm is the first) passes `CodeGate::Code(<typed>)` directly on EITHER
  leg — the popup's own dialog (P-PV3, task #132; unified across both
  directions by R1) collects a typed code exactly like the CLI tty/
  `--code` paths do, so it rides the SAME gate rather than a separate
  no-prompt variant. Don't reintroduce a no-check gate variant (the old
  `InboundGate::DialogConfirmed`, "the dialog itself IS the confirmation,
  no code check", was already retired before R1) for a future dialog
  surface without re-deriving why the typed-code gate doesn't apply there.
- **BOTH approve halves gate on a TYPED code now, and neither approve
  prompt echoes the expected value (task #120 P3; R1 extended this from
  inbound-only to both legs).** `approve_inbound` gates on `derive_sas`
  (the code the REQUESTER's screen shows); `commit_outbound` gates on
  `derive_reply_sas` (the code the APPROVER's screen shows) — a SECOND,
  DIFFERENT code from the first, never the same value re-typed (`pairing.rs`'s
  own module doc has the two-code construction; typing a value back at its
  own source would prove nothing, the entire reason R1 exists). Both
  prompts and mismatch messages name only the code's SHAPE (`NNN-NNN`),
  never its value — printing the expected code beside the input would
  collapse the out-of-band comparison into a copy exercise (bare
  `aoide pair` shows NO code at all, P-PV2 — the threat model is the
  comparison, not secrecy, but a listing either operator can glance at
  defeats it just the same as an echoed prompt would). A wrong code —
  interactive or `--code` — persists ONE cumulative try per direction
  (`aoide_storage::pairing::record_inbound_code_try`/
  `record_outbound_code_try`); the third cumulative mismatch auto-resolves
  (`auto_deny_inbound`/`auto_abort_outbound`: the parked entry taken,
  nothing committed, `reason: "auto-deny-on-code-mismatch"`/
  `"auto-abort-on-code-mismatch"` for the audit log). An abort (`Esc`/EOF)
  counts no try on either leg. `--yes` maps to `CodeGate::Unavailable`'s
  taught refusal on BOTH directions now — never a bypass on either.
- **`reject_by_id(cmd, id)` is `handle_pair_reject`'s entire body,
  extracted (P-P5) so a caller with only an id — no `&Invocation` to
  construct — can reject a pairing request too.** Keep it a pure
  `(cmd, id) -> Outcome`; don't grow it a `skip_confirm`-shaped parameter
  — a reject was never confirmation-gated (module doc above: "a clean
  refusal"), so there is nothing for a caller to skip.
- **`pair_watch::reconcile` is a SEPARATE, independent re-implementation
  of the SAS-deriving arg orders `approve_inbound`/`approve_outbound`
  hold — not a shared helper, DELIBERATELY (P-P5).** Bare `aoide pair`
  itself carries NO SAS at all (P-PV2, the User's locked spec) — the
  code is read off the requester's own screen and typed on the
  approver's, never shown in a listing either operator could just glance
  at — so `reconcile`'s own swap-catcher pins against the APPROVE path's
  derivation instead. The two arg orders
  (inbound: `(entry.pubkeyHex, own_pubkey, requester_nonce,
  entry.approverNonceHex)`; outbound: `(own_pubkey, entry.pubkeyHex,
  requester_nonce, approver_nonce)`) are asymmetric and easy to swap by
  accident — `pair_watch`'s own byte-equality test
  (`reconcile_derives_the_same_sas_approve_inbound_would`) is
  what catches a swap in EITHER copy, but it can only do that because the
  two copies are independent; collapsing them into one shared function
  would make that test tautological (it would just be comparing a value
  to itself). If a real DRY opportunity ever presents itself here, keep
  the swap-catching test's independence some other way — never delete it
  "since there's only one implementation now."
- **A feed line's own `payload` fields are safe for PASSIVE narration
  (`narrate`/`event_to_json`) — they are never safe for anything that
  drives an ACTION.** `name` is `valid_node_name`-charset-restricted
  before `a2a.rs::pair_request` ever parks it, the same "validated before
  it's usable" stance every other displayed field already has — this
  mirrors `aoide_secrets::watch::narrate_event`'s own identical trust in
  its feed line's fields for narration-only output. [`reconcile`] is the
  hard line: it NEVER reads the feed, only
  `aoide_storage::pairing::list_inbound`/`list_outbound` directly — the
  popup arm's `confirm_title`/`confirm_text` (P-P5) build their displayed
  text and SAS from `reconcile`'s own `Pending` exclusively, never from a
  `PairEvent`'s fields, no matter how validated those look — a future
  change that threads a `PairEvent` into either function is the one thing
  to refuse on sight. Don't fold the two trust levels back into one "just
  use the feed line" path.
- **`decide` (P-P5) maps a `SpawnError`/`DialogFailure` to `Backoff`,
  NEVER `Ignore` — the same rule `aoide_secrets::watch::popup_loop`
  already holds for its own `ZenityResult` match.** `Ignore` is a
  SESSION-ONLY, USER-CHOSEN dismissal (a bare Cancel/Escape); a dialog
  that failed to even open never received a user's choice, so treating it
  as `Ignore` would permanently stop offering a request over what could
  be a transient glitch (a display hiccup, a momentarily-missing
  binary). `REJECT_LABEL` (`"Reject request"`) is this arm's OWN string,
  never `aoide_protocol::dialog::DISMISS_LABEL` — `run_entry_dialog`
  takes its dismiss label as a parameter specifically so two ceremonies
  sharing the loop can each pass their own.
- **`run_pair_request` (P-P6) is the ONLY body of `pair_via_url`
  past its own `<url>`/`--name`/`--self-url`/`--self-via` parsing, and
  `pair_via_hostname` and bare `pair` (`handle_pair`, task #120 P3) reach
  the SAME function — never a second copy — through `pair_with_heard`, the
  shared settled-target tail (dial-URL composition off the OBSERVED
  source, `resolve_pair_vias`'s `dial_via`/`record_via` derivation, task
  #131). `handle_node_pair` (P-PV2, the User's locked spec) is the ONE
  registered entry point over both arms — SMART TARGET dispatch on the
  first positional arg's shape (`"://"` → `pair_via_url`, else →
  `pair_via_hostname`), never a second command path.** Don't reintroduce
  K1's old split where only `record_via` got
  the observed-address default and `dial_via` stayed `None` by default —
  a loopback-only door (the case task #131 exists for) is simply
  undialable that way; `resolve_pair_vias` is the ONE place both are
  derived, unit-tested directly (no dial, no tempdir), so a future change
  to that derivation touches one pure function, never two call sites that
  could drift. CONTRACTS.md §6's "Discovery advertisement" subsection
  promises `pair`'s hostname arm "runs the ceremony," and this is
  what makes that literally true rather than aspirational: a future
  change to the ceremony's wire calls, its outbound-parking shape, or its
  SAS derivation touches ONE function and every caller inherits it
  identically. `handle_pair` holds bare `session`'s exact door
  discipline — CLI + real tty (`pick::interactive`) or a taught refusal
  naming the scripted spellings, never a read from a stdin nobody is
  typing into — and filters self-advertisements (`is_self_target`)
  BEFORE the menu renders, so picking a row can stand as the
  proceed-confirmation without a second y/N. `run_pair_request` does NOT
  re-validate its `name` argument (`valid_node_name`) — that check stays in
  `pair_via_url` alone, since only a CLI-typed `--name` needs
  it; `pair_via_hostname`'s `name` already came off an advertisement
  `aoide_storage::advertise::parse_and_validate` validated before it was
  ever displayed. Don't move the `valid_node_name` check INTO `run_pair_request`
  "for symmetry" — it would just re-run a check that has already passed on
  the hostname arm, for no benefit, and would misattribute a `pair`
  usage error to a check that only ever fires for the OTHER arm in
  practice.
- **`discover`'s `run_sweep`/`resolve_invite_target` never touch
  `node_store` for writing, and `handle_node_discover`/`pair_via_hostname`
  must not either (P-P6) — nor may `run_sweep`'s cross-crate consumer,
  `aoide-conduct::graph`'s `node list` (task #120 P2).** Discovery grants
  nothing
  (`docs/architecture/PAIRING.md`'s "Discovery (advertise-but-locked)"
  section) — the only node-record write path in this crate is, and stays,
  `run_pair_request`'s `park_outbound` plus `approve_inbound_leg`/
  `resume_outbound_leg`'s
  `upsert_paired_node` calls. A future `node discover`/`aoide pair` edit
  that seems to want a registry write (e.g. "remember what was last
  discovered") belongs in a NEW, explicitly-named cache, never folded into
  `state/nodes.json` itself.
- **An advertisement's `host`/`user` are CLAIMS; a `Heard`'s `src_addr`
  is an OBSERVATION — never swap which one is trusted (P-S1).**
  `host`/`user` are whatever the advertiser put on the wire; `src_addr`
  is the UDP packet's actual source IP, captured by THIS process's own
  socket, never sent by the advertiser and never believed to be anything
  but what was measured. Everything that dials — `pair_via_hostname`'s
  composed target, the K1 default `via` — takes its ADDRESS from
  `src_addr`; the claimed `user` rides along only as the ssh login, and
  the claimed `host` is display-only. `Advertisement` itself never grows
  a `src_addr` field (the wire shape is CONTRACTS-pinned; the
  observation belongs on `Heard`, which is local-only and unpinned), and
  it never regrows a door-URL or key field either (task #120:
  rendezvous, not authentication). Do not add a "dial the claimed host
  instead" fallback or flag — guessing which of the two the operator
  meant is not this code's job.
- **`tunnel` is the ONE place `Command::new("ssh")` is ever written in this
  workspace (P-S3) — a new cross-box call site resolves a dial url through
  `open_or_reuse`, never spawns its own `ssh`.** `aoide_storage::tunnel`
  (P-S2) owns the record's shape and its pure helpers (parsing, path
  rewriting, the runtime-dir layout); this module owns the child process:
  spawning it, probing whether its forward answers, reusing a still-live
  one, and tearing it down. `BatchMode=yes` on `spawn_ssh`'s argv is an
  INVARIANT, not a preference — it is the mechanical form of the house rule
  that aoide never automates ssh key setup: no password or host-key prompt
  can ever appear, so a missing `authorized_keys` entry on the far end
  fails fast (an `ssh` exit, caught by `open_or_reuse_with`'s own
  `try_wait` check inside its poll loop, never merely waited out) instead
  of hanging on a prompt nothing here could ever answer. **Aoide never
  writes to anyone's `~/.ssh/authorized_keys`** — the taught errors
  `spawn_ssh`/`open_or_reuse` return on a failed or timed-out open name the
  one-time manual step (add this box's key to the far box's
  `authorized_keys`) but never attempt it themselves. The recycled-pid
  guard (`looks_like_our_ssh`, reading `/proc/<pid>/cmdline`; wrapped as
  `kill_if_still_our_ssh`) is a DELIBERATE, documented tiny race, not an
  oversight: a pid recorded by an earlier `aoide` invocation may have been
  recycled by the OS to an unrelated process by the time anything acts on
  it, so a pid is never trusted alone — only one whose own cmdline is still
  `ssh` carrying this record's exact `-L` spec is ever signaled. **This
  guard is not `close`'s alone** — `open_or_reuse_with`'s own stale-record
  path runs it on a live-but-dead-port record's OLD pid before that record
  is REPLACED by a freshly opened one at the same `(session_id, key)`;
  skipping this on the reopen path would make the old child permanently
  untrackable the instant its record is replaced, since `close`/
  `close_all_for_session`/the reaper (P-S5) can only ever act on a pid they
  load FROM a record. **`kill_if_still_our_ssh` is `#[must_use]` and returns
  whether the pid is now safe to forget — `true` (never alive, never ours,
  or ours and confirmed dead) versus `false` (confirmed ours and STILL
  alive once the bounded kill elapses).** No new code path may replace or
  drop a tunnel record without first routing the pid it named through
  `kill_if_still_our_ssh` AND gating on that return value: `close` leaves a
  survivor's record in place rather than dropping it, and
  `open_or_reuse_with`'s stale-record path REFUSES the reopen outright
  (a taught error, never a silent overwrite) rather than replacing a
  record while the old child it named is still alive and about to become
  untracked — a second forward to the same target is never opened
  alongside a live, untracked one. `terminate_pid` reaps with a real
  `waitpid(pid, WNOHANG)` poll before ever falling back to its `/proc`
  poll — required, not cosmetic, for the case where `open` and `close` (or
  a stale reopen) run in the SAME process: that pid genuinely IS this
  process's own child, and nothing else will ever collect it, so skipping
  `waitpid` there would leave a real zombie. `ECHILD` (the ordinary
  cross-invocation case — an earlier `aoide` run parented the child, not
  this process) falls back to the `/proc` poll, same as always.
- **Every cross-box network call resolves its dial url through
  `resolve_dial_url` (P-S4) — not just the signed POSTs, and never
  `post_json(&node.url, …)`/`post_json(&some_raw_url, …)`/`run_curl(&["--",
  &some_raw_url], …)` directly.** `post_json_to_node(node, …)` (a
  registered `Node`) and `post_json_via(logical_url, via, tunnel_key, …)`
  (a ceremony call with no `Node` record yet) are the two entry points for
  a POST; `commands::post_json` itself is UNCHANGED by this phase and must
  stay that way — dial resolution is a wrapper in FRONT of it, not a
  rewrite of it. **`handle_node_add`'s AgentCard fetch is a GET and was
  missed on first landing (review finding) — it now calls
  `resolve_dial_url` directly before its own `run_curl`, same as any other
  call.** `--no-verify` (M3, task #16) skips the fetch — and therefore this
  funnel — entirely, for a node known to serve no AgentCard; that is the
  ONLY way `handle_node_add` ever runs with no network call at all, and it
  is a deliberate opt-out of verification, never a second dial path around
  `resolve_dial_url`. Any FUTURE cross-box network call — POST or otherwise — needs the
  same funnel in front of it; a call site added without checking this
  invariant against the full list below (`grep -n 'run_curl\|post_json'`
  in this file) is exactly how the AgentCard fetch was missed the first
  time. **The
  identity guarantee is load-bearing:** `via: None` must return the
  logical url byte-for-byte, and `resolve_dial_url`'s tunnel-key/path
  handling must never diverge from `aoide_storage::tunnel::dial_url`'s own
  path extraction (`node_store::url_path`) — a second, independently
  written path cut here would silently break `sign_headers_for_node`'s
  canonical string the moment it drifted from the far door's own observed
  `HttpRequest.path`. **`--via` beats `Node.via`, never the reverse** —
  `spawn_on_node_via`'s `via_override` parameter is checked FIRST,
  `node.via` only when the override is absent; a new `--via`-accepting
  command follows this same precedence, not a per-command variant of it.
  **The session key (`tunnel_session_id`, K3) is resolved and passed
  through here, but this crate never closes a tunnel itself, by design.**
  `pull_node_live`/`send_message_to_node`/`spawn_on_node` are called from
  `aoide-conduct`, which this crate cannot wrap — closing only at the
  client-owned CLI handlers while those call sites stayed unclosed would
  make identical code behave inconsistently by caller. **Do not add a
  partial close here.** The real lifecycle lives one crate up, in
  `aoide-conduct`: a session-keyed tunnel is closed on its session's own
  clean exit (`graph::session_store::do_session_end`'s fast path, via
  `close_all_for_session`) and, for a session that never runs that exit,
  by `reap::sweep_orphan_tunnels`'s backstop (`kill_if_still_our_ssh` —
  `pub` in this module for exactly that reaper to reuse, never
  re-implemented there); a bare-shell `pid-<pid>` tunnel has no session
  lifecycle to hook, so it is left for that same sweep's ordinary dead-pid
  arm to collect once its one-shot CLI process has exited.
- **A tunneled request is safe against a real node, not merely possible.**
  Every request delivered through an ssh forward reaches the far A2A door
  as `ConnOrigin::Loopback` (`aoide-server::a2a::classify_origin`), which
  carries an unconditional Inject delivery free pass for an UNSIGNED
  request. This module makes the tunnel work; `aoide-server` narrows that
  free pass (`origin_for_inject`, CONTRACTS.md §6) so a verified per-request
  signature never rides Loopback's trust, with a like-for-like
  signature-rung autogate restoring delivery for a node the operator
  already marked auto-deliver. `--via`/`Node.via` are safe to recommend for
  a real cross-box pair.
- **The self-pair guard (`discover::is_self_target`) runs BEFORE the
  proceed-confirm and BEFORE the ceremony, in `pair_via_hostname`, never
  inside `run_pair_request` (P-S1).** `run_pair_request` is shared with
  `pair_via_url`, whose `<url>` a human typed and is entitled
  to point at their own door on purpose (loopback testing, a self-pair
  smoke test); only the DISCOVERED (hostname) arm needs the "you just
  tried to pair with yourself" refusal, because only there does the
  target come from an automated resolution the operator didn't type by
  hand. Known gap: the guard's `own_name` is env/hostname-tier only, so a
  serve advertising under a custom `--node-name` FLAG escapes the name
  arm while the self-heard broadcast arrives on the physical interface
  (missing the loopback arm) — such a pair dials this box's own door; the
  SAS ceremony backstops it (both codes land in front of one operator).
- **`mesh::drift` stays pure — no I/O, no clock, no env (task #135 P4).**
  `handle_mesh` is the one impure edge; every ruling below is enforced
  THERE, in the comparison, never smuggled into a handler-only code path
  that a unit test can't reach.
  - **`Node` gains no field for this.** A mesh's shape lives entirely in
    `config.toml`'s `[mesh.*]`; the live registry (`node_store::Node`) is
    read, never written, by this comparison, and never grows a
    mesh-shaped column to go stale against the declaration it would be
    shadowing.
  - **`allows` divergence is not a drift class.** `mesh.<name>.grant` is
    stamped at FIRST verification and only there: `mesh pair` hands it to
    the ceremony as `PairFinish::grant`, and `node_store::
    upsert_paired_node` leaves an already-verified node's set exactly as it
    was. So the declaration is a default for the moment a pair is minted,
    never a continuous invariant over it — a human narrowing or widening
    `allows` afterward via `node allow` is a deliberate decision this
    comparison has no standing to re-flag on every subsequent call. Do not
    add a fourth class that compares `grant` against live `allows`.
  - **`undeclared` (paired, named in no mesh) is reported, never accused.**
    It is its own field on `MeshReport`, outside every drift count, and
    its rendering never suggests an action. Plenty of legitimate nodes are
    undeclared forever; stating the fact and stopping is the whole
    contract.
  - **The local host is skipped silently**, in the comparison itself
    (never filtered post hoc by a caller) — a mesh declared identically
    across every member box will list that box's own name among its
    nodes, and that is not a node relationship to report on.
  - **`via: None` on an otherwise-matched node is the severe sub-case of
    `ViaMismatch`**, not a fourth class: a call with no `via` dials the
    node's bare `url` directly, which for an already-paired node is
    commonly a loopback address, so it silently dials THIS box's own
    loopback. Severity is derived at render time (`recorded.is_none()`),
    never stored as a second field redundant with `recorded`.
- **`mesh pair` NEVER modifies an existing verified node (task #135 P5).**
  `plan` selects `missing` and `unverified` and nothing else; a
  `via-mismatch` comes back `skipped`, naming `aoide pair <name>` as the
  fix. Three reasons, and none of them has weakened: re-pairing rotates key
  material (`docs/architecture/PAIRING.md`: never silently),
  `commands::confirm_repair_if_verified` already gates that behind a human
  y/N, and writing `via` outside a ceremony commit would make this module a
  second writer of a field `node_store::set_node_via` reserves to that
  commit. The payoff is idempotence by construction — a second run is
  all-`skipped` — and a test pins it. Do not widen the selection to "repair
  what drifted".
  - **Zero ceremony logic lives in `mesh.rs`.** Every selected node goes
    through `commands::run_pair_request`, which already posts request +
    reveal, parks, and (on a nonzero wait) polls and commits. A second poll
    loop, a second commit path, or a hand-rolled request here is the exact
    design error the `poll_outbound_once`/`commit_outbound` split exists to
    prevent.
  - **The outcome vocabulary is four words** — completed / parked /
    UNREACHABLE / skipped — and a fifth is a spec change, not an
    implementation detail. `classify` decides between them on two facts
    handed in (the ceremony's envelope, and what `pairing::list_outbound`
    holds for that node afterward), never on a `data.reason` string, which
    would hostage the vocabulary to the ceremony's wording. `Unreachable`
    has no id FIELD, so no report can ever invite a resume of something
    that was never parked.
  - **Parked state is read only through `pairing::list_inbound`/
    `list_outbound`**, never by touching the file. A new optional field on
    a parked entry must stay invisible to this module.
  - **`sameOperator` is declared and not acted on.** Whether a converge may
    ever satisfy the far side's typed code on an operator's behalf is
    undecided. A mesh declaring it converges byte-identically to one that
    does not, and the report carries ONE note saying the flag was seen and
    not acted on — a note, never a row, never a status, never a refusal,
    and in `--json` its own field outside `rows`. Do not make it change a
    selection, a count, or a gate before it is ruled.
  - **`mesh pair` carries no door gate, for the same reason `pair` carries
    none.** Off any door but the CLI, `pick::interactive` is false and both
    legs' `CodeGate` resolves to `Unavailable`, so a remote caller can start
    requests and can never commit one. A converge inherits that whole; a
    gate here would be a new guard where the convention already answers.
  - **`mesh pair` adds no audit call of its own.** Auditing is per-dispatch
    (`cli/src/dispatch.rs`), not per-ceremony — the record commits make no
    `audit` call, and `aoide-client` makes none outside `adapter.rs`. So a
    converge over five nodes writes ONE line named `mesh.pair` where five
    `aoide pair` runs write five. That coarsening is deliberate: a converge
    audit line belongs to the pairing-audit-sweep slice (design record §7,
    T4), which owns the three ceremony audit sites, not to this command.

## Extension points

- **A new outbound A2A command** adds a `cmd!`/`register` entry in
  `commands.rs`, wired into the owning app crate's `commands::all()`.
- **A new adapter consumer** (beyond melete) gets its own module beside
  `adapter.rs`, built the same neutral-event-in/typed-event-out shape.
- **A new Melete tool** needs NO new command — `melete call <tool>
  --args <json>` already reaches any tool name by construction (M2, task
  #14's whole point: immune to Melete's own tool-list drift). Only a tool
  worth a FIRST-CLASS command (its own parsed args, its own state-dir write —
  `melete graph`'s own shape) earns a new `cmd!` entry in `mcp_client.rs`,
  built the same `resolve_config` → `require_cli` → `mcp_client::call`
  pipeline the existing three already share.
- **A new session-write handler that should route through the daemon**
  calls `daemon::daemon_dispatch(inv)` as its own first line and returns
  early on `Some(outcome)` — the exact one-line prefix every P-D6 handler
  in `conduct` already uses; nothing in THIS crate changes for a new
  routed command, since `daemon_dispatch` is already generic over any
  `Invocation`.
- **A new `mesh::DriftClass` variant** is a new match arm in `drift` (still
  pure — see the invariant above) plus a new `render_row` arm; the variant
  itself stays internally tagged (`#[serde(tag = "class", rename_all =
  "kebab-case")]`) so `--json` keeps emitting one flat `{"node": …, "class":
  …}` object per row. Add the unit tests for the new class beside the
  existing per-class tests in `mesh::tests` before touching the handler.

## Docs update required in the same commit

- This `README.md` when a new module or CLI command group is added.
- `CONTRACTS.md §6`/`§7` when an A2A or node-federation wire shape changes.
- `pkgs/aoide/crates/AGENTS.md` for cross-crate invariants — not restated
  here.
