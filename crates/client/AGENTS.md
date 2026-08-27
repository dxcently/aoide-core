# AGENTS.md — aoide-client

## Invariants

- **Outbound only.** This crate is the CLIENT half of A2A — peer
  registration/messaging, the pairing ceremony's CLI half, the melete
  adapter. The serve/listen half lives in `aoide-server` and must never
  migrate here.
- **The `conduct → client` edge is load-bearing, not a smell.** `conduct`'s
  presence projection (`who`, workstream C2, landed) calls this crate's
  `commands::pull_peer_live` for its live per-peer probe. Don't "heal" it
  by inverting the dependency or duplicating the transport in `conduct` —
  see `docs/architecture/PACKAGE-LAYOUT.md`'s "Verified facts" note on this
  exact edge.
- **`build_message_send_body` hardcodes `context_id: None` today.** A caller
  adding cross-host context threading extends the function's parameters
  rather than working around it — the server side already routes a
  `context_id` when given one.
- **`sign_headers_for_peer` (P-P4) is the ONE production call site that
  ever builds the `X-Aoide-*` signature headers — every real peer-POST
  function threads `post_json`'s `extra_headers` through it, never
  hand-rolls a header set inline.** It returns `vec![]` for an
  unverified/unpaired peer, never a partial or malformed header set —
  `verify_signed_request` (`aoide-server`) refuses a request carrying SOME
  but not all four headers, so a future edit that adds a header
  conditionally (e.g. "only send `X-Aoide-Nonce` if X") would silently
  turn every affected outbound request into a hard refusal on the far
  end. The pairing ceremony's own three wire calls
  (`aoide/pairRequest`/`aoide/pairReveal`/`aoide/pairApprove`) always pass
  an empty header slice — they are unauthenticated by protocol design (see
  the P-P2 ceremony invariants below), not merely "not yet wired."
- **`HTTP_METHOD` (P-P5b, closing a P-P4 review finding) is the ONE named
  constant `post_json`'s `-X` argument AND `sign_headers_for_peer`'s
  `canonical_string` call both read — never re-introduce a second
  hardcoded `"POST"` literal at either site.** Before this fix the two
  carried independent literals that merely happened to agree; if this
  crate ever sends a non-POST request, thread the real method through
  `HTTP_METHOD`'s call sites instead of adding a third guess.
- **`spawn_on_peer` is the ONE place that builds and sends a spawn-shaped
  `message/send` — never re-implement it at a second call site.** Extracted
  (U4, command-defrag lane U) from `handle_peer_spawn` so `aoide-conduct`'s
  manifest remote-summon path (`graph::resurrect::summon_remote`) could
  reuse the exact same signed wire call rather than shelling out to the
  `aoide` CLI or hand-rolling a second `post_json`/`sign_headers_for_peer`
  pairing. It is the FIRST production seam to sign a `contextId`-less
  (spawn-shaped) body via `sign_headers_for_peer`. `handle_peer_spawn`
  (P-P5b, `peer spawn`) gates LOCALLY on exactly one question before
  calling it — is the named peer a registered, `verified` entry at all —
  and NOTHING else; `summon_remote` gates on the SAME question (plus
  "is there anything to summon with" — its own concern, no wire involved)
  before calling it too. Every refusal shape beyond "unknown/unpaired peer"
  (`allows` lacking `spawn`, an unsigned-but-paired caller, clock skew, an
  unreachable peer) belongs to the REMOTE door's own gate
  (`aoide-server::a2a::spawn_admitted`/`spawn_refusal`) or the transport —
  surfaced verbatim as `spawn_on_peer`'s `Err`, never re-derived or
  duplicated at either call site. Don't add a second local check for any of
  those; the local refusal exists ONLY to save an obviously-doomed round
  trip (an unsigned request can never resolve `PeerRung::Signature`), never
  to second-guess the door's own authority (PAIRING.md decision 6).
- **Forwarded event text from `adapter` is untrusted data**, same as root
  `AGENTS.md` house rule 4 — an adapter never lets forwarded text execute as
  a command.
- **`daemon::daemon_dispatch` is outbound too, not an exception to "outbound
  only."** It is the CLIENT side of the fourth door (P-D6): a routed
  handler in `conduct`/`server` calling OUT to the resident `aoided`'s
  socket, never anything that listens. `daemon::socket_path` re-derives
  `aoide_server::daemon::socket_path`'s exact convention rather than
  importing it — this crate sits BELOW `aoide-server` in the DAG (`server`
  depends on `conduct`, which depends on this crate), so an import would
  invert it; a change to the daemon socket's resolution rule updates BOTH
  copies in the same commit.
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

- **`handle_peer_pair_approve` dispatches by DIRECTION — inbound first,
  outbound second (P-P2) — and the
  two halves have opposite wire-then-commit orderings, not a shared one.**
  `approve_inbound` (this instance is the APPROVER) keeps the original
  ordering: the approval callback (`aoide/pairApprove`) MUST be delivered
  to the requester's own door and acknowledged BEFORE this instance writes
  its own `pubkey`/`verified` peer record — never the reverse, never in
  parallel. An unreachable or refusing requester must leave BOTH ends
  unpaired, not just the approver's; committing local state first would
  let a network hiccup produce an asymmetric pair (one side verified, the
  other not) with no way for either operator to notice. `approve_outbound`
  (this instance is the REQUESTER, confirming AFTER the approver's own
  callback already landed — `OutboundState::AwaitingConfirm`) makes NO
  wire call at all: the approver already committed its own record before
  ever sending that callback, so there is nothing left to acknowledge —
  confirming the SAS commits THIS instance's own record directly via
  `upsert_paired_peer`. `approve_inbound` also refuses outright
  (`"awaiting-reveal"`) on an entry whose `requester_nonce_hex` is still
  `None` — the commitment hasn't been revealed yet, so there
  is no SAS to confirm. The SAS itself is ALWAYS re-derived from this
  instance's own identity plus the parked entry's stored fields
  (`aoide_storage::pairing::derive_sas`) on EITHER path — never trusted
  from anything the wire carries, since the entire point of the ceremony
  is a code neither side can spoof to the other.
- **`handle_peer_pair_request` sends the commitment and the reveal as TWO
  sequential POSTs inside ONE invocation (P-P2) — never split
  across two separate CLI calls.** It mints its own nonce locally, POSTs
  `build_pair_request_body` carrying only `derive_commit(pubkey, nonce)`
  (the nonce itself never rides that first message), then immediately
  POSTs `build_pair_reveal_body(id, nonce)` to the SAME door before ever
  computing or printing a SAS — a reveal that fails (unreachable,
  HTTP error, or the peer refusing with a commitment mismatch) fails the
  whole `peer pair request` call; nothing is parked as a usable outbound
  entry with an unrevealed commitment on this side, since this side chose
  the nonce and always has it.
- **`handle_peer_pair_reject` tries the inbound queue, THEN the outbound
  queue — never just one (P-P2).** An outbound entry at EITHER
  `OutboundState` aborts cleanly on reject; this is the ceremony's only
  abort command, so collapsing this back to inbound-only would leave a
  requester with no way to cancel a pairing it no longer wants.
- **`approve_inbound`/`approve_outbound` take `skip_confirm: bool`, not
  `&Invocation` (P-P5) — a signature-only refactor.** Don't reach for
  `inv.flag_present("yes")` inside either function again; the ONLY caller
  that reads that flag is `handle_peer_pair_approve`, which passes the
  result in. A future caller with no `Invocation` at all (`pair_watch`'s
  popup arm is the first) passes `true`/`false` directly — the dialog
  itself IS the confirmation, so it always passes `true`.
- **`reject_by_id(cmd, id)` is `handle_peer_pair_reject`'s entire body,
  extracted (P-P5) so a caller with only an id — no `&Invocation` to
  construct — can reject a pairing request too.** Keep it a pure
  `(cmd, id) -> Outcome`; don't grow it a `skip_confirm`-shaped parameter
  — a reject was never confirmation-gated (module doc above: "a clean
  refusal"), so there is nothing for a caller to skip.
- **`pair_watch::reconcile` is a SEPARATE, independent re-implementation
  of the SAS-deriving loop `handle_peer_pair_pending` already has —
  not a shared helper, DELIBERATELY (P-P5).** The two arg orders
  (inbound: `(entry.pubkeyHex, own_pubkey, requester_nonce,
  entry.approverNonceHex)`; outbound: `(own_pubkey, entry.pubkeyHex,
  requester_nonce, approver_nonce)`) are asymmetric and easy to swap by
  accident — `pair_watch`'s own byte-equality test
  (`reconcile_derives_the_same_sas_handle_peer_pair_pending_prints`) is
  what catches a swap in EITHER copy, but it can only do that because the
  two copies are independent; collapsing them into one shared function
  would make that test tautological (it would just be comparing a value
  to itself). If a real DRY opportunity ever presents itself here, keep
  the swap-catching test's independence some other way — never delete it
  "since there's only one implementation now."
- **A feed line's own `payload` fields are safe for PASSIVE narration
  (`narrate`/`event_to_json`) — they are never safe for anything that
  drives an ACTION.** `name` is `valid_peer_name`-charset-restricted
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
- **`run_pair_request` (P-P6) is the ONLY body of `handle_peer_pair_request`
  past its own `<url>`/`--name`/`--self-url` parsing, and `handle_peer_invite`
  calls the SAME function — never a second copy.** `peer invite`'s own doc
  and CONTRACTS.md §6's "Discovery beacon" subsection both promise `peer
  invite` "runs the ceremony," and this is what makes that literally true
  rather than aspirational: a future change to the ceremony's wire calls,
  its outbound-parking shape, or its SAS derivation touches ONE function
  and both callers inherit it identically. `run_pair_request` does NOT
  re-validate its `name` argument (`valid_peer_name`) — that check stays in
  `handle_peer_pair_request` alone, since only a CLI-typed `--name` needs
  it; `handle_peer_invite`'s `name` already came off a beacon
  `aoide_storage::beacon::parse_and_validate` validated before it was ever
  displayed. Don't move the `valid_peer_name` check INTO `run_pair_request`
  "for symmetry" — it would just re-run a check that has already passed on
  the invite path, for no benefit, and would misattribute a `peer.invite`
  usage error to a check that only ever fires for the OTHER caller in
  practice.
- **`discover`'s `run_sweep`/`resolve_invite_target` never touch
  `peer_store` for writing, and `handle_peer_discover`/`handle_peer_invite`
  must not either (P-P6).** Discovery grants nothing
  (`docs/architecture/PAIRING.md`'s "Discovery (advertise-but-locked)"
  section) — the only peer-record write path in this crate is, and stays,
  `run_pair_request`'s `park_outbound` plus `handle_peer_pair_approve`'s
  `upsert_paired_peer` calls. A future `peer discover`/`peer invite` edit
  that seems to want a registry write (e.g. "remember what was last
  discovered") belongs in a NEW, explicitly-named cache, never folded into
  `state/peers.json` itself.
- **A beacon's `url` is a CLAIM; a `Heard`'s `src_addr` is an OBSERVATION —
  never swap which one is trusted (P-S1).** `url` is whatever the
  advertiser put on the wire (a loopback-bound door always claims
  `http://127.0.0.1:<port>/`, useless as a dial target for anyone but
  itself); `src_addr` is the UDP packet's actual source IP, captured by
  THIS process's own socket, never sent by the advertiser and never
  believed to be anything but what was measured. `invite_dial_url` reads
  the host from `src_addr` and everything else (scheme, port, path) from
  `url` — it is a targeted substitution, not a preference for one field
  wholesale over the other, and `Beacon` itself never grows a `src_addr`
  field (the wire shape is CONTRACTS-pinned; the observation belongs on
  `Heard`, which is local-only and unpinned). Do not add a "trust the
  advertised url instead" fallback or flag — an advertiser that wants its
  advertised url dialed can bind its door somewhere routable; guessing
  which of the two the operator meant is not this code's job.
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
  `post_json(&peer.url, …)`/`post_json(&some_raw_url, …)`/`run_curl(&["--",
  &some_raw_url], …)` directly.** `post_json_to_peer(peer, …)` (a
  registered `Peer`) and `post_json_via(logical_url, via, tunnel_key, …)`
  (a ceremony call with no `Peer` record yet) are the two entry points for
  a POST; `commands::post_json` itself is UNCHANGED by this phase and must
  stay that way — dial resolution is a wrapper in FRONT of it, not a
  rewrite of it. **`handle_peer_add`'s AgentCard fetch is a GET and was
  missed on first landing (review finding) — it now calls
  `resolve_dial_url` directly before its own `run_curl`, same as any other
  call.** Any FUTURE cross-box network call — POST or otherwise — needs the
  same funnel in front of it; a call site added without checking this
  invariant against the full list below (`grep -n 'run_curl\|post_json'`
  in this file) is exactly how the AgentCard fetch was missed the first
  time. **The
  identity guarantee is load-bearing:** `via: None` must return the
  logical url byte-for-byte, and `resolve_dial_url`'s tunnel-key/path
  handling must never diverge from `aoide_storage::tunnel::dial_url`'s own
  path extraction (`peer_store::url_path`) — a second, independently
  written path cut here would silently break `sign_headers_for_peer`'s
  canonical string the moment it drifted from the far door's own observed
  `HttpRequest.path`. **`--via` beats `Peer.via`, never the reverse** —
  `spawn_on_peer_via`'s `via_override` parameter is checked FIRST,
  `peer.via` only when the override is absent; a new `--via`-accepting
  command follows this same precedence, not a per-command variant of it.
  **The session key (`tunnel_session_id`, K3) is resolved and passed
  through here, but this crate never closes a tunnel itself, by design.**
  `pull_peer_live`/`send_message_to_peer`/`spawn_on_peer` are called from
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
- **A tunneled request is safe against a real peer, not merely possible.**
  Every request delivered through an ssh forward reaches the far A2A door
  as `PeerOrigin::Loopback` (`aoide-server::a2a::classify_origin`), which
  carries an unconditional Inject delivery free pass for an UNSIGNED
  request. This module makes the tunnel work; `aoide-server` narrows that
  free pass (`origin_for_inject`, CONTRACTS.md §6) so a verified per-request
  signature never rides Loopback's trust, with a like-for-like
  signature-rung autogate restoring delivery for a peer the operator
  already marked auto-deliver. `--via`/`Peer.via` are safe to recommend for
  a real cross-box pair.
- **The self-invite guard (`discover::is_self_target`) runs BEFORE the
  proceed-confirm and BEFORE the ceremony, in `handle_peer_invite`, never
  inside `run_pair_request` (P-S1).** `run_pair_request` is shared with
  `handle_peer_pair_request`, whose `<url>` a human typed and is entitled
  to point at their own door on purpose (loopback testing, a self-pair
  smoke test); only the DISCOVERED path needs the "you just invited
  yourself" refusal, because only there does the target come from an
  automated resolution the operator didn't type by hand.

## Extension points

- **A new outbound A2A command** adds a `cmd!`/`register` entry in
  `commands.rs`, wired into the owning app crate's `commands::all()`.
- **A new adapter consumer** (beyond melete) gets its own module beside
  `adapter.rs`, built the same neutral-event-in/typed-event-out shape.
- **A new session-write handler that should route through the daemon**
  calls `daemon::daemon_dispatch(inv)` as its own first line and returns
  early on `Some(outcome)` — the exact one-line prefix every P-D6 handler
  in `conduct` already uses; nothing in THIS crate changes for a new
  routed command, since `daemon_dispatch` is already generic over any
  `Invocation`.

## Docs update required in the same commit

- This `README.md` when a new module or CLI command group is added.
- `CONTRACTS.md §6`/`§7` when an A2A or peer-federation wire shape changes.
- `pkgs/aoide/crates/AGENTS.md` for cross-crate invariants — not restated
  here.
