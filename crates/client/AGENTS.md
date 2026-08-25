# AGENTS.md — aoide-client

## Invariants

- **Outbound only.** This crate is the CLIENT half of A2A — message
  building/sending, agent registration, the melete adapter. The serve/listen
  half lives in `aoide-server` and must never migrate here.
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
  abort verb, so collapsing this back to inbound-only would leave a
  requester with no way to cancel a pairing it no longer wants.

## Extension points

- **A new outbound A2A verb** adds a `cmd!`/`register` entry in
  `commands.rs`, wired into the owning app crate's `commands::all()`.
- **A new adapter consumer** (beyond melete) gets its own module beside
  `adapter.rs`, built the same neutral-event-in/typed-event-out shape.
- **A new session-write handler that should route through the daemon**
  calls `daemon::daemon_dispatch(inv)` as its own first line and returns
  early on `Some(outcome)` — the exact one-line prefix every P-D6 handler
  in `conduct` already uses; nothing in THIS crate changes for a new
  routed verb, since `daemon_dispatch` is already generic over any
  `Invocation`.

## Docs update required in the same commit

- This `README.md` when a new module or CLI verb group is added.
- `CONTRACTS.md §6`/`§7` when an A2A or peer-federation wire shape changes.
- `pkgs/aoide/crates/AGENTS.md` for cross-crate invariants — not restated
  here.
