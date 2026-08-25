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
- `wire` — client-side A2A JSON-RPC message builders/parsers
  (`build_message_send_body` and siblings).
- `adapter` — the melete neutral-event adapter (consumes events, stays
  agnostic of any one downstream agent's shape).
- `peer` — peer-federation client half (CONTRACTS.md §7), joined at P-P2 by
  the pairing ceremony's own wire builders/parsers:
  `build_pair_request_body`/`parse_pair_request_response` (the requester's
  `aoide/pairRequest` call, now carrying a `commitHex` rather than a
  `nonceHex` — review-bounce Finding 1), `build_pair_reveal_body`/
  `check_pair_reveal_response` (the requester's immediately-following
  `aoide/pairReveal` call), and `build_pair_approve_body`/
  `check_pair_approve_response` (the approver's `aoide/pairApprove`
  callback) — pure JSON-RPC envelope builders/parsers only, same split as
  the graphSummary pair above them; the server-side handlers
  (`pair_request`/`pair_reveal`/`pair_approve_callback`) live in
  `aoide-server::a2a`, never duplicated here.
- `commands` — this crate's CLI verbs: `a2a agent add/list/remove/send`,
  `peer add/list/remove/pull/status/hub`, `peer pair request/pending/
  approve/reject` (P-P2, CONTRACTS.md §6/§7, review-bounce fix forward —
  `confirm_sas`/`default_self_url` are this group's own local helpers: the
  y/N confirmation prompt mirrors `aoide-secrets::client::
  confirm_overwrite`'s exact idiom rather than importing it, since this
  crate holds no dependency on that one). `handle_peer_pair_request` sends
  the commitment and its reveal as two sequential POSTs in one invocation
  (Finding 1) before ever computing a SAS. `handle_peer_pair_approve`
  dispatches by direction: on an INBOUND entry (`approve_inbound`) it
  refuses an unrevealed one outright, then delivers the `aoide/pairApprove`
  callback to the requester BEFORE writing any local peer record — an
  unreachable requester must leave BOTH ends unpaired, never just the
  approver's; on an OUTBOUND entry (`approve_outbound`, reached only once
  the approver's own callback already transitioned it to
  `awaiting-confirm`) it makes no wire call at all and commits THIS
  instance's own record directly on confirmation (Finding 2 — decision 4's
  mutual confirmation, on both ends now). `handle_peer_pair_reject` tries
  the inbound queue then the outbound queue, aborting an outbound entry at
  any stage — the ceremony's own missing abort verb.
  `adapter melete` (`peer hub
  <name> [--clear]`, P-D5, designates at most one registered peer as the
  hub `aoide_storage::addr::resolve_with_hub` prefers as a last-resort
  remote target — `peer_store::set_hub`/`clear_hub` hold the invariants,
  this handler just reports which of set/moved/cleared/no-op happened);
  also exposes two
  non-verb functions that are the `conduct → client` edge's crossing
  points: `pull_peer_live` (`who`'s live per-peer probe, read-only) and
  `send_message_to_peer` (`graph send --to <peer>/<query>`'s delivery,
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

## What it consumes

`aoide-protocol` and `aoide-storage` (the client-side agent roster and peer
cache persist through `storage`), and `aoide-secrets` (task #84 — outbound
per-peer bearer resolve, `aoide_secrets::client::resolve_bounded`, reused
rather than a second wire client written here).

## How it composes

`conduct`, `screen`, `server` (dev-dependency only, for one round-trip
test), and `cli` depend on it. **The `conduct → client` edge is intentional,
not technical debt**: `conduct`'s `who` presence verb (workstream C2,
landed) calls this crate's `commands::pull_peer_live` for its live
per-peer probe, `graph send --to`'s remote branch (workstream C3, landed)
calls `commands::send_message_to_peer` to deliver, and (P-D6) every
session-write handler (`graph session start/phase/end/hook`, `graph reap`)
calls `daemon::daemon_dispatch` first — the edge stays even though the
original reason (`screen/send.rs`) moved out to the `screen` crate at P-A1
(`docs/architecture/PACKAGE-LAYOUT.md`, "Verified facts").
