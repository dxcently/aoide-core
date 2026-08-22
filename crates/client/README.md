# aoide-client

Aoide's outbound door: the A2A client-side wire builders/parsers and the
melete neutral-event adapter. Drives external agents and talks to `aoided`;
never the inbound/serve half (that's `aoide-server`).

## Named seams (what it exposes)

- `wire` — client-side A2A JSON-RPC message builders/parsers
  (`build_message_send_body` and siblings).
- `adapter` — the melete neutral-event adapter (consumes events, stays
  agnostic of any one downstream agent's shape).
- `peer` — peer-federation client half (CONTRACTS.md §7).
- `commands` — this crate's CLI verbs: `a2a agent add/list/remove/send`,
  `peer add/list/remove/pull/status`, `adapter melete`; also exposes
  `pull_peer_live` (not a verb itself — the `conduct → client` edge's one
  crossing point, `who`'s live per-peer probe).

## What it consumes

`aoide-protocol` and `aoide-storage` (the client-side agent roster and peer
cache persist through `storage`).

## How it composes

`conduct`, `screen`, `server` (dev-dependency only, for one round-trip
test), and `cli` depend on it. **The `conduct → client` edge is intentional,
not technical debt**: `conduct`'s `who` presence verb (workstream C2,
landed) calls this crate's `commands::pull_peer_live` for its live
per-peer probe — the edge stays even though the original reason
(`screen/send.rs`) moved out to the `screen` crate at P-A1
(`docs/architecture/PACKAGE-LAYOUT.md`, "Verified facts").
