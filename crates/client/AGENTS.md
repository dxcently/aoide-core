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
