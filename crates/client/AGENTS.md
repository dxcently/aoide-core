# AGENTS.md — aoide-client

## Invariants

- **Outbound only.** This crate is the CLIENT half of A2A — message
  building/sending, agent registration, the melete adapter. The serve/listen
  half lives in `aoide-server` and must never migrate here.
- **The `conduct → client` edge is load-bearing, not a smell.** `conduct`'s
  presence projection (`who`, planned — workstream C2, not yet implemented)
  needs this crate's peer-pull transport. Don't
  "heal" it by inverting the dependency or duplicating the transport in
  `conduct` — see `docs/architecture/PACKAGE-LAYOUT.md`'s "Verified facts"
  note on this exact edge.
- **`build_message_send_body` hardcodes `context_id: None` today.** A caller
  adding cross-host context threading extends the function's parameters
  rather than working around it — the server side already routes a
  `context_id` when given one.
- **Forwarded event text from `adapter` is untrusted data**, same as root
  `AGENTS.md` house rule 4 — an adapter never lets forwarded text execute as
  a command.

## Extension points

- **A new outbound A2A verb** adds a `cmd!`/`register` entry in
  `commands.rs`, wired into the owning app crate's `commands::all()`.
- **A new adapter consumer** (beyond melete) gets its own module beside
  `adapter.rs`, built the same neutral-event-in/typed-event-out shape.

## Docs update required in the same commit

- This `README.md` when a new module or CLI verb group is added.
- `CONTRACTS.md §6`/`§7` when an A2A or peer-federation wire shape changes.
- `pkgs/aoide/crates/AGENTS.md` for cross-crate invariants — not restated
  here.
