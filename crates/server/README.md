# aoide-server

`aoided` and the door serve-loops: A2A JSON-RPC/HTTP/SSE, MCP-over-stdio,
listeners, sessions, snapshots, the audit sink. Untrusted input stops here —
the inbound half of the two-door contract (the outbound half is
`aoide-client`).

## Named seams (what it exposes)

- `daemon` — the `aoided` policy skeleton and `run` entry point.
- `mcp` — `serve_stdio`, the MCP stdio server.
- `a2a` — the serve half of A2A (JSON-RPC/HTTP/SSE); the client half stays
  in `aoide-client`. Two `message/send` arms, two different relationships to
  the inbox (messaging plan P-C6, `state/inbox.json`): `do_inject` (Inject,
  an EXISTING session) delivers through `aoide_conduct::graph::session_send`
  — the same door `graph send` uses — which is where a delivered message
  gets filed; `do_inject` itself files no entry of its own, since its
  Invocation can only ever reach `session_send`'s LOCAL branch (see
  `do_inject`'s doc comment). `do_spawn` (Spawn, a BRAND-NEW session) types
  the opening turn via `spawn_inject_prompt`, which files ITS OWN entry
  right after the write — a spawned session has no `SessionRecord` yet at
  that moment, so it cannot reach `session_send` at all (see
  `spawn_inject_prompt`'s doc comment for the race that rules it out).
  These are the only two inbox-filing call sites in the whole tree.
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
- `commands` — this crate's CLI verbs: `daemon`, `shellbridge` (registration
  only — the files stay in `conduct`), `a2a serve`.

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
