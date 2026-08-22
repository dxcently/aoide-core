# aoide-server

`aoided` and the door serve-loops: A2A JSON-RPC/HTTP/SSE, MCP-over-stdio,
listeners, sessions, snapshots, the audit sink. Untrusted input stops here —
the inbound half of the two-door contract (the outbound half is
`aoide-client`).

## Named seams (what it exposes)

- `daemon` — the `aoided` policy skeleton and `run` entry point.
- `mcp` — `serve_stdio`, the MCP stdio server.
- `a2a` — the serve half of A2A (JSON-RPC/HTTP/SSE); the client half stays
  in `aoide-client`. `do_inject` (`message/send`'s Inject arm) delivers
  through `aoide_conduct::graph::session_send` — the same door `graph send`
  uses — which is also where a delivered message gets filed into
  `aoide_storage::inbox` (messaging plan P-C6): `do_inject` itself files no
  entry of its own, since its Invocation can only ever reach
  `session_send`'s LOCAL branch (see `do_inject`'s doc comment).
- `commands` — this crate's CLI verbs: `daemon`, `shellbridge` (registration
  only — the files stay in `conduct`), `a2a serve`.

## What it consumes

`aoide-protocol`, `aoide-storage`, `aoide-conduct`. `aoide-client` is a
dev-dependency only (one round-trip test) — production code never calls
into the outbound client from here.

## How it composes

Sits above `conduct` (reads/writes session state via `do_inject`/`do_spawn`/
`tasks/get`) and `storage`. **The registry-parameter seam**: `mcp::serve_stdio`
and `a2a::serve` take the assembled `Registry` and dispatcher as parameters
rather than reaching for a crate-global singleton — that singleton doesn't
exist until the app crate (`cli`/`lyra`) assembles it, and `server → cli`
would invert the dependency direction the whole split exists to forbid.
