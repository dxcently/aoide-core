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
  wire framing verbatim: `ping` (liveness) and `subscribe` (follow the
  daemon's own events feed — `$AOIDE_DAEMON_EVENTS`, else a sibling of the
  socket, `daemon::events_path` — filtered by an explicit `classes` array,
  default-deny) are live; `dispatch` (the fourth door, `Door::Daemon`) is
  P-D4. `registry`/`dispatch` fn parameters thread all the way to the
  per-connection handler, unused until P-D4 — the same DI seam
  `mcp::serve_stdio`/`a2a::serve` already close at their own launch sites.
- `producers` (P-D3, `docs/architecture/AOIDED.md`'s "L1" section) — the
  daemon tick's two producers, both constructed once at `run_loop` startup
  and ticked every iteration. `SecretsMirror` tails the secrets broker's
  OWN events feed (`producers::secrets_socket_path`/`secrets_events_path`
  — the SAME `$AOIDE_SECRETS_SOCKET`/`$AOIDE_SECRETS_EVENTS` resolution
  `aoide_secrets::socket` documents, reimplemented here rather than
  imported: this crate's own `aoide-secrets` dependency exists only for
  the A2A door's inbound bearer resolve, and the mirror is deliberately
  kept off that crate's wire/record TYPES so "never copy an unknown field"
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
  never reverts a hand edit. `note_own_write` is the seam a FUTURE
  daemon-side write path (P-D6) folds its own writes into so they are
  never reported back as a hand edit; no such write path exists yet this
  phase, so it has no live caller today.
- `events` — `tail`, the blocking loop behind `aoide events tail` (P-D3):
  follows the daemon's own events feed with a `Follower` and prints every
  line whose `class` passes an (optional, comma-separated) filter, `--json`
  verbatim or narrated otherwise. `poll_once` is the bounded, non-blocking
  core a test drives directly; `tail` is the thin `SIGINT`-handling wrapper
  around it, mirroring `aoide_secrets::watch`'s own tail-loop shape.
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
  only — the files stay in `conduct`), `a2a serve`, `events tail` (P-D3,
  appended newest — CLI-only, the same door-policy shape `a2a serve`/
  `aoide_secrets::commands::handle_secrets_watch` already hold for a
  foreground/blocking verb).

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
