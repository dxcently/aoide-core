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
  wire framing verbatim, request lines read via `read_capped_line`'s
  `fill_buf`/`consume` loop (P-D4 — the byte cap is checked on every buffer
  fill, not only after a `\n` arrives, closing the P-D2-flagged gap where a
  newline-less stream could grow one connection's buffer unbounded). Three
  ops: `ping` (liveness), `subscribe` (follow the daemon's own events feed
  — `$AOIDE_DAEMON_EVENTS`, else a sibling of the socket,
  `daemon::events_path` — filtered by an explicit `classes` array,
  default-deny), and `dispatch` (P-D4, the fourth door) — builds an
  `Invocation { path, args, flags, door: Door::Daemon }` LITERALLY from the
  wire's `path`/`args`/`flags` and runs it through the injected `dispatch`
  fn, replying with one `{"outcome": <the full Outcome envelope>}` line.
  Door policy is not reimplemented here: every command's own `inv.door`
  branch (a CLI-only admin verb's refusal, a gated command's `gated: true`,
  `mcp.serve`/`a2a.serve`'s non-Cli metadata reply) runs exactly as it
  already does over MCP/A2A, since the injected fn IS
  `cli::dispatch::dispatch` — no daemon-specific allowlist exists or is
  planned (`docs/architecture/AOIDED.md`'s "L2" section). `registry` still
  rides along the DI seam unused — no op resolves a dotted tool name
  against it the way MCP's `tools/call` does.
- `producers` (P-D3, `docs/architecture/AOIDED.md`'s "L1" section) — the
  daemon tick's two producers, both constructed once at `run_loop` startup
  and ticked every iteration. `SecretsMirror` tails the secrets broker's
  OWN events feed, its location resolved via `aoide_secrets::socket::
  socket_path`/`events_path` (`daemon::run_loop`'s own construction site —
  plain, wire-type-free `PathBuf` resolvers, reused rather than re-derived;
  this crate's `aoide-secrets` dependency also covers the A2A door's
  inbound bearer resolve). The mirror IS deliberately kept off that
  crate's wire/record TYPES for parsing, so "never copy an unknown field"
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
  never reverts a hand edit. `note_own_write` is the seam P-D6's own
  tick-reconcile/reap writes (below) fold into so they are never reported
  back as a hand edit. **The watcher itself is a single `Arc<Mutex<
  HandEditWatcher>>` (task #92), shared between the tick thread and
  `handle_conn`'s connection threads** — not tick-private: a dispatched
  session verb (`graph session start/end`/etc., `{"op":"dispatch"}`) writes
  stage files on ITS OWN connection thread, not the tick's, so
  `rebaseline_stage_roster` re-baselines the WHOLE roster after every
  completed dispatch (roster-wide, not a per-verb "which files did this
  write" table) before that connection's reply goes out — closing the
  window where the daemon's own routed write got reported back to itself as
  a hand edit one tick later.
- **Graph residency (P-D6, `docs/architecture/AOIDED.md`'s "L4")** —
  `run_loop`'s tick, after narrating the hand-edit sweep above, does two
  more things every iteration: `reconcile_graph_projection(changed_files)`
  re-derives `song/stage/graph.json` (via the exact `graph emit` handler —
  no forked logic) whenever `sessions.json`/`hooks.json` is among the
  files the sweep just reported changed, so an out-of-band write (the
  direct-fallback CLI path, or a hand edit) is folded into the projection
  on the very next tick rather than waiting for the next dispatch to touch
  it; `run_internal_reap` calls the SAME `aoide_conduct::reap::
  reap_and_announce` `graph reap` always runs, every `REAP_EVERY_TICKS`
  (12) ticks (~12s, matching the systemd timer's own cadence), re-baselining
  `HandEditWatcher` via `note_own_write` for whatever it touched so its own
  sweep is never mistaken for a hand edit next tick. Neither producer keeps
  a separate in-memory roster — every dispatch (routed or internal) reads
  the stage files fresh, so "fold in the newest write" falls directly out
  of "the file on disk is the single source of truth at every instant";
  `daemon::handle_conn`'s `dispatch` op is also how a REMOTE `graph
  session start/phase/end/hook`/`graph reap` call actually executes once
  routed here — `internal_invocation` builds the same shape of
  `Invocation { door: Door::Daemon, .. }` for the tick's own internal
  calls, so the tick's writes and a routed client's writes go through
  literally the same code.
- **Boot-time auto-resume trigger (P-D8, `docs/architecture/AOIDED.md`'s
  "L5"/"Open knobs")** — `daemon::run_boot_auto_resume`, called exactly
  ONCE at `run_loop`'s entry, before the tick loop starts (never from
  inside it). Boot-epoch guarded: `epoch_already_fired` (a pure predicate,
  unit-testable with no `/proc/stat` involved) compares a one-line marker
  file under `state_dir` (`daemon::auto_resume_marker_path`) against
  `aoide_conduct::reap::boot_epoch()` — reused directly rather than
  re-derived, that function's own doc names this exact caller — so a
  `Restart=on-failure` restart within the SAME boot is a no-op, and only a
  real reboot (a changed epoch) reopens the guard. On a fresh boot, for
  every `autoResume` project (`projects.json`, P-D8) with no live
  (non-`done`) session anchored to it (`aoide_conduct::graph::anchor_for`),
  calls `aoide_conduct::graph::session_resurrect` in-process
  (`Door::Daemon`) — the identical command core `graph resurrect --project`
  runs over the CLI, the same in-process-call pattern `run_internal_reap`
  already uses for `graph reap`. That function never hard-errors on a
  per-candidate spawn failure; a headless host's taught "no
  `$AOIDE_TERMINAL`" error is only `eprintln!`'d here, never propagated —
  the tick/loop itself is never at risk.
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
  **The pairing ceremony's two methods (P-P2, CONTRACTS.md §6's "Pairing
  wire" subsection)** — `pair_request` (`aoide/pairRequest`) and
  `pair_approve_callback` (`aoide/pairApprove`) — join this same JSON-RPC
  dispatch table, deliberately UNGATED by `read_ok`/bearer verification:
  the ceremony's whole point is establishing a credential where none
  exists yet, so gating either method on one would be circular. Neither
  grants anything beyond a `pubkey`/`verified` peer record on approval —
  no `allows`/permission, no spawn/bearer gate (P-P3's lane). `pair_request`
  validates every field (64-hex pubkey, 32-hex nonce, a `valid_peer_name`
  name, a non-empty `://`-bearing url) before calling
  `aoide_storage::pairing::park_inbound` — malformed input never reaches
  the parked-state file. `pair_approve_callback` looks up the matching
  `aoide_storage::pairing::take_outbound` entry by id, re-parks it (never
  destroys it) on a pubkey mismatch so a legitimate retry after a
  transient hiccup isn't permanently broken, and only on a match commits
  the local peer record via `aoide_storage::peer_store::upsert_paired_peer`.
  Both audit via the existing `Door::A2a` audit sink
  (`a2a.pairRequest`/`a2a.pairApprove`), same as every other A2A method.
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
