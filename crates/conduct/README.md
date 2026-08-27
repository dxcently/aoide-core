# aoide-conduct

Aoide's session core: the PTY multiplexer (`aoide conduct`), the session DAG
(bare `aoide graph`), Claude-Code hook plumbing, and liveness reaping. Makes
every terminal a tracked, conductable session (root `AGENTS.md`, "Conducting
— aoide's headline"). Core, never `lyra` — headless-safe by construction.

## Named seams (what it exposes)

- **Graph residency (P-D6, `docs/architecture/AOIDED.md`'s "L4")**: the
  session-write family — `session start/phase/end`, `session
  hook`, and `session reap` (below) — each try `aoide_client::daemon::
  daemon_dispatch(inv)` FIRST and fall back to their pre-existing direct
  stage-write path byte-identically on `None`. The daemon executes the
  SAME registered handler code (its `dispatch` fn IS `cli::dispatch::
  dispatch`) — no logic forks, no daemon-specific policy anywhere in this
  crate. `session_hook` smuggles its already-read stdin payload through
  the routed `Invocation`'s `flags` map under an internal-only key
  (`STDIN_PAYLOAD_FLAG`) rather than growing the daemon wire a stdin
  channel — the daemon-side handler reads that flag first and never
  touches its own stdin.
- `graph/spawn.rs` — `spawn [--windowed] [--undying]` (P-D7,
  `docs/architecture/AOIDED.md`'s "L5"): the child is always `aoide conduct
  -- <agent cmd>`, built by the ONE shared `build_conduct_args` (`--headless`
  aside) — headless by default (detaches, re-execs this same binary), or,
  under `--windowed`, execs a real terminal named by `$AOIDE_TERMINAL` (env
  only) that runs the identical conducted command, so registration, the
  control socket, and the parent-autogate lane come for free either way.
  `build_terminal_argv` parses the template (whitespace split, a `{cmd}`
  placeholder token spliced in as separate argv slots when bare, or POSIX
  single-quote-joined into ONE slot when the token is quote-wrapped —
  `foot sh -c '{cmd}'`) — pure, unit-tested, never a real terminal spawned in
  a test. Taught errors, no process ever touched: no `$AOIDE_TERMINAL` set,
  or neither `$WAYLAND_DISPLAY` nor `$DISPLAY` present (a headless host,
  steered back to plain `spawn`). `--undying` (P-C3, durable-sessions
  plan) marks the spawned id in `state/undying.json` once — and only once —
  the registration wait actually succeeds; an id that never registers has no
  live session behind it, so nothing is marked.
- `graph/send.rs`'s `session hook` stamps `SessionRecord.
  harness_session_id` (P-D7) from the raw hook payload's own `session_id`
  on every event that carries one, mapped-to-an-action or not — see
  `CONTRACTS.md`'s `sessions.json` entry for the full field contract.
- `graph` — the session DAG: build/merge/send/spawn/wrap, `normalize_addr`
  (widened to `pub` at P-A1 so `screen` could reach it without duplicating
  it), `SessionRecord`/`SessionsFile`/`load_stage`/`write_stage`. `--id`
  accepts a bare session id OR the exact `session:<id>` form bare `graph
  --json` emits for a node id (a known prefix stripped before matching,
  same discipline `focus_session` already used) — bare `graph`'s own
  emitted contract is unchanged, only what `--id`/`--to` accept
  as input widened; an id with any OTHER prefix still errors as unknown,
  unchanged. `send` gained `--to <target>` (messaging plan P-C3, mutually exclusive
  with `--id`): resolves via `aoide_storage::addr::resolve` (itself
  `session:`-prefix-tolerant on its exact-id tier) against local
  sessions + registered peers — a LOCAL match re-drives the exact `--id`
  path unchanged, a REMOTE match (`peer/<query>`, resolved against that
  peer's CACHED graph, never a live pull) delivers over A2A `message/send`
  instead, gated entirely on the RECEIVING peer's side (this door's own
  `--yes`/pending/autogate machinery is a local-socket concept and does not
  apply to a remote delivery). A `--to` query that resolves against neither
  a local session nor any peer/prefix form falls through to a registered
  **hub peer** (P-D5's `peer hub`, wired here at P-D6 —
  `aoide_storage::addr::resolve_with_hub`, given the one peer with
  `hub: true` if any) instead of erroring `not-found` — the ONE routing
  consumer of the hub preference in this crate; `who.rs`'s own listing
  filter deliberately keeps the plain, hub-blind `addr::resolve`. `send::deliver_local`'s success path is ONE
  of exactly TWO seams that file a delivered message into
  `aoide_storage::inbox` (messaging plan P-C6, `state/inbox.json`) — every
  route that lands a message into an ALREADY-REGISTERED session (direct
  `--id`, `--to` local, `pending approve`'s re-drive, AND `aoide-server`'s
  A2A `do_inject`, which reaches this same function through `session_send`)
  is covered by that one call. The OTHER seam lives in `aoide-server`
  itself (`spawn_inject_prompt`, `a2a.rs`): a brand-new A2A-spawned
  session's first turn is typed before that session has a `SessionRecord`
  at all, so it can't reach `deliver_local` and files itself instead — see
  `aoide_storage::inbox`'s module doc for the full two-writer reasoning.
- **The undying mark (P-C2/P-C3, durable-sessions plan; renamed from "carry"
  at command-defrag lane U1, 2026-08-27):** `graph/undying.rs`'s
  `session_undying` (`session undying on|off [--self | --id <id>]`) is the
  command over `aoide_storage::undying`'s store (`state/undying.json`) — a
  session id marked DURABLE, so a project's whole undying set can later be
  resurrected together. Unlike every other `session *` handler in this
  crate, it takes no stage lock and does not route through `daemon_dispatch`:
  `undying.json` is not a `state/stage/` file, so it sits entirely outside
  the L4 dual-writer surface. `--id` targets any session id, live or not —
  no roster lookup gates the write, which is what makes the mark flippable
  post-mortem off a bare ledger id; bare and `--self` both resolve the
  target from `$AOIDE_SESSION_ID`. Two more sites touch the same store:
  `spawn --undying` marks at birth (above), and `graph/resurrect.rs`'s
  `resurrect_one` moves the mark from an old, undying ledger id onto its
  freshly spawned replacement — new id added, old id dropped, in ONE
  `save_undying` call, only when the spawn actually reached `Status::Ok` and
  only when the old id was undying to begin with. The new id is added
  BEFORE the old one is dropped in the shared in-memory vector, so a crash
  between that edit and the write leaves the OLD id undying (retryable)
  rather than neither (silent loss) — the same bias a failed spawn gets
  deliberately, by never touching the store at all.
- **The undying picker (U3, command-defrag lane U):** `graph/session_pick.rs`'s
  `session_pick` is bare `session`'s handler — a parent command registered
  alongside `session.*` the same way bare `graph` sits alongside `graph
  link` (R1's pattern, reused rather than re-derived). CLI-only, tty-only
  (`aoide_protocol::pick::interactive`, gated on `Door::Cli` first the same
  shape `secrets`' admin quartet holds); a non-interactive reach — a
  non-CLI door, no tty, or `--json` — always steers to `session undying
  on|off --id <id>`, U1's scripted spelling, which stays the ONLY scripted
  form: no `--undying` flag was added to bare `session` (one spelling per
  capability). The picker itself reaches `aoide_protocol::pick::choose_many`
  DIRECTLY — no new seam: that function already supports pre-checked
  defaults and a clean `None` on Esc/EOF, and this crate already depends on
  `aoide-protocol` the same way `song`'s own `prune_picker` does; there was
  no missing primitive to add to `pick.rs`. Rows come from this box's own
  roster (`merged_sessions`, never re-derived) plus every registered peer's
  CACHED graph via `who.rs`'s `sessions_from_graph` (widened to `pub(super)`
  this phase for exactly this second consumer, `SessionView` alongside it —
  see `glyph`'s own widening note in `who.rs` for the precedent) — no live
  peer probe anywhere in this module. A LOCAL row's mark toggles
  `state/undying.json` through one load, N mutations, one save (widening
  `session_undying`'s own single-id discipline to a whole confirm's diff at
  once); a PEER row's mark writes a `.aoide/project.json` spec instead — the
  id lives on the peer, so this conductor cannot write ITS store — resolved
  against the CURRENT project via the exact same `walk_up` `resurrect`'s
  bare mode already uses, U2, and NEVER auto-created: no manifest above cwd
  reports every peer mark/unmark in that confirm as `skipped[]`, while any
  local rows in the SAME confirm still land. A peer cwd that cannot be
  relativized under the project root (review round 1's fix) is likewise
  rejected BEFORE it ever touches `manifest.sessions` — never a raw-cwd
  fallback, which `save_manifest`'s own whole-batch validation would refuse
  outright, silently sinking every other legitimate peer change in the same
  confirm; `changed[]` only ever names what the save actually persisted.
  Unmarking removes EVERY spec matching `{host, dir, agent}`, not just the
  first. See `CONTRACTS.md`'s `.aoide/project.json` section for the exact
  spec-derivation and dedupe rules.
- `reap` — liveness reaping (`aoide session reap`), sweeping sessions a
  `SIGKILL`'d terminal could never mark `done`. `reap_and_announce` (the
  registered CLI handler) routes through `daemon_dispatch` first like every
  other session-write command above; the toast-free `reap` underneath is what
  every in-crate caller and unit test calls directly, and what the
  daemon's own tick runs internally on its ~12s cadence — the systemd timer
  becomes a redundant backstop once a daemon is resident, never a second
  liveness mechanism.
- `graph/window.rs` — window discovery/backfill/listener PLUS the
  automatic-parenting seam (task #89, corrected in review round 2):
  `is_windowless_wrap` (a conducted record is windowless when `headless` is
  set OR its own `windowAddress` is empty — `headless` overrides a stray
  address) backs `windowless_by_lineage`, which checks a session's OWN
  record first before walking its parent chain, so a nested headless
  `conduct`/`spawn` never pid-ancestry-walks to its enclosing terminal's
  window — neither for itself nor for its descendants. `stamp_headless`
  (`session_store.rs`) is the one writer of the permanent `headless` marker,
  called from `graph/conduct.rs::session_conduct` right after registration;
  that same call site gates its window-discovery call on `!headless`, so a
  headless wrap never even attempts discovery. `ancestry_parent`/
  `resolve_registration_parent` (the `--parent` flag > `/proc` ancestry ↔
  `hookAncestry` > `AOIDE_SESSION_ID` env precedence `wrap`/`conduct`/`spawn`
  registration resolve their parent through). `session_store::lineage_of`
  (ancestors + descendants) is the matching widened carve-out for the
  same-window registration-time eviction, reused by `reap.rs`'s dedup pass
  as defense in depth. See AGENTS.md's invariants for the full reasoning
  and every site that must agree: the discovery gate, the listener
  self-check, and the four historical backfill call sites.
- `shellbridge`, `herald` — files only; their CLI commands (registry lines)
  moved to `lyra` at P-A2, but both stay resident here (see charter smudge
  below).
- `commands` — this crate's CLI commands: 19 paths registered in one
  `register()` call (`conduct/src/commands/graph.rs`, still that file's name
  post-cutover) — the `graph` family narrowed at task #101 R1 to the bare
  render plus `graph link`, while `send`/`spawn`/`resurrect` went bare and
  `session *`/`project *` promoted to their own top-level groups — plus
  `conduct`, `hooks install`, `who`.
- **The durable session ledger + resurrect (P-D8, `docs/architecture/
  AOIDED.md`'s "L5"):** `graph/doc.rs::ledger_session_exit` is the ONE
  shared call both `session_store.rs::do_session_end_inner` (a clean
  `session end`) and `reap.rs::reap_inner` (every id its `reaped` set
  collects) route through to append one `aoide_storage::ledger::
  LedgerEntry` line at the exact instant a session leaves the roster —
  never two independently-written appenders, so a given session
  contributes exactly one ledger line regardless of which path retired it.
  `graph/resurrect.rs::session_resurrect` (`resurrect --project
  <name> [--all | --id <ledgerSessionId>]`) reads that ledger and anchors
  entries to a project by the SAME `anchor_for` longest-prefix rule bare
  `graph` uses. Selection then branches on the flags: `--all` widens to every
  anchored entry, `--id` narrows to one specific `sessionId`, and bare
  (neither flag) resumes the project's WHOLE undying set
  (`aoide_storage::undying`, `state/undying.json`, durable-sessions plan
  P-C4) — `undying_selection` keeps only anchored entries currently marked
  durable, drops any id already alive (non-`done`) in `sessions.json`, and
  dedups by `sessionId` keeping the entry with the newest `endedAt` (an
  undying id that was resurrected and exited again appears twice in the
  append-only ledger). `--all` and `--id` are unchanged escapes: both widen
  or narrow past the undying set regardless of the mark. An empty bare-mode
  selection is an honest `Outcome::ok` no-op naming the undying set as
  empty, never a silent success. Every surviving candidate then resolves
  through TWO arms
  (`resolve_candidate`, P-C6): the harness arm, unchanged, filters to
  harnesses with a verified `AgentProfile.resume_args`
  (`aoide_protocol::agents`); a candidate the harness arm finds nothing for
  falls to the TERMINAL arm — a `restore` snapshot present (P-C5) means it
  is a conducted shell, not a harness, so it resolves `[<login shell>, "-l"]`
  (`login_shell`, the same `$SHELL` → passwd → `/bin/sh` order
  `modules/dendrites/kitty.nix`'s own wrapper uses) rather than a
  `--resume <id>` no shell could ever honor. A candidate neither arm
  resolves is skipped with a taught message naming it, never a guessed
  invocation. Every resolved candidate spawns via the windowed path
  (`graph/spawn.rs`, P-D7) with its resolved argv and `--cwd` set to the
  ledger entry's own cwd.
  A resurrected session is ALWAYS a fresh `sessionId` — ids are never
  recycled — and gets stamped `resumedFrom` (`session_store.rs::
  stamp_resumed_from`) naming the ledger entry it continues; `build_graph`
  projects that as an additive `resumed` edge beside `spawned`/`anchors`.
  Never a hard `Outcome::error` over a per-candidate spawn failure (a
  headless host's taught "no `$AOIDE_TERMINAL`" error, for one) — every
  outcome folds into `resurrected`/`skipped`/`failed` and the command
  itself stays `Ok`, which is what lets the daemon's own boot-time
  auto-resume trigger (`aoide-server`'s `daemon.rs`) call this exact
  command core in-process without ever risking its own tick on a
  headless box.
  **Post-spawn restore delivery (P-C6):** once a terminal candidate's spawn
  actually registers, `restore_delivery` decides what — if anything — lands
  in the new pty, through `send::session_send` in-process, never a
  direct socket write. Working (`idle: false`) with a foreground `argv`
  re-execs it (`--yes --submit`) — EXCEPT when `argv[0]`'s basename is
  `sudo` (`is_sudo_argv`, the orchestrator's ruling on durable-sessions
  plan open knob 5): a privileged command is never re-exec'd unattended, so
  only the cwd restores. Idle (`idle: true`) with a clean `typed` line
  preloads it (`--yes`, and — permanently — no `--submit`): the text sits
  in the new prompt until a human presses Enter, never running itself. Idle
  with no `typed` delivers nothing; a terminal reopened at its own cwd is
  already the complete answer. See AGENTS.md for why the two branches are
  never unified behind a shared boolean parameter.
  **Bare-manifest mode (U2, command-defrag lane U):** `resurrect` with NONE
  of `--project`/`--all`/`--id` walks up from cwd
  (`aoide_storage::manifest::walk_up`) for the nearest `.aoide/
  project.json` and, if found, revives THAT manifest's specs directly
  (`resurrect_from_manifest`) — self-sufficient, no `projects.json`
  registration read or required. Not found — genuinely bare, no flag
  either — falls through to the flag-mode path above, whose usage error
  then names both misses. Any of the three flags present routes straight
  past the manifest check AND skips the walk entirely — mutually exclusive
  with bare-manifest mode by construction, so an invocation missing
  `--project` but carrying `--id`/`--all` gets `require_flag`'s own
  ORIGINAL, accurate usage error, never the both-misses wording (review
  fix, U2 round 1 — that branch used to return the manifest-miss message
  unconditionally on ANY `require_flag` failure, which lied for a flag-mode
  caller: a flag WAS given, no walk was ever attempted). Each spec
  (`{host, dir, agent, command?}`) resolves independently, one spec's
  failure never aborting the rest: a spec whose `host` isn't this host's
  own name (`aoide_storage::display::local_host_name`) is skipped (remote
  summoning is U4); a local spec's `dir` resolves through
  `aoide_storage::manifest::resolve_spec_dir` (the containment guard — a
  `..`-laden `dir` is refused, never resolved outside the project root;
  lexical only, so a symlink INSIDE the project pointing outside it still
  escapes at use time — accepted under the manifest's host-local,
  operator-authored trust model, not a gap this guard closes). **The
  enrichment rule (the User's design decision):** the manifest decides WHAT
  exists, the ledger decides HOW — the newest entry in THIS HOST's own
  session ledger whose `cwd`/`agent` match the spec revives through the
  exact SAME `resolve_candidate`/`resurrect_one` path `--id` drives; no
  match clean-spawns instead (`clean_spawn_from_spec`), windowed, the
  spec's own `command` when given (whitespace-split only, no shell-quote
  awareness — an embedded-space argument cannot be expressed) else the
  agent's registered `AgentProfile::launch` default — the same
  `session_spawn` windowed path every other candidate spawns through, never
  a forked launch mechanism. An agent with neither is a taught `failed[]`
  entry. Every row of the outcome carries a `disposition`
  (`revived-from-ledger`/`clean-spawned`/`skipped-remote`/`skipped`/
  `failed`) — including a row `resurrect_one` itself pushed, stamped after
  the fact since that function has no idea it's being called from manifest
  mode (review fix, U2 round 1: those rows used to carry no `disposition`
  at all). **Manifest-revived sessions are marked undying** (orchestrator
  design ruling, U2 round 1), both paths, once their spawn reaches
  `Status::Ok` (`mark_manifest_revival_undying`, its own
  `load_undying`/`set_undying`/`save_undying` call — not a flag threaded
  into `spawn`, and never gated on live registration, which this crate's
  own tests never exercise end-to-end): the manifest spec IS the durable
  declaration, so a LATER bare `resurrect --project <name>` or the daemon's
  boot sweep finds the revived session in the undying set without
  re-walking the manifest — unconditional, unlike flag-mode's own TRANSFER
  a few paragraphs up, which only ever moves a PRE-existing mark. Every
  outcome (both modes) is audited exactly once (`audit_resurrect`),
  including an empty selection — the boot-sweep postmortem's own finding
  that an early return must never silently skip the audit line a full run
  gets.
- **Terminal restore capture (P-C5, durable-sessions plan):**
  `graph/conduct.rs`'s PTY tick (`conduct_refresh_shell`, ~1 Hz, the same
  tick that drives `cwd`/`activity`/`state`) also builds a
  `RestoreSnapshot` (`restore_snapshot`, pure, mirrors `shell_snapshot`'s
  injected-lookup shape) and lands it on the record change-only through
  `do_session_refresh` — `cwd`/`idle`/RAW `argv` (`proc_argv`, never
  `proc_command`'s truncated DISPLAY label) off the pty's foreground
  process group. `idle` is captured as its OWN field rather than read back
  off `state` later: `reap.rs`'s sweep overwrites `state` to `"done"`
  BEFORE its ledger write, so idleness is unrecoverable from `state` by
  then. This is a CONTINUOUS capture, not a reap-time snapshot — by the
  time a sweep condemns a session its process is already gone (the exact
  signal it reaped on), so a `/proc` read there returns nothing, every
  time; `doc.rs::ledger_session_exit` projects the record's last-captured
  `restore` verbatim into the ledger line, no new call site. `typed` (the
  reconstructed unsubmitted prompt line) is REFUSAL-based: `conduct_
  multiplex` feeds every byte written to the master — from BOTH real stdin
  and an injection connection, since both land in the same shell readline
  buffer — into a capped `TypedLineBuffer`; `\r`/`\n` submit-clears it, and
  ANY other control byte (an escape sequence, `^R`, Tab, `^U`/`^W`) or
  invalid UTF-8 POISONS the current line to `None` rather than guessing.
  `typed_capture_active` gates the buffer's very existence to an
  interactive shell (`is_shell && read_stdin`) — a headless conduct never
  reads stdin, so it never populates `typed`. See AGENTS.md for why this
  is refusal-based, not best-effort.
- **Session origin (P-P3, `docs/architecture/PAIRING.md` decision 7):**
  `session_store.rs::stamp_origin` stamps `SessionRecord.origin` —
  `"peer:<name>"` for a session `aoide-server`'s A2A door spawned on
  behalf of an identified, paired peer — right after `do_session_start`,
  same seam `stamp_headless` uses. `graph/conduct.rs::session_conduct`
  reads it off the `AOIDE_SESSION_ORIGIN` env var `aoide-server`'s
  `a2a::do_spawn` sets on the child it launches; a locally-launched
  `conduct` (a plain terminal, `spawn`, etc.) never has that env var
  set, so `origin` stays absent. No `graph.json` projection (like
  `headless`/`hookAncestry`, consumed internally, not rendered) —
  `doc.rs::ledger_session_exit` is the ONE place it surfaces, projected
  verbatim into the durable session ledger's own `origin` field. `origin`
  is attribution, not authentication: any same-uid process can set
  `AOIDE_SESSION_ORIGIN` before running `aoide conduct` and forge
  `"peer:X"` with no door involved, the same ordinary spoofable
  same-user process state `--from`/`AOIDE_SESSION_ID` already are — nothing
  may ever gate on it without upgrading it to an authenticated channel
  first (task #63's lane).
- `who` — `aoide who [filter] [--json] [--all]` (`graph/who.rs`): live
  presence over this box's own sessions plus every registered peer,
  probed in parallel on each invocation (messaging workstream C2). A
  PROJECTION, never a store — it never writes `state/peer-cache/`;
  `build_graph`'s own fold (`doc.rs`) owns that file. `glyph` (the
  online/unreachable/never-pulled node-presence map) is `pub`, re-exported
  at `graph::glyph` — the conductor's ROSTER panel (P-C4) is its second
  consumer, reusing it rather than redrawing its own copy.

## What it consumes

`aoide-protocol`, `aoide-storage`, `aoide-client` (`who`'s live per-peer
probe calls `aoide_client::commands::pull_peer_live` — the peer-pull
transport `peer pull` itself uses, workstream C2; `send --to`'s
remote branch calls `aoide_client::commands::send_message_to_peer`,
workstream C3; every session-write handler calls `aoide_client::daemon::
daemon_dispatch`, P-D6; see `client`'s own README for why that edge stays).

## How it composes

`screen`, `server`, `conductor`, `cli`, and `lyra` all depend on it.
**Charter smudge**: `shellbridge.rs`/`herald.rs` stay as FILES here even
though their CLI commands moved to `lyra` — `permit.rs` publishes summons
through `herald`, and `conductor/ui.rs` reads the socket path `shellbridge`
owns, so both are entangled with core
(`docs/architecture/PACKAGE-LAYOUT.md`, "Charter exceptions").
