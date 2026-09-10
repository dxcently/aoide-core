# aoide-conduct

`session project --id ID --project NAME` assigns an explicit registered project;
`--clear` restores cwd anchoring. The override is preserved in exit history and
restored on resurrection when the project remains registered. `session kill
--id ID` requests SIGTERM for a dedicated conducted process using a Linux pidfd
and a fresh daemon-seal verification. Shared app processes, unsealed records,
and stale identities refuse. Both operations require the local daemon; exit
is observed by the existing reaper, never fabricated by the kill response.

Registered Codex sessions refresh their native conversation titles during the
reaper metadata pass. The pass reads `CODEX_HOME/session_index.jsonl` (default
`~/.codex/session_index.jsonl`) once, retaining the latest valid nonempty name
for each exact thread ID. Native renames update `title`; petnames, lifecycle,
control sockets and window mappings remain unchanged. Historical index entries
do not enroll sessions. This metadata reader supplies neither Codex lifecycle
tracking nor a control transport; Codex is not sent through Claude's transcript
extractors.

Aoide's session core: the PTY multiplexer (`aoide conduct`), the session DAG
(bare `aoide graph`), Claude-Code hook plumbing, and liveness reaping. Makes
every terminal a tracked, conductable session (root `AGENTS.md`, "Conducting
— aoide's headline"). Core, never `lyra` — headless-safe by construction.

## Named seams (what it exposes)

- `graph::session_bind` implements `session bind --id <session> --agent-id
  <key>` through aoided. Only local CLI/Daemon doors may bind; the CLI does
  not fall back when aoided is absent. The key uses `valid_node_name` grammar
  and need not have a Mneme mapping. An unknown session, invalid key, or
  conflicting binding refuses without mutation; the same key is idempotent.
  The enduring key appears in the graph and exit ledger, independently of
  executor-specific mail readers. Resurrection does not implicitly bind it.

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
- **The check lane (task #139), wired into `session hook`'s three lifecycle
  triggers — Stop records, the next context-reaching event speaks.**
  `hook_for_profile`'s `HookAction::Start` arm reads the STORED `hooks.json`
  phase for `id` (`session_store::stored_phase`, before this arm's own
  mutating calls) to tell a fresh launch from a mid-turn resume, then calls
  `aoide_upkeep::checklane::on_session_start(&id, cwd, mid_turn)`; its
  `HookAction::Phase` arm calls `checklane::on_prompt_submit(&id)` when
  `phase == "working"` (the one phase string only `UserPromptSubmit`
  produces) and `checklane::on_stop(&id, cwd)` when `phase == "stopped"`
  (the one phase string only `HookClass::Stop` produces — both via
  `map_hook`), so `awaiting` transitions touch neither. `on_stop` itself
  returns nothing — its own stdout never reaches the model — it persists the
  rendered delta as a PENDING note that `on_session_start`/
  `on_prompt_submit` drain. Whichever of those two calls actually produced a
  note (`lane_note`) rides on the SAME `Outcome` `session hook` already
  builds — appended to `inner.message` after an em dash, and surfaced
  separately as `data.checkLane` — never a second message, never a second
  door. This is part of why `commands/hooks.rs::door_command`'s claude
  wrapper stopped blanket-swallowing stdout (`aoide_protocol::door::run`'s
  `println!` on an `Ok` outcome is the ONLY channel a rendered body ever
  reaches the harness through) — but the wrapper only unmuffles
  `SessionStart`/`UserPromptSubmit`, the two events Claude Code itself folds
  a hook's stdout into the model's context for
  (`docs/Aoide-Wiki/protocol/dev/HARNESS-CLAUDE-CODE.md`'s "Traps" section);
  `Stop` stays swallowed on purpose (blocking the turn to force the note
  through was rejected on design grounds — see `door_command`'s own doc).
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
  sessions + registered nodes — a LOCAL match re-drives the exact `--id`
  path unchanged, a REMOTE match (`node/<query>`, resolved against that
  node's CACHED graph, never a live pull) delivers over A2A `message/send`
  instead, gated entirely on the RECEIVING node's side (this door's own
  `--yes`/pending/autogate machinery is a local-socket concept and does not
  apply to a remote delivery). A `--to` query that resolves against neither
  a local session nor any node/prefix form falls through to a registered
  **hub node** (P-D5's `node hub`, wired here at P-D6 —
  `aoide_storage::addr::resolve_with_hub`, given the one node with
  `hub: true` if any) instead of erroring `not-found` — the ONE routing
  consumer of the hub preference in this crate; `who.rs`'s own listing
  filter deliberately keeps the plain, hub-blind `addr::resolve`. `send::deliver_local`'s success path is ONE
  of exactly TWO seams that file a delivered message into
  `aoide_storage::mail` as a receipt (messaging plan P-M1,
  `state/mail/base.jsonl`) — every route that lands a message into an
  ALREADY-REGISTERED session (direct `--id`, `--to` local, `pending
  approve`'s re-drive, AND `aoide-server`'s A2A `do_inject`, which reaches
  this same function through `session_send`) is covered by that one call
  (`mail::file_receipt`). The OTHER seam lives in `aoide-server` itself
  (`spawn_inject_prompt`, `a2a.rs`): a brand-new A2A-spawned session's
  first turn is typed before that session has a `SessionRecord` at all,
  so it can't reach `deliver_local` and files itself instead — see
  `aoide_storage::mail`'s module doc for the full two-writer reasoning.
- **`send.rs::write_delivery`** is the one place a delivered payload actually
  reaches a target's control socket (task #124): the text write, then — on
  `--submit` — a SEPARATE, later write of the target's own submit keystroke,
  never one concatenated write. A concatenated write is exactly what kimi's
  TUI paste-coalesces into a composer newline instead of Enter, leaving the
  prompt unsubmitted; see `SUBMIT_KEYSTROKE_DELAY`'s doc comment (AGENTS.md
  has the full invariant) for the empirically-pinned delay between the two
  writes. `deliver_local_with` is the one production caller.
- **`graph::doorbell`** (`ring`, `mail_ring`, `RingReport`; P-M5a-2,
  `docs/architecture/MAIL.md` "Delivery and the doorbell") is the mailbase
  latch's actual ringer: filing an arming letter nudges every armed,
  headless, hook-fed-and-at-the-prompt reader, raw-injected through the
  SAME `send.rs::write_delivery` this crate's ordinary deliveries use, under
  a dedicated `.ring.lock` file (`aoide_storage::mail::with_ring_lock`) —
  never `.stage.lock`, and only the daemon's own serializer, not a second
  policy boundary. `ring` executes only under `Door::Daemon`: its two
  callers are `mail_ring`'s own `Door::Daemon` arm and this crate's
  Stop-hook replay when that hook is likewise being handled by the
  daemon. Every other door forwards instead of ringing — `mail_ring`
  itself, reached from the CLI or MCP, and the Stop-hook replay's
  no-daemon local fallback, both go through `aoide_client::daemon::
  daemon_dispatch` (or replay nothing) rather than calling `ring`
  directly; `aoide-server`'s A2A deposit arm does not ring at all
  (P-M5b-2 gives it its own forward path).
- **The undying mark (P-C2/P-C3, durable-sessions plan; renamed from "carry"
  at command-defrag lane U1, 2026-08-27; relocated under `session grant` at
  the session-surface redesign, command-defrag lane X, 2026-08-28):**
  `graph/undying.rs`'s
  `undying_grant` (`session grant undying on|off [--self | --id <id>]`) is the
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
  **The nothing-to-restore warning (task #100):** both mark sites — `session
  grant undying on` and `spawn --undying` — carry `undying.rs::
  nothing_to_restore_warning(agent, has_capture)` into their own Outcome
  MESSAGE (never a log line) whenever a session is marked undying with
  neither arm `resurrect.rs::resolve_candidate` tries able to resolve it
  later: no restore capture (`has_capture`, the P-C5 snapshot above) and no
  registered harness `AgentProfile.resume_args`. `spawn --undying` computes
  `has_capture` directly off the command it just built
  (`captures_like_a_shell`, no race against the conducted child's own first
  tick); `session grant undying on --id <id>` reads it off the LIVE roster
  record's own `restore` field, and stays silent for an id absent from the
  roster (no live signal to warn from, the same posture `live` already
  takes) or when marking OFF (a future restore is no longer promised
  either way, so there is nothing to warn about).
- **The grant family (session-surface redesign, command-defrag lane X,
  2026-08-28 — supersedes U3/U1; task #20 adds the second kind):**
  `graph/grant.rs`'s `session_grant` is `session grant`'s handler — a
  POSITIONAL `<kind>` grammar (`secrets automate <name> on|off` style, not
  a second registered path per kind). Two kinds today, `undying` and
  `exempt`. `undying`: bare `session grant undying` (no state)
  dispatches to the interactive PICKER (`undying_picker`, U3's exact body
  relocated verbatim from what used to be bare `session`'s own handler —
  bare `session` now renders the roster instead, see the `who`/roster-core
  bullet below); `session grant undying on|off [--self | --id <id>]`
  dispatches to the SCRIPTED mark (`super::undying::undying_grant`, U1's
  exact body relocated from the standalone `session undying` command,
  which this absorbs and retires — hard cutover, no alias). `session
  grant` with no kind teaches the grantable set; an unknown kind is a
  taught refusal.
  The picker is CLI-only, tty-only (`aoide_protocol::pick::interactive`,
  gated on `Door::Cli` first the same shape `secrets`' admin quartet
  holds); a non-interactive reach — a non-CLI door, no tty, or `--json` —
  always steers to the scripted spelling above, which stays the ONLY
  scripted form (one spelling per capability). The picker itself reaches
  `aoide_protocol::pick::choose_many` DIRECTLY — no new seam: that function
  already supports pre-checked defaults and a clean `None` on Esc/EOF, and
  this crate already depends on `aoide-protocol` the same way `song`'s own
  `prune_picker` does; there was no missing primitive to add to `pick.rs`.
  Rows come from this box's own roster (`merged_sessions`, never
  re-derived) plus every registered node's CACHED graph via `who.rs`'s
  `sessions_from_graph` (`pub(super)`, `SessionView` alongside it — see
  `glyph`'s own widening note in `who.rs` for the precedent) — no live node
  probe anywhere in this module. A LOCAL row's mark toggles
  `state/undying.json` through one load, N mutations, one save (widening
  `undying_grant`'s own single-id discipline to a whole confirm's diff at
  once); a NODE row's mark writes a `.aoide/project.json` spec instead — the
  id lives on the node, so this conductor cannot write ITS store — resolved
  against the CURRENT project via the exact same `walk_up` `resurrect`'s
  bare mode already uses, U2, and NEVER auto-created: no manifest above cwd
  reports every node mark/unmark in that confirm as `skipped[]`, while any
  local rows in the SAME confirm still land. A node cwd that cannot be
  relativized under the project root (review round 1's fix) is likewise
  rejected BEFORE it ever touches `manifest.sessions` — never a raw-cwd
  fallback, which `save_manifest`'s own whole-batch validation would refuse
  outright, silently sinking every other legitimate node change in the same
  confirm; `changed[]` only ever names what the save actually persisted.
  Unmarking removes EVERY spec matching `{host, dir, agent}`, not just the
  first. The kind dispatch in `session_grant` is a plain match arm — a
  future kind (#127, secret grants is the next one named, not yet built)
  adds one arm, reusing the picker's own CLI+tty gate shape rather than
  re-deriving it. See `CONTRACTS.md`'s `.aoide/project.json` section for the
  exact spec-derivation and dedupe rules.
  **`exempt` (task #20) — the reaper's safety valve, no picker:**
  `session grant exempt on|off [--self | --id <id>]` (`grant.rs::
  exempt_grant`) sets or clears `SessionRecord::exempt`, vetoing `reap`'s
  staleness judgments (`is_session_dead`'s third signal,
  `abandoned_spawned_shells`'s own arm) for a session that IS them — never
  window-gone/pid-gone/ghosts/orphans, which fire on positive evidence a
  session is gone or is structural cruft, and never `resurrect`'s job. Bare
  `session grant exempt` (no state) is a taught refusal naming the scripted
  form — this kind has no picker at all, since its caller is a script
  (`--self`/`--id`), not an interactive tty session. Unlike `undying`,
  `--id` must name a session CURRENTLY on the roster (an off-roster id is a
  refusal, not a valid post-mortem target) and the write routes through
  `aoide_client::daemon::daemon_dispatch` FIRST, stage-lock fallback second
  — the same L4 dual-writer discipline `session_store.rs`'s
  `session_start`/`session_phase`/`session_end` and `reap_and_announce`
  hold, since `sessions.json` (unlike `undying.json`) is a stage-tree file.
  The mark dies with the record: no state file, no inheritance (a spawned
  child mints its own record, `exempt` absent by default), nothing to sweep
  post-mortem — an exemption's meaning ends exactly where undying's begins.
- `reap` — liveness reaping (`aoide session reap`), sweeping sessions a
  `SIGKILL`'d terminal could never mark `done`. `reap_and_announce` (the
  registered CLI handler) routes through `daemon_dispatch` first like every
  other session-write command above; the toast-free `reap` underneath is what
  every in-crate caller and unit test calls directly, and what the
  daemon's own tick runs internally on its ~12s cadence — the systemd timer
  becomes a redundant backstop once a daemon is resident, never a second
  liveness mechanism. Beyond session records, the same pass collects two
  kinds of leavings a killed session left in `$XDG_RUNTIME_DIR/aoide`: its
  control socket (`sweep_orphan_sockets`) and, for the ssh-transport lane,
  every tunnel it opened and never closed (`sweep_orphan_tunnels` — a
  roster-less, settled record's still-answering `ssh -N` child is signaled
  via `aoide_client::tunnel::kill_if_still_our_ssh`, and the record is
  unlinked ONLY once that call confirms the pid actually gone; a stubborn
  child that survives the bounded kill keeps its record on disk instead, so
  the very same record simply comes back as a candidate on the next sweep
  pass and gets retried — no separate retry bookkeeping needed).
  `orphan_tunnel_candidates`' own idea of "roster-less" is narrower than the
  socket sweep's: a session already `done` — a clean exit that closed its
  own tunnels but has not yet been pruned off the roster (`prune_done` only
  runs on a pass that reaped something) — counts as gone for TUNNEL
  candidacy specifically, so a record `close` had to keep does not wait on
  `prune_done`'s own schedule. Socket sweeping is untouched by this: a
  `done` session's control socket is already gone by the time
  `do_session_end` returns. A tunnel's fast path is
  `session_store::do_session_end`, which closes every tunnel a session
  opened (`aoide_client::tunnel::close_all_for_session`) on its own clean
  exit — likewise removing a record only once its pid is confirmed gone,
  and refusing (rather than silently overwriting) a stale reopen whose old
  child survives its own bounded kill; this sweep is only the
  SUPER+Q/SIGKILL backstop for the session that never got to run that exit
  path, or the retry for one whose fast-path kill didn't finish in time —
  so an ssh child can never outlive its session and become a resident
  daemon. `abandoned_spawned_shells` adds ONE narrow carve-out into the
  kind gate that otherwise keeps every shell record out of staleness
  judgment: a SPAWNED conducted shell (`spawned`), ticked at least
  once as a shell (`restore.is_some()`), sitting at a bare idle prompt with
  its per-session pty log (`log_path`) untouched past
  `REAP_SPAWNED_SHELL_STALE_SECS` (2 days) — the worker terminal an agent's
  own `spawn` left running and never returned to. **Windowed or not**:
  `spawn --windowed` execs a real terminal running the same `aoide conduct`,
  and an agent abandons one as readily as a headless one, so the gate is
  `spawned`, never `headless`. This is the only sweep here with two speeds.
  The band belongs to the UNATTENDED pass (the ~12s timer, the daemon's
  tick); a HUMAN GESTURE waives it and takes every idle spawned shell on the
  spot, carried as `--now` and resolved at the door by `with_human_gesture` —
  the dock's `[ reap ]` control passes the flag itself, and a bare
  `aoide session reap` typed at a terminal picks it up off
  `pick::interactive`. It must be decided at the door: `daemon_dispatch`
  forwards the flags to a resident `aoided` that has no tty of its own, so a
  probe made on the far side would read every gesture as the timer. No other
  band moves with it. **`exempt` (task #20) sits ABOVE the band, not inside
  it:** an agent-marked exempt shell is filtered out of candidacy before
  either the banded or the waived question is even asked, so `--now` cannot
  take it either — the same veto `is_session_dead`'s third signal holds for
  an exempt agent record. `--now` sparing an exempt shell is reported back
  in the sweep's own message and `data.spared` (never `changed` — nothing
  moved on the roster), the unattended pass staying silent about it the same
  way `refresh_live_agents`'s own report never toasts a quiet 12s tick. The
  touch signal is the log file's own mtime: any byte ever
  crossing the pty, from the original spawned command's output through any
  later injected `aoide send`, resets it, so a human's later use of an
  agent-spawned terminal is safe from this signal without the injection
  door ever needing to attribute WHO sent it (`send.rs`'s own
  `resolve_sender` doc: that attribution is self-reported and never
  enforced). `restore`/`log_path` are P-C5 fields the record already
  carries — `log_path` now stamped by every conduct-owned pty, headless and
  interactive alike (task #15, "everything tees"); `spawned` is the one new
  field, stamped by `stamp_spawned` inside the child `spawn` re-execs.
  **The unattended band reaches exactly as far as the guards do:** a
  `spawn --windowed` worker's terminal runs ordinary interactive conduct,
  which opens `state/sessions/<id>.log` the same as a headless one, so it
  carries a real touch signal and the timer can take it on its own —
  the gesture (`--now`) is no longer the only path in.
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
  below). The socket answers exactly one command with a reply,
  `sessionaction`: a closed five-action whitelist (`undying`, `project`,
  `kill`, `createproject`, `editproject`) that re-execs `aoide session
  project|kill|grant undying` or `aoide project add|edit` through aoided
  with `--json` and writes one JSON reply line before the connection
  closes. `createproject` is two invocations in order — `project add
  <name> <paths…> --new`, then `session project --id <id> --project
  <name>` to assign it — that stop at the first failure and report a
  partial honestly rather than rolling back. Every other socket command
  stays fire-and-forget.
- `commands` — this crate's CLI commands: 19 paths registered in one
  `register()` call (`conduct/src/commands/graph.rs`, still that file's name
  post-cutover) — the `graph` family narrowed at task #101 R1 to the bare
  render plus `graph link`, while `send`/`spawn`/`resurrect` went bare and
  `session *`/`project *` promoted to their own top-level groups — plus
  `conduct`, `hooks install`, `node list` (the standalone `who` command that
  used to round out this list is retired, session-surface redesign,
  command-defrag lane X, 2026-08-28 — folded into bare `session`/`--hosts`).
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
  `graph` uses — longest-prefix across EVERY root of the project, not just
  its first, since a project is a set of anchor roots (`project add`
  appends to that set, `project edit` replaces it outright, `project
  remove` drops one root or the whole project; see `Project::roots()`,
  `aoide-storage`'s own docs). Selection then branches on the flags: `--all` widens to every
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
  own name (`aoide_storage::display::local_host_name`) is SUMMONED through
  the node door (U4, `summon_remote` — resolves `host` against
  `state/nodes.json` by node NICKNAME, refuses locally into `failed[]` for
  an unregistered or unverified node or nothing to summon with, then calls
  `aoide_client::commands::spawn_on_node` — the same signed spawn-shaped
  `message/send` `aoide node spawn` drives, never a re-implementation; the
  wire carries no cwd, so a spec wanting a specific remote directory says
  so inside its own `command`); a local spec's `dir` resolves through
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
  (`revived-from-ledger`/`clean-spawned`/`summoned-remote`/`skipped`/
  `failed`) — including a row `resurrect_one` itself pushed, stamped after
  the fact since that function has no idea it's being called from manifest
  mode (review fix, U2 round 1: those rows used to carry no `disposition`
  at all). **Manifest-revived sessions are marked undying, LOCAL revivals
  only** (orchestrator design ruling, U2 round 1) — a remote summon's id
  lives on the node, never marked here — both LOCAL paths, once their spawn
  reaches
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
- **Terminal restore capture (P-C5, durable-sessions plan) — gated on the
  WRAPPED COMMAND, never the agent label (task #100).**
  `session_conduct`'s `is_shell` (everything below this bullet: the ~1 Hz
  refresh tick, `typed_capture_active`'s buffer, the restore snapshot) comes
  from `captures_like_a_shell(&program)` — `program`'s own basename against
  `bash`/`zsh`/`fish`/`sh`, never `agent == "shell"`. `agent` is a caller-
  chosen label (`--agent <name>`, or the command's own basename by default)
  that can disagree with what actually execs on the pty; the P-C7 soak's
  live finding was exactly that gap — `spawn --agent soak-a -- bash` ran a
  real interactive shell whose record never ticked, because its label
  wasn't the literal string `"shell"`. kitty.nix's own terminal wrapper
  needs no special case here: it always execs the resolved login shell
  explicitly as the conducted command, so its basename lands in the same
  set any other shell invocation does. `graph/conduct.rs`'s PTY tick
  (`conduct_refresh_shell`, ~1 Hz, the same
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
- **Session origin (P-P3, `docs/architecture/PAIRING.md` decision 7;
  write-authority tightened at LANE IDENTITY P-ID0, G16/G5, review round 1):**
  `session_store.rs::stamp_origin` (now `pub`, crossing the crate boundary)
  stamps `SessionRecord.origin` — `"node:<name>"` for a session
  `aoide-server`'s A2A door spawned on behalf of an identified, paired node.
  It has exactly two legitimate STAMP callers: `aoide-server`'s
  `a2a::do_spawn` calls it DIRECTLY on the just-spawned record
  (`stamp_spawn_origin`, polling for the record's registration the same way
  `spawn_inject_prompt` already does), from the door where the node name is
  actually authenticated — the only place a `node:*` value may originate.
  `graph/conduct.rs::session_conduct` calls it for a LOCAL-CLASS value off
  its own inherited `AOIDE_SESSION_ORIGIN` env, right after
  `do_session_start`, same seam `stamp_headless` uses — and REFUSES a
  `node:*` shape read from that env (a taught refusal, never a panic):
  inherited env is exactly what a same-uid process can set on itself before
  invoking `aoide conduct` directly, so a `node:*` value threaded that way
  was never trustworthy. A THIRD path reads `origin` back rather than
  stamping it fresh: `doc.rs::ledger_session_exit` projects
  `SessionRecord.origin` verbatim into the durable session ledger's own
  `origin` field at exit (no `graph.json` projection — like
  `headless`/`hookAncestry`, consumed internally, not rendered), and
  `graph/resurrect.rs::origin_to_carry` reads that field BACK on a revival to
  carry a LOCAL-class session's own provenance forward onto its revived
  record (G6, same phase). It REFUSES a `node:*` shape found there too
  (eprintln, never carried): `state/session-ledger.jsonl` is a plain,
  same-uid-writable, append-only file — a same-uid process can append a line
  claiming `origin:"node:X"` and then run the ungated local `aoide
  resurrect`, which has no door and no seal behind it to re-mint that
  authority. `origin_to_carry` is pure and directly unit-tested for exactly
  this refusal. **This closes the STAMP paths, not the files**: a
  hand-crafted `sessions.json`/ledger line claiming `node:X` is still a
  readable, unflagged string on disk — nothing here makes the files
  tamper-evident; that is P-ID1 (the daemon-signed credential, below) —
  minted and stored, verified on the per-session control socket's own
  accept and consumed by the send gate as of P-ID2, and both remaining
  sockets get a peercred floor of their own as of P-ID3 (below).
  **The raw field is attribution, never a gate**: a same-uid process can
  still forge a LOCAL-class `origin` string, so nothing gates a security
  decision on the field as read off disk — the authenticated form is the
  `originClass` carried inside a VERIFIED seal (below), which is what the
  secrets broker's origin gate (P-ID4) consumes; the consumer NAME
  presenting a request stays unauthenticated either way (a separate,
  unbuilt axis — CONTRACTS.md's identity-lane accounting). What P-ID0
  closes: every record-STAMP path this codebase drives refuses a `node:*`
  shape it didn't mint itself at the door — env AND ledger both.
- **Sealed session credential (LANE IDENTITY P-ID1/P-ID2) — minted by
  `aoide-server`'s daemon, verified and consumed inside this crate.**
  `session_store.rs::stamp_seal` is `SessionRecord.seal`/`sealedIssuedAt`'s
  ONE stamp function (crosses the crate boundary, `pub`, mirroring
  `stamp_origin`: change-once, no `graph.json` projection), with TWO
  legitimate callers — `aoide-server`'s daemon `dispatch` handler (mints
  right after a `session start` dispatch whose record already carries a
  pid) and the daemon's own tick-driven `seal_unsealed_live_sessions`
  sweep (closes the gap the dispatch-only path left: a DIRECTLY-registered
  `aoide conduct` session, the common case, never touches `dispatch` at
  all). `window.rs::pid_starttime` (re-exported at `graph::pid_starttime`;
  its body — the `/proc/<pid>/stat` field-22 read — lives in
  `aoide_storage::attest` as of LANE IDENTITY P-ID4, this crate
  delegating) is read both at MINT time (the daemon, over the pid a record
  already carries) and at VERIFY time (this crate's own
  `graph/identity.rs`, re-reading it FRESH for the connecting/attested pid
  — never trusting a stored value, the pid-reuse defense).
  `graph/identity.rs` is where the gate lands: `attested_sender` walks a
  pid's real `/proc` ancestry (`window.rs::pid_ancestry`; both walk bodies
  likewise delegated to `aoide_storage::attest`, shared with the secrets
  broker's P-ID4 origin gate) to
  find a session whose seal `verify_seal_over` confirms against the
  daemon's LIVE public key (`aoide_client::daemon::daemon_seal_pubkey_hex`
  — a fresh `ping` round trip, never cached, never a file; that channel is
  only as trustworthy as the daemon socket's same-uid exclusivity, which
  `bind_socket`'s unlink-then-bind with no flock/pidfile does NOT actually
  provide against a same-uid attacker — P-ID3's job to floor, stated
  honestly in `CONTRACTS.md` rather than oversold here); `peer_cred`
  reads `SO_PEERCRED` off an accepted `UnixStream` (a local
  reimplementation of `aoide_secrets::peercred`'s own shape — no new
  cross-crate edge for one struct+fn). `graph/conduct.rs`'s per-session
  accept loop calls `peer_cred` on every accepted connection and refuses
  one whose OWN nearest live registered session (`identity::
  is_self_originated` — nearest-first, session-boundary aware, review
  round 1 MUST-FIX: an earlier revision refused on raw ancestry
  CONTAINMENT, which broke a child sending to its own live parent, since
  `session_conduct` registers without detaching) resolves to the socket's
  OWN session — the un-bypassable replacement for the OLD client-side
  `is_self_send`
  guard `graph/send.rs` used to carry. `graph/send.rs`'s `deliver_local`
  calls `attested_sender` over ITS OWN process's real ancestry (as
  unforgeable a kernel fact, for that SAME real process, as a peercred
  read of it would be) to feed `sender_is_parent`/
  `siblings_share_live_parent` — `AOIDE_SESSION_ID` is gone from every gate
  predicate, kept only as attribution. See `CONTRACTS.md` §4's `seal`
  paragraph and `aoide-storage`'s own README for the full mechanism and the
  OQ1-A reasoning. **What P-ID2 does NOT close**: the per-session socket
  still forwards bytes from any OTHER connection it doesn't specifically
  refuse (a raw, unrelated same-uid connection bypassing `aoide send`
  still injects ungated — the socket carries no envelope, so `--yes`
  cannot be told apart from an ordinary send at the receiving end).
- **The remaining two sockets get a peercred floor (LANE IDENTITY P-ID3).**
  `identity::peer_cred`/`PeerCred` widened `pub(crate)` (was `pub(in
  crate::graph)`) so `shellbridge.rs` — a sibling module of `graph`, not a
  descendant — reuses the SAME primitive rather than a second `SO_PEERCRED`
  read. `shellbridge::serve`'s accept loop (and `aoide-server`'s own
  `accept_loop`, over `aoide_secrets::peercred` — already `pub`, already a
  dependency, so no widening needed there) now refuses any connection whose
  peer uid doesn't match the process's own euid, fail-closed on an
  unidentified peer exactly like the secrets broker's `admin_gate`
  precedent (`shellbridge::cross_uid_gate`/`daemon::cross_uid_gate`, pure
  and unit-tested without a real different-uid connection). **This is a
  CROSS-uid floor only** — under OQ1-A every legitimate connector on both
  sockets (the QML herald/bar widgets, `aoide herald push`, `session
  permit`'s own raise, the CLI's `daemon_dispatch` proxy) already shares
  the operator's own uid, so a same-uid attacker synthesizing a
  `heraldverdict` on shellbridge's verdict door is an OQ1-A-inherent
  residual this floor does not close — stated honestly in `CONTRACTS.md`
  rather than oversold here, the same posture P-ID2's own per-session
  socket residual holds. Two attribution leaks close alongside the floor:
  `aoided`'s `invocation_from_dispatch_request` stamps an absent `from` on
  a dispatched `send` explicit-empty (`--from ""`, `resolve_sender`'s own
  documented "no attribution" form) rather than leaving it to fall through
  to the DAEMON's own ambient `AOIDE_SESSION_ID` when a `send` handler runs
  inside its process (G8); `aoide-server`'s `a2a::do_inject` does the exact
  same for an unattributed remote inject, so it never picks up `aoide a2a
  serve`'s own ambient env either (G9). Neither closes the GATE itself —
  `real_attested_sender`'s `std::process::id()` walks whichever process is
  actually running `deliver_local`, which for a dispatched/injected send is
  the daemon's/`a2a serve`'s own ancestry, not the original caller's; in
  production that ancestry never resolves a live sealed session, so this
  already fails closed to `pending` by construction, not because either fix
  re-derives the real caller's identity — threading the connecting peer's
  pid into the gate itself would touch `send.rs`, out of this phase's scope
  fence.
- **`session` (bare) — the ROSTER (session-surface redesign, command-defrag
  lane X, 2026-08-28; supersedes the U3 picker AND the standalone `aoide
  who` command, both retired — hard cutover, no alias).** `aoide session
  [filter] [--hosts] [--json] [--all]` (`graph/who.rs`, now the shared
  roster core): live presence over this box's own sessions plus every
  registered node, probed in parallel on each invocation (messaging
  workstream C2 — the exact pipeline `who` used to run, unchanged). Bare
  groups sessions by PROJECT (`project_bucket`: a registered `projects.json`
  name via `anchor_for`, else a `.aoide/project.json` manifest directory's
  own basename via `walk_up`, else a trailing `(no project)` bucket);
  `--hosts` groups by HOST instead — this host, then each node,
  byte-identical to `who`'s old rendering (`render_nodes`/`node_json`
  survive unchanged). `filter`/`--all` narrow `nodes` BEFORE either split,
  so they apply to both groupings uniformly. A PROJECTION, never a store —
  it never writes `state/node-cache/`; `build_graph`'s own fold (`doc.rs`)
  owns that file. `glyph` (the online/unreachable/never-pulled node-presence
  map) is `pub`, re-exported at `graph::glyph` — the conductor's ROSTER
  panel (P-C4) is its second consumer, reusing it rather than redrawing its
  own copy (its dispatch moved from `who` to `session --hosts`, same
  `Outcome` shape).
- `node list` — `aoide node list [--json]` (`graph/node_list.rs`, task
  #120 P2): the one-glance mesh roster — this host, every registered node,
  every advertising instance heard in one bounded ~2s discovery sweep
  (`aoide_client::discover::run_sweep`, run concurrently with the probes),
  each node's running sessions indented beneath. A PURE fold over the
  roster core's own probe (`probe_nodes`/`build_node_node`/`build_local_node`/
  `sessions_from_graph`, `pub(super)`) plus the sweep's
  heard-set — never a second prober, never a second presence model, and
  it writes nothing (`state/nodes.json`/`state/node-cache/` stay other
  modules' files). Lives in THIS crate, not `aoide-client` beside the
  rest of the `node` family, because `aoide-client` cannot depend on
  `aoide-conduct`; `node status` (client) keeps the deep per-node
  registry view. CONTRACTS.md §7's CLI surface pins the row/mark grammar
  and the `--json` shape.
- `mail_bridge` (P-M2, architect's ruling 1: "spool in storage, wire lane
  in client, bridge through conduct") — a thin, two-function passthrough
  onto `aoide_client::mail_wire`'s outbox drain, with no logic of its own.
  It exists purely as a crate-DAG detour: `aoide-server` depends on
  `aoide-client` only as a dev-dependency (a production edge is refused by
  the manifest, not merely discouraged), but `aoide-conduct` already
  carries a real one (`graph::who` → `pull_node_live`, `graph::resurrect`
  → `spawn_on_node`), so the daemon tick and the A2A door both reach
  `mail_wire::drain_node` through here instead of either depending on
  `aoide-client` directly. `drain_node(name)` drains one node's outbox
  once; `drain_all()` — the daemon tick's own call, mirroring
  `daemon::run_internal_reap`'s "reach a sibling crate's handler on its
  tick" shape — walks every node `aoide_storage::outbox::nodes_with_outbox`
  reports, letting one node's `Err` (a genuine local I/O failure, never an
  ordinary unreachable-node outcome) skip that node without stopping the
  sweep.

## What it consumes

`aoide-protocol`, `aoide-storage`, `aoide-upkeep` (`session hook`'s check-lane
trigger, above — the ONLY reach into that crate from outside `cli`),
`aoide-client` (bare `session`/`--hosts`'s
and `node list`'s live per-node probes call `aoide_client::commands::pull_node_live`
— the node-pull transport `node pull` itself uses, workstream C2; `node
list`'s discovery sweep calls `aoide_client::discover::run_sweep` —
P-P6's one sweep implementation, task #120 P2; `send --to`'s
remote branch calls `aoide_client::commands::send_message_to_node`,
workstream C3; every session-write handler calls `aoide_client::daemon::
daemon_dispatch`, P-D6; `mail_bridge`'s two functions call
`aoide_client::mail_wire::drain_node`, P-M2, ruling 1 — the ONE other edge
this crate carries specifically so `aoide-server` never has to; see
`client`'s own README for why that edge stays).

## How it composes

`screen`, `server`, `conductor`, `cli`, and `lyra` all depend on it.
**Charter smudge**: `shellbridge.rs`/`herald.rs` stay as FILES here even
though their CLI commands moved to `lyra` — `permit.rs` publishes summons
through `herald`, and `conductor/ui.rs` reads the socket path `shellbridge`
owns, so both are entangled with core
(`docs/architecture/PACKAGE-LAYOUT.md`, "Charter exceptions").
