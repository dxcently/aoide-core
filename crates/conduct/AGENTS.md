# AGENTS.md — aoide-conduct

- **Session actions preserve identity and scope.** Project assignment changes
  `project`, never `cwd` or ancestry. Termination is local daemon-only and
  requires a dedicated conductable process, exclusive live PID ownership,
  fresh seal verification, and pidfd signaling. Never fall back to `kill(pid)`
  or infer completion from successful signal delivery.

## Invariants

- **Codex titles use exact native thread IDs.** The reaper reads the configured
  Codex session index once per metadata pass and updates only already registered
  `agent == "codex"` records. The latest valid nonempty index title owns that
  field, including renames; every other field is preserved. Never enroll index
  history or infer a window, lifecycle event, or control channel from a title.
  Other harnesses retain their existing title precedence.

- **`session bind` assigns continuity, never authority.** Keep the operation
  daemon-owned and local-only; no missing-daemon fallback. It does not load
  optional Mneme config, change grants, or replace executor-specific mail
  reader keys. A binding is immutable within a session; same-key calls are
  no-ops. Project the explicit binding into the graph and exit ledger.

- **This crate is core, never lyra.** Nothing here may gain a
  wayland/image/quickshell dependency — that's exactly what P-A1 moved OUT
  (to `screen`) to keep this crate headless-safe. `cargo tree -p
  aoide-conduct` staying free of those deps is a standing gate.
- **`shellbridge.rs`/`herald.rs` are a named, deliberate charter smudge.**
  Their CLI commands live in `lyra`; the files stay here because `permit.rs`
  (this crate) publishes through `herald`, and `conductor/ui.rs` reads the
  socket path `shellbridge` owns. Don't move the files to chase the commands —
  see `docs/architecture/PACKAGE-LAYOUT.md`'s "Charter exceptions" for the
  full reasoning before touching either.
- **`sessionaction`'s five-action whitelist never becomes a translator.**
  `session_action_args` is the ONE authority for the whitelist and the ONE
  call site for the gate; nothing else builds argv from wire values it did
  not validate. `safe_action_value` (session ids, project/create/edit
  names) rejects empty, `-`-prefixed, whitespaced, or control-charactered
  strings before they reach an argv; `safe_action_path` is a deliberately
  separate, looser rule for path arguments — a path is absolute and
  control-free, whitespace included, with the list length bounded
  (`MAX_ACTION_PATHS`). The reply is one JSON line on its own dedicated
  connection and the QML callback contract is exactly-once. A multi-step
  action (`createproject`'s add-then-assign) stops at its first failure and
  reports the partial state honestly rather than rolling back. The bridge
  never pre-checks what the CLI already refuses — `project add --new` owns
  "this name exists," not this file. No reply channel on the connection
  means no dispatch at all. The audit line carries only the action name and
  status, never an argument value. The accept loop gives every connection
  its own thread, with no read timeout added: a client is allowed to idle
  (the bar's own shared socket does, between human gestures), and one that
  does must never starve another's.
- **`normalize_addr` is `pub`, not `pub(crate)`, on purpose** — `screen`
  reaches it directly rather than duplicating it. Don't narrow it back
  without checking that dependency first.
- **`commands::hooks::skill_source` is `pub`, not `pub(crate)`, on purpose**
  (P-I2, ONBOARD.md decision 10) — `aoide-cli`'s `onboard` reaches it
  directly for its from-a-checkout refusal (the only repo-root detector in
  the tree) rather than re-deriving the walk-up. Don't narrow it back
  without checking that dependency first.
- **`reap::proc_exists` is `pub`, not private, on purpose** (task #33) —
  `aoide-server`'s A2A `tasks/get` resolution feeds this SAME `/proc` probe
  into `is_session_dead` at read time, so a session that dies after its
  spawn ack reads `failed` instead of stale `submitted`, without a second
  `/proc`-reading predicate forked into `server`. Don't narrow it back
  without checking that dependency first.
- **A killed terminal never self-reports `done`.** `reap` is the only
  sanctioned sweep of dead sessions; don't add a second liveness mechanism.
  Reaping now also runs IN the daemon's own tick (P-D6, ~12s cadence) when
  one is resident — that is the SAME sweep (`reap`), not a second one; the
  ~12s systemd timer's own `session reap` becomes a redundant backstop, never
  a third mechanism.
- **`reap` collects two kinds of leavings a killed session left in
  `$XDG_RUNTIME_DIR/aoide`, not one.** `sweep_orphan_sockets` and the
  ssh-transport lane's tunnel sweep are the SAME sweep pass conceptually:
  only a roster-less, settled candidate is ever touched, and a candidate
  whose session IS still live is spared outright regardless of what a
  pid/port probe would say. **"Roster-less" is NOT the same test for the
  two sweeps, on purpose.** The socket sweep treats any session record
  still present in `sessions.json` as live, whatever its `state`. The
  tunnel sweep is narrower: a session already `done` — a clean exit that
  ran `close_all_for_session` but has not yet been pruned off the roster
  (`prune_done` only fires on a pass that reaped something) — counts as
  gone for tunnel candidacy specifically, so a record `close` had to KEEP
  (its child survived the fast path's own bounded kill) does not wait,
  unbounded, on `prune_done`'s own schedule. This asymmetry is deliberate
  and narrow: it changes ONLY `orphan_tunnel_candidates`' own roster
  computation in `reap_inner`, never `sweep_orphan_sockets`'s, and never
  `prune_done` itself — a `done` session's control socket is already gone
  by the time `do_session_end` returns, so the socket sweep has no
  equivalent problem to solve. **`kill_if_still_our_ssh`'s bool return is
  `#[must_use]` and gates removal at every call site, never discarded —
  `close`, `open_or_reuse_with`'s stale-record path, and
  `sweep_orphan_tunnels` all unlink/replace a record ONLY on `true`
  (confirmed dead or never actually ours); on `false` (confirmed ours and
  still alive) the record is left exactly where it was, so the reaper's
  next sweep pass re-gathers the SAME record and retries the kill — no
  separate retry bookkeeping, and no candidate is ever unlinked out from
  under a live, untracked child.** **The two sweeps are NOT symmetric about
  the stage lock, on purpose.** `sweep_orphan_sockets` runs entirely inside
  `with_stage_lock` (`reap_inner`) because unlinking a leftover socket file
  is cheap. A tunnel candidate's `ssh -N` child may still be alive, and
  signaling it (`aoide_client::tunnel::kill_if_still_our_ssh` →
  `terminate_pid`'s bounded `SIGTERM` + `waitpid`/`/proc` poll) can take up
  to ~1s PER candidate — doing that under `.stage.lock` would serialize
  every other stage writer (hooks, the ~1Hz conduct ticks, the window
  listener, `session start`/`end`, `send`) for as long as it takes. So the
  tunnel sweep is split: `reap_inner` only GATHERS candidates under the lock
  (`orphan_tunnel_candidates` — roster/settle checks against already-loaded
  state, no process signaling), and `reap` runs the KILL half
  (`sweep_orphan_tunnels`, never re-implemented here; `aoide-conduct` sits
  above `aoide-client` in the crate DAG and reuses `kill_if_still_our_ssh`
  verbatim) AFTER `with_stage_lock` returns, folding the result into the
  same `Outcome` the lock-held pass already built (the `gathered_addrs`/
  `window_owners` split `reap` already holds for its own pre-lock window
  gather is the same shape, mirrored on the other side of the lock instead).
  **Any new candidate-collector that must probe or signal a live process
  belongs on the post-lock side of this same split — never inside
  `reap_inner` "for consistency" with the socket sweep.** Nothing about a
  tunnel may become a resident daemon either way:
  `session_store::do_session_end` closes a session's own tunnels on its
  clean exit (`aoide_client::tunnel::close_all_for_session`, the fast path,
  likewise run AFTER the stage lock releases since it may block on a real
  `waitpid`); the reaper's tunnel sweep is only the backstop for the session
  that never got to run that exit path, or the retry for one whose
  fast-path kill didn't finish in time. A new leaving-kind under this same
  runtime directory joins the sweep the same way — never a separate cleanup
  mechanism.
- **Every session-write handler routes through `aoide_client::daemon::
  daemon_dispatch(inv)` FIRST, as its own first line, falling back to its
  pre-existing direct stage-write path byte-identically on `None` (P-D6,
  `docs/architecture/AOIDED.md`'s "L4").** `session start/phase/end`,
  `session hook`, and `reap::reap_and_announce` all follow this exact
  one-line prefix. A new session-write handler joins the family the same
  way — see `client`'s own `AGENTS.md` extension-point note. **`graph/
  undying.rs`'s `undying_grant`, `graph/spawn.rs`'s `--undying` mark, and
  `graph/resurrect.rs`'s undying transfer are a deliberate exception, not an
  oversight:** `state/undying.json` is not a `state/stage/` file, so none of
  the three has L4 residency to route through — don't add a `daemon_dispatch`
  prefix to any of them "for consistency" with the family above; that would
  put an extra writer on a file the undying store's own atomic-write CRUD
  already lets multiple call sites share safely (each call is load-mutate-
  save on the whole set, never a partial write).
- **The check lane's three hook calls are best-effort and gated on the EXACT
  event, never on a broader phase family (task #139).**
  `graph/send.rs::hook_for_profile` calls `aoide_upkeep::checklane::
  on_session_start` only from `HookAction::Start`, `checklane::
  on_prompt_submit` only inside `HookAction::Phase` guarded on
  `phase == "working"`, and `checklane::on_stop` only inside the same arm
  guarded on `phase == "stopped"` — the one phase string each of
  `UserPromptSubmit`/`HookClass::Stop` alone produces (`map_hook`); don't
  widen either guard to fire on `awaiting` too, or the lane's own delta
  arithmetic (baseline vs. "what changed") stops meaning what its message
  claims. `on_session_start`/`on_stop` take the raw payload's OWN `cwd`
  (present on every real hook payload, not a stage-file lookup);
  `on_prompt_submit` takes neither `cwd` nor config — it only drains a file.
  All three degrade to a no-op on a missing `cwd`, a disabled lane, or an
  unloadable config — same best-effort stance every other hook action in
  this function already holds; a check-lane failure must never fail the
  hook. **The `HookAction::Start` arm reads `session_store::stored_phase(id)`
  BEFORE its own mutating calls** (`do_session_start`, then
  `do_session_phase_if`) to derive `mid_turn` — reading it after either
  would risk observing a phase this same event already changed. Never
  substitute the hook payload's own `source` field for this: a manual
  between-turns `/compact` says `source: "compact"` too, but IS a settled
  boundary — only the stored phase tells the two apart.
  **`commands/hooks.rs::door_command`'s claude wrapper must keep letting
  `SessionStart`/`UserPromptSubmit`'s stdout through** (`2>/dev/null` for
  exactly those two events; every other event, `Stop` included, keeps the
  original `>/dev/null 2>&1` swallow ON PURPOSE — don't widen either
  direction). Stdout is the only PIPE a `session hook` `Outcome` ever
  reaches the harness through (`aoide_protocol::door::run`'s `println!` on
  `Ok`) — reaching the harness is not reaching the model; which events
  Claude Code actually folds into context is
  `docs/Aoide-Wiki/protocol/dev/HARNESS-CLAUDE-CODE.md`'s call (its "Traps"
  section), not restated here, and it names exactly `SessionStart`/
  `UserPromptSubmit`. Restoring the old blanket swallow on those two
  silently kills every lane note without touching a single assertion in
  this crate's own test suite, since none of those tests observe the
  harness's actual stdout — only the returned `Outcome` in-process.
  Conversely, unmuffling `Stop` (or any other event) would only leak routine
  hook chatter into a channel nobody reads on that event — `on_stop`'s
  delivery is the pending-note relay through `on_prompt_submit`/
  `on_session_start`, never a wrapper change.
- **The undying transfer is one `save_undying` call, never two.**
  `resurrect.rs`'s `resurrect_one` adds the new id and drops the old one in
  the SAME in-memory `Vec<UndyingSession>` before writing — the new id goes
  in first, so a crash between the in-memory edit and the write leaves the
  OLD id undying (the next sweep retries it) rather than leaving neither
  undying (silent loss). The transfer only fires when the old id was
  actually undying (`is_undying` gates it) and only when the spawn reached
  `Status::Ok` — an ordinary `--all`/`--id` revive of a not-undying session
  must never start marking it undying, and a failed spawn must leave the old
  id exactly as it was. Don't split the add and the drop across two
  `save_undying` calls, and don't drop the check that the old id was
  undying.
- **Bare `resurrect --project` selects the undying set, not a single
  "most recent" entry (P-C4, durable-sessions plan).** `resurrect.rs`'s
  `undying_selection` is the one place that reads `sessions.json` for
  liveness — the daemon's boot sweep (`aoide-server`'s `daemon.rs`) no
  longer runs its own liveness check before calling `session_resurrect`; it
  calls unconditionally for every `autoResume` project and relies on this
  function to drop already-alive ids per candidate. Don't reintroduce a
  project-wide liveness gate in the daemon loop — a multi-session undying
  set needs the exclusion done per id, not per project, or one live
  terminal suppresses reviving the rest of the set. `--all` and `--id` stay
  exactly as they were: neither consults the undying mark at all.
- **Bare `resurrect` (no `--project`/`--all`/`--id` at all) tries a project
  MANIFEST before anything else (U2, command-defrag lane U).**
  `resurrect.rs`'s `session_resurrect` walks up from cwd
  (`aoide_storage::manifest::walk_up`) and, on a hit, hands the whole
  outcome to `resurrect_from_manifest` — never falls through to
  `require_flag(inv, "project")` in that case. Any of the three flags
  present routes straight past the manifest check to the pre-existing
  flag-mode path unchanged; the two modes are mutually exclusive by
  construction, not by an explicit guard someone could accidentally widen.
  Don't make the manifest check consult `projects.json` — the whole point
  is that a manifest is self-sufficient on a host that has never registered
  the project at all.
- **The both-misses usage error is conditioned on having actually tried the
  walk (review fix, U2 round 1).** `flag_mode` (`--project`/`--id`/`--all`,
  any one present) is computed ONCE at the top of `session_resurrect` and
  consulted a SECOND time at the `require_flag(inv, "project")` failure
  branch: `flag_mode == true` there returns `require_flag`'s own original
  `Err` untouched (a flag WAS given, `--project` just wasn't — the walk was
  never attempted, so the manifest-miss wording would lie); only
  `flag_mode == false` builds the "no .aoide/project.json above `<cwd>` and
  no --project/--all/--id given" message. A regression here (returning the
  both-misses message unconditionally on any `require_flag` failure) is
  exactly the bug the round-1 review caught — `id_without_project_is_the_
  ordinary_missing_flag_error_not_the_manifest_message`/`all_without_
  project_is_the_ordinary_missing_flag_error_not_the_manifest_message`
  pin it down.
- **Every row of `resurrect_from_manifest`'s outcome carries a
  `disposition` (review fix, U2 round 1).** `resurrect_one` is reused
  VERBATIM for the enrichment path and knows nothing about being called
  from manifest mode — none of its own pushes into `resurrected`/
  `skipped`/`failed` carry a `disposition` key. `resurrect_from_manifest`
  snapshots each bucket's length before calling it and stamps
  `"revived-from-ledger"`/`"skipped"`/`"failed"` onto whichever ONE grew
  afterward (`resurrect_one` always pushes into exactly one, never zero,
  never two, per call) — this loop's OWN pushes (`summon_remote`'s
  `summoned-remote`/`failed`, `clean_spawn_from_spec`'s
  `clean-spawned`/`failed`) already carry theirs inline. Don't add a new
  `resurrect_one`/`clean_spawn_from_spec`/`summon_remote` push path
  without also covering it here — an un-stamped row is exactly the defect
  a consumer filtering the outcome by `disposition` would silently drop.
- **A remote spec (`host` != this host) is `summon_remote`'s job, not a
  skip (U4, command-defrag lane U).** It resolves `spec.host` against
  `state/nodes.json` by node NICKNAME (the same nickname U3's picker writes
  a spec's `host` as), refuses LOCALLY into `failed[]` — never `skipped[]`
  — for an unregistered node, a registered-but-unverified one (mirrors
  `aoide-client::commands::handle_node_spawn`'s own local gate: an unsigned
  request can never satisfy the remote door's `Signature`-rung spawn gate),
  or nothing to summon with (`summon_text` returns `None`), THEN calls
  `aoide_client::commands::spawn_on_node` — never re-implement that wire
  call here, never shell out to the `aoide` CLI; the `conduct` → `client`
  edge is documented in `conduct`'s own `Cargo.toml`. `summon_text` never
  whitespace-splits a spec's `command` (there is no argv on this wire, only
  one prompt string) — don't reuse `clean_spawn_from_spec`'s split/rejoin
  logic here, it would collapse whitespace the operator wrote on purpose.
  The wire carries no cwd: don't add a `--cwd`-shaped field to the spawn
  request to compensate — that is a later phase's wire change, gated on the
  fleet's doors all running a binary new enough to read it.
- **Manifest-revived sessions are marked undying unconditionally, gated on
  `Status::Ok` alone — never on live registration (orchestrator design
  ruling, U2 round 1) — LOCAL paths only.** `mark_manifest_revival_undying`
  is called from `resurrect_from_manifest` itself, right after EITHER LOCAL
  path (enrichment via `resurrect_one`, clean-spawn via
  `clean_spawn_from_spec`) lands a row in `resurrected` — which by
  construction only happens past `Status::Ok`. `summon_remote`'s own rows
  never reach this call: the resurrected id lives on the node, and
  `state/undying.json` only ever names ids that live on THIS host — don't
  route a `summoned-remote` row through `mark_manifest_revival_undying`,
  it would mark an id this host has no authority over.
  This is its OWN `load_undying`/`set_undying`/`save_undying` call, NOT a
  `--undying` flag threaded into the shared `spawn` invocation: gating on
  `registered` (what `aoide spawn --undying` itself gates on) would make
  this unconditionally untestable in this crate — a live terminal
  registering is exactly the line `spawn.rs`'s own module doc draws as
  "never this crate's tests." Don't fold this into flag-mode's own undying
  TRANSFER block (`resurrect_one`'s pre-existing, untouched
  `is_undying(&c.entry.session_id)`-gated logic) — that block only ever
  moves a PRE-existing mark and must stay that way for an ordinary
  `--all`/`--id` revive; manifest-mode marks unconditionally because every
  manifest-mode spawn already came from an explicit, operator-authored
  declaration, not an ordinary revive.
- **The enrichment rule is a hard ordering: the manifest decides WHAT
  exists, the ledger decides HOW (the User's own design decision, U2).**
  `resurrect_from_manifest` never invents a candidate the manifest didn't
  name, and never lets the ledger override which specs get considered —
  it only ever enriches a spec that's already there, picking the NEWEST
  ledger entry whose `cwd`/`agent` match (host is never compared again at
  this point: a spec's `host` mismatch already skipped it earlier in the
  same loop, and the ledger itself is host-local state that is never
  synced, so every remaining entry IS this host's). A match reuses
  `resolve_candidate`/`resurrect_one` VERBATIM — don't fork a second
  harness/terminal-arm resolver for the manifest path. No match
  clean-spawns via `clean_spawn_from_spec`, which reuses `session_spawn`'s
  own windowed path — don't hand-roll a second spawn call here either.
- **`resolve_spec_dir` (`aoide_storage::manifest`, U2) is the ONLY
  place a manifest spec's `dir` becomes a filesystem path.** It refuses,
  never clamps, a `..` that would resolve outside the project root after
  LEXICAL normalization — don't resolve a spec's `dir` by hand (a bare
  `project_root.join(dir)`) anywhere else; that would silently reopen the
  containment hole this function exists to close. It is a STRING check,
  not a filesystem one: a `dir` with no `..` at all can still pass through
  a symlink pointing outside the project root at USE time, undetected —
  accepted under the manifest's host-local, operator-authored trust model
  (the operator who writes a spec already controls their own disk), not a
  gap to close with a `canonicalize` call here.
- **`reap` (toast-free) and `reap_and_announce` (the registered CLI/daemon
  handler) are deliberately two functions, not one.** `reap_and_announce`
  spawns a REAL `notify-send` on the live desktop whenever the sweep
  changed anything (or `--announce` is passed) — every in-crate caller and
  unit test calls the bare `reap` instead, and MUST keep doing so; a test
  that dispatches the real `session reap` command path (proving daemon/socket
  routing, not sweep logic) reaches `reap_and_announce` for real and has to
  neutralize `notify-send` itself (e.g. blanking `$PATH` for that one call)
  rather than letting a test fire a real toast on the machine running it.
- **A session's exit — a clean `session end` OR a `reap` sweep — MUST
  append exactly one line to the durable session ledger, through the SAME
  shared call (P-D8, `docs/architecture/AOIDED.md`'s "L5").**
  `graph/doc.rs::ledger_session_exit` is that one call;
  `session_store.rs::do_session_end_inner` gates it on the record's own
  `state != "done"` BEFORE mutating (a re-run `session end` on an
  already-done id must never double-append — `do_session_end` never prunes
  its primary record the way `reap` does, so a second call on the same id
  is a real, reachable case), while `reap_inner` needs no such gate since
  every id in its `reaped` set is already filtered to `state != "done"` by
  construction and gets physically pruned within the same call. Don't add
  a second ledger-append call site for a new session-write handler — route
  it through `ledger_session_exit` (re-exported `pub(crate)` at `graph.rs`
  specifically so `reap.rs`, a sibling module, can reach it) the same way.
- **This crate's own `env_lock()` (`lib.rs`)'s first call in a test binary
  also floors
  `$AOIDE_DAEMON_SOCKET` at a path nothing could ever listen on, unless a
  test already set one (P-D6 safety net — an incident, this phase: a real
  resident `aoided` on this exact dev box shares the default socket path
  every routed test handler resolves to when unset, and a test that forgot
  its own override silently mutated PRODUCTION `~/Aoide/state/stage/
  sessions.json` through it before this floor existed).** Don't remove or
  weaken this floor to "simplify" `env_lock()` — a test that WANTS to prove
  real daemon routing still installs its own `$AOIDE_DAEMON_SOCKET`
  override afterward, same as any other env var here. **A second floor
  (P-D8, same reasoning, one env var over) does the identical thing for
  `$AOIDE_STATE_DIR`:** `session_store.rs`/`reap.rs` had zero prior
  references to it before the ledger write landed, so without this floor
  every `session_end`/`reap` test in either file would silently append
  into the REAL `~/Aoide/state/session-ledger.jsonl` on this box the
  moment its own test forgot (or never needed) an override. Same rule:
  don't remove it, and a test proving something about the ledger installs
  its own `$AOIDE_STATE_DIR` override on top, same as any other env var.
- **A nested headless session is windowless BY CONSTRUCTION — never
  pid-ancestry-walk it to a window (task #89, corrected in review round 2).**
  It is NOT enough to gate the four historical backfill call sites — a
  headless wrap's OWN record needs the same protection its descendants get,
  or the whole mechanism re-poisons on a live compositor. Two parts, both
  required:
  - **The discovery gate.** `graph/conduct.rs::session_conduct` must never
    call window discovery for a `--headless` registration in the first
    place — gated on `!headless`, right where the winsize/headless branch
    already lives. `setsid()` detaches the tty/session-leader relationship,
    not the OS parent-child (`/proc` ppid) one, so an unconditional
    discovery call on a headless wrap resolves straight through to its
    ENCLOSING terminal's window — the review-round-2 defect. The same call
    site stamps the permanent `headless: bool` marker via
    `session_store::stamp_headless` (change-only, written once, never
    cleared) right after registration.
  - **The listener self-check.** `window::windowless_by_lineage` checks a
    session's OWN record FIRST (via `is_windowless_wrap`: `conductable` and
    (`headless` OR its own `windowAddress` empty)) before ever walking its
    parent chain — so the wrap's own record is caught by the same function
    that catches its descendants, not by a bolted-on second mechanism. Every
    backfill site routes through this one function: `resolve_pending_session_windows`
    (the shellbridge event listener), `graph/window.rs::ensure_session_window`,
    and the two `discover_window()` call sites in `graph/send.rs`'s hook
    Start handling. Miss the discovery gate, the self-check, OR any one of
    the four backfill sites, and a nested `conduct --headless`/`spawn`
    re-acquires the ENCLOSING terminal's window — which is exactly what made
    the same-window eviction (below) treat an agent and its own headless
    grandchild as stale twins, and (via `reap`'s dedup pass, next bullet)
    then retire one of them.
  - `headless` deliberately overrides a stray non-empty `windowAddress`:
    it is a PERMANENT self-reported registration fact, not a live re-check,
    so a bug elsewhere that stamps a window onto a headless wrap's record
    still can't make `is_windowless_wrap` say otherwise.
- **The same-window eviction carve-out is the new record's WHOLE lineage,
  not just its direct parent (task #89).** `session_store::lineage_of`
  (ancestors + descendants, walking `parentSessionId`) is what
  `do_session_start_inner`'s registration-time eviction excludes from
  retirement — widened from "direct parent only" because a nested
  `conduct`/`spawn` chain can legitimately land a same-window pair that are
  grandparent/grandchild (or cousins through a shared ancestor), not direct
  parent/child. A genuine same-window twin with NO lineage relation (a
  compact/resume pair) still collapses instantly — don't widen the carve-out
  further than actual graph membership. `reap`'s own same-window dedup pass
  (`superseded_agent_duplicates`) carries the IDENTICAL `lineage_of`
  carve-out as defense in depth (review round 2) — a windowless-by-
  construction session never enters a same-window dedup group to begin
  with, but if the discovery gate or the listener self-check above ever
  regresses and lets one acquire a window anyway, `reap` still won't retire
  its own lineage. Both carve-outs must move together: widening or
  narrowing `lineage_of` changes both call sites at once, by construction —
  don't let one drift from the other with a hand-rolled duplicate.
- **`typed` is REFUSAL-based, never best-effort reconstruction (P-C5,
  durable-sessions plan) — the single most important invariant in this
  crate's restore capture.** Readline editing (arrow keys, `^R` history
  search, Tab completion, `^U`/`^W` kills) means the raw keystroke stream
  written into the pty master is NOT the shell's prompt buffer the moment
  any of it happens — a byte-for-byte replay would be WRONG, not merely
  lossy, and a silently wrong `typed` puts text the operator never composed
  one keystroke from running (a LATER phase preloads it into a resurrected
  terminal's own prompt). `conduct.rs::TypedLineBuffer::feed` POISONS the
  current line to `None` on any byte below `0x20` other than `\r`/`\n`
  (which submit-clear it instead), or `0x7f` — never attempts to interpret
  what the edit did. A line running past `TYPED_LINE_CAP` poisons for the
  same reason: a clipped line is wrong text, not a short one. **Bytes
  arriving over an INJECTION connection poison too (`feed_injected`), and
  that is a live finding, not caution:** `send` prefixes a delivered
  payload with its provenance, so the P-C7 soak captured a `typed` of
  `from quiet-birch (…1892): echo hello` — a line no human composed, which
  would not even run if preloaded. Don't restore the old "injection
  accumulates like stdin" reading; injected text reaching the same readline
  buffer is precisely why the line stops being reconstructable. `typed()`
  additionally refuses non-UTF-8 and an empty line. Don't widen the clear
  set past `\r`/`\n`, don't let overflow truncate instead of refusing, and
  don't try to make a poisoned line recoverable by inspecting WHICH control
  byte fired — the whole point is that `None` is a fully acceptable product
  of this capture and a guess is not.
- **`RestoreSnapshot.idle` is captured as its OWN field, never inferred
  from `state` (P-C5).** `reap.rs`'s sweep assigns `s.state = "done"`
  BEFORE calling `ledger_session_exit` — by the time the ledger line is
  written, the pre-exit idle/working state is already gone from `state`.
  `restore_snapshot` computes `idle` off the SAME `fg <= 0 || fg ==
  shell_pid` predicate `shell_snapshot` uses for `state`, but stores it
  independently, so a later reader (the ledger, and eventually a resurrect
  consumer) never has to reconstruct it from a field the reap path has
  already overwritten.
- **`proc_argv` and `proc_command` are deliberately two functions, never
  merged (P-C5).** `proc_command` is a DISPLAY label — it basename-
  collapses `argv[0]` and truncates at 48 chars — built for the roster's
  `activity` column. `proc_argv` is a re-exec CANDIDATE — raw, uncollapsed,
  unclipped `/proc/<pid>/cmdline` — built for `RestoreSnapshot.argv`, which
  a later phase re-execs. Reusing `proc_command` for `argv` would re-exec
  the wrong binary (a collapsed `argv[0]`) or a truncated one; don't share
  the two even though they both start from the same `/proc` read
  (`parse_cmdline` is the pure split they DO share).
- **Shell-likeness is derived from the WRAPPED COMMAND, never the display
  name (task #100, the P-C7 soak's live finding).** `session_conduct`'s
  `is_shell` — which gates the ENTIRE P-C5 refresh/capture path (cwd
  tracking, working/idle state, foreground argv, the restore snapshot, and
  `typed_capture_active`'s buffer below) — comes from `conduct.rs::
  captures_like_a_shell(&program)`: `program`'s own basename (what actually
  execs on the pty) against `bash`/`zsh`/`fish`/`sh`. It is NOT `agent ==
  "shell"` — `agent` is a caller-chosen label (`--agent <name>`, or the
  command's own basename by default) that can disagree with what is
  actually conducted on purpose (a soak harness, an experiment). `spawn
  --agent soak-a -- bash` is the exact live shape that broke under the old
  string compare: a real interactive shell whose roster record never
  ticked, because its label wasn't the literal string `"shell"` — marking
  it undying yielded a ledger entry with `restore: null`, so resurrect
  reopened nothing but a default cwd. Don't widen this back to a name
  compare "for simplicity" — a caller is always free to label a shell
  anything it likes, and the capture path must not depend on that choice.
  kitty.nix's own terminal wrapper needs no separate case: it always execs
  the resolved login shell explicitly as the conducted command, so its
  basename satisfies the predicate the same way any other shell invocation
  does. `undying.rs::nothing_to_restore_warning` is the mark-time corollary
  — see its own bullet below.
- **`typed_capture_active` gates the `TypedLineBuffer`'s existence, not just
  its output (P-C5).** A headless conduct never reads stdin at all
  (`read_stdin == false`, unconditionally — no controlling tty), so it has
  no typed line, ever; don't "helpfully" instantiate the buffer anyway and
  rely on `restore_snapshot`'s idle-gate to hide it — the buffer must not
  exist for a session that structurally cannot have a prompt to reconstruct.
- **A restored terminal's preloaded line NEVER runs itself (P-C6, durable-
  sessions plan) — the consumption-side twin of `typed`'s own capture-side
  refusal above, and this crate's single most important resurrect
  invariant.** `resurrect.rs::restore_delivery` hardcodes two branches, each
  building its OWN `session_send` flag map inline, and MUST NEVER be
  collapsed into one "deliver" helper parameterized by a `submit: bool`: the
  re-exec branch (a demonstrably RUNNING foreground command) carries `--yes
  --submit`; the preload branch (an idle session's clean `typed` line)
  carries `--yes` and PERMANENTLY omits `submit` from its flag map. A shared
  boolean parameter is exactly the shape that lets a later refactor add
  `--submit` to the preload branch by changing one call site's argument —
  don't introduce one. A stale `rm -rf` sitting in `typed` and firing itself
  at boot, unattended, is the failure this separation exists to prevent.
- **Restore delivery is SELF-ATTRIBUTED (`--from <new-id>`), and
  `send.rs`'s self-attribution rule delivers such bytes verbatim — both
  halves stay, together (P-C7 live finding #2).** `send` prefixes a
  delivered payload with `from <sender>: ` for attribution; restore rides
  `send`, so the live soak's resurrected re-exec arrived as `from
  quiet-birch (…1892): /run/…/sleep 900` — a bash syntax error — and the
  preload as a line no human typed. The fix keys off the ATTRIBUTED sender
  (`resolve_sender`, i.e. `--from`), never the gate's own sender identity
  (LANE IDENTITY P-ID2: a kernel-attested session, `graph/identity.rs::
  attested_sender` — the two are separate axes on purpose, module doc):
  restore is delivered from ANOTHER session's env, which is exactly how it
  got mis-prefixed. Removing the `from` flag from either
  `restore_delivery` branch, or the `attributed_to_target` suppression in
  `deliver_local`, silently reintroduces the corruption. Not a gate
  widening: `--from ""` (explicit anonymous) already skipped the prefix,
  and the audit line records the attributed sender either way.
- **A SHELL target's delivered bytes are ALSO always verbatim, for every
  sender, not only a self-attributed one (#116, the same "delivered bytes
  arrive verbatim" discipline the bullet above holds).** `deliver_local_with`
  gates the `provenance_prefix` call on `rec.agent` being neither `"shell"`
  nor empty (the same shell-shaped check `profile_for_agent`'s own fallback
  already treats as equivalent) — a shell has no concept of an attribution
  comment on its input; whatever reaches the socket is read as a COMMAND
  LINE, so `from <sender>: rm -rf /tmp/x` corrupts the command exactly like
  an unprefixed restore delivery would have. An AGENT target (any other
  `rec.agent`) keeps the prefix — a prompt is not a command line, and the
  agent benefits from seeing who sent it; don't widen this check to agents
  "for consistency." The audit line records the attributed sender
  regardless of target kind — this invariant only ever governs the bytes
  written to the socket.
- **The submit keystroke is a SEPARATE, LATER socket write, never
  concatenated onto the text payload (task #124, live-diagnosed on kimi
  0.31.1).** `send.rs::write_delivery` writes `payload` first, sleeps
  `SUBMIT_KEYSTROKE_DELAY`, then writes `submit_key` alone — a `\r`/`\n`
  arriving in the SAME pty write as preceding text is what kimi's TUI input
  parser paste-coalesces into a composer newline instead of Enter, leaving
  the prompt unsubmitted; a keystroke arriving as its own later write
  submits correctly. `conduct_multiplex`'s injection relay (`graph/
  conduct.rs`) already does one `read()`-then-pty-`write()` per `poll()`
  wakeup, so this needed no relay-side change — only the WRITER side had to
  stop concatenating. That relay shape is a timing argument, not a message
  boundary: SOCK_STREAM carries none, so a relay thread starved past the
  delay would read both writes back as one concatenated chunk — the delay
  IS what keeps the two writes distinct at the pty. Two callers pay it
  beyond the CLI: the a2a door's inject (per-connection thread, fine) and
  boot auto-resume's restore resubmits, which run serially before the
  daemon's tick loop starts — N undying resubmits delay reaper start by
  N×300ms, bounded and boot-once. `SUBMIT_KEYSTROKE_DELAY` (300ms) is empirically
  pinned, not guessed: a live windowed kimi session on this box reproduced
  the exact newline-not-submit failure at 120ms and submitted cleanly,
  twice, at 300ms — don't shrink it back down without repeating that live
  proof. Applied to EVERY profile, one code path, no per-agent branch: a
  separately-written `\n` is semantically identical to the old concatenated
  one for claude/pi, so this is a delay, not a behavior change, for either.
  Don't reintroduce `payload.push_str(submit_key)` before the write — that
  is the exact regression this invariant guards against.
- **A recorded foreground of `sudo …` is never re-exec'd (P-C6, orchestrator
  ruling on durable-sessions plan open knob 5).** `resurrect.rs::
  is_sudo_argv` is the one, narrow, named check — `argv[0]`'s basename
  exactly `sudo`, nothing cleverer (no `doas`/`pkexec` guessing, no argument
  inspection) — `restore_delivery` consults before ever building a re-exec
  invocation. Re-running a privileged command unattended at boot is not a
  restore: at best it hangs forever on a password prompt nobody is
  watching, at worst it silently re-runs something destructive. The cwd
  still restores; only the delivery is refused.
- **The terminal candidate arm is gated on `entry.restore.is_some()`, never
  on `agent == "shell"` (P-C6).** `resolve_candidate` tries the harness arm
  first (`AgentProfile.resume_args`, unchanged) and only falls to the
  terminal arm — `[<login shell>, "-l"]` via `login_shell` — when the
  harness arm found nothing AND a `restore` snapshot is present. A
  `restore`-less shell entry (predating P-C5) still hits the pre-existing
  taught skip; don't widen the gate to bare `agent == "shell"`, which would
  resolve a candidate this crate has no captured facts about.
- **`reap`'s one carve-out into the shell kind gate is `restore.is_some()` +
  `spawned` + `state == "idle"`, never `pid`-liveness alone
  (`abandoned_spawned_shells`, `reap.rs`).** The kind gate every other
  signal in `is_session_dead` respects exists because "a shell record's pid
  IS its terminal" — a live pid must never be overruled by staleness. That
  holds for a shell the operator opened, where a live pid means a human is
  (or may be) sitting at the window. It does not hold for a worker shell
  `aoide spawn` left running behind an agent: there the
  ONLY way anything ever reaches it again is the injection door
  (`aoide send`), which cannot tell an agent's own follow-up from a
  human's (`send.rs`'s own `resolve_sender` doc — attribution is
  self-reported and unenforced, never a trust boundary). So the touch
  signal is the per-session pty LOG FILE's mtime (`log_path`), not
  attribution: ANY byte crossing the pty — the spawned command's own
  output, or any later send from anyone — resets the clock, which is what
  keeps a human's later use of an agent-spawned terminal safe from this
  signal without ever needing to know who touched it. `restore.is_some()`
  (stamped only by the P-C5 tick, itself gated on
  `captures_like_a_shell`) keeps this from ever reaching a headless
  AGENT or a one-shot command — neither ever populates `restore`, so
  `log_mtime` structurally has nothing to read for them and the signal
  never fires. **A shell has no self-heal, unlike an agent** (whose hook
  door re-registers a falsely-reaped record on its next event) — this is
  why the carve-out stays this narrow, and why widening it needs the same
  bar this bullet documents, not a looser one.
- **Every conduct-owned pty tees to `state/sessions/<id>.log` (task #15,
  "everything tees" — no opt-out flag), through the ONE `open_session_log`
  open+stamp path `graph/conduct.rs::session_conduct` calls for both arms.**
  Three properties stay load-bearing if this is ever touched: (1) it tees
  the MASTER-READ side only — what the pty emits — never raw stdin, so a
  no-echo `sudo` password prompt never lands in the log; (2) a log write
  failure DEGRADES (`OutputSink::write_log` just stops mirroring) and must
  never block or kill the interactive pump, which is raw-mode and
  latency-sensitive; (3) the directory (`0700`) and file (`0600`) modes are
  set explicitly via `OpenOptionsExt`/`PermissionsExt`, never left to
  umask. Don't reintroduce a second open/stamp call site for either arm —
  headless and interactive both go through the one function.
- **Gate the sweep on `spawned`, never on `headless` and never on
  `parentSessionId`.** `headless` is the wrong axis: `spawn --windowed`
  execs a real terminal running the same `aoide conduct`, and a windowed
  worker terminal is abandoned exactly as readily as a headless one.
  `parentSessionId` is worse than wrong — `graph/doc.rs` clears a child's
  parent edge when the parent leaves the roster, so it is empty at
  precisely the moment a shell becomes leftover, and a predicate keyed on
  it would match only shells whose agent is still alive. `spawned` is
  stamped once by `stamp_spawned` inside the child `spawn` re-execs and
  never cleared, and `aoide spawn` is its only writer — which is what makes
  "an agent left this, the operator did not" decidable at all.
- **The abandoned-shell band is `REAP_SPAWNED_SHELL_STALE_SECS` (2 days) and
  stays its own constant.** Don't fold it back into `REAP_IDLE_STALE_SECS`
  to save a line: that band guards a session that might still be someone's
  and has to clear a weekend, while this one judges a terminal an agent
  created and walked away from, where being early costs an untracked shell
  that keeps running (no signal in `reap.rs` kills a process) and being late
  costs a roster full of worker terminals. The two move for different
  reasons and will keep diverging.
- **A human gesture waives that band, and is resolved AT THE DOOR
  (`with_human_gesture`), never inside the sweep.** `reap_and_announce`
  normalizes it onto the invocation as `--now` BEFORE `daemon_dispatch`,
  because a resident `aoided` runs the sweep over there with no tty and a
  `Door::Daemon` invocation: a `pick::interactive` probe made on the far
  side answers false for every gesture, and the dock button's behaviour
  would then depend on whether the daemon happened to be up. **The flag is
  the fact; the probe is only how the CLI door computes it** — a new caller
  that means the gesture passes `--now` itself (`shellbridge.rs`'s
  `dispatch_recheck_sessions` does, since a detached child has no tty to
  probe). Waiving drops ONLY the staleness clause: `spawned` +
  `restore.is_some()` + `state == "idle"` + `!exempt` all still hold, and no
  other band in the pass moves.
- **`exempt` (task #20) is filtered out of candidacy BEFORE the band
  question, in both `is_session_dead`'s third signal and
  `abandoned_spawned_shells`, so it survives `--now` structurally rather
  than as a special case inside either.** Don't implement it as "skip this
  id in the sweep loop" bolted on after the fact — the veto belongs inside
  the SAME predicates every other guard in this file lives in
  (`spawned_shell_shape` is the one shared shape both
  `abandoned_spawned_shells` and `spared_exempt_spawned_shells` read, so a
  record can never be both reaped and reported spared, or neither). It
  vetoes staleness ONLY: window-gone, pid-gone, pre-boot ghosts, superseded
  duplicates, orphaned subagents, and done-sibling tombstones all still fire
  on an exempt record, because those are positive-evidence signals, not
  staleness — the exemption's whole promise is "never take a LIVE session,"
  not "never take this id."
- **`--announce` is not a second spelling of `--now`.** It means "toast even
  on a quiet pass" — a display concern — and welding the two together would
  leave a caller that wants the answer without the sweeping-now no way to
  say so. Both flags happen to ride the dock button; that is the button's
  choice, not an implication.
- **The nothing-to-restore warning fires at MARK time, not at resurrect
  time (task #100).** `undying.rs::nothing_to_restore_warning(agent,
  has_capture)` mirrors `resolve_candidate`'s own two arms — a registered
  harness `AgentProfile.resume_args`, or `has_capture` (this session's own
  P-C5 restore snapshot, gated by `captures_like_a_shell` above) — and both
  mark sites (`spawn --undying`, `session grant undying on --id <id>`) append its
  text onto their own Outcome MESSAGE, never a log line, whenever NEITHER
  arm would resolve. `spawn --undying` computes `has_capture` directly off
  the command it just built (no roster read-back, no race against the
  conducted child's own first refresh tick); `session grant undying on` reads it
  off the LIVE roster record's `restore` field and stays silent for an id
  absent from the roster (no live signal to warn from — same posture `live`
  already takes) and for `off` (a future restore isn't promised either way,
  so there is nothing to warn about). Don't move this check to resurrect
  time "to simplify" — the whole point is the operator finds out BEFORE the
  undying set is relied on, not after a later resurrect silently restores
  nothing.
- **`hookAncestry` is stamped ONCE, at a hook session's own registration,
  never touched again.** `session_store::stamp_hook_ancestry` is the only
  writer (change-only: it refuses to overwrite an already-populated
  record) — a later `wrap`/`conduct`/`spawn` registration with no explicit
  `--parent` reads it via `window::ancestry_parent`/
  `resolve_registration_parent` to find its true launching agent by
  intersecting ITS OWN `/proc` ancestry against every live agent's
  `hookAncestry` (deepest/closest match wins), falling back to the ambient
  `AOIDE_SESSION_ID` env only when nothing intersects. Precedence is
  explicit `--parent` > ancestry walk > env, in that order, for all three of
  `wrap`/`conduct`/`spawn` (spawn re-execs `conduct --headless`, so fixing
  `conduct`'s own call covers it).
- **`who` and bare `session`'s old undying-picker meaning are BOTH retired
  (session-surface redesign, command-defrag lane X, 2026-08-28 — hard
  cutover, no alias).** Bare `session` is now the ROSTER (`who.rs`'s
  `session_roster`/`session_roster_with` — grouped by PROJECT bare, by HOST
  under `--hosts`), and the undying picker/mark live at `session grant
  undying` (`grant.rs`'s `session_grant`, dispatching on a positional
  `<kind>`). Don't reintroduce a standalone `who` registration or a bare
  `session` picker "for compatibility" — both spellings are unknown now,
  same as a typo; the mechanisms they backed (the roster's probe pipeline,
  the picker's row-building) survive unchanged, only the registered paths
  moved.
- **`session grant` has exactly one scripted spelling for the undying
  mark — `session grant undying on|off --id <id>` (U1, relocated).** Don't
  add a `--undying` flag or any other scripted shortcut anywhere else — a
  non-interactive reach to the picker branch (non-CLI door, no tty,
  `--json`) is ALWAYS steered to that one existing spelling
  (`grant.rs::require_cli_tty`), never given a second one of its own. Don't
  gate the picker on `Door::Cli` alone either — `pick::interactive` also
  requires a real stdin/stdout tty, and `--json` must refuse even ON a real
  tty (a picker's prompts have no business interleaving with a
  machine-readable stream a caller explicitly asked for). The scripted
  branch (`undying.rs::undying_grant`) carries NO such gate — unchanged
  from `session undying`'s own reach from any door, since a script/daemon
  needs it too.
- **`grant.rs`'s picker branch never live-probes a node.** Its node rows
  come from `node_store::load_node_cache` fed through `who.rs`'s
  `sessions_from_graph` (`pub(super)`, `SessionView` alongside it, U3). Don't
  route it through `who.rs::probe_nodes`/`collect_roster`'s live-pull path
  "for freshness" — the brief this landed under is explicit that the
  picker's own tty round-trip must never block on network I/O, and bare
  `session`/`--hosts` already own the live-presence job.
- **A node row's mark writes a `.aoide/project.json` spec, never
  `state/undying.json` (U3) — the id lives on the node, this conductor
  cannot write ITS store.** `grant.rs::apply_diff` resolves "current
  project" via `aoide_storage::manifest::walk_up` from cwd, the identical
  discovery `resurrect`'s own bare-manifest mode uses (U2); no manifest
  found there is NEVER a reason to create one — every node
  mark/unmark in that confirm reports `skipped[]` with a taught reason
  instead, while any LOCAL rows in the SAME confirm still apply normally.
  Don't fold the "no manifest" case into a hard command failure — a picker
  confirm can genuinely be half-local, half-node, and the local half's
  success must never be held hostage to the node half's missing manifest.
- **A node row's cwd that `node_spec_dir` cannot relativize under the
  project root has NO savable fallback — it is REJECTED before it ever
  reaches `manifest.sessions`, never the raw absolute cwd (review round 1,
  U3).** `save_manifest` refuses the WHOLE batch if ANY spec carries an
  absolute `dir`; a raw-cwd fallback here would therefore not merely write
  an inferior spec, it would silently fail the save for every OTHER
  legitimate node change queued in the SAME confirm while `changed[]` still
  reported them all as persisted (the exact defect this bullet's own review
  round caught). Don't reintroduce a `(dir, relativized)`-shaped fallback —
  `node_spec_dir` returns `Option<String>`, `None` means "no spec, skip
  with a taught reason," full stop. Correspondingly, `apply_diff`'s
  `changed[]` for the node path is populated ONLY after `save_manifest`
  returns `Ok` — a failed save folds every pending node change for that
  confirm into `skipped[]` instead, never a false `changed` entry for a
  write that never landed. `build_rows`' own node pre-check goes through
  the SAME `node_spec_dir` relativization for the identical reason: a raw
  cwd compared straight against a manifest spec's (always project-relative)
  `dir` can never match, which would silently show an already-undying node
  session as unmarked.
- **Unmarking a node row removes EVERY spec matching `{host, dir, agent}`,
  not just the first (`Vec::retain`, never a single `Vec::remove` by
  position).** A hand-duplicated entry in `.aoide/project.json` (an
  operator who edited the file directly) is cleaned up in one unmark, not
  one confirm per copy — don't narrow this back to a first-match removal.
- **The roster (`who.rs`, reached at bare `session`/`--hosts`) is a
  projection, never a store.** It must never write
  `state/node-cache/<name>.json` — `build_graph`'s own fold (`doc.rs`) is
  the ONLY writer of that cache. Its live probe reads straight off the
  network via `aoide_client::commands::pull_node_live` and falls back to
  the cache (read-only) for an unreachable node; don't "helpfully" have a
  successful live probe refresh the cache as a side effect.
- **`session --hosts`'s and bare `session`'s PROJECT grouping share ONE
  `collect_roster` — never two collection passes.** `who.rs`'s `Roster`
  struct (`host`, `projects`, `locals`, `nodes`) is built ONCE per
  invocation; `session_roster_with` branches ONLY on how it renders/groups
  `nodes` afterward (`render_nodes`/`node_json` for `--hosts`,
  `group_by_project`/`render_groups`/`group_json` otherwise). Don't
  duplicate the local-stage-load + node-probe sequence for a future
  grouping — extend the branch, not the collection.
- **`project_bucket` reuses whichever project attribution the codebase
  already computes — never a third one.** A registered `projects.json`
  name via `anchor_for` (pure string matching — works identically for a
  node session's cwd under the fleet's shared-path convention) wins; else a
  `.aoide/project.json` manifest found by walking up FROM THE SESSION'S OWN
  CWD on this host's own filesystem (`aoide_storage::manifest::walk_up`)
  renders by that directory's basename. Don't walk up from the CURRENT
  process's cwd instead (that's `grant.rs`'s "current project" concept, a
  different thing) — `project_bucket` must attribute EVERY session by its
  OWN cwd, local or node, or a multi-session listing would silently
  misattribute every session but the first.
- **A project is a set of anchor roots — `anchor_for` is longest-root-wins
  across EVERY root of EVERY project, not just each project's first.**
  `cwd_under` itself stays single-root (unchanged) and is simply called
  once per root; only its caller spans the set. `project add NAME PATH…`
  ADDS one or more roots to a name — registering it if new, growing it if
  not — and never replaces what is already there; `--new` is the guard
  against a typo'd name silently joining an existing project instead of
  registering its own. `project edit NAME PATH…` is the ONLY command that
  REPLACES a project's whole root list outright (first path → `path`, rest
  → `roots`); it never touches the name or `autoResume` — `add`/`remove`
  stay the only ways a project appears or disappears. `project remove NAME
  [PATH]` drops one root, promoting the next remaining one into `path` so
  `path` always equals the first root, or with no `PATH` drops the whole
  project (unchanged behaviour). `project add` and `project edit` both
  validate EVERY given path (absolute, an existing directory) BEFORE
  mutating anything — one bad path in a multi-path call writes nothing.
- **`node list` (`graph/node_list.rs`, task #120 P2) is the roster core's
  probe under a wider fold — never a fork of it.** Its presence/session data
  comes ONLY from `who.rs`'s `pub(super)` seam (`probe_nodes`/
  `build_local_node`/`build_node_node`/`SessionView`/
  `NODE_PROBE_TIMEOUT_SECS`) and its advertising data ONLY from
  `aoide_client::discover::run_sweep` — a second prober, a second presence
  classifier, or a private sweep re-implementation here is the exact
  cross-copy this crate's discipline forbids. It inherits the roster's
  projection rule wholesale (writes nothing: not `state/nodes.json`, not
  `state/node-cache/`), a failed/empty sweep only ANNOTATES the roster
  (never fails the command — the paired half is still true), and both
  network seams (`PullFn`, `SweepFn`) stay injected so its tests never
  open a socket. Row/mark grammar and `--json` shape are CONTRACTS.md
  §7-pinned — a rendering change is a contract edit first.
- **`send::deliver_local`'s success path is ONE of exactly TWO mailbase-filing
  calls reached through `session_send` — never add a second one on that
  path.** Every consumer that delivers into an ALREADY-REGISTERED session's
  socket (`send --id`, `--to` resolving local, `pending approve`'s
  re-drive, `aoide-server`'s A2A `do_inject`) reaches it through
  `session_send`; do NOT add a second `aoide_storage::mail::file_receipt`
  call for any of those — `do_inject` in particular reaches this exact
  function too, so a call there would double-file every A2A message
  delivered into an existing session. The OTHER of these two lives OUTSIDE
  this crate, in `aoide-server`'s `spawn_inject_prompt` (`a2a.rs`) — a
  brand-new A2A-spawned session's first turn is typed before that session
  has a `SessionRecord` at all, so it can never reach
  `deliver_local`/`session_send` and has to file itself (see
  `aoide_storage::mail`'s module doc for the full two-writer reasoning).
  **A THIRD, orthogonal filing call exists since P-M2** — `aoide-server`'s
  `mail_deposit` (`a2a.rs`) calls `aoide_storage::mail::deposit` directly
  for a letter/receipt arriving over the wire FROM a peer node. It never
  touches `session_send`/`deliver_local` (there is no local session on
  either end of that path), so it does not widen this bullet's "exactly
  two, never a second" rule — that rule is scoped to `session_send`'s own
  callers, and wire-deposited mail was never one of them.
- **The doorbell's `.ring.lock` is never `.stage.lock`, and it is the
  ONLY lock this crate ever holds across real socket I/O** (P-M5a-2,
  `graph::doorbell`). `with_ring_lock` and `try_stage_lock` are separate
  files for exactly that reason — the stage lock's every other holder
  only ever does a brief in-memory read-modify-write, and a ring's own
  socket connect, write, and submit-keystroke delay must never make one
  of those wait. Don't fold them into one lock, and don't add a second
  socket-holding critical section under `.stage.lock`. It is the
  daemon's own serializer for concurrent rings, not a second policy
  boundary — see the next bullet for the actual boundary.
- **A ring executes only under `Door::Daemon`** (P-M5a-2c, the
  architecture owner's ruling on b8af466): the resident daemon is the
  policy and audit boundary for every ring, not `.ring.lock`. `ring`
  itself has exactly two callers — `mail_ring`'s own `Door::Daemon` arm,
  and the Stop-hook replay when that hook is likewise being handled
  under `Door::Daemon` — and every other door forwards through
  `aoide_client::daemon::daemon_dispatch` instead of calling it. Do not
  add a third caller of `ring` outside those two; a door that needs to
  ring forwards, it never links around the daemon.
- **A ring only ever stamps its latch (`stamp_rung`) AFTER a socket write
  that returned `Ok`, never before and never on a write failure.** The
  reader stays armed on any failure — unreachable socket, dead process,
  a transient write error — so a target that misses one nudge is still
  caught by the next trigger. Do not reorder the stamp ahead of the
  write, and do not stamp inside a `Result`-discarding path that can't
  tell success from failure.
- **A ring never writes to a non-headless (interactive) wrap, full stop
  — there is no override flag, no `--force`.** An interactive composer is
  someone's own terminal; auto-submitting into it needs a control-layer
  guard that does not exist yet (P-M5a-3, the labeled residual
  `docs/architecture/MAIL.md` "Delivery and the doorbell" leaves open).
  Don't lift this check without landing that guard first, and update
  MAIL.md's doorbell section in the same commit that does.
- **A ring's readiness signal is the CHILD's hook state, checked with
  `aoide_protocol::agents::agent_profile` (returns `None` for an
  unrecognized harness) — never `profile_for_agent` (its `CLAUDE_PROFILE`
  fallback always succeeds and would hide the "never hooked" signal a
  ring needs).** And the keystroke a ring submits with is the CHILD's own
  harness key, never the wrap's — a `kimi` child under a `claude` wrap
  submits with `\r`, not `\n`.
- **The Stop-hook ring replay (`graph/send.rs`) is best-effort and never
  changes the hook's own outcome.** It runs after the hook's real work is
  already decided, discards its `Result`, and never turns a successful
  Stop hook into a reported failure just because a deferred ring's socket
  write failed.
- **The Stop-hook ring replay never rings on the no-daemon local path**
  (P-M5a-2c): `session_hook` gates the replay on `inv.door ==
  Door::Daemon`, threaded down as a single `may_ring` boolean, never a
  global, thread-local, or env var. When the hook cannot reach a daemon
  and falls back to handling itself locally, the replay is skipped
  outright — not attempted and swallowed — and every name still armed
  for that reader stays armed for the next daemon-handled trigger. The
  hook's own `Outcome` is identical either way; only the replay is
  gated.
- **`doorbell.rs` changes update `docs/architecture/MAIL.md`'s "Delivery
  and the doorbell" section in the same commit** (house rule 8) — that
  section is the design's canonical prose statement; this file states
  only the invariants an editor must hold while changing the code.
- **`graph/spawn.rs`'s `build_conduct_args` is the ONE place the `aoide
  conduct -- <agent cmd>` argv gets built (P-D7).** Both `spawn`
  launch modes — headless (default) and `--windowed` (execs a real terminal
  from `$AOIDE_TERMINAL` instead of detaching) — call it, `--headless`
  aside; do NOT hand-roll a second argv builder for the windowed path, or
  registration/the control socket/the parent-autogate lane can drift
  between the two modes. `build_terminal_argv` (the `$AOIDE_TERMINAL`
  template parser) is a PURE function on purpose — no env read, no spawn —
  so it stays directly unit-testable; do the env reads (`terminal_template`/
  `require_display`) in the thin callers around it, never inside it.
- **`SessionRecord.origin` is a PERMANENT birth fact stamped ONCE per
  record, the same discipline `headless`/`hookAncestry` already hold
  (P-P3, `docs/architecture/PAIRING.md` decision 7) — never re-derived
  later. Write AUTHORITY is split by SHAPE, not by caller count, tightened
  at LANE IDENTITY P-ID0 (G16/G5, review round 1).**
  `session_store.rs::stamp_origin` is `pub` (crosses the crate boundary)
  and is the ONE writer function, with THREE call sites today — but the
  invariant that matters is narrower than "exactly two callers": **a
  `node:*` shape may be stamped from exactly ONE place, `aoide-server`'s
  `a2a::do_spawn` (`stamp_spawn_origin`)**, called DIRECTLY on the
  just-spawned record — polling for the record's registration the same way
  `spawn_inject_prompt` already does — from the door where the node name IS
  authenticated. Every OTHER call site may stamp a LOCAL-CLASS value but
  MUST refuse a `node:*` shape, because neither has a door behind it:
  `graph/conduct.rs::session_conduct` reads its own inherited
  `AOIDE_SESSION_ORIGIN` env (a same-uid process can set that on itself
  before invoking `aoide conduct` directly) and `graph/
  resurrect.rs::origin_to_carry` reads a revived session's OWN ledger entry
  back (`state/session-ledger.jsonl` is a plain, same-uid-writable,
  append-only file — a same-uid process can append a line claiming
  `origin:"node:X"` and then run the ungated local `aoide resurrect`,
  which likewise has no door behind it). Both REFUSE (eprintln, never
  panic) a `node:*` value from their own untrusted source instead of
  stamping it. **A future third-plus call site is fine as long as it holds
  this same refusal** — the invariant is "node:* only from an authenticated
  door", never "count the callers". No `restage_graph()` — like `headless`,
  `origin` is consumed internally (`doc.rs::ledger_session_exit`'s
  projection into the durable ledger, and `origin_to_carry` reading that
  field back to carry a LOCAL-class session's provenance forward onto its
  revived record — G6, same phase, `node:*` excluded per above), not
  rendered into `graph.json`. **This closes the STAMP paths, not the
  files**: a hand-crafted `sessions.json`/ledger line claiming `node:X` is
  still a readable, unflagged string on disk — nothing here makes the files
  tamper-evident; that is P-ID1 (the daemon-signed credential, below) —
  minted and stored, verified on the per-session control socket's own
  accept and consumed by the send gate as of P-ID2, and both remaining
  sockets get a peercred floor of their own as of P-ID3 (below).
  **The raw `origin` field is attribution, not an
  authenticated credential** — a same-uid process can still forge a
  LOCAL-class origin (`stamp_origin` trusts whatever non-`node:*` value it
  is given). Don't let a consumer gate a security decision on the raw
  field: the authenticated form is the sealed credential (below), and the
  secrets broker's origin gate (P-ID4) is the model consumer — it gates on
  `originClass` read off a VERIFIED seal, never the raw `origin` field.
  The consumer NAME presenting a request stays unauthenticated either way
  (a separate, unbuilt axis — CONTRACTS.md's identity-lane accounting).
  What P-ID0 closes is narrower and real: every
  record-STAMP path this codebase drives now refuses a `node:*` shape it
  didn't mint itself at the door — env AND the unsealed ledger both.
- **`SessionRecord.seal`/`sealedIssuedAt` are STAMPED from `aoide-server`
  only, but VERIFIED from inside this crate (LANE IDENTITY P-ID1/P-ID2).**
  `session_store.rs::stamp_seal` is `pub` (crosses the crate boundary) the
  same way `stamp_origin` does, but unlike `origin` it has no local-class
  call site in `conduct.rs` at all — the seal's signing key
  (`aoide_storage::identity::mint_ephemeral`) lives only in the DAEMON
  process's memory (OQ1-A) and this crate has no access to it, so both
  legitimate callers (the `dispatch` handler's `session start` path, and
  the daemon's own tick-driven sweep for directly-registered sessions) live
  in `aoide-server`. Don't add a `stamp_seal` call site in this crate "for
  symmetry with `stamp_origin`" — there is no key to sign with here.
  VERIFYING, by contrast, needs only the PUBLIC key (never secret,
  `aoide_client::daemon::daemon_seal_pubkey_hex` fetches it fresh over
  `ping`) — that half's SEAMS live here, but as of LANE IDENTITY P-ID4
  their BODIES live in `aoide_storage::attest` (the secrets broker's
  origin gate needs the identical walk/verify and `aoide-secrets` cannot
  depend on this crate — that module's doc has the full DAG argument):
  `graph/identity.rs::verify_seal_over`, `attested_sender`, and
  `window.rs::pid_ancestry`/`pid_starttime` are thin delegates keeping
  every `crate::graph` call site and test unchanged. Edit the body in
  `aoide-storage::attest`, never regrow one in a delegate here.
  `graph/send.rs`'s gate and `graph/conduct.rs`'s accept loop are the two
  consumers in this crate — see each file's own module doc.
- **`identity::peer_cred`/`PeerCred` are `pub(crate)`, not `pub(in
  crate::graph)` (LANE IDENTITY P-ID3) — `shellbridge.rs` reuses them
  directly.** Widened once, for exactly the reason `graph.rs`'s own `mod
  identity` doc comment gives: a sibling module reusing the SAME kernel-
  truth primitive beats a second `SO_PEERCRED` read in this crate. Do not
  widen further to plain `pub` "for convenience" — this stays an internal
  primitive, never crossing the `aoide-conduct` -> `aoide` crate boundary
  root's shim re-exports onward; `aoide-server` reuses `aoide_secrets::
  peercred` instead (already `pub`, already a dependency) rather than
  reaching into this crate for it, the same "small local reimplementation
  over a one-fn cross-crate edge" discipline `identity.rs`'s own module doc
  states for its relationship to `aoide-secrets::peercred`. **The cross-uid
  floor on shellbridge/`aoided` (`cross_uid_gate` in each file, pure,
  unit-tested without a real different-uid connection) does NOT stop a
  same-uid attacker** — every legitimate connector on both sockets already
  shares the operator's own uid under OQ1-A. Do not add a same-uid
  restriction to shellbridge's verdict door in this crate to "finish the
  job": the legitimate verdict caller is the desktop QML process, which is
  NOT part of any agent session's ancestry, so an ancestry-shaped floor
  would refuse the real caller, not just an attacker — this residual is
  documented, not silently left, in `CONTRACTS.md`'s identity section.
  `send.rs`'s own gate (`real_attested_sender`) stays untouched by this
  phase — a request dispatched through `aoided`'s socket (or injected
  through `a2a serve`) resolves the GATE against whichever process is
  actually running `deliver_local`, which is the daemon's/`a2a serve`'s own
  ancestry, not the original caller's; don't "fix" this by threading a
  peercred pid into `send.rs` without opening that as its own scoped phase
  — P-ID3 closed only the ATTRIBUTION half of that gap (`aoided`'s
  `invocation_from_dispatch_request` and `a2a::do_inject` both stamp an
  absent `from` explicit-empty rather than let it fall through to their own
  process's ambient `AOIDE_SESSION_ID`), not the gate's own identity
  resolution.
- **Conductability is `is_conductable_now` (`doc.rs`: the stored flag AND
  the socket file's own existence on disk) at every reporting AND acting
  boundary, never the stored flag echoed verbatim.** `build_graph`'s
  `conductable` node field derives it at read time (`graph`'s JSON/tree,
  `resolve_graph_document`'s federation wire response); `send.rs`'s own
  gate (`deliver_local_with`) calls the SAME function before ever dialing
  a socket, so a caller never acts on a staler answer than a reporter
  would give. The STORED `SessionRecord.conductable` is a permanent fact
  about a session's NATURE — it IS a conducted PTY wrap — and
  `window.rs`/`reap.rs` classification (`is_agent_kind`, the lineage
  checks) keeps reading that field directly; a session does not stop
  being a conducted wrap just because its socket briefly vanished, so
  don't migrate or clear the stored field to "fix" a stale report.
  `shellbridge.service` owns `$XDG_RUNTIME_DIR/aoide` with
  `RuntimeDirectoryPreserve=yes` (`modules/nucleus/shellbridge.nix`), so
  an ordinary service restart no longer deletes a live session's socket
  file out from under it — but the on-disk check stays regardless,
  because a socket file can still outlive or predate its process (a
  crashed wrap, a record restored from stage, a runtime directory
  cleared at logout): liveness is judged at every boundary, never from
  the stored flag or a remembered path alone. A missing or empty socket
  path is not-conductable.
- **`mail_bridge` carries NO logic of its own — it stays two passthrough
  functions, forever (P-M2, ruling 1).** It exists only because
  `aoide-server` may not carry a production `aoide-client` dependency
  while this crate already does; growing a real decision, retry policy, or
  new drain shape inside `mail_bridge` itself — rather than in
  `aoide_client::mail_wire`, which owns the actual drain — would leave two
  crates each partially responsible for one behavior. A change to WHEN or
  HOW a node's outbox drains belongs in `mail_wire`; a change to WHICH
  crates may reach it does not belong here either — that is the manifest's
  job. Don't add a third function to this module without first checking
  whether it truly cannot be `mail_wire::drain_node`/`drain_all` called
  directly.

## Extension points

- **`resurrect` writes exactly ONE audit line per invocation
  (`audit_resurrect`, U2) — never zero, never one per candidate/spec.**
  Every return past a pure usage/stage-file miss (an unresolved project
  name, an unresolved `--id`, an empty selection, the final per-candidate
  or per-spec loop outcome, in either mode) calls it once; a pure
  `require_flag`/`stage_error` early exit does not, the same posture
  `send.rs`'s `audit_send`/`pending.rs`'s `audit_pending` already hold
  toward their own early exits. The gate-6 finding this closes: an empty
  bare-mode selection used to return before ever reaching an audit call at
  all — don't reintroduce a return path between "a real decision was made"
  and the `audit_resurrect` call that reports it.
- **A new `graph`/`conduct`/`hooks` command** adds a `cmd!`/`register` entry in
  `commands/`, wired into `cli`'s `commands::all()` (this crate's commands are
  core, never `lyra`'s).
- **A new `session grant` kind** (`exempt`, task #20, is the second one
  landed after `undying`; #127's secret grants are the next one named, not
  yet built) adds one `match` arm in `grant.rs::session_grant` — no new
  registered path, no `commands/` entry: `<kind>` is a positional argument
  on the ONE `["session", "grant"]` path, `secrets automate <name> on|off`
  style. A picker is OPT-IN, not mandatory — `exempt` has none at all (bare
  `session grant exempt` is a taught refusal naming the scripted form
  directly, since its caller is a script, not a tty session). If a new kind
  DOES want a picker, reuse `grant.rs::require_cli_tty`'s CLI+tty gate shape
  rather than re-deriving it — there is still only one multi-select
  primitive (`aoide_protocol::pick::choose_many`) in this crate.
- **A new hook event or harness profile** extends `aoide_protocol::agents`,
  not this crate — the harness-profile table lives one layer down.

## Docs update required in the same commit

- This `README.md` when a public module, seam, or charter-smudge reasoning
  changes.
- `CONTRACTS.md` when a graph/session wire shape changes.
- `pkgs/aoide/crates/AGENTS.md` for cross-crate invariants — not restated
  here.
- `doorbell.rs` changes update `docs/architecture/MAIL.md`'s "Delivery and
  the doorbell" section — that document is the design's canonical prose
  statement, this file only the invariants an editor must hold.
- A change to shellbridge's `sessionaction` whitelist or reply shape
  updates `ShellBridge.qml`'s protocol comment and
  `concepts/cli/Doors-and-Nodes.md`'s socket-command list, in the same
  commit.
