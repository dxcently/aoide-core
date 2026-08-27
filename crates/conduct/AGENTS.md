# AGENTS.md — aoide-conduct

## Invariants

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
- **`normalize_addr` is `pub`, not `pub(crate)`, on purpose** — `screen`
  reaches it directly rather than duplicating it. Don't narrow it back
  without checking that dependency first.
- **`commands::hooks::skill_source` is `pub`, not `pub(crate)`, on purpose**
  (P-I2, ONBOARD.md decision 10) — `aoide-cli`'s `onboard` reaches it
  directly for its from-a-checkout refusal (the only repo-root detector in
  the tree) rather than re-deriving the walk-up. Don't narrow it back
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
  pid/port probe would say. **The two are NOT symmetric about the stage
  lock, on purpose.** `sweep_orphan_sockets` runs entirely inside
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
  that never got to run that exit path. A new leaving-kind under this same
  runtime directory joins the sweep the same way — never a separate cleanup
  mechanism.
- **Every session-write handler routes through `aoide_client::daemon::
  daemon_dispatch(inv)` FIRST, as its own first line, falling back to its
  pre-existing direct stage-write path byte-identically on `None` (P-D6,
  `docs/architecture/AOIDED.md`'s "L4").** `session start/phase/end`,
  `session hook`, and `reap::reap_and_announce` all follow this exact
  one-line prefix. A new session-write handler joins the family the same
  way — see `client`'s own `AGENTS.md` extension-point note. **`graph/
  undying.rs`'s `session_undying`, `graph/spawn.rs`'s `--undying` mark, and
  `graph/resurrect.rs`'s undying transfer are a deliberate exception, not an
  oversight:** `state/undying.json` is not a `state/stage/` file, so none of
  the three has L4 residency to route through — don't add a `daemon_dispatch`
  prefix to any of them "for consistency" with the family above; that would
  put an extra writer on a file the undying store's own atomic-write CRUD
  already lets multiple call sites share safely (each call is load-mutate-
  save on the whole set, never a partial write).
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
  `state/peers.json` by peer NICKNAME (the same nickname U3's picker writes
  a spec's `host` as), refuses LOCALLY into `failed[]` — never `skipped[]`
  — for an unregistered peer, a registered-but-unverified one (mirrors
  `aoide-client::commands::handle_peer_spawn`'s own local gate: an unsigned
  request can never satisfy the remote door's `Signature`-rung spawn gate),
  or nothing to summon with (`summon_text` returns `None`), THEN calls
  `aoide_client::commands::spawn_on_peer` — never re-implement that wire
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
  never reach this call: the resurrected id lives on the peer, and
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
  (`resolve_sender`, i.e. `--from`), never the gate's env-resolved
  `is_self_send`: restore is delivered from ANOTHER session's env, which is
  exactly how it got mis-prefixed. Removing the `from` flag from either
  `restore_delivery` branch, or the `attributed_to_target` suppression in
  `deliver_local`, silently reintroduces the corruption. Not a gate
  widening: `--from ""` (explicit anonymous) already skipped the prefix,
  and the audit line records the attributed sender either way.
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
- **The nothing-to-restore warning fires at MARK time, not at resurrect
  time (task #100).** `undying.rs::nothing_to_restore_warning(agent,
  has_capture)` mirrors `resolve_candidate`'s own two arms — a registered
  harness `AgentProfile.resume_args`, or `has_capture` (this session's own
  P-C5 restore snapshot, gated by `captures_like_a_shell` above) — and both
  mark sites (`spawn --undying`, `session undying on --id <id>`) append its
  text onto their own Outcome MESSAGE, never a log line, whenever NEITHER
  arm would resolve. `spawn --undying` computes `has_capture` directly off
  the command it just built (no roster read-back, no race against the
  conducted child's own first refresh tick); `session undying on` reads it
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
- **Bare `session` is the undying PICKER, and there is exactly one scripted
  spelling for the mark — `session undying on|off --id <id>` (U1).** Don't
  add a `--undying` flag or any other scripted shortcut to bare `session`'s
  own registration — a non-interactive reach (non-CLI door, no tty,
  `--json`) is ALWAYS steered to that one existing spelling
  (`session_pick.rs::require_cli_tty`), never given a second one of its
  own. Don't gate the picker on `Door::Cli` alone either — `pick::
  interactive` also requires a real stdin/stdout tty, and `--json` must
  refuse even ON a real tty (a picker's prompts have no business
  interleaving with a machine-readable stream a caller explicitly asked
  for).
- **`session_pick.rs` never live-probes a peer.** Its peer rows come from
  `peer_store::load_peer_cache` fed through `who.rs`'s `sessions_from_graph`
  (widened `pub(super)`, `SessionView` alongside it, U3) — the SAME
  cache `send --to peer/<query>` resolves against. Don't route it through
  `who::probe_peers`/`who_with`'s live-pull path "for freshness" — the
  brief this landed under is explicit that the picker's own tty round-trip
  must never block on network I/O, and `who`/`who --all` already own the
  live-presence job.
- **A peer row's mark writes a `.aoide/project.json` spec, never
  `state/undying.json` (U3) — the id lives on the peer, this conductor
  cannot write ITS store.** `session_pick.rs::apply_diff` resolves "current
  project" via `aoide_storage::manifest::walk_up` from cwd, the identical
  discovery `resurrect`'s own bare-manifest mode uses (U2); no manifest
  found there is NEVER a reason to create one — every peer
  mark/unmark in that confirm reports `skipped[]` with a taught reason
  instead, while any LOCAL rows in the SAME confirm still apply normally.
  Don't fold the "no manifest" case into a hard command failure — a picker
  confirm can genuinely be half-local, half-peer, and the local half's
  success must never be held hostage to the peer half's missing manifest.
- **A peer row's cwd that `peer_spec_dir` cannot relativize under the
  project root has NO savable fallback — it is REJECTED before it ever
  reaches `manifest.sessions`, never the raw absolute cwd (review round 1,
  U3).** `save_manifest` refuses the WHOLE batch if ANY spec carries an
  absolute `dir`; a raw-cwd fallback here would therefore not merely write
  an inferior spec, it would silently fail the save for every OTHER
  legitimate peer change queued in the SAME confirm while `changed[]` still
  reported them all as persisted (the exact defect this bullet's own review
  round caught). Don't reintroduce a `(dir, relativized)`-shaped fallback —
  `peer_spec_dir` returns `Option<String>`, `None` means "no spec, skip
  with a taught reason," full stop. Correspondingly, `apply_diff`'s
  `changed[]` for the peer path is populated ONLY after `save_manifest`
  returns `Ok` — a failed save folds every pending peer change for that
  confirm into `skipped[]` instead, never a false `changed` entry for a
  write that never landed. `build_rows`' own peer pre-check goes through
  the SAME `peer_spec_dir` relativization for the identical reason: a raw
  cwd compared straight against a manifest spec's (always project-relative)
  `dir` can never match, which would silently show an already-undying peer
  session as unmarked.
- **Unmarking a peer row removes EVERY spec matching `{host, dir, agent}`,
  not just the first (`Vec::retain`, never a single `Vec::remove` by
  position).** A hand-duplicated entry in `.aoide/project.json` (an
  operator who edited the file directly) is cleaned up in one unmark, not
  one confirm per copy — don't narrow this back to a first-match removal.
- **`who` is a projection, never a store.** It must never write
  `state/peer-cache/<name>.json` — `build_graph`'s own fold (`doc.rs`) is
  the ONLY writer of that cache. `who`'s live probe reads straight off the
  network via `aoide_client::commands::pull_peer_live` and falls back to
  the cache (read-only) for an unreachable peer; don't "helpfully" have a
  successful live probe refresh the cache as a side effect.
- **`send::deliver_local`'s success path is ONE of exactly TWO inbox-filing
  calls in the whole tree — never a third.** Every consumer that delivers
  into an ALREADY-REGISTERED session's socket (`send --id`, `--to`
  resolving local, `pending approve`'s re-drive, `aoide-server`'s A2A
  `do_inject`) reaches it through `session_send`; do NOT add a second
  `aoide_storage::inbox::receive` call for any of those — `do_inject` in
  particular reaches this exact function too, so a call there would
  double-file every A2A message delivered into an existing session. The
  OTHER filing call lives OUTSIDE this crate, in `aoide-server`'s
  `spawn_inject_prompt` (`a2a.rs`) — a brand-new A2A-spawned session's first
  turn is typed before that session has a `SessionRecord` at all, so it
  can never reach `deliver_local`/`session_send` and has to file itself
  (see `aoide_storage::inbox`'s module doc for the full two-writer
  reasoning).
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
- **`SessionRecord.origin` is a PERMANENT birth fact stamped ONCE, the same
  discipline `headless`/`hookAncestry` already hold (P-P3, `docs/
  architecture/PAIRING.md` decision 7) — never re-derived or re-stamped
  later.** `session_store.rs::stamp_origin` is the one writer;
  `graph/conduct.rs::session_conduct` calls it right after
  `do_session_start`, reading `AOIDE_SESSION_ORIGIN` off the process env —
  this crate has no dependency on `aoide-server` and cannot see the A2A
  door directly, so the env var IS the seam (mirrors how `AOIDE_AUDIT_LOG`
  already threads a per-child fact from a spawning process into a
  `conduct` child). No `restage_graph()` — like `headless`, `origin` is
  consumed internally (`doc.rs::ledger_session_exit`'s projection into the
  durable ledger), not rendered into `graph.json`. **`origin` is
  attribution, not authentication** — `stamp_origin` trusts whatever
  `AOIDE_SESSION_ORIGIN` says, and any same-uid process can set that var
  before running `aoide conduct` and forge `"peer:X"` with no door
  involved at all; don't let a future consumer gate a decision on it
  without first upgrading it to an authenticated channel (task #63's
  lane) — it is exactly as spoofable as `--from`/`AOIDE_SESSION_ID`
  already are.

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
- **A new hook event or harness profile** extends `aoide_protocol::agents`,
  not this crate — the harness-profile table lives one layer down.

## Docs update required in the same commit

- This `README.md` when a public module, seam, or charter-smudge reasoning
  changes.
- `CONTRACTS.md` when a graph/session wire shape changes.
- `pkgs/aoide/crates/AGENTS.md` for cross-crate invariants — not restated
  here.
