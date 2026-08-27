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
  ~12s systemd timer's own `graph reap` becomes a redundant backstop, never
  a third mechanism.
- **Every session-write handler routes through `aoide_client::daemon::
  daemon_dispatch(inv)` FIRST, as its own first line, falling back to its
  pre-existing direct stage-write path byte-identically on `None` (P-D6,
  `docs/architecture/AOIDED.md`'s "L4").** `graph session start/phase/end`,
  `graph session hook`, and `reap::reap_and_announce` all follow this exact
  one-line prefix. A new session-write handler joins the family the same
  way — see `client`'s own `AGENTS.md` extension-point note. **`graph/
  carry.rs`'s `session_carry`, `graph/spawn.rs`'s `--carry` mark, and
  `graph/resurrect.rs`'s carry transfer are a deliberate exception, not an
  oversight:** `state/carry.json` is not a `song/stage/` file, so none of the
  three has L4 residency to route through — don't add a `daemon_dispatch`
  prefix to any of them "for consistency" with the family above; that would
  put an extra writer on a file the carry store's own atomic-write CRUD
  already lets multiple call sites share safely (each call is load-mutate-
  save on the whole set, never a partial write).
- **The carry transfer is one `save_carry` call, never two.** `resurrect.rs`'s
  `resurrect_one` adds the new id and drops the old one in the SAME
  in-memory `Vec<CarriedSession>` before writing — the new id goes in first,
  so a crash between the in-memory edit and the write leaves the OLD id
  carried (the next sweep retries it) rather than leaving neither carried
  (silent loss). The transfer only fires when the old id was actually
  carried (`is_carried` gates it) and only when the spawn reached
  `Status::Ok` — an ordinary `--all`/`--id` revive of an uncarried session
  must never start carrying it, and a failed spawn must leave the old id
  exactly as it was. Don't split the add and the drop across two
  `save_carry` calls, and don't drop the check that the old id was carried.
- **Bare `graph resurrect --project` selects the carried set, not a single
  "most recent" entry (P-C4, durable-sessions plan).** `resurrect.rs`'s
  `carried_selection` is the one place that reads `sessions.json` for
  liveness — the daemon's boot sweep (`aoide-server`'s `daemon.rs`) no
  longer runs its own liveness check before calling `session_resurrect`; it
  calls unconditionally for every `autoResume` project and relies on this
  function to drop already-alive ids per candidate. Don't reintroduce a
  project-wide liveness gate in the daemon loop — a multi-session carried
  set needs the exclusion done per id, not per project, or one live
  terminal suppresses reviving the rest of the set. `--all` and `--id` stay
  exactly as they were: neither consults the carry mark at all.
- **`reap` (toast-free) and `reap_and_announce` (the registered CLI/daemon
  handler) are deliberately two functions, not one.** `reap_and_announce`
  spawns a REAL `notify-send` on the live desktop whenever the sweep
  changed anything (or `--announce` is passed) — every in-crate caller and
  unit test calls the bare `reap` instead, and MUST keep doing so; a test
  that dispatches the real `graph reap` command path (proving daemon/socket
  routing, not sweep logic) reaches `reap_and_announce` for real and has to
  neutralize `notify-send` itself (e.g. blanking `$PATH` for that one call)
  rather than letting a test fire a real toast on the machine running it.
- **A session's exit — a clean `graph session end` OR a `reap` sweep — MUST
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
  its own override silently mutated PRODUCTION `~/Aoide/song/stage/
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
    the four backfill sites, and a nested `conduct --headless`/`graph spawn`
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
  that is a live finding, not caution:** `graph send` prefixes a delivered
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
- **`who` is a projection, never a store.** It must never write
  `state/peer-cache/<name>.json` — `build_graph`'s own fold (`doc.rs`) is
  the ONLY writer of that cache. `who`'s live probe reads straight off the
  network via `aoide_client::commands::pull_peer_live` and falls back to
  the cache (read-only) for an unreachable peer; don't "helpfully" have a
  successful live probe refresh the cache as a side effect.
- **`send::deliver_local`'s success path is ONE of exactly TWO inbox-filing
  calls in the whole tree — never a third.** Every consumer that delivers
  into an ALREADY-REGISTERED session's socket (`graph send --id`, `--to`
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
  conduct -- <agent cmd>` argv gets built (P-D7).** Both `graph spawn`
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
