# AGENTS.md — aoide-conduct

## Invariants

- **This crate is core, never lyra.** Nothing here may gain a
  wayland/image/quickshell dependency — that's exactly what P-A1 moved OUT
  (to `screen`) to keep this crate headless-safe. `cargo tree -p
  aoide-conduct` staying free of those deps is a standing gate.
- **`shellbridge.rs`/`herald.rs` are a named, deliberate charter smudge.**
  Their CLI verbs live in `lyra`; the files stay here because `permit.rs`
  (this crate) publishes through `herald`, and `conductor/ui.rs` reads the
  socket path `shellbridge` owns. Don't move the files to chase the verbs —
  see `docs/architecture/PACKAGE-LAYOUT.md`'s "Charter exceptions" for the
  full reasoning before touching either.
- **`normalize_addr` is `pub`, not `pub(crate)`, on purpose** — `screen`
  reaches it directly rather than duplicating it. Don't narrow it back
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
  way — see `client`'s own `AGENTS.md` extension-point note.
- **`reap` (toast-free) and `reap_and_announce` (the registered CLI/daemon
  handler) are deliberately two functions, not one.** `reap_and_announce`
  spawns a REAL `notify-send` on the live desktop whenever the sweep
  changed anything (or `--announce` is passed) — every in-crate caller and
  unit test calls the bare `reap` instead, and MUST keep doing so; a test
  that dispatches the real `graph reap` command path (proving daemon/socket
  routing, not sweep logic) reaches `reap_and_announce` for real and has to
  neutralize `notify-send` itself (e.g. blanking `$PATH` for that one call)
  rather than letting a test fire a real toast on the machine running it.
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
  override afterward, same as any other env var here.
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

## Extension points

- **A new `graph`/`conduct`/`hooks` verb** adds a `cmd!`/`register` entry in
  `commands/`, wired into `cli`'s `commands::all()` (this crate's verbs are
  core, never `lyra`'s).
- **A new hook event or harness profile** extends `aoide_protocol::agents`,
  not this crate — the harness-profile table lives one layer down.

## Docs update required in the same commit

- This `README.md` when a public module, seam, or charter-smudge reasoning
  changes.
- `CONTRACTS.md` when a graph/session wire shape changes.
- `pkgs/aoide/crates/AGENTS.md` for cross-crate invariants — not restated
  here.
