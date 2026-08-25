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
- **A nested headless session is windowless BY CONSTRUCTION — never
  pid-ancestry-walk it to a window (task #89).** `window::windowless_by_lineage`/
  `_from_parent` is the ONE gate: a session whose `parentSessionId` chain
  passes through a conducted (`conductable`) wrap with an EMPTY
  `windowAddress` must skip the backfill outright, everywhere a window gets
  discovered for it — `graph/window.rs::ensure_session_window`, the two
  `discover_window()` call sites in `graph/send.rs`'s hook Start handling,
  AND `resolve_pending_session_windows` (the shellbridge event listener).
  Miss any one of those four and a nested `conduct --headless`/`graph spawn`
  re-acquires the ENCLOSING terminal's window, which is exactly what made
  the same-window eviction (below) treat an agent and its own headless
  grandchild as stale twins. `reap`'s own dedup pass (`superseded_*`) needs
  NO parallel lineage check — it groups by `windowAddress`, and a windowless
  session by construction never enters a group at all; don't add a second
  mechanism there either.
- **The same-window eviction carve-out is the new record's WHOLE lineage,
  not just its direct parent (task #89).** `session_store::lineage_of`
  (ancestors + descendants, walking `parentSessionId`) is what
  `do_session_start_inner`'s registration-time eviction excludes from
  retirement — widened from "direct parent only" because a nested
  `conduct`/`spawn` chain can legitimately land a same-window pair that are
  grandparent/grandchild (or cousins through a shared ancestor), not direct
  parent/child. A genuine same-window twin with NO lineage relation (a
  compact/resume pair) still collapses instantly — don't widen the carve-out
  further than actual graph membership.
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
