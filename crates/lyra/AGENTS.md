# AGENTS.md — aoide-lyra

## Invariants

- **Never `a2a serve`, never `conductor`.** Those are core `aoide` identity
  (root `AGENTS.md`) — adding either here reopens the exact boundary P-A4
  drew. If a paint feature seems to need the graph or A2A, that's a signal
  it belongs in core, not a reason to add the dependency here.
- **Lyra's golden is independent of core's.** `registry.rs`'s snapshot (44
  paths) is its own list, not a subset check against `cli`'s 69 — the two
  evolve separately.
- **`commands::all()`'s order is byte-stable**, same discipline as `cli`'s —
  append, never reorder (see `pkgs/aoide/crates/AGENTS.md`).
- **May be nix-dependent — the one binary allowed to.** `song::widgets`'s
  `nix eval` and `commands::onboard`'s `nix eval`/`nix-instantiate` shell-outs
  live reachable from here; that dependency must never migrate toward
  `aoide-cli` or any core crate (root `AGENTS.md`, "core is
  nix-independent").
- **`onboard`'s option derivation is DERIVED, never a hand-list.** Every
  `aoide.*` option `aoide.nix` documents comes from `flake.nix`'s
  `aoideOptions` output (`lib/options.nix`, `lib.evalModules` +
  `lib.optionAttrSetToDocList`) — a new dendrite/facet option needs no edit
  here or in `lib/options.nix`, it just appears on the next `lyra onboard`
  run. The env-knob appendix (`ENV_KNOBS` in `commands/onboard.rs`) is the
  ONE allowed hand-list, because env vars aren't module options and so
  can't be derived the same way — keep it small.
- **`shellbridge`/`herald` registration only, never the files.** The command
  registration lines for these live in lyra's `commands`; the implementation
  files stay in `aoide-conduct` (see that crate's charter-smudge note) —
  don't duplicate or move them here.
- **`commands::secrets::spawn_quickshell` arms `PR_SET_PDEATHSIG` on the
  quickshell child BEFORE it execs — this is what actually closes an ask
  dialog when `lyra secrets ask` itself is killed, not this process's own
  cleanup code (review fix, this commit; the ownership chain, since it
  crosses this crate and `aoide-secrets`, is documented in BOTH crates'
  `AGENTS.md`, this bullet is this crate's half).** `aoide_secrets::watch`'s
  own near-expiry/resolved-elsewhere kill path (`run_entry_dialog`'s
  `child.kill()`) sends `SIGKILL` to the `lyra` PROCESS it spawned — `SIGKILL`
  is UNTRAPPABLE, so `spawn_and_wait_for_marker`'s own best-effort
  `child.kill()` on the quickshell grandchild NEVER RUNS in that case (the
  `lyra` process is dead before its own code gets a chance to). Without
  `PR_SET_PDEATHSIG`, that grandchild — quickshell, with a live window open —
  would simply be reparented to a subreaper (or pid 1) and keep running
  forever: the exact "orphaned window left open" failure mode `aoide-
  secrets`' own `AGENTS.md` names as the reason `run_zenity_entry`/
  `run_lyra_entry` hold the child's EXACT pid at all. `PR_SET_PDEATHSIG`
  makes the KERNEL deliver `SIGKILL` to the quickshell process itself the
  instant its parent (`lyra`) dies for ANY reason — no cooperation from
  either process's own code required at the moment of death. Armed inside
  `Command::pre_exec` (runs in the forked child, strictly between `fork()`
  and `execve()` — only async-signal-safe calls belong in that closure:
  `prctl`/`getppid`/`_exit`, nothing that allocates or locks) with the
  standard TOCTOU close: `getppid()` re-checked against the parent pid
  captured BEFORE `fork()`, exiting immediately if they differ (the parent
  already died in the fork/prctl window, so a signal armed now would never
  fire, and executing into quickshell anyway would silently orphan it the
  same way). Don't drop this from a future `spawn_quickshell` rewrite "since
  `spawn_and_wait_for_marker` already kills the child" — that cleanup only
  runs when the FUNCTION returns normally, never when the whole process is
  killed out from under it. Live-verified (this commit): opened a dialog,
  `kill -9`'d the `lyra` pid, confirmed via `pgrep quickshell` that the
  dialog's own quickshell process was gone within the same second — no
  polling, no timeout, the kernel delivered it synchronously with the
  parent's death.
- **`commands::secrets::EXIT_INFRA_FAILURE` (exit `3`) is RESERVED for "the
  dialog infrastructure itself broke" and must NEVER collide with `0`
  (approved) or `1` (dismissed/cancelled) — live-incident fix, this commit,
  that constant's own doc has the full incident.** Every internal-failure
  path in `commands::secrets` (a `quickshell` spawn error, `AskResult::
  Failed` — `spawn_and_wait_for_marker`'s own case for a marker-less exit)
  routes through `handle_secrets_ask`'s `"failed"` outcome tag, which
  `lib.rs`'s `special` hook is the ONE place that maps onto this exit code
  PLUS an `eprintln!` naming what happened. Don't add a new internal-failure
  case that falls through to the generic `_` arm (now USAGE-only,
  `lib.rs`'s own comment) or reuses `output::exit::ERROR` — either would
  silently reintroduce the exact incident this exists to close: `aoide-
  secrets`' own `watch::run_entry_dialog` (the OTHER side of this contract,
  no shared Rust type — this crate must never depend on `aoide-secrets` or
  vice versa, root `AGENTS.md`'s core/paint boundary, so both sides
  duplicate the literal `3` in their own doc comments) reads exit `1` as a
  bare user cancel, never as a failure worth retrying.

## Extension points

- **A new paint command** adds a `cmd!`/`register` entry in the owning domain
  crate (`song`, `screen`, or `conduct` for shellbridge/herald), wired into
  lyra's `commands::all()`.
- **A new special-cased command** extends the `special` closure passed to
  `aoide_protocol::door::run` in `run_lyra`.

## Docs update required in the same commit

- This `README.md` when the command count or a dependency changes.
- The golden snapshot in `registry.rs` when the command-path set changes.
- `docs/architecture/PACKAGE-LAYOUT.md`/`CONTRACTS.md §3` when the
  core/lyra split itself shifts.
