# AGENTS.md — aoide-lyra

## Invariants

- **Never `a2a serve`, never `conductor`.** Those are core `aoide` identity
  (root `AGENTS.md`) — adding either here reopens the exact boundary P-A4
  drew. If a paint feature seems to need the graph or A2A, that's a signal
  it belongs in core, not a reason to add the dependency here.
- **Lyra's golden is independent of core's.** `registry.rs`'s snapshot (46
  paths) is its own list, not a subset check against `cli`'s 80 — the two
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
- **`commands::dialog_qml::spawn_quickshell` arms `PR_SET_PDEATHSIG` on the
  quickshell child BEFORE it execs — this is what actually closes an ask
  dialog when `lyra secrets ask`/`lyra pair ask`/`lyra pair confirm` itself is killed, not this
  process's own cleanup code (originally a `commands::secrets` review fix;
  moved here at the P-PV3 extraction, unchanged — the ownership chain,
  since it crosses this crate and `aoide-secrets`/`aoide-client`, is
  documented in every crate's `AGENTS.md`, this bullet is this crate's
  half).** `aoide_secrets::watch`'s/`aoide_client::pair_watch`'s own
  near-expiry/resolved-elsewhere kill path (`run_entry_dialog`'s
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
  killed out from under it. Live-verified (original `commands::secrets`
  commit): opened a dialog, `kill -9`'d the `lyra` pid, confirmed via
  `pgrep quickshell` that the dialog's own quickshell process was gone
  within the same second — no polling, no timeout, the kernel delivered it
  synchronously with the parent's death.
- **`commands::dialog_qml::EXIT_INFRA_FAILURE` (exit `3`) is RESERVED for
  "the dialog infrastructure itself broke" and must NEVER collide with `0`
  (approved) or `1` (dismissed/cancelled) — live-incident fix originally in
  `commands::secrets`, moved to the shared module at the P-PV3 extraction,
  that constant's own doc has the full incident.** Every internal-failure
  path in `commands::secrets`/`commands::pair` (a `quickshell` spawn error,
  `AskResult::Failed` — `spawn_and_wait_for_marker`'s own case for a
  marker-less exit) routes through each command's own `"failed"` outcome
  tag, which `lib.rs`'s `special` hook (one arm per command, `["secrets",
  "ask"]`/`["pair", "ask"]`) is the ONE place that maps onto this exit code
  PLUS an `eprintln!` naming what happened. Both commands re-export the
  constant at their own path (`commands::secrets::EXIT_INFRA_FAILURE`/
  `commands::pair::EXIT_INFRA_FAILURE`) purely so `lib.rs`'s two `special`
  arms don't have to reach into `dialog_qml` directly — don't add a new
  internal-failure case that falls through to the generic `_` arm (now
  USAGE-only, `lib.rs`'s own comment) or reuses `output::exit::ERROR` —
  either would silently reintroduce the exact incident this exists to
  close: `aoide-secrets`' own `watch::run_entry_dialog` / `aoide-client`'s
  own `pair_watch::run_entry_dialog` (the OTHER side of this contract, no
  shared Rust type — this crate must never depend on `aoide-secrets`/
  `aoide-client` or vice versa, root `AGENTS.md`'s core/paint boundary, so
  every side duplicates the literal `3` in its own doc comments) reads
  exit `1` as a bare user cancel, never as a failure worth retrying.
- **`commands::dialog_qml` is the ONE place either surface renders — the
  six-box ENTRY component and the plain-code CONFIRM component alike — a
  caller adds wording/flags, never a second QML template of either shape
  (P-PV3: the extraction `commands::pair`'s own `pair ask` forced the
  entry side; `pair confirm`'s own design revert, same phase, forced the
  confirm side).** A future caller needing either shape reuses this
  module the same way `commands::pair` does; don't copy
  `commands::secrets`' pre-extraction shape again "since it's just one
  file," and don't reach for the ENTRY surface to build a confirm-shaped
  dialog "since it's already there" — `commands::pair`'s own module doc
  has the review finding that makes that substitution actively misleading
  (a retype over an already-visible code proves nothing an Approve click
  doesn't).

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
- `commands::dialog_qml`'s own module doc, plus every caller's doc
  (`commands::secrets`, `commands::pair`, `aoide-secrets`' `watch.rs`,
  `aoide-client`'s `pair_watch.rs`) when the shared output contract
  (marker line shapes, exit codes) changes — it is duplicated prose across
  a boundary no shared Rust type can enforce (root `AGENTS.md`'s core/paint
  split), so a drift here is silent until a dialog answers wrong.
