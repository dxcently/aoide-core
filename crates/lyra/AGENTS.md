# AGENTS.md — aoide-lyra

## Invariants

- **Never `a2a serve`, never `conductor`.** Those are core `aoide` identity
  (root `AGENTS.md`) — adding either here reopens the exact boundary P-A4
  drew. If a paint feature seems to need the graph or A2A, that's a signal
  it belongs in core, not a reason to add the dependency here.
- **Lyra's golden is independent of core's.** `registry.rs`'s snapshot (42
  paths) is its own list, not a subset check against `cli`'s 68 — the two
  evolve separately.
- **`commands::all()`'s order is byte-stable**, same discipline as `cli`'s —
  append, never reorder (see `pkgs/aoide/crates/AGENTS.md`).
- **May be nix-dependent — the one binary allowed to.** `song::widgets`'s
  `nix eval` lives reachable from here; that dependency must never migrate
  toward `aoide-cli` or any core crate (root `AGENTS.md`, "core is
  nix-independent").
- **`shellbridge`/`herald` registration only, never the files.** The verb
  registration lines for these live in lyra's `commands`; the implementation
  files stay in `aoide-conduct` (see that crate's charter-smudge note) —
  don't duplicate or move them here.

## Extension points

- **A new paint verb** adds a `cmd!`/`register` entry in the owning domain
  crate (`song`, `screen`, or `conduct` for shellbridge/herald), wired into
  lyra's `commands::all()`.
- **A new special-cased verb** extends the `special` closure passed to
  `aoide_protocol::door::run` in `run_lyra`.

## Docs update required in the same commit

- This `README.md` when the command count or a dependency changes.
- The golden snapshot in `registry.rs` when the command-path set changes.
- `docs/architecture/PACKAGE-LAYOUT.md`/`CONTRACTS.md §3` when the
  core/lyra split itself shifts.
