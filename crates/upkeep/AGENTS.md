# AGENTS.md — aoide-upkeep

## Invariants

- **Report-only, forever.** This is a binding correction, not a v0
  shortcut: neither `soundcheck` nor `checklane` may ever move, delete,
  format, or repair anything they find. A finding names a problem precisely
  enough for a human or agent to fix it elsewhere — this crate does not do
  the fixing.
- **Working-tree only.** Anything `nix flake check` (`lib/checks.nix`) can
  already see belongs there, not here — this crate's whole charter is the
  gap `nix eval` structurally cannot reach (gitignored/uncommitted state,
  and — `checklane` specifically — untracked files no flake check was ever
  handed).
- **Nix appears as data, never as source.** `checklane::run_verify` shells
  out to whatever command `aoide_storage::config::Upkeep::verify_command`
  hands it; this crate never spawns `nix` itself and never parses that
  command's own output — only its exit code. See `checklane`'s module doc.
- **A hook never fails.** `checklane`'s three entry points degrade to `None`
  (or, for `on_stop`, silently write nothing) on a missing config, an
  unloadable config, a lane left disabled, or a verify command that can't
  even launch — never a panic, never an error that would abort the calling
  hook.
- **`checklane`'s own state stays under this crate's state dir**
  (`state/checklane/<session-id>.json`), never inside `aoide-conduct`'s
  session store — a session's conduct record is what HAPPENED to the
  session; a `SessionLane` (baseline + pending note) is this crate's own
  bookkeeping about a run.
- **Stop records, the next context-reaching event speaks.** `on_stop` never
  returns a note to its caller — only `SessionStart`/`UserPromptSubmit` fold
  a hook's stdout into the model's context, per
  `docs/Aoide-Wiki/protocol/dev/HARNESS-CLAUDE-CODE.md`'s "Traps" section —
  it persists the rendered delta as a pending note instead. Don't reintroduce
  an `Option<String>` return on `on_stop`, and don't have it emit anything a
  caller might be tempted to surface directly; the relay is the only path.
- **The persisted shape fails loudly on a stranger key, never guesses.**
  `LaneRun` and `SessionLane` both carry `#[serde(deny_unknown_fields)]` —
  the guard has to sit on `SessionLane` itself (the struct `load_lane`
  actually parses), not only on the nested `LaneRun`, or a bare old-shaped
  file's keys are never even compared against it (review finding, task #139
  phase 2: a phase-1-shaped file silently read as a default-valued, falsely
  CLEAN baseline — no panic, no signal, and load-bearing for attribution).
  A file that fails to parse reads as "no baseline recorded", which is
  safe; a wrong baseline is not. A future field on either struct needs
  `#[serde(default)]` to stay backward-compatible on ADDITION, but must
  never relax this guard to accept a field it does not recognize.

## Extension points

- **A new check** adds a scan function to `scan.rs` and a finding case to
  its report format — see `scan`'s module doc for exactly which checks live
  here and the finding shape.
- **A new check-lane signal** (beyond verify-red and untracked-`.nix`) adds
  a field to `checklane::LaneRun`, a comparison in `diff`, and a clause in
  both `session_start_message`/`stop_message` — the walkable shape those
  four already hold, not a new parallel struct.

## Docs update required in the same commit

- This `README.md` when a new check category or check-lane signal is added.
- `CONTRACTS.md`'s `config.toml` subsection when `[upkeep]` gains a key.
- `pkgs/aoide/crates/AGENTS.md` for cross-crate invariants — not restated
  here.
