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
- **A hook never fails.** `checklane`'s two entry points degrade to `None`
  on a missing config, an unloadable config, a lane left disabled, or a
  verify command that can't even launch — never a panic, never an error
  that would abort the calling hook.
- **`checklane`'s own state stays under this crate's state dir**
  (`state/checklane/<session-id>.json`), never inside `aoide-conduct`'s
  session store — a session's conduct record is what HAPPENED to the
  session; a lane baseline is this crate's own bookkeeping about a run.

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
