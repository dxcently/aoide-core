# AGENTS.md — aoide-upkeep

## Invariants

- **Report-only, forever.** This is a binding correction, not a v0
  shortcut: `soundcheck` may never move, delete, format, or repair anything
  it finds. A finding names a problem precisely enough for a human or agent
  to fix it elsewhere — this crate does not do the fixing.
- **Working-tree only.** Anything `nix flake check` (`lib/checks.nix`) can
  already see belongs there, not here — this crate's whole charter is the
  gap `nix eval` structurally cannot reach (gitignored/uncommitted state).

## Extension points

- **A new check** adds a scan function to `scan.rs` and a finding case to
  its report format — see `scan`'s module doc for exactly which checks live
  here and the finding shape.

## Docs update required in the same commit

- This `README.md` when a new check category is added.
- `pkgs/aoide/crates/AGENTS.md` for cross-crate invariants — not restated
  here.
