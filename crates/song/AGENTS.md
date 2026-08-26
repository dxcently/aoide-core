# AGENTS.md — aoide-song

## Invariants

- **This crate is lyra-only and stays nix-independent itself.** `widgets.rs`
  is the one `nix eval` call in the whole workspace — it's here because
  `song` is `lyra`'s domain, but nothing else in this crate may shell out to
  Nix; the ricing engine must apply a song on generic Linux too (root
  `AGENTS.md`, "Nix-independence").
- **`livery`/`live` stay dependency-free leaves.** `compose`/`cover` are the
  ones allowed to pull in `aoide-storage` (Phase 5b); don't push a storage
  dependency down into `livery`/`live` without re-deriving why that
  boundary existed.
- **Staging/draft/declarative-mode gating lives in `commands`, not here.**
  `rice stage`/`cover set` refuse outside an unlocked mode — that gate is a
  `commands` concern layered over these pure/near-pure engine modules.

## Extension points

- **A new `rice`/`livery`/`cover` command** adds a `cmd!`/`register` entry in
  `commands/`, wired into `lyra`'s `commands::all()` only.
- **A new emitter target** (stage/hyprctl/osc/file exist today) extends
  `livery::emit`, keeping the schema-validate → resolve → emit pipeline
  shape.

## Docs update required in the same commit

- This `README.md` when a new module or CLI command group is added.
- `docs/architecture/PACKAGE-LAYOUT.md`'s "song rices portably" note if the
  nix-independence boundary shifts.
- `pkgs/aoide/crates/AGENTS.md` for cross-crate invariants — not restated
  here.
