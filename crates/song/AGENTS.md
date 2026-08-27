# AGENTS.md — aoide-song

## Invariants

- **This crate is lyra-only and stays nix-independent itself.** `widgets.rs`
  is the one `nix eval` call in the whole workspace — it's here because
  `song` is `lyra`'s domain, but nothing else in this crate may shell out to
  Nix; the ricing engine must apply a song on generic Linux too (root
  `AGENTS.md`, "Nix-independence").
- **`widgets::eval_songbook`'s templates fallback (L-C3, task #107) is
  triggered structurally, never by catching a `nix eval` failure.** It
  checks `flake_root().join("flake.nix").is_file()` FIRST and routes to
  `eval_songbook_from_templates` before ever building a `nix` command —
  don't "simplify" this into a try-nix-then-fall-back-on-error shape; that
  would spawn a doomed `nix` process on every repo-less-host call (slow, and
  a wrong error message when `nix` itself isn't on `PATH`) for no benefit.
- **`eval_songbook_from_templates` only ever resolves a NO-`_widgets/`-shelf
  song — it must refuse, not guess, when `name` has one.** Borrowed/composed
  widget ownership can only be resolved by `composeSong` in the nix
  evaluator (`widgets.rs`'s own module doc); `rice compose` never writes a
  shelf, so this is a real but narrow gap, not an oversight. Don't extend
  `scan_own_entry` to attempt shelf resolution — that would silently
  reproduce ownership nix alone can correctly compute.
- **The templates dir's baked `manifest.json`/`registry.json` are the
  baseline for every OTHER song; `name`'s own entry ALWAYS comes from a
  fresh scan, never the baked file, even for a song that IS itself shipped
  in the templates.** Mirrors the real `nix eval` path's own "self-heals
  every call" posture (module doc) — a local edit to a template song's
  `widgets/`/`livery.json` must be reflected immediately, the same as it
  would be on a checkout host.
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
