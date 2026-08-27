# aoide-song

Aoide's ricing/design engine: the native livery engine (schema validation,
`{group.key}` deref + component fallback, stage/hyprctl/osc/file emitters),
`rice compose`'s scaffolding/rendering, cover-art derivation, and the
Hyprland geometry keyword live-apply. Paint-side — ships in `lyra`, not
core.

## Named seams (what it exposes)

- `livery` — the design-token engine: schema, resolve, emit.
- `live` — computes + (best-effort) applies the Hyprland geometry/border
  keyword list a staged notes document implies.
- `compose` — the pure `rice compose` scaffolding/rendering engine.
- `cover` — cover-art derivation + resolution.
- `widgets` — the `nix eval` call for widget geometry (lyra-only; core must
  stay nix-independent — `docs/architecture/PACKAGE-LAYOUT.md`,
  "Nix-independence"). On a repo-less host (no `flake.nix` at
  `aoide_storage::fs::flake_root()`, L-C3, task #107) it never shells to
  `nix` at all: `eval_songbook` routes to `eval_songbook_from_templates`,
  which reads the shipped/env templates dir's (`fs::song_templates_dir`)
  prebaked `manifest.json`/`registry.json` as the baseline for every OTHER
  committed song and patches in the currently-staged song's own entry from
  a direct, nix-free scan (`scan_own_entry`) — the only shape `rice
  compose` can ever produce (no `_widgets/` shelf).
- `ipc`, `lint`, `reap` — the song IPC surface, `rice lint`, and stale-song
  reaping.
- `commands` — this crate's CLI commands: `rice *`, `livery *`, `cover set`.
  `rice compose --from <song>` resolves its source via `commands::rice::
  resolve_from_notes_path` (L-C3, task #107): `songbook_dir(from)` first,
  else `<templates>/<from>/livery.json` (`fs::song_templates_dir`) — a
  repo-less host still has something to copy from. Compose TO always writes
  the host songbook under the runtime root, never the templates dir.

## What it consumes

`aoide-protocol`, `aoide-storage` (`aoide_storage::fs::song_dir`/
`flake_root`/`song_templates_dir`/`songbook_dir`), plus `aoide-test-support`
as a dev-dependency. `livery`/`live` are otherwise dependency-free leaves.

## How it composes

Only `lyra` depends on it. **Rices portably**: applying a song can't require
Stylix/NixOS-module plumbing, so this crate itself stays free of that
assumption even though its sole consumer (`lyra`) is nix-dependent.
