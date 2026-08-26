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
  "Nix-independence").
- `ipc`, `lint`, `reap` — the song IPC surface, `rice lint`, and stale-song
  reaping.
- `commands` — this crate's CLI commands: `rice *`, `livery *`, `cover set`.

## What it consumes

`aoide-protocol`, `aoide-storage` (`aoide_storage::fs::song_dir`), plus
`aoide-test-support` as a dev-dependency. `livery`/`live` are otherwise
dependency-free leaves.

## How it composes

Only `lyra` depends on it. **Rices portably**: applying a song can't require
Stylix/NixOS-module plumbing, so this crate itself stays free of that
assumption even though its sole consumer (`lyra`) is nix-dependent.
