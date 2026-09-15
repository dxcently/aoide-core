# aoide-song

Aoide's ricing/design engine: the native livery engine (schema validation,
`{group.key}` deref + component fallback, stage/hyprctl/osc/file emitters),
`rice compose`'s scaffolding/rendering, cover-art derivation, the Hyprland
geometry keyword live-apply, and the element render pipeline (non-QML rice
targets — waybar, dunst, anything with a config file). Paint-side — ships
in `lyra`, not core.

## Named seams (what it exposes)

- `livery` — the design-token engine: schema, resolve, emit.
- `live` — computes + (best-effort) applies the Hyprland geometry/border
  keyword list a staged notes document implies.
- `compose` — the pure `rice compose` scaffolding/rendering engine.
- `cover` — cover-art derivation + resolution.
- `elements` — the element descriptor + render pipeline
  (docs/architecture/ELEMENTS.md): parses/validates a song's
  `elements/<name>/element.json` (v0 — name shape, directory-name match,
  `files[].src`/`dest` traversal, `run.via` ∈ {unit, exec-once}), then
  renders every declared file into `run/elements/<name>/` — verbatim byte
  copy for `template: false`, `livery::emit::file::render` for
  `template: true`. `seed_tree` is the pure whole-songbook walker (explicit
  paths, no env, `_`-prefix dirs shelved); `seed_song` is the thin wrapper
  resolving `songbook_dir`/`run_elements_dir` and the song's own committed
  livery for it. A render error fails only that one element and leaves its
  existing config untouched — every file for an element renders into memory
  first, and nothing is written until all of them succeed.
- `widgets` — the `nix eval` call for widget geometry (lyra-only; core must
  stay nix-independent — `docs/architecture/PACKAGE-LAYOUT.md`,
  "Nix-independence"). On a repo-less host (no `flake.nix` at
  `aoide_storage::fs::flake_root()`, L-C3, task #107) it never shells to
  `nix` at all: `eval_songbook` routes to `eval_songbook_from_templates`,
  which reads the shipped/env templates dir's (`fs::song_templates_dir`)
  prebaked `manifest.json`/`registry.json` as the baseline for every OTHER
  committed song and patches in the currently-staged song's own entry from
  a direct, nix-free scan (`scan_own_entry`) — the only shape `rice
  compose` can ever produce (no `_widgets/` shelf). `snapshot_widget_bodies`
  (`lyra reload` design, settled 2026-08-31) captures the same
  `songbook/<song>/widgets/` tree `sync_song_widgets` copies FROM — never
  `run/qml`'s deployed copy — as the take store's own widget-body payload;
  read-only, no restore counterpart (`rice back` still never touches widget
  bodies — they stay git's substrate).
- `ipc`, `lint`, `reap` — the song IPC surface, `rice lint`, and stale-song
  reaping.
- `commands` — this crate's CLI commands: `rice *`, `livery *`, `cover set`,
  `element seed`, `rice take`/`take.*`/`rice back`, `quickshell healthcheck`,
  and `reload` (`lyra reload` design, settled 2026-08-31 — the one
  mode-aware iteration command; absorbed `quickshell reload` outright).
  `rice compose --from <song>` resolves its source via
  `commands::rice::resolve_from_notes_path` (L-C3, task #107):
  `songbook_dir(from)` first, else `<templates>/<from>/livery.json`
  (`fs::song_templates_dir`) — a repo-less host still has something to copy
  from. Compose TO always writes the host songbook under the runtime root,
  never the templates dir. `commands::rice::seed_songbook_from_templates`
  (task #41) reuses the SAME `fs::song_templates_dir` resolver for a
  different write: the first `rice stage <name>`/`rice mode stage <name>`
  for a SHIPPED song the runtime `songbook_dir(name)` lacks entirely copies
  that song's whole template tree in — once, dir-level never-clobber (a
  songbook dir with anything in it, even partially, is left alone), so
  idempotent by construction. Both staging entry points call it before
  `handle_rice_stage` (the sync) ever reads the songbook; `rice mode
  declarative`'s re-pin and `lyra reload`'s staging arm reuse
  `handle_rice_stage` directly and need nothing extra, since by then the
  song already resolved through one of the two entry points. `element seed
  <song>` (L-E1) is the shell-reachable
  bridge to `crate::elements::seed_song` — the render pipeline's only
  caller today; `rice stage` (L-E2) and the elements facet's activation
  hook (L-E3) call the same function later, not a fork of it.

## What it consumes

`aoide-protocol`, `aoide-storage` (`aoide_storage::fs::song_dir`/
`flake_root`/`song_templates_dir`/`songbook_dir`/`songbook_notes`/
`declared_notes`/`run_elements_dir`), plus `aoide-test-support` as a
dev-dependency.
`livery`/`live` are otherwise dependency-free leaves.

`declared_notes` (`song/declared/livery.json`, CONTRACTS.md §4) is the
DECLARED song's own notes, venue override applied — published by the
quickshell facet's activation seed, read-only here.
`commands::rice::notes_source` reads it whenever its `"song"` field equals the
name being staged (never otherwise), so a runtime re-stage of the declared song
reproduces the venue recolour instead of reverting it;
`commands::rice::declared_song` is the same field exposed to `rice mode
declarative`'s no-`<name>` resolve. A host with no such file falls back to
`songbook_notes` unchanged.

## How it composes

Only `lyra` depends on it. **Rices portably**: applying a song can't require
Stylix/NixOS-module plumbing, so this crate itself stays free of that
assumption even though its sole consumer (`lyra`) is nix-dependent.
