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
- **`eval_songbook_from_templates` is a THREE-layer merge, not
  baseline-plus-current-song — don't collapse it back to two.** (1) the
  templates dir's baked `manifest.json`/`registry.json`, authoritative for
  every shipped, read-only song; (2) `overlay_surviving_entries` copies the
  EXISTING on-disk file's entries for any song that still has a directory in
  the host songbook on top of that baseline — without this, staging song B
  right after song A silently drops A's entry (A is a runtime composition,
  in neither the frozen baseline nor B's own scan), and `StagingEngine.qml`
  falls back to resolving A's widgets against some OTHER song's slot with no
  error anywhere (the exact regression a review caught live); (3) `name`'s
  own entry, ALWAYS from a fresh scan, never the baked file OR the overlay,
  even for a song that is itself shipped in the templates — this is what
  self-heals the STAGED song on every call, mirroring the real `nix eval`
  path's own posture for that one song, while layer 2 is what preserves
  every OTHER still-live song across calls (the nix path doesn't need a
  layer 2 at all — its eval is already total). A song whose songbook
  directory is removed is NOT overlaid — that is the prune, not a bug; don't
  add a "keep it anyway" fallback that would leave an immortal stale key.
- **`livery`/`live` stay dependency-free leaves.** `compose`/`cover` are the
  ones allowed to pull in `aoide-storage` (Phase 5b); don't push a storage
  dependency down into `livery`/`live` without re-deriving why that
  boundary existed.
- **Staging/draft/declarative-mode gating lives in `commands`, not here.**
  `rice stage`/`cover set` refuse outside an unlocked mode — that gate is a
  `commands` concern layered over these pure/near-pure engine modules.
- **`commands::rice::handle_rice_stage` is Staging's write path, NEVER
  Draft's — don't call it from a Draft-mode code path.** It reads the
  COMMITTED songbook and writes the result into `stage/livery.json`. In
  `Staging` mode that file is a plain file, so this is exactly "re-derive
  declared content" — correct by design. While routed into a `Draft`,
  `stage/livery.json` is a SYMLINK into the draft's own file
  (`commands/mode.rs`'s own doc), and `atomic_write` is symlink-transparent
  — calling `handle_rice_stage` there would silently overwrite the draft
  with plain committed truth, destroying the edits draft mode exists to
  hold. `commands/reload.rs`'s own `sync_draft_in_place` is the guard this
  bit live once (`lyra reload` design, settled 2026-08-31) — a Draft-mode
  caller needing the widget-sync/hyprctl-apply tail reuses THAT, or the bare
  `crate::live`/`crate::widgets` primitives directly, never
  `handle_rice_stage`.
- **`commands::rice::seed_songbook_from_templates` (task #41) is called
  from the STAGING ENTRY POINTS, never from inside `handle_rice_stage`
  itself.** `handle_rice_stage_entry` (`rice stage <name>`) and
  `commands::mode::handle_mode_stage` (`rice mode stage <name>` — the
  realistic fresh-host first call, since it unlocks AND stages in one go
  where bare `rice stage` just refuses while still locked) each call it
  before handing off to `handle_rice_stage`, the shared sync core that only
  ever READS the songbook. Don't move the seed inside `handle_rice_stage`
  itself — that would also fire it from `rice mode declarative <name>`'s
  re-pin, turning a lock command into a write-adjacent one for no reason.
  `lyra reload`'s staging arm doesn't need it either: it only ever runs
  once `mode.json`'s `song` field is set, which only happens after one of
  the two seed-checking entry points already resolved that song
  successfully — reload calling `handle_rice_stage` directly is therefore
  never a gap. The check itself is dir-level and existence-only
  (`songbook_dir(name).exists()`) — never a per-file fill; a caller adding
  a THIRD staging entry point must call the same function, not reimplement
  the check.
- **`aoide_storage::takes`' functions take `draft: Option<&str>`, not
  `&str` — `None` means staging-mode (`songbook/<song>/takes/`), `Some`
  means a routed draft (`songbook/<song>/drafts/<name>/takes/`).**
  `commands/take.rs::resolve_scope` is the one place that resolves which
  scope applies, off `mode.json` — every take/back/prune command in that
  file threads its `Option<&str>` straight through rather than re-deriving
  it. `TakeRecord` also carries `widgets: Value` (the song's widget bodies
  at mint time, `widgets.rs::snapshot_widget_bodies`) — captured on every
  take in both scopes, but never restored by `rice back` (see the
  `handle_rice_stage` bullet above: widget bodies stay git's substrate,
  deliberately out of the revert path).
- **`health.rs` is a second liveness mechanism, deliberately — not a
  violation of `aoide-conduct`'s "don't add a second liveness mechanism"
  rule.** That rule (`pkgs/aoide/crates/conduct/AGENTS.md`) guards ONE
  domain: a killed terminal's PROCESS liveness, owned entirely by `reap`.
  `health.rs` watches a different failure class with nothing in common but
  the word "liveness" — a quickshell process that is very much alive (no
  crash, no exit) but has silently lost its Wayland output and rendered
  onto Qt's internal placeholder screen. Different subject (screen
  attachment, not a session), different predicate (a live `hyprctl layers`
  zero-surface reading, then a journal placeholder-screen line to decide
  whether a restart is the known cure, not a pid/window-address probe),
  different crate (`lyra`-only, vs `conduct`'s core-only `reap`). Don't fold this into `reap` or generalize `reap` to
  cover it — the two mechanisms check unrelated things on unrelated
  subjects, and merging them would only muddy both.
- **`elements::seed_tree` takes explicit paths and touches no global
  state — `elements::seed_song` is the only env-resolving wrapper around
  it.** Every other elements test exercises `seed_tree`/`render_files`/
  `write_files` directly against a tmp dir, no `AOIDE_STAGE_DIR`/
  `env_lock` needed; only `commands::elements`'s own handler test and
  `seed_song` itself need the env rig. Don't fold `seed_song`'s
  `songbook_dir`/`run_elements_dir` resolution back into `seed_tree` — that
  would make the whole-songbook walker untestable without a stage override,
  the same split `widgets.rs`'s `copy_tree_atomic`/`sync_song_widgets`
  already holds.
- **An element render error must never partially write that element.**
  `render_files` renders every declared file into memory FIRST and returns
  the first error without writing anything; `write_files` runs only once
  `render_files` returned `Ok` for the WHOLE element. Don't merge these two
  passes into one read-render-write-per-file loop — that would leave a
  half-updated `run/elements/<name>/` on a mid-list render failure, exactly
  what ELEMENTS.md's "leaves its old config in place" rules out.
- **Element/song name validation reuses `compose::valid_song_name` —
  don't fork the regex.** `element.json`'s `element` field holds to the
  identical `^[a-z0-9][a-z0-9-]*$` shape `rice compose` already enforces on
  song names; a second copy of that check would drift the moment one of
  them changes.

## Extension points

- **A new `rice`/`livery`/`cover`/`element` command** adds a `cmd!`/
  `register` entry in `commands/`, wired into `lyra`'s `commands::all()`
  only.
- **A new emitter target** (stage/hyprctl/osc/file exist today) extends
  `livery::emit`, keeping the schema-validate → resolve → emit pipeline
  shape.
- **A new element-descriptor field** extends `elements::Descriptor`/
  `FileEntry`/`RunSpec` (serde, additive) and `parse_descriptor`'s
  validation — `docs/architecture/ELEMENTS.md`'s "The descriptor" section is
  the field-rule authority; `CONTRACTS.md §5`'s "Elements" subsection is
  pinned in the same commit as any change to those rules.

## Docs update required in the same commit

- This `README.md` when a new module or CLI command group is added.
- `docs/architecture/PACKAGE-LAYOUT.md`'s "song rices portably" note if the
  nix-independence boundary shifts.
- `CONTRACTS.md §5`'s "Elements" subsection when a descriptor field rule
  changes.
- `CONTRACTS.md §4`'s "shipped score templates" paragraph when a new
  consumer of `fs::song_templates_dir` is added — `rice compose --from`,
  the widget registry/manifest regeneration, and `seed_songbook_from_templates`
  are the three today.
- `pkgs/aoide/crates/AGENTS.md` for cross-crate invariants — not restated
  here.
