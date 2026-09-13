# AGENTS.md — aoide-lyra

## Invariants

- **Never `a2a serve`, never `conductor`.** Those are core `aoide` identity
  (root `AGENTS.md`) — adding either here reopens the exact boundary P-A4
  drew. If a paint feature seems to need the graph or A2A, that's a signal
  it belongs in core, not a reason to add the dependency here.
- **Lyra's golden is independent of core's.** `registry.rs`'s snapshot (54
  paths) is its own list, not a subset check against `cli`'s own — the two
  evolve separately.
- **`commands::preview`'s root is a SIBLING of the live socket dir, never a
  descendant.** Its default (`$XDG_RUNTIME_DIR/aoide-preview`) and every
  `--root` a caller supplies must never resolve under
  `$XDG_RUNTIME_DIR/aoide/` — that is the live daemon's own socket dir
  (`aoided.sock`, `session-*.sock`), and the live reaper's socket globs
  look there; a preview root nested inside it would be swept as a dead
  session or mistaken for a live one. The same posture holds for the
  spawned canvas's own env: `AOIDE_DAEMON_SOCKET` is set to a path that
  deliberately never exists, and `AOIDE_ROOT`/`AOIDE_STATE_DIR`/
  `AOIDE_STAGE_DIR` are repointed at the isolated root on the CHILD only —
  never the invoking `lyra` process's own env. Don't relax either to "just
  reuse the live root for a quick test" — that is the exact live-state
  corruption this command exists to make impossible.
- **`commands::preview`'s `--livery <spec>` has exactly FOUR forms, all
  routed through the SAME `aoide_song::livery::resolve::resolve` +
  `to_json_string` engine call `lyra livery resolve` itself uses (never a
  hand-rolled shortcut for any one form):** `live` (the resolved LIVE stage
  twin, `aoide_storage::fs::stage_dir().join("livery.json")` — read only,
  never written); a bare song name (that song's own
  `song/songbook/<name>/livery.json` — independent of the preview's own
  `--song`); a path to a livery file; or a path to a base16 scheme (JSON
  `{"base00": …, …}` or the flat `key: value` line shape — detected by
  `base00` present and `palette` absent, synthesized into a palette by
  `livery_from_base16` per CONTRACTS.md §1's base16 column reversed). A
  resolve failure is an error that leaves the previous staged file intact —
  never a partial write. Default (no `--livery`) is the preview's own
  `--song`.
- **`preview.json` never carries a bare `livery` key.** The P2 canvas
  treats it as a legacy alias of `liverySource` and deletes it on every
  save of its own; the builder and `preview set` do the same on every
  write (migrating away any legacy key an older doc still carries), so the
  two never ping-pong the key back and forth. `liverySource` is the one
  name for the spec as given.
- **`preview.json`'s `lyra` key is the launching binary's own
  `std::env::current_exe()`, written once at root build only.** `preview
  set` never touches it. The P2 canvas spawns every rail action against
  `controlDoc.lyra`, falling back to a bare `lyra` on PATH only for a doc
  written before this field existed — a deployed `lyra` on PATH may predate
  `preview set` entirely, which is exactly why a canvas launched by an
  older or different binary must not trust PATH for its own rail.
- **`commands::preview`'s root seeds four OTHER facet-read stage files a
  song's own widgets/livery never touch, so nothing starts with a parse
  warning on a missing file:** `song/stage/mode.json`
  (`LiveryState.qml`'s convention) is REWRITTEN on every build and on
  `preview set --song` — it always names the CURRENT song, never stale;
  `song/stage/cover.json`, `song/stage/grimoire.json` (`GrimoireLedger`'s
  `launches` is an OBJECT keyed by app id, never an array — matches the
  live file's own shape), and `state/usage.json` are written ONCE, only
  when absent, and a rebuild must never clobber one a canvas or a test has
  since mutated (`seed_if_absent`'s own contract).
- **`commands::preview declare` copies checkout-ward, never the reverse.**
  It is the canvas's own `rice declare` counterpart (same "stage vs.
  commit" split, `Self-Ricing.md`): the previewed widget body and/or
  resolved palette become `song/songbook/<song>/` truth, byte-diffed so a
  repeat with nothing new is a true no-op, and it NEVER runs `git`, touches
  the live stage, `~/.aoide`, or `run/qml` — commit and rebuild stay the
  user's own gate (house rule 2). A `widget` field outside `run/qml/songs/`
  (a facet symlink) is refused with a usage error, never silently declared
  — and the `starts_with("songs/")` check alone is a STRING match, not a
  boundary: a `..` component is rejected outright, and the canonicalized
  source is additionally required to land inside a real songbook
  `widgets/` dir, since a `..`-laden field can otherwise satisfy the
  prefix check while resolving straight out to a facet file. `--slot` is
  validated against the
  same shape as a song name (`valid_song_name`) before it is ever joined
  into a path — an unvalidated slot is exactly the same class of escape.
- **`commands::all()`'s order is byte-stable**, same discipline as `cli`'s —
  append, never reorder (see `pkgs/aoide/crates/AGENTS.md`).
- **Every `run/qml/` entry under EVERY preview root is a COPY of a
  checkout file, never a symlink into it** (`commands::preview`'s
  `stage_qml_copies`/`stage_song_copies`; `remove_stale` replaces a link
  left by an older root). The checkout is edited in the checkout; the
  root's copies are refreshed by the canvas from `preview.json`'s `stage`
  map before every reload and by a `--no-launch` rebuild. Nothing in
  `commands::preview_tools` writes under `run/qml/`, and no code path may
  reintroduce a link there: a live incident during this crate's own P6
  phase wrote through such a link and truncated `modules/facets/
  quickshell/qml/WidgetPreview.qml` (no git copy — recovered only because
  a reviewer's `Read` transcript held the file byte-for-byte);
  `a_write_through_run_qml_never_reaches_the_checkout` is the regression
  test. The facet's `icons/` tree is copied the same way (`stage_qml_copies`),
  so the canvas toolbar's `Qt.resolvedUrl("icons/...")` never leaves the
  root. `resolve_widget_abs` resolves a `widget` field to the CHECKOUT
  file, never through the root, and `preview declare`'s containment check
  runs on that path. Every test that needs a `qs`-shaped canvas builds its
  OWN scratch root out of plain files under a temp dir and drops a fake
  `qs` shell script on `PATH` (guarded by `aoide_test_support::
  env_lock()`) — never any of `p2-root`/`smoke-root`/`review-root` or the
  real `$XDG_RUNTIME_DIR/aoide-preview`.
- **`resolve_root` is the one `--root` gate** for all six preview
  commands: a `..` component and anything at or under the live daemon's
  dir are usage errors (`check_root`); no command takes a root any other
  way. The live dir comes from `live_daemon_dir` (`$XDG_RUNTIME_DIR/aoide`,
  falling back exactly as `aoide_storage::attest::daemon_socket_path()`
  does when the variable is unset) -- deliberately NOT that function
  itself, which also honors `$AOIDE_DAEMON_SOCKET`; the canvas's own child
  env repoints that at `<root>/no-daemon.sock` (`child_env`), so trusting
  it here would make a preview root look like the live dir from inside its
  own canvas and refuse every rail action. The candidate is compared both
  as spelled and with its deepest existing ancestor canonicalized, so a
  `--root` that is a symlink into the live dir is refused too.
- **`commands::preview_tools` shells `qs` at exactly one seam
  (`qs_ipc_call`) and joins the runtime tree against the static QML parse
  at exactly one seam (`join_level`)** — `preview shot`'s widget/element
  enrichment, `preview tree`'s own dump, and `preview notes`'s read-time
  `element` -> `source` resolution all call through these, never a second
  forked copy of either (this crate's own "no cross-crate copying" holds
  within a crate too). The element path grammar (`Type[i]` per level,
  `#objectName` suffix informational, `i` counting among same-type
  children at that level) matches P7's own pick-mode grammar byte for
  byte — a change to either needs the matching edit in the QML side's own
  doc in the same commit. **It is CANVAS-AUTHORITATIVE, not re-derived**:
  every runtime node already carries its own `path` string verbatim
  (`RuntimeNode::path`/`JoinedNode::path`), and `resolve_element_path` does
  a plain recursive string-equality search against it — load-bearing
  because a `Repeater`'s generated items land as SIBLINGS of the
  `Repeater` in `children`, which a Rust-side Type[i]-counting walk is not
  guaranteed to replicate correctly. Never reintroduce an index-counting
  resolver here; the canvas's own numbering is the only source of truth.
- **`join_level`'s match kinds have a fixed precedence — `"file"`, then
  `objectName`, then `positional` (same-level sibling, then a sibling
  `Repeater`'s own `delegate`-bound child), then `wrapper`, else `"none"`
  — and `"file"` is checked unconditionally before and independently of
  the other three.** A `Repeater`'s stamped-out delegate instances land in
  the RUNTIME tree as the `Repeater`'s own SIBLINGS, never its children,
  while the delegate is parsed as a REAL static child of the `Repeater`
  (`StaticNode::binding == Some("delegate")`, `line_opens_bound_node`) —
  so a runtime sibling with no same-level static match gets one more
  positional attempt against every sibling `Repeater`'s own delegate
  child before falling to `wrapper`/`none`; ALL instances resolve to that
  SAME static child (never marked `used`, since it was never a member of
  the level's own `statics` list to begin with) and share its `id`/line.
  Do not let this reach past `Repeater` to other binding kinds
  (`contentItem`/`background`/`sourceComponent`) — those are ordinary
  single-value properties, not repeated instantiations, so the runtime
  tree already nests them as real children and plain positional matching
  already reaches them once the parser opens them as real nodes at all.
  `"file"` covers TWO source shapes through one
  `ComponentMap`, never special-cased apart: a `watch`-listed file keyed
  by basename, and an inline `component Name: Type { ... }` declaration
  (captured by `parse_static_qml`'s second return value, registered by
  `build_component_map`) keyed by `Name` — GLOBAL scope across the whole
  map, not per declaring file, because QML component names are already
  expected to be unique project-wide; a name collision is last-file-
  parsed-wins, not an error. A new component-map source added later joins
  this same map under this same match kind rather than growing a second
  kind. `"wrapper"` exists for a runtime node with no static match whose
  type has ZERO static siblings at that level in the FULL sibling list
  (used or not) — a framework-synthesized container (`Flickable`/
  `ListView`'s implicit `contentItem`, a `Loader`'s loaded item) — and
  hands its OWN children the SAME static sibling list it failed to match,
  carrying `source` down from `parent_source` (the nearest ancestor that
  DID resolve) rather than from itself; a runtime node whose type DOES
  have a static sibling at that level (even one already claimed) is a
  genuine mismatch and must stay `"none"`, never fall through to
  `wrapper` — that distinction is the one thing not to reorder or
  loosen when touching this function.
- **`preview shot`'s `<out>.json` sidecar is OURS for every `--what` kind.**
  For screen/canvas kinds, `aoide_screen::capture::shot` writes its OWN
  sidecar at a DIFFERENT path (`<out>` with the extension swapped, not
  `append_suffix`'d) — read it, fold it into ours under a `"capture"`
  key, and delete it, or it is an orphan file nobody points at. Never
  claim the two sidecars collide at the same path; they don't, which is
  exactly why leaving the other one unfolded/undeleted goes unnoticed.
  The canvas's own `<out>.meta.json` (widget/element kinds only) is
  `{widgetRect, scale}` — only `scale` is merged in, then the file is
  deleted; a missing or unparsable meta file is a silent no-op, never a
  failure of an otherwise-successful shot. `elementRect` in our sidecar
  never comes from the canvas — see the next point.
- **The canvas's own element-kind ipc call is permanently broken by
  design (always a transparent/failed capture) and must never be
  invoked.** `--what element` calls the canvas with `"widget"` ALWAYS,
  then crops the resulting PNG here in Rust (the `image` crate) to the
  element's live rect from the same tree join `preview tree` uses,
  scaled and clamped to the image bounds; `elementRect` in the sidecar is
  this crop's own pixel rect. Reintroducing the ipc `"element"` call is a
  regression, not a simplification.
- **The canvas answers `shot` with exactly one of two files, never a
  success/failure code on the ipc call itself**: `<out>` (the image) AND
  `<out>.meta.json` on success, or `<out>.error` (plain text) and NO image
  on failure — `poll_for_shot` polls for either within 5s (100ms) and
  surfaces `.error`'s own text as the command's error message. And every
  one of `<out>.json` (ours)/`<out>.meta.json`/`<out>.error` is `--out`'s
  FULL value with the suffix LITERALLY APPENDED (`append_suffix`) — NEVER
  `PathBuf::with_extension`, which replaces the part after the last dot
  and would turn `foo.png` into `foo.meta.json` (dropping `.png`) instead
  of the real `foo.png.meta.json`. This was a real bug caught only by
  reading the canvas's actual on-disk output, not by reasoning about the
  contract — when in doubt about a P7 file-naming convention, check the
  files it actually wrote before trusting a Rust API's own naming
  intuition.
- **May be nix-dependent — the one binary allowed to.** `song::widgets`'s
  `nix eval` and `commands::onboard`'s `nix eval`/`nix-instantiate` shell-outs
  live reachable from here; that dependency must never migrate toward
  `aoide-cli` or any core crate (root `AGENTS.md`, "core is
  nix-independent").
- **`onboard`'s option derivation is DERIVED, never a hand-list.** Every
  `aoide.*` option `aoide.nix` documents comes from `flake.nix`'s
  `aoideOptions` output (`lib/options.nix`, `lib.evalModules` +
  `lib.optionAttrSetToDocList`) — a new dendrite/facet option needs no edit
  here or in `lib/options.nix`, it just appears on the next `lyra onboard`
  run. The env-knob appendix (`ENV_KNOBS` in `commands/onboard.rs`) is the
  ONE allowed hand-list, because env vars aren't module options and so
  can't be derived the same way — keep it small.
- **`shellbridge`/`herald` registration only, never the files.** The command
  registration lines for these live in lyra's `commands`; the implementation
  files stay in `aoide-conduct` (see that crate's charter-smudge note) —
  don't duplicate or move them here.
- **`commands::dialog_qml::spawn_quickshell` arms `PR_SET_PDEATHSIG` on the
  quickshell child BEFORE it execs — this is what actually closes an ask
  dialog when `lyra secrets ask`/`lyra pair ask`/`lyra pair show` itself is killed, not this
  process's own cleanup code (originally a `commands::secrets` review fix;
  moved here at the P-PV3 extraction, unchanged — the ownership chain,
  since it crosses this crate and `aoide-secrets`/`aoide-client`, is
  documented in every crate's `AGENTS.md`, this bullet is this crate's
  half).** `aoide_secrets::watch`'s/`aoide_client::pair_watch`'s own
  near-expiry/resolved-elsewhere kill path (`run_entry_dialog`'s
  `child.kill()`) sends `SIGKILL` to the `lyra` PROCESS it spawned — `SIGKILL`
  is UNTRAPPABLE, so `spawn_and_wait_for_marker`'s own best-effort
  `child.kill()` on the quickshell grandchild NEVER RUNS in that case (the
  `lyra` process is dead before its own code gets a chance to). Without
  `PR_SET_PDEATHSIG`, that grandchild — quickshell, with a live window open —
  would simply be reparented to a subreaper (or pid 1) and keep running
  forever: the exact "orphaned window left open" failure mode `aoide-
  secrets`' own `AGENTS.md` names as the reason `run_zenity_entry`/
  `run_lyra_entry` hold the child's EXACT pid at all. `PR_SET_PDEATHSIG`
  makes the KERNEL deliver `SIGKILL` to the quickshell process itself the
  instant its parent (`lyra`) dies for ANY reason — no cooperation from
  either process's own code required at the moment of death. Armed inside
  `Command::pre_exec` (runs in the forked child, strictly between `fork()`
  and `execve()` — only async-signal-safe calls belong in that closure:
  `prctl`/`getppid`/`_exit`, nothing that allocates or locks) with the
  standard TOCTOU close: `getppid()` re-checked against the parent pid
  captured BEFORE `fork()`, exiting immediately if they differ (the parent
  already died in the fork/prctl window, so a signal armed now would never
  fire, and executing into quickshell anyway would silently orphan it the
  same way). Don't drop this from a future `spawn_quickshell` rewrite "since
  `spawn_and_wait_for_marker` already kills the child" — that cleanup only
  runs when the FUNCTION returns normally, never when the whole process is
  killed out from under it. Live-verified (original `commands::secrets`
  commit): opened a dialog, `kill -9`'d the `lyra` pid, confirmed via
  `pgrep quickshell` that the dialog's own quickshell process was gone
  within the same second — no polling, no timeout, the kernel delivered it
  synchronously with the parent's death.
- **`commands::dialog_qml::EXIT_INFRA_FAILURE` (exit `3`) is RESERVED for
  "the dialog infrastructure itself broke" and must NEVER collide with `0`
  (approved) or `1` (dismissed/cancelled) — live-incident fix originally in
  `commands::secrets`, moved to the shared module at the P-PV3 extraction,
  that constant's own doc has the full incident.** Every internal-failure
  path in `commands::secrets`/`commands::pair` (a `quickshell` spawn error,
  `AskResult::Failed` — `spawn_and_wait_for_marker`'s own case for a
  marker-less exit) routes through each command's own `"failed"` outcome
  tag, which `lib.rs`'s `special` hook (one arm per command, `["secrets",
  "ask"]`/`["pair", "ask"]`) is the ONE place that maps onto this exit code
  PLUS an `eprintln!` naming what happened. Both commands re-export the
  constant at their own path (`commands::secrets::EXIT_INFRA_FAILURE`/
  `commands::pair::EXIT_INFRA_FAILURE`) purely so `lib.rs`'s two `special`
  arms don't have to reach into `dialog_qml` directly — don't add a new
  internal-failure case that falls through to the generic `_` arm (now
  USAGE-only, `lib.rs`'s own comment) or reuses `output::exit::ERROR` —
  either would silently reintroduce the exact incident this exists to
  close: `aoide-secrets`' own `watch::run_entry_dialog` / `aoide-client`'s
  own `pair_watch::run_entry_dialog` (the OTHER side of this contract, no
  shared Rust type — this crate must never depend on `aoide-secrets`/
  `aoide-client` or vice versa, root `AGENTS.md`'s core/paint boundary, so
  every side duplicates the literal `3` in its own doc comments) reads
  exit `1` as a bare user cancel, never as a failure worth retrying.
- **`commands::dialog_qml` is the ONE place either surface renders — the
  six-box ENTRY component and the plain-code SHOW component alike — a
  caller adds wording/flags, never a second QML template of either shape
  (P-PV3: the extraction `commands::pair`'s own `pair ask` forced the
  entry side; `pair confirm`'s own design revert, same phase, forced the
  ORIGINAL confirm side, which R2 (the mutual-code redesign's popup phase)
  repurposed into the show side once the outbound leg's own gate moved
  onto the entry surface instead).** A future caller needing either shape
  reuses this module the same way `commands::pair` does; don't copy
  `commands::secrets`' pre-extraction shape again "since it's just one
  file," and don't reach for the ENTRY surface to build a display-only
  dialog "since it's already there" — a typed-entry component asks the
  operator to prove something; a display component has nothing left for
  them to prove (`commands::pair`'s own module doc has the full
  reasoning both ways: the entry surface is for a code from a genuinely
  different screen, the show surface is for a code this instance already
  committed to and is merely relaying).

- **`commands::icon`'s SVG assembly is a PORT, not a reinterpretation, of
  upstream Iconify's `@iconify/utils`** (I1, `design/p-icon-brief.md` §B) —
  the alias-chain fold (`getIconData`/`mergeIconData`/
  `mergeIconTransformations`) and `iconToSVG`/`iconToHTML`'s box/transform
  string math, cited by fetched-source line number in the module doc. A
  future change to the emitted `<g transform="…">`/`viewBox` shape must
  re-derive from the actual upstream TypeScript (`raw.githubusercontent.com/
  iconify/iconify/main/packages/utils/src/`), never from a paraphrase —
  this crate's own module doc already flags one place the brief's prose and
  the fetched `svg/build.ts` disagree (pre- vs post-swap `viewBox` dims on
  an odd rotation; neither pinned collection exercises it, so only the
  hand-authored fixture in `commands::icon::tests` proves which one this
  code does). **Zero new Rust dependencies**: every IconifyJSON/catalog/
  selection document is a bare `serde_json::Value` — this crate has no
  direct `serde` dependency (only `serde_json`), so a typed struct needing
  `#[derive(Serialize/Deserialize)]` does not belong here without adding
  one. `icon resolve` follows `preview declare`'s byte-diff no-op
  discipline (`write_if_changed` compares bytes before writing) AND prunes:
  an asset the CURRENT selection doesn't name is deleted, not just left
  behind — the same "removable without a trace" house rule `commands::
  preview`'s own root-isolation invariant above cites.

## Extension points

- **A new paint command** adds a `cmd!`/`register` entry in the owning domain
  crate (`song`, `screen`, or `conduct` for shellbridge/herald), wired into
  lyra's `commands::all()`.
- **A new special-cased command** extends the `special` closure passed to
  `aoide_protocol::door::run` in `run_lyra`.

## Docs update required in the same commit

- This `README.md` when the command count or a dependency changes.
- The golden snapshot in `registry.rs` when the command-path set changes.
- `docs/architecture/PACKAGE-LAYOUT.md`/`CONTRACTS.md §3` when the
  core/lyra split itself shifts.
- `commands::dialog_qml`'s own module doc, plus every caller's doc
  (`commands::secrets`, `commands::pair`, `aoide-secrets`' `watch.rs`,
  `aoide-client`'s `pair_watch.rs`) when the shared output contract
  (marker line shapes, exit codes) changes — it is duplicated prose across
  a boundary no shared Rust type can enforce (root `AGENTS.md`'s core/paint
  split), so a drift here is silent until a dialog answers wrong.
- `commands::preview_tools`'s own module doc, plus the QML canvas's own
  doc (P7, `modules/facets/quickshell/qml/WidgetPreview.qml`), when the
  `qs ipc call` argv shape, the element path grammar, or the
  `IpcHandler { target: "preview" }` function signatures change — same
  no-shared-type boundary as the dialog contract above, Rust on one side
  and QML on the other.
