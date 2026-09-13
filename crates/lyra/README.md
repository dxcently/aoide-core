# aoide-lyra (bin `lyra`)

The paint app crate — the second composition root over the same
domain-crate handler code `aoide-cli` assembles (P-A4). In Cordis terms
(CONTRACTS.md §0): a BUNDLE, same as `cli` — its own ordered
`commands::all()` profile over an independent `Registry`. Owns the
self-ricing loop, `screen`, `herald`, `shellbridge`, and `quickshell`;
deliberately never conducting, the graph, A2A, nodes, or the daemon (those
are core `aoide` identity, root `AGENTS.md`).

## Named seams (what it exposes)

- `bin/lyra` — the binary entry point.
- `dispatch`/`registry` — lyra's own argv parsing, dispatch, and golden
  command-path snapshot (54 paths), independent of core's.
- `guide` — `lyra guide`.
- `commands` — lyra's `commands::all()`, pulling in `song`, `screen`, and
  `conduct`'s `shellbridge`/`herald` registration lines (the files stay in
  `conduct`; only the registry lines are lyra's), plus lyra's own root-
  coupled `onboard` (below).
- `commands::onboard` — `lyra onboard` (P-I3, docs/architecture/ONBOARD.md):
  the nix half of the onboarding flow, reached only via `aoide onboard`'s
  delegate spawn once `rice_bin()` resolves. Shells `nix eval --json
  <checkout>#aoideOptions` (flake.nix/lib/options.nix — every `aoide.*`
  option declared across `modules/{nucleus,facets,dendrites}`, derived, not
  hand-listed) and renders `aoide.nix`: a nix module the user imports, every
  option commented out at its default. Reruns over a previously-generated
  file warn, back up to `<out>.bak`, and regenerate; a hand-written file at
  the target path is refused, never overwritten. Never touches the user's
  flake.
- `run_lyra` — drives `aoide_protocol::door::run` with lyra's own registry/
  dispatcher and its own smaller `special` hook (`mcp serve --stdio`,
  `guide`/`schema`/`livery`/`secrets ask`/`pair ask`/`pair show` raw
  output). Deliberately absent: `a2a serve`, `conductor`.
- `commands::dialog_qml` (P-PV3, task #132; the confirm surface repurposed
  into the show surface at R2) — the shared quickshell code-entry/show
  SURFACES `secrets ask`/`pair ask` (entry) and `pair show` (show) render:
  the entry variant's six boxes, the dash, the underlying `TextInput`; the
  show variant's plain code display, a Copy control (a hidden read-only
  `TextInput` backing `selectAll()`/`copy()`), and a Done control — no
  reject control, since this dialog fires only after the ceremony's own
  commit already succeeded; both share the spawn/wait-for-marker/cleanup
  orchestration, `qml_escape`, and the `EXIT_INFRA_FAILURE` reservation —
  a caller supplies only a window title, a styled header block
  (`HeaderLine::bold`/`italic`/`muted`), and its own `RESULT_MARKER`
  prefix (the entry variant also takes its own dismiss-control label; the
  show variant also takes the code to display, but has no dismiss label
  of its own to take). A header line WRAPS at the window's own width
  (`win.width - 40`) and the window's height grows with the wrapped
  content: the window is a fixed-size hint (that hint is what makes
  Hyprland float it), so a line longer than 400px used to render at its
  natural width and get cut at both edges — live-proven on the pairing
  ask, which lost its node name and its request id that way. Extracted from `commands::secrets` (P3's original
  module) the moment a SECOND caller needed the identical entry
  component; the show variant followed when `commands::pair` needed a
  SECOND surface for its own reply-code display (originally a confirm
  surface for the ceremony's outbound direction, repurposed at R2 once the
  mutual-code redesign moved that direction onto the entry surface
  instead) — never a copy of either template. Writes the generated QML to
  a scratch temp path and spawns
  `quickshell -p <path>` as a genuinely standalone process
  (`song::commands::reload`'s own IPC-reload beat only ever sends IPC into
  an ALREADY-running instance, by contrast); `PR_SET_PDEATHSIG`
  (`libc::prctl`) keeps a killed dialog from ever orphaning its own window
  (`AGENTS.md`'s own invariant has the full ownership-chain reasoning);
  `qml_escape` covers backslash/quote, `\n`/`\r`/`\t`, U+2028/U+2029 (JS
  line terminators even inside a string literal), and the remaining C0
  range, since every header line — and the show variant's own code —
  is treated as untrusted display text on principle. The generated QML
  lands under `$XDG_RUNTIME_DIR` when set (else `temp_dir()`), written
  `0600` from creation — matching `aoide-secrets`' own `store::
  secure_file` discipline even though these files only ever hold display
  data.
- `commands::secrets` — `lyra secrets ask` (P3): the rice-shaped code-entry
  dialog `aoide secrets watch --popup` spawns in place of `zenity --entry`
  once it resolves (`aoide_secrets::watch::resolve_lyra_bin`). Owns only its
  own flags (`--secret`/`--consumer`/`--seconds`/`--reason`/`--from`) and
  header wording ("release `X` -> Y") on top of `commands::dialog_qml`'s
  shared entry surface; speaks zenity's own output contract byte for byte
  (code on stdout + exit 0; `Dismiss ask` on stdout + exit 1; a bare
  cancel, exit 1 with nothing on stdout) so `aoide-secrets`' own
  dialog-result parsing never needs to know which binary answered — that
  crate's `watch.rs` module doc has the wire-side half. `EXIT_INFRA_FAILURE`
  (exit `3`, reserved for a spawn failure or a marker-less quickshell exit,
  never folded into a bare cancel) is a re-export of `dialog_qml`'s own
  constant, kept at this path since `lib.rs`'s `special` hook already
  reads it here.
- `commands::pair` — the pairing ceremony's own TWO dialog commands,
  spawned by `aoide pair watch --popup` in place of the matching zenity
  invocation once `aoide_client::pair_watch::resolve_lyra_bin` finds this
  binary: **`lyra pair ask`** is the six-box entry surface, on EITHER
  pairing direction now (the mutual-code redesign, R1) — `--id`/`--name`/
  `--context` only, no `--code` flag at all, because the whole gate is
  typing a value that arrives from elsewhere (the requester's own screen
  on the approver's inbound leg, the approver's reply code on the
  requester's outbound leg). **`lyra pair show`** (R2) is the reply-code
  DISPLAY surface — `--id`/`--name`/`--context`/`--code` (the last
  REQUIRED: a display dialog with nothing to show would be a blank
  window), rendering this instance's own locally-derived reply SAS large
  and plain with a Copy control and a Done control, no reject control at
  all: it fires AFTER an approver's own commit already succeeded, so
  there is nothing left to approve or reject. Both share
  `commands::dialog_qml`'s underlying surfaces and a
  `AOIDE_PAIR_ASK_RESULT:` marker; `pair ask` alone carries the
  `"Reject request"` dismiss label, since `pair show` has no dismiss path
  to label. `--context` is pre-formatted ONCE by the caller (untrusted,
  node-supplied display text: a requesting host + short id, or a reply
  code's own recipient name) so zenity and the matching lyra dialog
  render byte-identical wording, the same "one place this wording lives"
  discipline `aoide_secrets::watch::format_origin_line` holds for its own
  `--from`. **`pair show` is `pair confirm` (P-PV3, task #132),
  repurposed and renamed**: that command was originally the OUTBOUND
  leg's own Approve/Reject shape — a confirm surface reviewed and kept
  after an earlier pass on the same phase had tried reusing `pair ask`'s
  own entry surface for that direction too (with the code pre-shown as
  context, retyped into the boxes) and a review correctly called that
  copy-the-pixels theater, since the code was already on screen in the
  same window the boxes sat in. The mutual-code redesign (R1) later gave
  the outbound leg a genuinely SECOND code (the approver's own reply
  code, arriving from a different screen) to gate on, which is exactly
  the case that same review's own argument named as real typed entry —
  so the outbound leg moved onto `pair ask` above, and the confirm
  surface's only remaining job became showing the approver's reply code
  back, which is what `pair show` now is.
- `commands::preview` (P1, then a same-lane follow-up) — **`lyra preview
  [<widget>]`** builds an ISOLATED preview root (default
  `$XDG_RUNTIME_DIR/aoide-preview`, chosen deliberately as a SIBLING of the
  live daemon's own `$XDG_RUNTIME_DIR/aoide/` socket dir, never a
  descendant of it — the live reaper and socket globs look there) and
  spawns a standalone `quickshell -p <root>/run/qml/WidgetPreview.qml`
  (P2's own file, not yet landed) against it: its own
  `song/stage/livery.json`, its own
  `state/stage/{sessions,projects,hooks,herald}.json` seeded from a named
  fixture set or a directory (falling back to empty-but-valid defaults
  while no fixture set has landed yet), and its own `run/qml/` — COPIES,
  never symlinks into the checkout: one copy per facet `*.qml`, the facet's
  resolved `icons/` tree (the canvas toolbar's Iconoir glyphs, `lyra icon
  resolve` output already in the checkout), one copied
  tree per non-`_`-prefixed song's `widgets/` dir (`stage_qml_copies`/
  `stage_song_copies`, a stale symlink from an older root replaced), and
  `manifest.json`/`registry.json` copied from the live deployed tree when
  present else `{}`. `preview.json`'s `stage` map (`compute_stage_map`)
  pairs each `watch` entry with its copy so the canvas can refresh the
  copies before a reload; `resolve_widget_abs` maps a `widget` field to the
  CHECKOUT file it names (`songs/<s>/<rest>` → `song/songbook/<s>/widgets/
  <rest>`), never to the copy. `resolve_root` refuses a `..` component and
  any `--root` at, under, or symlink-resolving into the live daemon's dir
  (`live_daemon_dir`: `$XDG_RUNTIME_DIR/aoide`, or storage's own
  `daemon_socket_path()` fallback when that's unset -- read directly rather
  than through `daemon_socket_path()` itself, since that function also
  honors `$AOIDE_DAEMON_SOCKET`, which the canvas's own child env repoints
  at `<root>/no-daemon.sock` and must never make a preview root look like
  the live dir from inside its own canvas) as a usage error. A running
  canvas (`preview.pid` live) blocks only a second LAUNCH on its root;
  `--no-launch` re-stages the copies and merges into the control file
  while it stays up. Every OTHER facet-read stage file
  the isolated root needs merely to exist gets written too:
  `song/stage/mode.json` (`LiveryState.qml`'s own convention — `mode`,
  `song`, `stagingSong`, `since`) is REWRITTEN on every build and on
  `preview set --song`, always naming the current song; `song/stage/
  cover.json`, `song/stage/grimoire.json` (`GrimoireLedger`'s
  `launches: {}`, an object keyed by app id, never an array), and
  `state/usage.json` are seeded once, only if absent, and never clobbered
  by a later rebuild. `--livery <spec>` accepts FOUR
  forms, all resolved through the same
  `aoide_song::livery::resolve::resolve`/`to_json_string` engine
  `lyra livery resolve` itself uses: `live` (the resolved live stage twin,
  read-only), a bare song name (that song's own songbook livery.json), a
  path to a livery file, or a path to a base16 scheme (JSON or the flat
  `key: value` line shape — no yaml crate in this workspace) synthesized
  into a palette per CONTRACTS.md §1's base16 column reversed; default is
  the preview's own `--song`. `preview.json` carries `liverySource` (the
  spec as given, the one name for it) and `liveries` (every songbook song
  with a livery.json of its own, sorted) — never a bare `livery` key: the
  P2 canvas treats `livery` as a legacy alias of `liverySource` and
  deletes it on every save of its own, so both the builder and `preview
  set` drop it on every write (migrating away any legacy key an older doc
  still carries) rather than ping-ponging against the canvas. `preview.json`
  also carries `lyra` (the BUILDING binary's own `std::env::current_exe()`,
  written once at root build and never touched by `preview set`) — the P2
  canvas spawns every rail action against that path instead of a bare
  `lyra` on PATH, since a deployed `lyra` there may predate `preview set`
  entirely and would fail every rail action silently; a control doc from
  before this field existed leaves the canvas falling back to PATH. It also
  carries `watch` (every `*.qml` under the current song's
  own `widgets/` plus the previewed widget's own file when it lives
  elsewhere — the set the P2 canvas hot-reloads against). The child's env
  is rewritten (`AOIDE_ROOT`/`AOIDE_STATE_DIR`/`AOIDE_STAGE_DIR` repointed
  at the isolated root, `AOIDE_DAEMON_SOCKET` at a path that never exists
  so no facet QML can reach the real `aoided` even bypassing a stub
  bridge, and every widget-slot env override — `QS_STAGE`,
  `CONDUCTOR_WIDGET`, etc. — stripped) and `PR_SET_PDEATHSIG`-armed
  exactly like `commands::dialog_qml::spawn_quickshell`'s own discipline,
  rewritten locally rather than imported (that fn is private to its own
  module). A `preview.pid` file (the INVOKING `lyra` process's own pid,
  not quickshell's) refuses a second concurrent `lyra preview` against the
  same root. **`lyra preview set`** edits that root's `preview.json`
  control document (widget size/aspect, viewport size/preset/aspect,
  anchor, margin, zoom, background, fixture, livery) without any canvas
  needing to be running — every given flag is validated (a bad value is a
  usage error naming the allowed set) and merged: existing keys survive,
  only the given ones are overwritten, so a relaunch (or a live edit while
  the P2 canvas hot-reloads off the same file via `FileView`) preserves
  whatever the human last set; `--widget`/`--song` also recompute `watch`.
  Never touches the live desktop on its own — launching the canvas is the
  one side effect, and `--no-launch` skips even that, leaving a plain
  filesystem build a test or a CI check can run with no quickshell
  installed at all. **`lyra preview declare [--slot <name>]`** is the
  canvas's own counterpart of `rice declare` (`commands/stubs.rs`,
  `Self-Ricing.md`'s stage-vs-commit split): it copies the previewed
  widget body (refusing a `widget` outside `run/qml/songs/` — never a
  facet symlink) and, unless `liverySource` is exactly the preview's own
  song (its palette is already checkout truth), the resolved palette
  tiers (`palette`/`base16`/`bar`/`notif`/`window` only — every other
  authored key in the checkout's `livery.json` survives untouched, and
  `song` is never written there) into `song/songbook/<song>/`. Byte-diffed
  so a repeat with nothing new is a true no-op; it never runs `git`,
  touches the live stage, `~/.aoide`, or `run/qml` — the commit and
  rebuild stay the user's own gate (house rule 2), same as `rice declare`.
- `commands::preview_tools` (P6) — shell-first agent tools over that same
  isolated canvas: the QML side only PAINTS what these three commands
  already expose (root `AGENTS.md` house rule 7's "delete every `.qml`"
  test). All three take `--root`/`--json` (same resolution as `preview`)
  and read `ROOT/preview.json`; widget/element operations shell the canvas
  through `qs -p ROOT/run/qml/WidgetPreview.qml ipc call preview <function>
  <args...>` (`qs`'s own error text can land on stdout, not stderr — every
  ipc call reads and joins both so a failure is never silently empty).
  **`lyra preview shot [--what screen|canvas|widget|element] [--element
  <path>] [--annotated] [--out <png>]`** (default `--what widget`; `--out`
  defaults to `ROOT/shots/<what>-<utc-compact>-<pid>-<seq>.png`, a pid+seq
  tail so two shots in the same UTC second never collide; `--element`
  without `--what element` is a usage error): `screen`/`canvas` call
  `aoide_screen::capture::shot` directly (canvas by `--window <addr>`:
  `find_client_address(canvas_pid(root))` — class + title + the pid `qs
  list --all` reports for this root's `WidgetPreview.qml`, so two open
  roots never capture each other; "canvas not running" when absent) —
  its own sidecar (`<out>` with the extension swapped, `aoide-screen`'s
  own convention) is read, folded into ours under a `"capture"` key, and
  deleted, so no orphan `<stem>.json` is left beside `<out>.png.json`.
  `widget`/`element` ALWAYS call the canvas's `shot("widget", ...)` — the
  canvas's own element-kind ipc call is permanently broken (always a
  transparent/failed capture) and is never invoked — then poll for the
  canvas's own success/failure file pair: success writes `<out>` (the
  full widget image) AND `<out>.meta.json`; failure writes `<out>.error`
  (a plain-text message) and no image at all, surfaced verbatim as the
  command's own error. For `--what element`, lyra itself then resolves
  `--element`'s live rect through the same tree join used by `preview
  tree`, opens `<out>` with the `image` crate, crops it to that rect
  (scaled and clamped to the image bounds — an off-canvas or zero-area
  rect is an error, and the file is left as the uncropped widget capture)
  and overwrites `<out>` with the crop; `elementRect` in the sidecar is
  this crop's own pixel rect, never anything from the canvas.
  `<out>.json`/`<out>.meta.json`/`<out>.error` are all `--out`'s FULL value
  with the suffix LITERALLY APPENDED, never an extension swap — `--out
  widget.png` sidecars at `widget.png.json`, never `widget.json`. Every
  kind writes its own `<out>.json` sidecar —
  `{what, out, root, widget, song, widgetWidth, widgetHeight, scale?,
  element?, elementRect?, source?, capture?, notes}` (`capture` is the
  screen/canvas kinds' folded-in `aoide-screen` sidecar, above); for
  widget/element the canvas's own `<out>.meta.json` is `{widgetRect,
  scale}` ONLY — `scale` is merged in, `widgetRect` has no home in this
  sidecar — and the meta file is deleted. `Outcome` data is the sidecar
  object. **`lyra preview tree [--at x,y]`** (`--at` is validated as
  `x,y` before touching the canvas) calls the canvas's
  `tree(out)`, parses the live item tree (`{type, objectName, path,
  rect:{x,y,w,h}, visible, text?, children}`, widget-local coordinates —
  `path` is the canvas's OWN element-path string for that exact node,
  carried verbatim into every command that needs one, never re-derived),
  and joins it against a STATIC parse of the previewed widget's own QML
  source (`resolve_widget_abs`): a line matching `^\s*([A-Z][A-Za-z0-9_.]
  *)\s*\{` opens a node of that type (a dotted spelling like
  `MoodFaces.Face` strips to its last segment), OR a line matching
  `^\s*([a-zA-Z_]\w*)\s*:\s*([A-Z][A-Za-z0-9_.]*)\s*\{` opens one the same
  way while also recording the binding name (`delegate`, `contentItem`,
  `background`, `sourceComponent`, …) — `conductor.qml`'s own `Repeater`s
  all write their delegate as `delegate: Column { id: … }`, never a bare
  `Column {` on its own line, so this second form is not an edge case here,
  it's the ordinary shape a `Repeater`'s delegate takes; skipping it left
  the delegate's real children silently reattached one level too shallow,
  onto the `Repeater` itself (a live run: the `Repeater`'s own `id` field
  reading its delegate's `id: movement`). A binding-form opener's `Type`
  still comes from the SAME dotted-spelling rule; `property var x: { ... }`
  (a JS expression used as a property's value) is excluded with no special
  case — nothing but a plain `{` sits between its `:` and end of line, so
  there is no `Type` for either opener form to accept. `id:`/`objectName:`
  lines attach to whichever node is currently open, braces are counted per
  line with string literals and `//` comments blanked out first — no
  multi-line `/* */` support, and an opener (either form) must be the
  first thing on its own line; good enough for the style this workspace's
  widgets are written in, not a real QML parser (there is no such
  dependency in this workspace).
  Before any of that, at every node, a runtime node's own `type` is
  checked against a `ComponentMap` built from every `*.qml` file named in
  `preview.json`'s `watch` list (the song's `widgets/` directory plus the
  previewed widget's own file, each parsed once): each file registers
  itself keyed by basename, AND every inline `component Name: Type {
  ... }` declaration found while parsing any of those files registers
  itself keyed by `Name` in the SAME map, GLOBALLY — not scoped to its
  declaring file, since QML component names are already expected to be
  unique project-wide; a name collision across files resolves by
  last-file-parsed-wins. A hit either way (`"file"`) switches the static
  context to that entry's own root node (the parsed file's top level, or
  the inline component's own base-type frame and its already-nested
  children) and the runtime children are matched against it for the rest
  of the recursion — this crosses `Loader`/component boundaries
  (`conductor.qml` -> `SessionMenu` -> `SessionCard` -> ...) AND inline
  component boundaries (`conductor.qml`'s own `component SessionCard:
  FocusScope { ... }` — the runtime type is the component's name,
  `SessionCard`, not its base type) that a single-file static parse can't
  see into on its own. Only below that, the join matches a runtime child
  to a static sibling by exact `objectName` first, else by position among
  remaining same-type static siblings under an already-matched parent
  (`"positional"`). Failing both, a runtime sibling of a static `Repeater`
  whose type equals that SAME `Repeater`'s own `delegate:`-bound child's
  type also resolves `"positional"`, against that nested delegate child
  directly — a `Repeater`'s stamped-out instances land in the runtime tree
  as its SIBLINGS, never its children, so ordinary same-level matching
  alone can't reach a delegate one static level down; every instance
  (there may be many) resolves to that ONE static child, sharing its line,
  never consumed the way a normal positional match consumes its static
  sibling. Failing that too, if the FULL static sibling list at that
  level (used or not) has no entry of that runtime node's exact type, the
  node is a framework-synthesized transparent wrapper (`"wrapper"`) —
  `Flickable`/`ListView`'s implicit `contentItem`, a `Loader`'s loaded
  item, and the like — with no static counterpart of its own: its
  `source` is inherited from the nearest ancestor that DID resolve, and
  its OWN children are joined against the SAME static sibling list it
  just failed to match against, rather than against nothing, so a real
  static child one runtime level down (e.g. a `Column` inside a
  `Flickable`'s synthetic `contentItem`) still resolves. A static sibling
  of that exact type existing at that level — even one already claimed by
  an earlier same-type runtime sibling — takes wrapper treatment off the
  table; that case is a genuine mismatch and stays `"none"`. The file
  check runs unconditionally ahead of all of this, so a `"wrapper"` or
  `"none"` node does NOT close off the static side for its descendants —
  only a subtree with no basename/component-typed node anywhere below it
  stays unresolved; this is ORTHOGONAL to `path`, which identifies the
  node, not its static counterpart. Human output is an indented `Type#objectName
  x,y w×h  -> file:line (match)` tree; `--at x,y` returns the DEEPEST
  visible node whose rect contains the point regardless of match kind
  (descending through every containing child, not just matched ones), as
  JSON `chain` (its ancestor path — a different concept from each node's
  own `path` key, named accordingly). **Element path grammar** (shared by `shot
  --element`, `notes --element`, and this join): `Type[i]` per level
  joined by `/`, `#objectName` suffix informational only — `i` counts
  among same-TYPE children at that level, from the previewed widget's own
  root down, in declaration/creation order; CANVAS-AUTHORITATIVE (a
  `Repeater`'s generated items land as SIBLINGS of the `Repeater` in
  `children`, so only the canvas's own numbering is guaranteed to get it
  right) — `resolve_element_path` matches a node's `path` verbatim rather
  than re-deriving it. **`lyra preview notes`** (`[--json]` to read, `--add --text <t>
  [--rect x,y,w,h | --element <path>] [--shape rect|ellipse|arrow|line]`,
  `--done <n>`, or `--clear`) keeps `ROOT/notes.json` —
  `{schemaVersion: 0, notes: [{n, kind, shape?, rect?, element?, text,
  createdAt, done}]}`, atomic writes, `n` = max existing `n` + 1, never
  renumbered (`--clear` empties the list but keeps the file, so the next
  add after a clear restarts at 1 with no surviving max to add onto),
  `kind` = `highlight` for
  `--element`, `shape` for `--shape`, else `note`. On every read, a note's
  `element` is resolved to `source` (`file:line`) through the same tree
  join when the canvas is up; when it isn't, notes print with no `source`
  and the message says so. Human output is one `#n [kind] Type#obj
  (file:line) — text` line per note, done ones prefixed `✓` and dimmed
  (ANSI SGR faint).
- `commands::icon` (I1, `design/p-icon-brief.md`) — `icon collections`/
  `icon list`/`icon resolve`: pack-independent widget icons, Iconify
  `<collection>:<name>` identifiers resolved against a pinned, hashed local
  copy of each collection's IconifyJSON (`pkgs/iconify-data`, `--data <dir>`/
  `$AOIDE_ICON_DATA`), never a network fetch at resolve time. `resolve` is
  the only writer — `<out>/<collection>/<name>.svg` (or `<out>/custom/
  <slug>.<ext>` for a `file:<path>`/bare-path asset) plus one `<out>/
  catalog.json` — byte-diffed (`preview declare`'s no-op discipline) and
  PRUNING any asset the current selection no longer names. The SVG assembly
  is a direct port of upstream Iconify's own `@iconify/utils` alias-chain
  fold and `iconToSVG`/`iconToHTML` string math (module doc cites the
  fetched source lines). **Not yet wired into `commands::all()`** — landed
  ahead of the concurrent preview lane per its own dispatch's registry
  procedure; the integrator appends `pub mod icon;` + `icon::register(&mut
  r)` last and the three golden paths (54 → 57) in the same commit that
  resolves that lane.

## What it consumes

`aoide-protocol`, `aoide-song`, `aoide-conduct` (for the `shellbridge`/
`herald` registry lines), `aoide-screen`, `aoide-server` (for `mcp
serve --stdio`'s door loop).

## How it composes

54 command paths: onboard/rice/draft/mode/cover/livery/quickshell/screen/
shellbridge/herald/take/element/secrets ask/pair ask/pair show/preview/
preview set/preview declare/preview shot/preview tree/preview notes —
everything that paints, or that only a desktop needs.
`element seed` (L-E1,
docs/architecture/ELEMENTS.md) renders a song's committed
`elements/*/element.json` (non-QML rice targets — waybar, dunst, anything
with a config file) into `run/elements/`. Never depends on
`aoide-client`/`aoide-conductor` — no A2A client, no TUI; those stay
core-only. May depend on Nix (`song::widgets`'s `nix eval`, and now
`commands::onboard`'s own `nix eval`/`nix-instantiate` shell-outs) — the
one binary allowed to (root `AGENTS.md`, "core is nix-independent").
