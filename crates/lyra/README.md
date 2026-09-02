# aoide-lyra (bin `lyra`)

The paint app crate — the second composition root over the same
domain-crate handler code `aoide-cli` assembles (P-A4). In Cordis terms
(CONTRACTS.md §0): a BUNDLE, same as `cli` — its own ordered
`commands::all()` profile over an independent `Registry`. Owns the
self-ricing loop, `screen`, `herald`, `shellbridge`, and `quickshell`;
deliberately never conducting, the graph, A2A, peers, or the daemon (those
are core `aoide` identity, root `AGENTS.md`).

## Named seams (what it exposes)

- `bin/lyra` — the binary entry point.
- `dispatch`/`registry` — lyra's own argv parsing, dispatch, and golden
  command-path snapshot (48 paths), independent of core's.
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
  ask, which lost its peer name and its request id that way. Extracted from `commands::secrets` (P3's original
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
  peer-supplied display text: a requesting host + short id, or a reply
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

## What it consumes

`aoide-protocol`, `aoide-song`, `aoide-conduct` (for the `shellbridge`/
`herald` registry lines), `aoide-screen`, `aoide-server` (for `mcp
serve --stdio`'s door loop).

## How it composes

48 command paths: onboard/rice/draft/mode/cover/livery/quickshell/screen/
shellbridge/herald/take/element/secrets ask/pair ask/pair show —
everything that paints, or that only a desktop needs. `element seed` (L-E1,
docs/architecture/ELEMENTS.md) renders a song's committed
`elements/*/element.json` (non-QML rice targets — waybar, dunst, anything
with a config file) into `run/elements/`. Never depends on
`aoide-client`/`aoide-conductor` — no A2A client, no TUI; those stay
core-only. May depend on Nix (`song::widgets`'s `nix eval`, and now
`commands::onboard`'s own `nix eval`/`nix-instantiate` shell-outs) — the
one binary allowed to (root `AGENTS.md`, "core is nix-independent").
