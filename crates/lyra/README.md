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
  command-path snapshot (44 paths), independent of core's.
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
  `guide`/`schema`/`livery`/`secrets ask` raw output). Deliberately absent:
  `a2a serve`, `conductor`.
- `commands::secrets` — `lyra secrets ask` (P3): the rice-shaped code-entry
  dialog `aoide secrets watch --popup` spawns in place of `zenity --entry`
  once it resolves (`aoide_secrets::watch::resolve_lyra_bin`). Writes a
  generated QML file to a scratch temp path and spawns `quickshell -p
  <path>` as a genuinely standalone process — the first command in this
  crate to do that (`song::commands::quickshell`'s own `quickshell reload`
  only ever sends IPC into an ALREADY-running instance). Speaks zenity's own
  output contract byte for byte (code on stdout + exit 0; `Dismiss ask` on
  stdout + exit 1; else non-zero) so `aoide-secrets`' own dialog-result
  parsing never needs to know which binary answered — see that crate's
  `watch.rs` module doc and this crate's own `commands/secrets.rs` module
  doc for the full mechanism, including the two live-quickshell findings
  (`console.log` lands on stdout, not stderr; a bare `Window {}` tiles under
  Hyprland unless it also declares a fixed-size hint) neither doc repeats
  from the other. `quickshell` itself is a runtime shell-out declared BY
  NAME — zero new Cargo dependencies (the same feature-detection posture
  `aoide-secrets`' own `zenity`/`qrencode` shell-outs already hold); it is
  simply assumed present here, since `lyra` itself is fundamentally built on
  Quickshell already.

## What it consumes

`aoide-protocol`, `aoide-song`, `aoide-conduct` (for the `shellbridge`/
`herald` registry lines), `aoide-screen`, `aoide-server` (for `mcp
serve --stdio`'s door loop).

## How it composes

44 command paths: onboard/rice/draft/mode/cover/livery/quickshell/screen/
shellbridge/herald/take/secrets ask — everything that paints, or that only a
desktop needs. Never depends on `aoide-client`/`aoide-conductor` — no A2A client, no
TUI; those stay core-only. May depend on Nix (`song::widgets`'s `nix eval`,
and now `commands::onboard`'s own `nix eval`/`nix-instantiate` shell-outs)
— the one binary allowed to (root `AGENTS.md`, "core is nix-independent").
