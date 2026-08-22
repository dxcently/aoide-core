# aoide-cli (lib `aoide`)

The core app crate — the `aoide`/`aoided` binaries. In Cordis terms
(CONTRACTS.md §0): this crate is a dsh-style BUNDLE, the ordered composition
performed at boot; its assembled `Registry` is the plugin tree. Its explicit
`commands::all()` list is the bundle's PROFILE, not a "registry an author
must edit to be seen" violation — composing a bundle at its root is how
Cordis composes too (`docs/architecture/PACKAGE-LAYOUT.md`, "Cordis
correspondence").

## Named seams (what it exposes)

- `bin/{aoide,aoided}` — the two binary entry points.
- `cli`/`dispatch` — argv parsing and the dispatcher, over
  `aoide_protocol::door::run`'s shared skeleton with core's own `special`
  hook (`mcp serve --stdio`, `a2a serve`, `conductor`, `guide`/`schema` raw
  output).
- `registry` — the golden command-path snapshot test (52 paths).
- `guide` — `aoide guide`, the onboarding tier map.
- `commands` — the three root-coupled groups that must read the ASSEMBLED
  registry: `meta` (guide/schema), `stubs` (not-yet-implemented
  placeholders), `infra` (`mcp serve`'s tool-count reporting). Every other
  command group lives in its domain crate and is pulled in here by
  `commands::all()`.
- `a2a`/`mcp`/`daemon`/`graph`/`output` — thin root-level wiring over the
  matching domain crate for the two binaries' entry points.

## What it consumes

`aoide-protocol`, `aoide-storage`, `aoide-conduct`, `aoide-client`,
`aoide-server`, `aoide-conductor`, `aoide-upkeep`. The DAG sink for core:
depends on everything core needs, nothing depends on it.

## How it composes

52 command paths (core's headless-capable, agent-orchestration surface: the
project/session graph, A2A, peers, presence, the daemon, usage, hooks, the
message inbox). Never depends on `aoide-song`/`aoide-screen` — painting is
`lyra`'s bundle, assembled the same way against the same domain crates'
`commands` modules.
