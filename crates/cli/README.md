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
  hook (`mcp serve --stdio`, `a2a serve`, `secrets serve`, `secrets exec`,
  `secrets enroll`, `secrets watch`, `events tail`, `peer pair watch`
  (P-P5), `conductor`, `guide`/`schema` raw output).
- `registry` — the golden command-path snapshot test (75 paths — this
  number tracks `crates/cli/src/registry.rs`'s own golden list; that file
  is the source of truth, this prose a restatement of it).
- `guide` — `aoide guide`, the onboarding tier map.
- `commands` — the root-coupled groups that must read the ASSEMBLED
  registry: `meta` (guide/schema), `stubs` (not-yet-implemented
  placeholders), `onboard` (`aoide onboard`, P-I2 — the first-boot flow:
  registers the clone, seeds the songbook, wires harness hooks by calling
  the already-registered `hooks.install` handler directly off the registry,
  probes for `lyra` and delegates the nix half to `lyra onboard` as a child
  process when it resolves, prints the closing guide), `infra` (`mcp
  serve`'s tool-count reporting). Every other command group lives in its
  domain crate and is pulled in here by `commands::all()`.
- `a2a`/`mcp`/`daemon`/`graph`/`output` — thin root-level wiring over the
  matching domain crate for the two binaries' entry points.

## What it consumes

`aoide-protocol`, `aoide-storage`, `aoide-conduct`, `aoide-client`,
`aoide-server`, `aoide-conductor`, `aoide-upkeep`, `aoide-secrets` (new at
P-V2). The DAG sink for core: depends on everything core needs, nothing
depends on it.

## How it composes

75 command paths (core's headless-capable, agent-orchestration surface: the
project/session graph (including `resurrect`, its ledger-backed
session revival), A2A, peers (including the `peer hub` designation,
P-D5, the `peer pair request|pending|approve|reject|watch` pairing
ceremony, P-P2/P-P5, the `peer allow <name> <cap> on|off`
closed-capability grant/revoke command backing the A2A spawn arm's hard
gate, P-P3, `peer spawn <name> -- <text…>`, P-P5b, the signed
spawn-shaped `message/send` that actually reaches that gate, and `peer
discover [--secs N]`/`peer invite <name> [--secs N] [--yes]`/`peer
advertise on|off`, P-P6 + task #120, the LAN discovery advertisement's
read-only sweep, its sugar-over-the-ceremony invite, and this instance's
own advertise switch), presence, the
daemon, its own event bus (`events tail`), usage, hooks, the message
inbox, the secrets broker, this instance's own `identity` (P-P1 of the
pairing workstream, `docs/architecture/PAIRING.md`)).
Never depends on
`aoide-song`/`aoide-screen` — painting is `lyra`'s bundle, assembled the
same way against the same domain crates' `commands` modules.
