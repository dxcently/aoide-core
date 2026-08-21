# AGENTS.md — aoide-protocol

## Invariants

- **This crate stays the DAG leaf.** It must never gain a dependency on
  another `aoide-*` crate — that would create a cycle back into a door this
  crate is supposed to be beneath. If a type feels like it needs a
  domain-crate fact, the fact belongs in the caller, not here.
- **Wire/schema shape is a published contract.** `registry`, `output::Outcome`,
  `wire`'s A2A/MCP payload shapes, and `state::canonical_state` are read by
  `schema --json` consumers outside this repo. A shape change is
  schema-visible; treat it like an API break, not a refactor.
- **`door::run`'s `special` hook is the only sanctioned one-shot escape.**
  A binary that needs to bypass the generic `Outcome` envelope (raw stdout,
  a long-running server) adds a case to its own `special` closure — never a
  second run loop.

## Extension points

- **A new door-shared type or macro** (something every domain crate would
  otherwise reimplement) lands in the matching module here.
- **A new agent harness** (beyond `claude`/`kimi`/`pi`) is a new
  `agents::agent_profile` table entry, not a scatter of `if harness == ...`
  conditionals elsewhere.
- **A new binary needing sibling-binary resolution** adds a tier to
  `bin.rs`'s resolver; it never hardcodes a bare `PATH` name.

## Docs update required in the same commit

- This `README.md` when a public module or seam is added or removed.
- `CONTRACTS.md` when a wire/schema shape changes.
- `pkgs/aoide/crates/AGENTS.md` is the layer above for registry-order and
  golden-discipline invariants that apply to CONSUMERS of this crate's
  `Registry` — this file only covers what changes here.
