# AGENTS.md — invariants across every crate in `pkgs/aoide/crates/`

Cross-crate rules only. A crate's own `AGENTS.md` holds what's local to it;
this file holds what would otherwise be repeated in all eleven. Points up to
the root `AGENTS.md` for the core-vs-lyra/AoideOS boundary and the house
rules that govern the whole repo.

## Registry order is load-bearing

`schema --json`, the MCP tool list, and the A2A `AgentCard` all derive from
the single `Registry` each app crate assembles
(`cli/src/commands/mod.rs::all()`, `lyra/src/commands/mod.rs::all()`) — see
`aoide-protocol::registry`'s module doc. The assembly order reproduces the
historical table byte-for-byte; **never reorder an existing `register()`
call**, only append. A command's home is its domain crate's own `commands`
module — nothing outside a domain's `register(&mut Registry)` function
enumerates that domain's commands.

## Golden discipline

Both app crates pin their exact command-path set in a golden snapshot test
(`cli/src/registry.rs::command_paths_match_the_golden_snapshot`,
`lyra/src/registry.rs`, same name). Adding, removing, or renaming a command
updates the matching golden list in the SAME commit as the `register()`
change — a red golden test is never "expected," it's the signal a
`commands::all()` edit forgot its snapshot.

## No cross-crate copying

Every crate born from the Phase 2–9 restructure carries a shim-discipline
note in its `lib.rs`: a moved symbol is re-exported at its old path via
`pub use`, never duplicated. The same discipline applies going forward —
reach into another crate's public API (`aoide_conduct::graph::normalize_addr`
is `screen`'s example), never copy its logic in. If a symbol a consumer
needs is `pub(crate)`, widen it; don't fork it.

## Per-crate tests only

`cargo test -p <crate>`, never `cargo test --workspace` on this machine —
`aoide-conduct`/`aoide-server` bind real sockets and a workspace-wide run
deadlocks locally. Each domain crate that touches process-global env
(`AOIDE_STAGE_DIR`, `AOIDE_AUDIT_LOG`, …) carries its own `env_lock()`
(delegating to `aoide-test-support::env_lock()` where it's a dev-dependency)
so its tests serialize against each other without needing to coordinate
across crates in the same process.

## Extension points, cross-crate

- **A new domain crate**: add it to `pkgs/aoide/Cargo.toml`'s `[workspace]
  members`, give it a `commands` module with `register(&mut Registry)`, wire
  that into the owning app crate's `commands::all()` (core → `cli`, paint →
  `lyra`), and add its golden README/AGENTS pair here.
- **A new command on an existing crate**: add a `cmd!`/`arg!`/`flag!` entry
  (`aoide-protocol::registry`) inside that crate's own `commands` module;
  the two app crates never need an edit for a command that isn't moving
  binaries.

## What needs a docs update in the same commit

- This crate's own `README.md`/`AGENTS.md` when its seams, deps, or
  invariants change.
- The owning app crate's golden snapshot when the command-path set changes.
- `docs/architecture/PACKAGE-LAYOUT.md` when a crate's charter changes —
  the per-crate READMEs distill it, never contradict it.
