# AGENTS.md — aoide-cli

## Invariants

- **This is core. It never depends on `aoide-song`/`aoide-screen`.** Adding
  either dependency here reintroduces the graphical surface P-A5 removed
  (golden 87 → 48) — a headless box must be able to build/run this crate
  with no wayland/image/nix weight anywhere in its tree.
- **`commands::all()`'s order is byte-stable.** It reproduces the historical
  `schema.rs` table order; `schema --json` and the MCP tool list must never
  reorder. Append new `register()` calls, never reorder existing ones — see
  `pkgs/aoide/crates/AGENTS.md`.
- **`meta`/`stubs`/`infra` stay here, not in a domain crate.** They exist
  because they read the fully-ASSEMBLED registry (tool count, schema dump) —
  a domain crate can't do that without depending on this crate, which would
  invert the DAG.
- **Nix-independent.** No nix shell-outs, no NixOS assumption, anywhere in
  this crate or what it depends on (root `AGENTS.md`, "core is
  nix-independent"). Only `lyra` may be nix-dependent.

## Extension points

- **A new root-coupled command** (one that must read the assembled
  registry) adds a case to `meta`/`infra`; anything else belongs in its
  domain crate's own `commands` module instead.
- **A new special-cased command** (bypassing the generic `Outcome` envelope)
  extends the `special` closure passed to `aoide_protocol::door::run` in
  `run_cli`.

## Docs update required in the same commit

- This `README.md` when the command count, a root-coupled group, or a
  special-cased command changes.
- The golden snapshot in `registry.rs` when the command-path set changes.
- `docs/architecture/PACKAGE-LAYOUT.md`/`CONTRACTS.md §3` when the
  core/lyra split itself shifts.
