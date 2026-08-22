# aoide-protocol

The single contract every door depends on: "one schema, N doors"
(`docs/architecture/PACKAGE-LAYOUT.md`, CONTRACTS.md §3) is structural here,
not conventional. Zero aoide-specific dependencies — the DAG leaf every
other crate in this workspace sits above.

## Named seams (what it exposes)

- `registry` — `Registry`/`Command`/`Arg`/`Flag` + the `cmd!`/`arg!`/`flag!`
  registration macros. Every domain crate's `commands::register` builds one
  of these; `schema --json`, the MCP tool list, and the A2A `AgentCard` all
  derive from the assembled `Registry`.
- `invocation` — `Invocation`, the parsed call handed to a dispatcher.
- `output` — `Outcome` + exit codes, the generic envelope every command
  returns.
- `audit` — `append_audit`/`audit`/`Door`/`EventClass`/`audit_log_path`, the
  one audit log both doors write through (root `AGENTS.md` house rule 6).
  `EventClass::Secret` (Workstream VAULT, P-V2) is the vault broker's
  name-only mirror (secret name, consumer, granted/denied — never a
  value); `append_audit` structurally forbids `untrusted_data` on that one
  class, stripping it (with an `eprintln!`, never a panic — an audit call
  must never take its caller down) rather than trusting every call site to
  never set it.
- `door` — the hand-rolled parse → dispatch → render run loop (`run`),
  parameterized by a `special` hook so each binary's one-shot exceptions
  (`mcp serve --stdio`, `a2a serve`, `conductor`, `guide`/`schema` raw
  output) don't fork the loop itself.
- `state` — `canonical_state`, the session-state vocabulary every producer
  folds onto and every reader trusts verbatim.
- `wire` — typed A2A-JSON-RPC and MCP payload shapes.
- `agents` — `agent_profile`, the per-harness knowledge table (hook
  vocabulary, model ceilings, transcript layout) keyed by harness name.
- `bin` — sibling-binary resolution (`core_bin`/`rice_bin`; env override →
  sibling-of-`current_exe` → bare `PATH` name).
- `pick`, `model`, `policy` — the numbered picker + tty gate, model context
  ceilings, and the daemon's `Gate`/`Subscription` policy types.

## What it consumes

Nothing aoide-specific. This is the one crate every other crate in the
workspace (`storage`, `client`, `conduct`, `screen`, `server`, `song`,
`conductor`, `upkeep`, and both app crates) depends on, directly or
transitively.

## How it composes

It is the boundary that makes "one schema, N doors" structural: a door
(CLI, MCP, A2A) is just a caller of `door::run` against a `Registry` this
crate defines the shape of. Neither app crate (`cli`, `lyra`) nor any
domain crate re-derives dispatch, audit, or wire framing independently.
