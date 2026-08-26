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
  returns. `Outcome`/`Status` derive `Deserialize` as well as `Serialize`
  (P-D6, `docs/architecture/AOIDED.md`'s "L4"): the daemon door's client
  half (`aoide-client`'s `daemon_dispatch`) parses a real `Outcome` back
  out of the wire's `{"outcome": ...}` reply rather than re-deriving a
  second envelope shape — `changed`/`data` pair `#[serde(default)]` with
  their existing `skip_serializing_if`, so a field this crate omits on
  serialize (an empty `changed`, an absent `data`) still deserializes
  cleanly instead of erroring "missing field."
- `audit` — `append_audit`/`audit`/`Door`/`EventClass`/`audit_log_path`, the
  one audit log both doors write through (root `AGENTS.md` house rule 6).
  `EventClass::Secret` (Workstream SECRETS, P-V2) is the secrets broker's
  name-only mirror (secret name, consumer, granted/denied — never a
  value); `append_audit` structurally forbids `untrusted_data` on that one
  class, stripping it (with an `eprintln!`, never a panic — an audit call
  must never take its caller down) rather than trusting every call site to
  never set it.
- `door` — the hand-rolled parse → dispatch → render run loop (`run`),
  parameterized by a `special` hook so each binary's one-shot exceptions
  (`mcp serve --stdio`, `a2a serve`, `conductor`, `guide`/`schema` raw
  output) don't fork the loop itself.
- `feed` — the append-only JSON-lines feed primitive: `FeedWriter` (append
  one JSON object per line, capped and truncated-in-place rather than
  rotated) and `Follower` (tail one file from EOF, delta-reads only,
  transparently reopening across both an in-place truncation and a
  delete-and-recreate). Extracted from `aoide-secrets`' broker/watch
  modules (`docs/architecture/AOIDED.md`'s "L1 — the event bus" section) so
  `aoided`'s own event bus and any future producer/consumer pair can share
  it — `aoide-secrets` consumes it via `pub use` at its old
  `watch::Follower` path.
- `state` — `canonical_state`, the session-state vocabulary every producer
  folds onto and every reader trusts verbatim.
- `wire` — typed A2A-JSON-RPC and MCP payload shapes.
- `agents` — `agent_profile`, the per-harness knowledge table (hook
  vocabulary, model ceilings, transcript layout, the hook-settings and
  skills-directory locations, and — P-D7 — the argv that launches a harness
  fresh and, where verified, the argv that resumes a prior session of it by
  its own id) keyed by harness name.
- `bin` — sibling-binary resolution (`core_bin`/`rice_bin`; env override →
  sibling-of-`current_exe` → bare `PATH` name).
- `pick` — the interactive prompt substrate (ONBOARD.md's "Prompt substrate"
  section, P-I1): `interactive`, the [`Door::Cli`] + tty gate a caller checks
  BEFORE opening any prompt at all, and four entry points a caller reaches
  for once it has — `choose`/`choose_many` (single/multi-select),
  `confirm` (y/N), `hidden_input` (password entry). Each forks on whether
  stdin/stdout are a capable terminal: a capable tty backs `choose`/
  `choose_many`/`confirm` with `inquire::Select`/`MultiSelect`/`Confirm`,
  and is the ONLY backend `hidden_input` (`inquire::Password`, no
  confirmation, hidden display mode) has — everything else (piped,
  redirected, or `TERM=dumb`, which reports as a real tty but by
  convention cannot render ANSI) keeps the ORIGINAL hand-rolled
  `BufRead`-driven core (`choose_reading`/`choose_many_reading`/
  `confirm_reading`) byte-identical. `inquire` (crates.io, minimal
  `crossterm`-only feature set) is this crate's own dependency, and stays
  that way — every other crate reaches these four functions through this
  seam, never `inquire` directly ("wrap, don't scatter"; the DAG-leaf
  invariant below still holds, since `inquire` is a third-party crate, not
  an `aoide-*` one).
- `model`, `policy` — model context ceilings, and the daemon's
  `Gate`/`Subscription` policy types.

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
