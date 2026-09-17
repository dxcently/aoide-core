# aoide-protocol

The single contract every door depends on: "one schema, N doors"
(`docs/architecture/PACKAGE-LAYOUT.md`, CONTRACTS.md §3) is structural here,
not conventional. Zero aoide-specific dependencies — the DAG leaf every
other crate in this workspace sits above.

## Named seams (what it exposes)

- `registry` — `Registry`/`Command`/`Arg`/`Flag` + the `cmd!`/`arg!`/`flag!`
  registration macros. Every domain crate's `commands::register` builds one
  of these; `schema --json`, the MCP tool list, and the A2A `AgentCard` all
  derive from the assembled `Registry`. `Registry::schema` takes `bin_name`
  and additionally builds `Schema::external` (task #138) via `bin::
  discover_external` — `ExternalCommand` entries, never `Command`s: an
  external subcommand cannot become one (`Command` is entirely `&'static`;
  `Registry::insert` panics on a duplicate path), so it is structurally
  excluded from the MCP tool list and the A2A `AgentCard` the same way it
  never enters the golden.
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
  never set it. `append_audit` also clamps `AuditRecord.message` to 512
  bytes on a UTF-8 boundary, appending a truncation marker when it clamps:
  the log records that an operation happened, not what it printed, so a
  command whose outcome message is also its rendered output (`aoide mail
  show`'s whole letter) never leaves a second, unbounded copy sitting in
  the log. Only the stored copy is bounded — the `Outcome` itself, and
  every door's human/JSON rendering of it, is untouched.
- `door` — the hand-rolled parse → dispatch → render run loop (`run`),
  parameterized by a `special` hook so each binary's one-shot exceptions
  (`mcp serve --stdio`, `a2a serve`, `conductor`, `guide`/`schema` raw
  output) don't fork the loop itself. `parse` also resolves CLI-only
  ergonomic shorthands (`ALIASES`, e.g. `node rm` for `node remove`) to
  their canonical path before the greedy match runs, so a shorthand is
  never a second registered command — the registry, `schema --json`, and
  every golden snapshot see only the canonical spelling. Flag arity is the
  registry's call, not the spelling's: a flag declared `"bool"` never
  consumes the following token as its value (`node add --no-verify alice`
  keeps `alice` positional), a valued flag consumes exactly one, and any
  token that reads both ways — a value colliding with a command-path
  segment, or a flag bool-for-one-candidate valued-for-another — is a loud
  usage error naming both spellings, never a silent guess. `run` also
  probes raw argv, immediately BEFORE `parse` runs, for a fallthrough to an
  executable `<bin_name>-<name>` on `PATH` (task #138, the git/cargo
  pattern) — a first-segment reservation (every registered command's own
  head, plus every `ALIASES` head) means a built-in always wins and a typo
  of one still reaches `parse`'s own did-you-mean; a hit audits one line
  then spawns `argv[1..]` verbatim, `Stdio::inherit()` throughout,
  returning the child's own exit code unchanged. The door boundary here is
  structural, not a guard: `run` is called from exactly the two CLI entry
  points (`aoide-cli`'s `run_cli`, lyra's `run_lyra`), so this is reachable
  from `Door::Cli` only — no `Door` check is added, because `dispatch` (the
  one door-agnostic dispatch point MCP/A2A/the aoided socket call directly)
  has no PATH-probing logic of its own and must never gain any.
- `feed` — the append-only JSON-lines feed primitive: `FeedWriter` (append
  one JSON object per line, capped and truncated-in-place rather than
  rotated) and `Follower` (tail one file from EOF, delta-reads only,
  transparently reopening across both an in-place truncation and a
  delete-and-recreate). Extracted from `aoide-secrets`' broker/watch
  modules (`docs/architecture/AOIDED.md`'s "L1 — the event bus" section) so
  `aoided`'s own event bus and any future producer/consumer pair can share
  it — `aoide-secrets` consumes it via `pub use` at its old
  `watch::Follower` path.
- `dialog` — the code-entry dialog substrate: `DialogResult` (a dialog
  child's outcome — approved/dismissed/cancelled/cancelled-externally/
  spawn-error/infra-failure) and `run_entry_dialog` (the generic
  spawn-poll-parse loop behind it), the screen-lock probes a popup gate
  consults first (`locked_state`, `is_locked`, `probe_loginctl_locked`,
  `probe_locker_running`, `locker_process_name`), the spawn-retry backoff
  (`next_spawn_backoff` + its floor/ceiling) and its interruptible sleep
  (`sleep_backoff_interruptible`, #108 — chops the backoff into ~200ms
  ticks against a caller-owned `AtomicBool` so Ctrl-C/shutdown never waits
  out the full up-to-60s backoff), and the one pure
  `strip_one_trailing_newline` trim every dialog child's stdout is read
  through. Extracted from `aoide-secrets`' `watch`/`client` modules (P-P5,
  same `feed`-precedent shape above) so a SECOND dialog consumer
  (`aoide-client`'s own pairing-confirm popup) shares it rather than
  forking a copy — `aoide-secrets` consumes every item back at its old
  `watch::`/`client::` paths via a `use`/`pub use` shim, matching whichever
  visibility each item already had there.
- `state` — `canonical_state`, the session-state vocabulary every producer
  folds onto and every reader trusts verbatim.
- `wire` — typed A2A-JSON-RPC and MCP payload shapes. MCP's
  `InitializeResult` (`wire::mcp`) carries `capabilities.experimental
  ["claude/channel"]` (an empty object, serde-renamed since `/` isn't a
  Rust identifier) and `instructions`, both unconditional (CONTRACTS.md §3,
  P-M5c-2) — the Claude Code channel capability announcement and the prose
  telling the model events arrive one-way as `<channel source="aoide">`.
- `agents` — `agent_profile`, the per-harness knowledge table (hook
  vocabulary, model ceilings, transcript layout, the hook-settings and
  skills-directory locations, the argv that launches a harness fresh and,
  where verified, the argv that resumes a prior session of it by its own
  id — P-D7 — and, where a harness offers one, the argv that delivers a
  message to a live session WITHOUT the pty composer at all —
  `native_send`, P-EIDOLON) keyed by harness name. `on_path` (P-I2,
  ONBOARD.md decision 7) is the `AgentProfile`-shaped wrapper over
  `bin::on_path`, over the profile's own `launch` program name — onboard's
  harness-picker preselection. The table gains a fourth row for `eidolon`,
  which has no hook file at all: its `hook_settings` names a Nix-owned
  config path only so `hooks install`'s Declarative refusal has something
  concrete to cite, its transcript is a single small swarm presence file
  (`meta.json`) rather than an append-only per-session log, so
  `permission_keys`, `skills_dir`, `resume_args`, and the transcript's
  `say`/`tool`/`context_tokens` are named-absent rather than filled — and
  it is the one profile so far with `native_send: Some(...)`, since a
  message to it never needs the pty composer a keystroke path would
  otherwise reach. `TranscriptSpec::trace` (`Option<fn(&Path) ->
  Option<Vec<String>>>`) is the new HARNESS CAPABILITY on the same table —
  `Some` only for a harness that mirrors its journal as one JSON record per
  line and names that file from its own presence metadata (eidolon, via
  `eidolon_trace_tail`); `None` for every harness whose only on-disk turn log
  is its transcript. It is what lets a consumer that needs a trace test for
  one without ever naming a harness by string (`if agent == "eidolon"` is
  exactly the scatter this table exists to avoid) — `aoide session trace` is
  its first caller. `eidolon_transcript_locate` returns that trace when the
  presence names one that exists (else `meta.json`, the stand-in it always
  returned), and `eidolon_transcript_tail` routes on the extension — so
  every extractor reads either shape. `TraceRecord`/`eidolon_trace_record`
  parse ONE trace line into its variant name and payload, the shape
  `docs/architecture/EIDOLON-TRACE.md` fixes (eidolon owns it; Aoide reads
  it) — the same parse `conduct`'s state fold reads, never a second one.
- `bin` — sibling-binary resolution (`core_bin`/`rice_bin`; env override →
  sibling-of-`current_exe` → bare `PATH` name), plus `on_path` (P-I2,
  ONBOARD.md decision 3): the proactive `PATH` probe the resolver's own
  bare-name tier deliberately leaves for `Command::spawn` to resolve at
  exec time — the caller onboard's own lyra probe needs, checked BEFORE
  spawning rather than caught as an `ENOENT` after. `resolve_executable_on_
  path` (task #138) is the SPAWNABLE sibling of `on_path`: it additionally
  checks the executable bit and returns the resolved absolute path rather
  than a bool — kept as its own walk rather than widening `on_path`'s
  contract, since `on_path`'s existing callers accept a non-executable
  same-named file as "found." `discover_external` walks all of `PATH` for
  every `<bin_name>-<name>` executable, sorted by name — the one PATH-scan
  `door::run`'s external-command probe and `registry::Schema`'s additive
  `external` key (CONTRACTS.md §3) both build on.
- `pick` — the interactive prompt substrate (ONBOARD.md's "Prompt substrate"
  section, P-I1): `interactive`, the [`Door::Cli`] + tty gate a caller checks
  BEFORE opening any prompt at all, and five entry points a caller reaches
  for once it has — `choose`/`choose_many` (single/multi-select),
  `confirm` (y/N), `hidden_input` (password entry), `text_input` (one
  echoed line — `hidden_input`'s visible sibling, for input the typist
  must see, like `aoide pair`'s typed pairing code). Each forks on
  whether stdin/stdout are a capable terminal: a capable tty backs
  `choose`/`choose_many`/`confirm` with `inquire::Select`/`MultiSelect`/
  `Confirm`, and is the ONLY backend `hidden_input` (`inquire::Password`,
  no confirmation, hidden display mode) and `text_input` (`inquire::Text`)
  have — everything else (piped, redirected, or `TERM=dumb`, which
  reports as a real tty but by convention cannot render ANSI) keeps the
  ORIGINAL hand-rolled `BufRead`-driven core (`choose_reading`/
  `choose_many_reading`/`confirm_reading`) byte-identical. `inquire`
  (crates.io, minimal `crossterm`-only feature set) is this crate's own
  dependency, and stays that way — every other crate reaches these
  entry points through this seam, never `inquire` directly ("wrap, don't
  scatter"; the DAG-leaf invariant below still holds, since `inquire` is
  a third-party crate, not an `aoide-*` one).
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
