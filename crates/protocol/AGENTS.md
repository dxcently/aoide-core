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
- **`output::Outcome`/`Status` are round-trippable, not serialize-only —
  keep every field's `#[serde(skip_serializing_if = ...)]` paired with
  `#[serde(default)]` (P-D6).** The daemon door's client half parses a
  real `Outcome` back out of a wire reply (`aoide-client`'s
  `daemon_dispatch`); a field omitted on serialize (an empty `changed`, an
  absent `data`) has to reconstruct on deserialize without `serde` erroring
  "missing field." A future field on `Outcome`/`Status` that skips
  serializing when absent/default needs the same pairing, or a daemon
  reply that omitted it stops parsing.
- **`door::run`'s `special` hook is the only sanctioned one-shot escape.**
  A binary that needs to bypass the generic `Outcome` envelope (raw stdout,
  a long-running server) adds a case to its own `special` closure — never a
  second run loop.
- **`feed::Follower::poll` MUST stat the PATH on every call, never only the
  open fd.** A producer restart under a `RuntimeDirectory=`-shaped tmpfs
  unlinks the file the fd still refers to; Linux keeps that deleted inode
  readable with its length FROZEN at deletion, so a length-only comparison
  can never see a same-or-larger replacement land at the same path — the
  `(dev, ino)` comparison against `std::fs::metadata(&self.path)` is what
  makes a delete-and-recreate (or a rename-away-and-recreate) transparent
  to a live tail instead of silently going deaf forever. Don't collapse
  this back to a bare `self.file.metadata()?.len()` check "for simplicity."
- **`feed::FeedWriter::append` truncates past `cap`, never rotates.** A
  feed is ephemeral cues, not an audit trail (that stays
  `aoide_protocol::audit`, unbounded, on a different path); rotation would
  need a second file and a retention policy neither this module nor any
  current caller wants. `Follower::poll`'s own `len() < pos` reopen-at-0
  branch is what makes a truncate-in-place transparent to a live tail —
  don't add rotation without re-deriving whether that branch still covers
  it.
- **Both halves stay pure I/O with no policy about WHAT a line means.**
  `feed` doesn't parse, validate, or interpret payload shape — it only
  frames one JSON value per line. A record shape (like `aoide-secrets`'
  `{"event": ..., "secret", "consumer", ...}` or `aoided`'s own
  `{"v":0,"class":...}`) is the CALLER's contract, decided beside that
  caller's own producer/consumer code, never encoded here.

## Extension points

- **A new door-shared type or macro** (something every domain crate would
  otherwise reimplement) lands in the matching module here.
- **A new agent harness** (beyond `claude`/`kimi`/`pi`) is a new
  `agents::agent_profile` table entry, not a scatter of `if harness == ...`
  conditionals elsewhere.
- **A new binary needing sibling-binary resolution** adds a tier to
  `bin.rs`'s resolver; it never hardcodes a bare `PATH` name.
- **A new feed producer/consumer** (`aoided`'s own event bus,
  `docs/architecture/AOIDED.md`'s "L1 — the event bus" section, is the
  first one beside `aoide-secrets`) constructs its own `feed::FeedWriter`/
  `feed::Follower` with its own path/cap/create_mode — never a new
  primitive beside these two; the module's job stops at "one JSON object
  per line, capped, tailable," and a caller's own record shape and cap
  choice never leak back into it.

## Docs update required in the same commit

- This `README.md` when a public module or seam is added or removed.
- `CONTRACTS.md` when a wire/schema shape changes.
- `pkgs/aoide/crates/AGENTS.md` is the layer above for registry-order and
  golden-discipline invariants that apply to CONSUMERS of this crate's
  `Registry` — this file only covers what changes here.
