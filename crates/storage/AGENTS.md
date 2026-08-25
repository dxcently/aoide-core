# AGENTS.md — aoide-storage

## Invariants

- **Stage files are read/written through `fs`/`stage`, never ad hoc.** A new
  consumer that wants a JSON file under the stage tree adds a typed
  accessor here rather than `serde_json::from_str`-ing a raw path elsewhere.
- **`takes`/`mode` are a deliberate charter smudge, not an oversight.** Don't
  "clean them up" into a paint-adjacent crate without re-reading
  `docs/architecture/PACKAGE-LAYOUT.md`'s "Charter exceptions" note — `mode`
  is read by `shellbridge` (which stays in `conduct`), so moving it would
  create the cross-crate edge the split exists to avoid.
- **Test env mutation is serialized.** Any test touching
  `AOIDE_STAGE_DIR`/`AOIDE_STATE_DIR` (or similar process-global env) takes
  this crate's `env_lock()` (delegates to `aoide-test-support`).
- **`ledger` is append-only and never a lookup key for live state (P-D8).**
  `append_ledger_entry` only ever opens `state/session-ledger.jsonl` in
  append mode — nothing in this crate truncates, rewrites, or prunes it;
  that is precisely what makes it survive `sessions.json`'s own pruning.
  Don't add a "compact the ledger" or "delete old entries" path without
  re-reading `docs/architecture/AOIDED.md`'s "L5" — the design leans on
  this file staying a complete, permanent record.

## Extension points

- **A new durable record shape** adds a type to `records` and a read/write
  pair to `fs`/`stage`; existing consumers never touch raw file paths for it.
- **A new CLI verb** (this crate has two groups today, `usage` and `inbox
  list|read|clear`) adds a `cmd!`/`register` entry in `commands.rs`, wired
  into the owning app crate's `commands::all()`.

## Docs update required in the same commit

- This `README.md` when a new module or stage-file shape is added.
- `CONTRACTS.md §4`/`§7` when a stage-file or peer-registry wire shape
  changes.
- `pkgs/aoide/crates/AGENTS.md` for cross-crate invariants (registry order,
  golden discipline) — not restated here.
