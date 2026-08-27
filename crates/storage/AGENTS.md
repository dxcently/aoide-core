# AGENTS.md — aoide-storage

## Invariants

- **Stage files are read/written through `fs`/`stage`, never ad hoc.** A new
  consumer that wants a JSON file under the stage tree adds a typed
  accessor here rather than `serde_json::from_str`-ing a raw path elsewhere.
- **Two stage roots, not one — pick the right one, don't blur them
  (command-defrag S1, 2026-08-27).** `fs::stage_dir` is rice/paint
  (`song/stage/`); `fs::conducting_stage_dir` is core orchestration state
  (`state/stage/`). A new stage-file accessor for something the
  `aoide`/`aoided` binaries alone read or write goes through
  `conducting_stage_dir`; a new one for something only `lyra`/QML writes
  goes through `stage_dir`. Don't "simplify" by routing a core file through
  `stage_dir` for convenience — that is exactly the coupling the split
  exists to remove (root `AGENTS.md`'s core-vs-lyra boundary, applied to the
  stage tree itself).
- **`fs::migrate_conducting_stage` is a ONE-SHOT, Once-guarded move, not a
  sync.** It runs at most once per process, only from
  `conducting_stage_dir`'s no-override fallback branch (an `$AOIDE_STAGE_DIR`
  override names the same directory for old and new, so there is nothing to
  move and that branch never calls it). It moves a file only when it exists
  at the OLD `song/stage/` path and is ABSENT at the new one — never
  clobbers a fresher `state/stage/` file, never touches a rice file. Don't
  turn this into a periodic or unconditional re-sync; a second boot with
  both a old-path leftover and a populated new path should leave the new
  path exactly as it is.
- **`takes`/`mode` are a deliberate charter smudge, not an oversight.** Don't
  "clean them up" into a paint-adjacent crate without re-reading
  `docs/architecture/PACKAGE-LAYOUT.md`'s "Charter exceptions" note — `mode`
  is read by `shellbridge` (which stays in `conduct`), so moving it would
  create the cross-crate edge the split exists to avoid.
- **Test env mutation is serialized.** Any test touching
  `AOIDE_STAGE_DIR`/`AOIDE_STATE_DIR` (or similar process-global env) takes
  this crate's `env_lock()` (delegates to `aoide-test-support`).
- **The identity private key never enters a `Serialize`/`Deserialize` type
  (P-P1, `docs/architecture/PAIRING.md`'s kill-list) — mechanically held,
  not prose-only.** `identity::Keypair` holds the raw `SigningKey` and
  derives nothing serializable from it except `IdentityInfo` (public
  material only). `identity.rs`'s own `no_private_material_in_any_serialize_type`
  test reads that file's source and fails the build if a future
  `#[derive(Serialize)]` struct there grows a key-shaped field name. A new
  field on `IdentityInfo` (or a new serializable type anywhere in
  `identity.rs`) that could plausibly carry key material gets checked
  against this test before it lands, not after.
- **`wire_auth::canonical_string`'s five-field order, NUL-separator, and
  lowercased/trimmed style are the wire contract, not an implementation
  detail (P-P4) — pinned by
  `tests::canonical_string_stability_vectors_never_drift`, mirroring
  `pairing::derive_sas`'s own pinning discipline.** A change to the field
  order, the separator, the case-folding, or the digest algorithm breaks
  both this test AND every deployed signer/verifier pair simultaneously
  (unlike `derive_sas`, where only display drifts) — it needs new pinned
  vectors AND a CONTRACTS.md §6 update in the same commit, never silent
  drift. **The nonce cache does NOT live in this crate, on purpose** — it
  is ephemeral, process-local, per-`a2a serve` runtime state with no
  durable file behind it, unlike everything else `aoide-storage` persists,
  so it lives in `aoide-server::a2a` next to its one consumer
  (`verify_signed_request`) instead. Don't "complete" `wire_auth` by
  adding a nonce store here — that would duplicate state across a
  crate boundary for no benefit, the same anti-pattern the "no cross-crate
  copying" cross-crate rule already forbids.
- **`fs::atomic_write_private` is the ONE way a sensitive file gets written
  in this crate** (`identity.rs`'s `ed25519.key` is its first caller) — the
  TEMP file is created ALREADY at `0600` (`OpenOptions::mode`, not
  `File::create`-then-`chmod`), so a `rename(2)` onto the live path never
  passes through a wider-mode window, mirroring `aoide-secrets/src/
  store.rs`'s `save_policies`/`save_totp_secret` (secure the temp BEFORE
  the rename, never the final path after it). Never write a sensitive
  file as a `File::create` + post-rename `set_permissions` pair — the
  temp inherits the umask-derived default mode and the live path sits
  world/group-readable until the `chmod` lands; that window is exactly
  what this function exists to close, and
  `fs::tests::the_private_temp_is_created_already_0600_before_any_rename`
  pins the invariant directly against the temp, not just the end state.
- **`fs::secure_private_dir` locks the DIRECTORY a sensitive file lives
  in, not only the file** (`identity.rs`'s `mint()` calls it on
  `identity_dir()` before writing anything into it) — a `0600` file inside
  a `create_dir_all`-default (`0755`) directory still leaves that
  directory's entries world-listable. A future sensitive file that lives
  in its OWN new subdirectory (not an existing already-secured one) calls
  this on that subdirectory the same way, before the first
  `atomic_write_private` into it.
- **`ledger` is append-only and never a lookup key for live state (P-D8).**
  `append_ledger_entry` only ever opens `state/session-ledger.jsonl` in
  append mode — nothing in this crate truncates, rewrites, or prunes it;
  that is precisely what makes it survive `sessions.json`'s own pruning.
  Don't add a "compact the ledger" or "delete old entries" path without
  re-reading `docs/architecture/AOIDED.md`'s "L5" — the design leans on
  this file staying a complete, permanent record.
- **`RestoreSnapshot`'s own fields never carry `skip_serializing_if`, in
  EITHER of its two homes (P-C5, durable-sessions plan).** The type is
  embedded on both `SessionRecord.restore` (additive, the outer
  `Option<RestoreSnapshot>` DOES skip when `None`) and
  `LedgerEntry.restore` (always present, possibly `null`) — but once a
  snapshot is `Some`, its own `cwd`/`idle`/`argv`/`typed` fields always
  serialize in both places, so a populated `restore` reads the identical
  complete shape whichever file it came from. Adding `skip_serializing_if`
  to one of `RestoreSnapshot`'s own fields would make the two homes diverge
  in shape for no reason — don't.
- **`peer_store::upsert_paired_peer` is the ONE write site for `Peer.pubkey`/
  `Peer.verified` (P-P2).** `peer add` never sets either field; a caller
  wanting to record a verified key relationship goes through this function,
  which touches only `pubkey`/`verified`/`url` on an existing entry and
  leaves `autogate`/`tokenFile`/`bearerSecret`/`hub` untouched — don't widen
  it to a general-purpose peer editor, and don't set those two fields via a
  raw `Peer { .. }` literal anywhere outside `peer_store.rs` itself.
- **`pairing`'s request ids are deliberately NOT `state/stage/pending.json`'s
  array-position ids.** A pairing correlation must survive the requester's
  CLI process exiting and an async `aoide/pairApprove` callback arriving
  arbitrarily later, so ids are stable 8-hex-char values
  (`gen_request_id`), generated once at park time and never renumbered by
  a later list mutation. Don't "simplify" this back to array-position ids
  — that would break exactly the cross-process correlation the module
  exists to hold.
- **`pairing::derive_sas`'s four-field order is the wire contract, not an
  implementation detail.** `(requester_pubkey, approver_pubkey,
  requester_nonce, approver_nonce)`, each lowercased/trimmed with a
  trailing NUL separator, is pinned by
  `tests::derive_sas_stability_vectors_never_drift` — changing the
  hash, the field order, the separator, or the truncation/format breaks
  the SAS rendering identically on both boxes, which is the entire point
  of the ceremony. A change here needs new pinned vectors AND a
  CONTRACTS.md §6 update in the same commit, never a silent drift.
- **`pairing::derive_commit` is a separate, one-way commitment, never
  folded into `derive_sas`.** It hashes exactly
  two fields (a pubkey and a nonce, same canonical lowercased/trimmed/
  NUL-separated style `derive_sas` uses) and returns the FULL 64-hex-char
  digest — no truncation, unlike the SAS's mod-1,000,000 shortening, since
  a commitment must stay cryptographically binding, not human-readable.
  The requester commits to its own nonce BEFORE ever sending it
  (`park_inbound`'s `commit_hex` param); `reveal_inbound` is the only
  function that ever checks a value against it. Don't let a future
  refactor merge this into `transcript_digest`'s SAS call site — the two
  hash different field counts for different purposes (binding vs. display)
  and must stay independently callable.
- **`InboundPairingRequest.requester_nonce_hex` is `Option<String>`, and
  `None` is a real, load-bearing state, not a placeholder.** An entry
  parks with it absent (`park_inbound` never takes
  a nonce — only a commitment) and gains it only once `reveal_inbound`
  verifies the commitment. A caller deriving a SAS from an inbound entry
  MUST check `is_some()` first (`peer pair pending`'s `sas: Option<..>`,
  `peer pair approve`'s "awaiting reveal" refusal) — treating `None` as
  "empty string" or defaulting it would let an unrevealed entry's SAS
  silently derive from an attacker-guessable value instead of refusing.
- **The inbound park queue is capped under the SAME lock the insert itself
  takes — check-then-insert, one lock
  acquisition, never a separate `len()` check followed by an unlocked
  push.** `park_inbound` acquires `PARK_LOCK`, sweeps expired entries,
  checks `requests.len() >= pairing_park_cap()` (default 32,
  `AOIDE_PAIRING_PARK_CAP` override), and only then mints an id and
  writes — mirroring `aoide-secrets::park::park_if_room`'s own
  check-then-insert discipline exactly, closing the same TOCTOU race a
  separate check-then-insert pair would reopen. `PARK_LOCK` is
  process-local (`static Mutex<()>`, poison-recovering); like the ledger
  and `peer_store`'s own file-based state, it does not serialize across
  separate OS processes touching the same `state/peer-pairing-inbound.json`
  concurrently — a known limitation, same shape as `aoide-secrets`'s own
  admin-CRUD note, not something this function's own lock can close.
  Outbound entries (`park_outbound`) are operator-created, one per `peer
  pair request` invocation, and carry no cap.
- **`OutboundPairingRequest.state` defers the requester's own peer-record
  commit past the approver's callback — never
  collapse the two-state machine back to an implicit "callback arrived
  means paired."** An entry parks `AwaitingApproval`;
  `mark_outbound_awaiting_confirm` (called from the `aoide/pairApprove`
  callback handler in `aoide-server`, on a pubkey match) transitions it to
  `AwaitingConfirm` and nothing else — no peer-store write happens inside
  this crate's own pairing module at all; that write is `aoide-client`'s
  own job, gated behind its own operator confirmation. A pubkey mismatch
  on the callback leaves the entry completely untouched (still
  `AwaitingApproval`) rather than re-parking or dropping it — a
  transient mismatch is recoverable without restarting the whole
  ceremony, and "untouched" is simpler to reason about than "re-parked
  with the same content."
- **`undying::set_undying`'s return value is the on/off TRANSITION, not
  "did anything on disk change" (P-C1, durable-sessions plan).** Re-marking
  an already-undying id refreshes `marked_at` in place and returns `false`;
  unmarking an absent id is a no-op and also returns `false`. Don't fold the
  timestamp refresh into the return value — the `session undying`
  command reports this bool verbatim as `changed`, and a `markedAt` bump
  reported as a state change would be misleading (nothing about undying/not
  actually flipped).
- **`undying.json` is written via plain `fs::atomic_write`, never
  `atomic_write_private` — deliberate, not an oversight.** It holds session
  ids, the same class of data `sessions.json`/`peers.json` already keep
  at default mode; `atomic_write_private` stays reserved for the
  identity/secret lane above.
- **`undying`'s legacy-migration check runs on every `load_undying` call,
  not behind a process-wide `Once` — deliberate, not an oversight
  (command-defrag lane U1, 2026-08-27).** Unlike
  `fs::migrate_conducting_stage` (six files, hot-path-called, worth a
  one-time guard), this migration moves ONE small file and its own check is
  a single `exists()` stat that becomes a guaranteed no-op the instant the
  legacy `carry.json` is gone — cheap enough to run unconditionally, and
  simpler to test (no cross-test `Once` state to isolate). Don't add a
  `Once` guard here "for consistency" with `fs.rs` — that would reintroduce
  exactly the test-ordering fragility a per-call idempotent check avoids.
- **`manifest::save_manifest` validates EVERY `SessionSpec.dir` before
  writing anything, never partially (command-defrag lane U1).** The
  absolute-path check runs over the whole `sessions` vec first; a rejection
  returns `Err` before `.aoide/` is even created, let alone
  `project.json` written — a manifest is committed and meant to move across
  clones/hosts, so an absolute `dir` is a bug in the caller, not a value
  this store should ever persist even once.
- **`manifest`'s `.aoide/.gitignore` is written ONLY when absent — never
  "helpfully" refreshed or reconciled on a later `save_manifest`.** An
  operator who hand-edited it (to un-ignore something, or to commit the
  directory on purpose) keeps their own content forever; `ensure_self_
  gitignore` is a create-if-absent, not a template sync.
- **`manifest::walk_up` never falls through a corrupt nearest manifest to an
  ancestor's.** The NEAREST `.aoide/project.json` (git-style, same
  precedent `.git` discovery sets) is the only one ever consulted — if
  `load_manifest` narrates it unreadable, `walk_up` returns `None` right
  there rather than continuing to search upward for a "better" one. Don't
  add a fallback-to-parent path; a broken nearest manifest is a bug to
  surface, not paper over with a stale grandparent's specs.
- **`beacon` never writes `peer_store`, and never will (P-P6).** It reaches
  into `peer_store` for exactly one READ (`valid_peer_name`, so the
  beacon's `name` shares the same nickname shape check every other
  peer-name field on the wire already holds to) — don't add a write path
  here "for convenience": discovery grants nothing is the whole point of
  the feature (`docs/architecture/PAIRING.md`'s "Discovery
  (advertise-but-locked)" section), and a write site in the ONE module
  every hearer's validation funnels through would be exactly the kind of
  quiet erosion that invariant depends on never happening. `GROUP`/`PORT`/
  `MAX_LINE_BYTES`/the `v` version constant are the wire contract, pinned
  by CONTRACTS.md §6's "Discovery beacon" subsection — a change to any of
  them needs a matching CONTRACTS update in the same commit, the same
  discipline `wire_auth`'s canonical string and `pairing::derive_sas`
  already hold above.

- **A tunnel record is RUNTIME state, never versioned, never a credential
  (ssh-transport lane, P-S2).** `tunnel-<sessionId>-<key>.json` lives under
  `$XDG_RUNTIME_DIR/aoide/`, never `state/` — it exists only to prove an ssh
  child is still alive and to let a later action reuse it, and it holds
  nothing an attacker could authenticate with (a pid, two local ports, the
  `--via` string it was opened for). It still writes at `0600`
  (`fs::atomic_write_private`) as a matter of this crate's private-file
  discipline, the same way `undying.json` deliberately does NOT — don't read
  that as the record carrying a secret; it doesn't, and it must never grow
  one (no key material, no bearer token) without re-opening this decision.
- **`tunnel::dial_url`'s path half MUST come from `peer_store::url_path`,
  never a second, independently-written cut of the same url.** The
  ssh-transport plan's §0.4 is the reason: `sign_headers_for_peer`
  (`aoide-client`) signs a canonical string built from the URL's path only,
  so a dial url's authority can be rewritten to `127.0.0.1:<local port>`
  with zero effect on what gets signed PROVIDED the path is copied verbatim.
  A future edit that hardcodes `/` or re-parses the path independently would
  silently break every signed call through a tunnel with an opaque
  `-32007` on the far end — `dial_url_never_invents_a_path_it_asserts_
  against_url_path_directly` (`tunnel.rs`) pins this directly, not just by
  eyeballing the two functions' output.
- **`tunnel::record_path`'s two id checks are deliberately DIFFERENT
  strictness, not an oversight.** `key` reuses `peer_store::valid_peer_name`
  verbatim (it names a peer or a `--via` target, the same nickname shape
  everywhere else on the wire). `sessionId` uses this module's own looser
  `is_safe_id` — a session id is not an operator-typed nickname (the default
  shape is `conduct-<pid>-<unix ts>`, and `aoide conduct --id <id>` lets an
  operator override it), so it can't hold to `valid_peer_name`'s
  lowercase-alnum-hyphen shape without rejecting real ids. Don't unify the
  two checks "for consistency" — `is_safe_id` still refuses every traversal
  shape `valid_peer_name` does (empty, `..`, `/`, a leading `.`), which is
  the actual invariant both exist to hold.

## Extension points

- **A new durable record shape** adds a type to `records` and a read/write
  pair to `fs`/`stage`; existing consumers never touch raw file paths for it.
- **A new CLI command** (this crate has three groups today, `usage`, `inbox
  list|read|clear`, and `identity`) adds a `cmd!`/`register` entry in
  `commands.rs`, wired into the owning app crate's `commands::all()`. The
  pairing ceremony's own CLI commands (`peer pair *`) live in `aoide-client`
  instead — this crate exposes the `pairing`/`peer_store` library only,
  since the ceremony needs outbound HTTP transport this crate never holds.

## Docs update required in the same commit

- This `README.md` when a new module or stage-file shape is added.
- `CONTRACTS.md §4`/`§7` when a stage-file or peer-registry wire shape
  changes.
- `CONTRACTS.md §6` when `wire_auth`'s canonical string, header names, or
  pinned vectors change (P-P4).
- `pkgs/aoide/crates/AGENTS.md` for cross-crate invariants (registry order,
  golden discipline) — not restated here.
