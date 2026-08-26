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
- **`peer_store::upsert_paired_peer` is the ONE write site for `Peer.pubkey`/
  `Peer.verified` (P-P2).** `peer add` never sets either field; a caller
  wanting to record a verified key relationship goes through this function,
  which touches only `pubkey`/`verified`/`url` on an existing entry and
  leaves `autogate`/`tokenFile`/`bearerSecret`/`hub` untouched — don't widen
  it to a general-purpose peer editor, and don't set those two fields via a
  raw `Peer { .. }` literal anywhere outside `peer_store.rs` itself.
- **`pairing`'s request ids are deliberately NOT `song/stage/pending.json`'s
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
