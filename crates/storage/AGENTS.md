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
- **`fs::migrate_root_once` is `pub` and deliberately NOT wired into any
  path getter (L-C2, lyra-carrier lane, task #107) — don't "fix" this by
  hanging it off `fs::root`'s no-override fallback the way
  `migrate_conducting_stage` hangs off `conducting_stage_dir`'s.** `root`/
  `stage_dir`/`state_dir` are reached by `with_stage_lock`, the SHARED lock
  primitive nearly every stage-file writer across the whole workspace
  routes through regardless of which file it is actually touching
  (`with_stage_lock`'s own doc: it always locks `stage_dir()`, even for a
  `conducting_stage_dir`-domain caller) — a real incident during this
  lane's own development proved that an ordinary `state_dir()`-only test
  (overriding only `$AOIDE_STATE_DIR`, never anticipating a need to touch
  `$AOIDE_STAGE_DIR` too) still reaches `stage_dir()`'s fallback through
  `with_stage_lock`, and would silently drive a real migration against the
  operator's actual `$HOME` the first time such a test ran unguarded.
  `conducting_stage_dir` has no such shared low-level caller, which is why
  ITS migration is safe to hang off its own resolution while `root`'s is
  not. The three real binaries call `migrate_root_once()` once, explicitly,
  at the top of their own `main()` instead (`crates/cli/src/bin/{aoide,
  aoided}.rs`, `crates/lyra/src/bin/lyra.rs`) — a test may call it directly
  too (it is a plain idempotent function, no `Once`/env-isolation dance
  needed, unlike `migrate_conducting_stage`'s own test suite).
- **`fs::song_templates_dir` returns `Option`, never a default (L-C3,
  lyra-carrier lane, task #107) — don't "helpfully" fall back to a
  hardcoded path when both tiers miss.** Unlike `root`/`flake_root` (always
  resolvable — a runtime path or a checkout path always HAS a default,
  even if nothing lives there yet), a templates dir with no baked
  `manifest.json`/`registry.json` is not useful to hand back silently; the
  caller (`aoide-song`'s `commands::rice`/`widgets`) is the one that knows
  how to phrase the taught error naming both locations it checked. Don't
  add a `$HOME`-derived third tier here "for consistency" — the two tiers
  mirror `aoide_protocol::bin`'s sibling-binary resolver on purpose, and
  that resolver has no such fallback either (its own tier 3, the bare name,
  only exists because `Command::spawn` can resolve it off `PATH` at exec
  time — there is no equivalent for a directory).
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
- **`identity::mint_ephemeral` never writes to disk, and a caller must mint
  it exactly ONCE per process (LANE IDENTITY P-ID1).** Unlike
  `load_or_mint` (idempotent — every call after the first re-reads the
  SAME on-disk key), `mint_ephemeral` mints a genuinely FRESH keypair on
  every call — it exists specifically so a same-uid attacker who can read
  every `0600` file under the operator's own uid still cannot read the
  key (OQ1-A: secrecy rests on process liveness plus Yama `ptrace_scope`,
  not file permissions). A caller that calls it more than once per process
  (or calls it lazily per-request instead of once at startup, held in a
  `OnceLock`/static) silently invalidates every seal minted under the
  prior key — `aoide-server`'s daemon is the one production caller today
  and holds it in exactly that shape. Don't add a disk-write path to this
  function "for consistency" with `mint` — that would defeat the entire
  point of OQ1-A.
- **`sealed_id::canonical_seal_string`'s five-field order, NUL-separator,
  AND its per-field normalization rule are the wire contract, not an
  implementation detail (LANE IDENTITY P-ID1) — pinned by
  `tests::canonical_seal_string_stability_vectors_never_drift` and
  `tests::canonical_seal_string_is_case_sensitive_for_identity_fields`,
  the same pinning discipline `wire_auth::canonical_string`/
  `pairing::derive_sas` already hold.** `sessionId`/`originClass` ride
  VERBATIM — no trim, no case-fold — DELIBERATELY, unlike `pid`/
  `pidStarttime`/`issuedAt`'s plain decimal rendering, and unlike
  `wire_auth::canonical_string`'s own trim+lowercase of its own fields:
  `sessionId` is the session store's case-sensitive primary key
  (`session_store.rs` compares it with plain `==`), and `originClass` is
  about to become P-ID4's origin-gate lookup key, so folding either would
  let a seal minted for one exact identity verify against a
  differently-cased one — exactly the cross-identity forgery a credential
  exists to prevent. **Don't "harmonize" this with `wire_auth::
  canonical_string`'s trim+lowercase "for consistency"** — the two
  functions solve different problems (HTTP header normalization vs. exact
  identity binding) and MUST stay independently normalized. A change to
  the field order, separator, or (re-)introduced folding breaks every
  already-minted seal's ability to re-verify — it needs new pinned vectors
  AND a `CONTRACTS.md` §4 update in the same commit.
- **A stored `pid_starttime` of `0` is UNVERIFIABLE, never "verified"
  (LANE IDENTITY P-ID1, `mint_seal`'s documented degrade path for a pid
  that vanished before mint) — pinned by `aoide-server::daemon::tests::
  mint_seal_over_a_vanished_pid_degrades_to_a_self_consistent_but_
  unrevalidatable_zero_starttime`.** No genuine `/proc/<pid>/stat` read
  ever reports starttime `0` (`window.rs::
  pid_starttime_reads_a_nonzero_value_for_our_own_real_pid` proves a real
  read is always `> 0`), so a verifier that reconstructs `SealedIdentity`
  from a fresh live read can never produce a matching `0`. `aoide_conduct::
  graph::identity::verify_seal_over` (P-ID2's verify-on-accept caller)
  branches on this explicitly, up front — a `None`/`0` live read is
  refused before ever reaching `verify_seal`, never falling through to an
  ordinary verify that would simply (and silently) fail for the wrong
  reason; pinned by that function's own `verify_seal_over_rejects_when_
  the_live_starttime_read_is_unreadable` test.
- **`SessionRecord.seal`/`sealedIssuedAt` are consumed OUTSIDE this
  crate — don't add a gate here.** This crate mints, stores, and
  cryptographically verifies a seal (`sealed_id::{mint_seal,verify_seal}`)
  but makes NO policy decision on one — both real consumers
  (`aoide-conduct`'s send gate and its per-session control socket's accept
  loop, LANE IDENTITY P-ID2) live in `aoide-conduct::graph::identity`,
  which reconstructs the exact `SealedIdentity` a stored `seal` was signed
  over and calls this crate's `verify_seal` against a pubkey it fetches
  itself over the daemon's `ping` reply. P-ID4 is the first phase to gate
  a REAL policy decision (per-secret `allowRemoteOrigin`) on a VERIFIED
  `originClass` — that policy logic belongs in `aoide-secrets`/
  `aoide-server`, not here either.
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
- **`peer_store::set_peer_via` is the ONE write site for `Peer.via` (P-S4),
  a SIBLING to `upsert_paired_peer`, never a parameter folded into it.**
  `upsert_paired_peer`'s signature is also called from `aoide-server`'s own
  pairing integration tests — a crate outside this field's blast radius —
  so a purely additive setter beside it (mirroring `set_hub`/
  `set_peer_allow`'s own precedent) keeps that signature untouched. Don't
  set `Peer.via` via a raw `Peer { .. }` literal anywhere outside
  `peer_store.rs` itself, and don't fold it into `upsert_paired_peer`
  without first checking every one of that function's existing callers.
  **A caller passing `None` must mean "nothing to say," never "clear
  it"** — `approve_outbound` (`aoide-client`) only calls `set_peer_via` at
  all when the ceremony resolved an actual via; a re-pair that named none
  leaves a previously-recorded `via` (e.g. one `peer invite` set) exactly
  as it was, the same untouched-unless-named stance `upsert_paired_peer`
  itself holds for `autogate`/`tokenFile`/`bearerSecret`/`hub`/`allows`.
- **`pairing`'s request ids are deliberately NOT `state/stage/pending.json`'s
  array-position ids.** A pairing correlation must survive the requester's
  CLI process exiting and an async `aoide/pairPoll` (Design A, task #119 —
  the requester's own poll, replacing what used to be an approver-initiated
  `aoide/pairApprove` callback) arriving arbitrarily later, so ids are
  stable 8-hex-char values (`gen_request_id`), generated once at park time
  and never renumbered by a later list mutation. Don't "simplify" this
  back to array-position ids — that would break exactly the cross-process
  correlation the module exists to hold.
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
  commit past the approver's approval — never collapse the two-state
  machine back to an implicit "the poll answered means paired."** An entry
  parks `AwaitingApproval`; `mark_outbound_awaiting_confirm` — Design A,
  task #119, now called from `aoide-client::commands::approve_outbound`'s
  own poll-then-mark step (a CLIENT call, never a server-side wire
  handler; the old `aoide/pairApprove` callback used to trigger this from
  `aoide-server`, but the FUNCTION ITSELF is unchanged) — transitions it to
  `AwaitingConfirm` and nothing else on a pubkey match; no peer-store write
  happens inside this crate's own pairing module at all; that write is
  `aoide-client`'s own job, gated behind its own operator confirmation. A
  pubkey mismatch on the release leaves the entry completely untouched
  (still `AwaitingApproval`) rather than re-parking or dropping it — a
  transient mismatch is recoverable without restarting the whole
  ceremony, and "untouched" is simpler to reason about than "re-parked
  with the same content." `InboundPairingRequest.approved` is the mirror
  on the approver's side (Design A, additive, `#[serde(default)]`): set by
  `mark_inbound_approved`, called ONLY from `aoide-client::commands::approve_inbound`
  (never a wire handler — approving is purely local now), and never
  removes the entry — `aoide/pairPoll` (`aoide-server`) only ever READS it.
- **`InboundPairingRequest.tries` counts wrong pairing codes; the
  auto-deny at 3 belongs to the CLI caller, never this crate (task #120
  P3).** `record_inbound_code_try` only increments-and-persists (returning
  the new cumulative count, `MarkApprovedError`'s refusal shape);
  `aoide-client::commands::approve_inbound` is its ONLY production caller
  and performs the deny itself via `take_inbound`. Don't fold a
  threshold or a removal into this function — the limit is CLI policy
  (`MAX_CODE_TRIES` lives in `aoide-client`), and a wire handler must
  never be able to burn or deny an entry by reaching a storage function
  that does both. Additive `#[serde(default)]` — a legacy record loads
  `0`, same discipline as `approved`.
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
- **`advertise` never writes `peer_store`, and never will (P-P6).** It
  reaches into `peer_store` for exactly one READ (`valid_peer_name`, so
  the advertisement's `name` shares the same nickname shape check every
  other peer-name field on the wire already holds to) — don't add a write
  path here "for convenience": discovery grants nothing is the whole
  point of the feature (`docs/architecture/PAIRING.md`'s "Discovery
  (advertise-but-locked)" section), and a write site in the ONE module
  every hearer's validation funnels through would be exactly the kind of
  quiet erosion that invariant depends on never happening. The wire
  carries name + ssh hop claim ONLY (task #120: rendezvous, not
  authentication) — never grow it a door URL, key, or fingerprint field.
  `BROADCAST_ADDR`/`PORT`/`MAX_LINE_BYTES`/the `v` version constant are
  the wire contract, pinned by CONTRACTS.md §6's "Discovery
  advertisement" subsection — a change to any of them needs a matching
  CONTRACTS update in the same commit, the same discipline `wire_auth`'s
  canonical string and `pairing::derive_sas` already hold above. The one
  state file this module owns, `state/advertise.json`, is a bool switch
  (default OFF) — keep it that way rather than growing it into a config
  surface.

- **A tunnel record is RUNTIME state, never versioned, never a credential
  (ssh-transport lane, P-S2).** `tunnel/<sessionId>/<key>.json` lives under
  `$XDG_RUNTIME_DIR/aoide/`, never `state/` — two path LEVELS, because both
  components may contain `-` and a flat joined filename let two distinct
  pairs collide on one record. It exists only to prove an ssh
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
