# AGENTS.md — aoide-storage

- **Explicit project membership survives UPSERT.** `SessionRecord.project`
  names a registered project independently of cwd. The exit ledger retains
  it; an unset field means automatic cwd anchoring.
- **A project is a set of anchor roots, plus a set of host memberships.**
  `Project.path` is always the first LOCAL root, mirrored at `roots[0]`;
  `Project.roots` is the FULL ordered local root list (ROOTS SERIALIZED
  COMPLETE) — always written by `project add`/`project edit`/
  `project remove`, never omitted or extras-only. A legacy record predating
  this field, or one hand-edited so `roots[0]` disagrees with `path`, still
  reads correctly: read roots through `Project::roots()`, never the raw
  fields directly — that is the one place the path-first, deduped ordering
  is guaranteed, and reading it never rewrites the record. Separately,
  `Project.hosts` (P-14 M1) is a `Vec<ProjectHost>` naming other registered
  nodes this project is a member of, each with its OWN root list — additive
  and `skip_serializing_if`-empty like `autoResume`, so a project untouched
  by `--host` stays byte-identical on the wire. A host root is a verbatim
  string never validated against this machine's filesystem (no `is_dir`, no
  canonicalization — the host is the only one who can check it) and never
  read by `Project::roots()`, which stays local-only. Membership is
  organizational only: it grants no reach, pairs, or dials.

## Invariants

- Structured thread/reply IDs are signed context, not membership or delivery authority. Legacy four-field content remains valid.
- Structured letter content is optional signed text, never a new transport header. Invalid or legacy content remains raw; decoding must not write or alter envelope identity.

- **Enduring identity is independent of knowledge configuration.** Bind an
  explicit `valid_node_name`-shaped key in `session::bind_enduring_agent`;
  do not infer it from a persona title, session name, or optional Mneme map.
  Refusals never mutate. UPSERT preserves the field. Session records omit an
  absent `enduringAgentId`; exit ledger records serialize it as null.

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
- **`config` holds INTENT; every other module here holds STATE — never move
  a value across that line (task #135 P-C).** `config.toml` records what an
  operator WANTS ahead of anything happening; `nodes.json`'s records/allows/
  hub, the pairing park queues, `advertise.json`'s switch, `undying.json`
  record what HAPPENED. A new decision an operator makes UP FRONT gets a
  `config` key; a fact the system observes or commits gets a state file.
  Don't migrate an existing state field into `config` "for tidiness" — a
  `state/*.json` value is written by code and a config value is written by a
  human, and the two have opposite ownership.
- **`config::SCHEMA` is the ONE place a config key is described — walk it,
  never restate it in a match arm.** The table carries each key's name,
  `ValueKind` vocabulary, summary, and a `read` fn projecting it off a typed
  `Config`; `validate`, `set`, and `commands.rs`'s `config` listing all walk
  it. A new key is one table row plus its struct field — and if a new key
  needs a shape the one `ValueKind` variant can't express, widen the enum
  and `parse_value`/`render_value` with it, never branch on the key's name.
  A later interactive picker (section → key → a value menu typed to that
  key) has to enumerate the same table; scattered match arms would make that
  a rewrite instead of a reader.
- **`config`'s vocabularies are borrowed from their own domain, never
  minted here.** `pairing.defaultGrant`'s `ValueKind::ClosedList` IS
  `node_store::NODE_CAPABILITIES` — the same closed set `node allow`
  enforces. A second list would drift the moment a capability lands, and
  `config.rs`'s own test asserts the two are the same value, not merely
  equal-looking.
- **`config::set` never partially writes, and never writes at all on a
  managed config.** The order is load-bearing: managed check → key lookup →
  read + parse the config already on disk (refusing to build on one that
  doesn't load) → parse the value → edit the document → RE-PARSE the
  rendered text through `parse` → atomic write. Nothing before the last step
  touches the filesystem, so every refusal leaves the file byte-identical.
  Don't "simplify" by writing first and validating after, and don't drop the
  re-parse — it is what guarantees a write can never leave behind a file the
  next `load` would refuse.
- **`config::set` edits the file's TEXT through `toml_edit`; it never
  serializes the whole `Config` back out.** The comments an operator wrote
  beside a grant ARE the reason this file is TOML rather than JSON, and a
  serialize-the-struct round trip erases them silently. The two crates split
  by direction on purpose — `toml` reads (typed, `deny_unknown_fields`),
  `toml_edit` writes (format-preserving) — don't collapse them onto one by
  routing the write through `toml::to_string`.
- **`$AOIDE_CONFIG` is absolute-path-wins, like every other override in
  `fs`.** A relative or empty value is ignored outright and resolution falls
  to `$AOIDE_ROOT/config.toml` — a runtime path is never resolved against an
  arbitrary cwd. Don't add a cwd-relative tier "for convenience".
- **`takes`/`mode` are a deliberate charter smudge, not an oversight.** Don't
  "clean them up" into a paint-adjacent crate without re-reading
  `docs/architecture/PACKAGE-LAYOUT.md`'s "Charter exceptions" note — `mode`
  is read by `shellbridge` (which stays in `conduct`), so moving it would
  create the cross-crate edge the split exists to avoid.
- **`takes`' functions take `draft: Option<&str>`, not `&str`** (`lyra
  reload` design, settled 2026-08-31): `None` resolves the take root to
  `songbook/<song>/takes/` (staging mode, no draft to nest under); `Some`
  resolves it to `songbook/<song>/drafts/<draft>/takes/`, the original
  shape. `takes_dir` is the one function that branches on it; every other
  function in the module derives its path through `takes_dir`/`take_path`/
  `head_path`/`marks_path` and just forwards the `Option` — don't
  reintroduce a `&str`-only overload "for convenience", it would fork the
  root-resolution logic in two places.
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
  ever reports starttime `0` (`attest.rs::
  pid_starttime_reads_a_nonzero_value_for_our_own_real_pid` proves a real
  read is always `> 0`), so a verifier that reconstructs `SealedIdentity`
  from a fresh live read can never produce a matching `0`.
  `attest::verify_seal_over` (P-ID2's verify-on-accept, its body lifted
  here at P-ID4 — `aoide_conduct::graph::identity` delegates) branches on
  this explicitly, up front — a `None`/`0` live read is refused before
  ever reaching `verify_seal`, never falling through to an ordinary
  verify that would simply (and silently) fail for the wrong reason;
  pinned by `attest.rs`'s own stale-starttime rejection test and the
  delegate-side `verify_seal_over_rejects_when_the_live_starttime_read_
  is_unreadable` test.
- **This crate RESOLVES a sealed caller (`attest`, LANE IDENTITY P-ID4)
  but never GATES on one — policy decisions stay outside.** `attest.rs`
  is the ONE implementation of the "pid → real `/proc` ancestry → sealed
  session → verified origin" lookup (the walk, the fresh-starttime
  `verify_seal_over`, the live `ping` seal-pubkey fetch) — lifted here
  because both consumers need it and the DAG forbids every other shared
  home (`aoide-secrets` may never depend on `aoide-conduct`/`aoide-client`;
  that module's own doc has the full argument). `aoide-conduct::graph::
  {window,identity}` and `aoide-client::daemon` keep their public seams as
  thin delegates onto it — edit the BODY here, never regrow one in a
  delegate. What each caller DOES with a resolved (or `None` =
  UNIDENTIFIED, never "verified") answer is that caller's own documented
  gate decision: the send gate + per-session accept loop (P-ID2, in
  `aoide-conduct`), and the secrets broker's per-secret `allowRemoteOrigin`
  origin gate (P-ID4, in `aoide-secrets`) — that policy logic never moves
  here.
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
- **`node_store::upsert_paired_node` is the ONE write site for `Node.pubkey`/
  `Node.verified` (P-P2).** `node add` never sets either field; a caller
  wanting to record a verified key relationship goes through this function,
  which touches only `pubkey`/`verified`/`url` on an existing entry and
  leaves `autogate`/`tokenFile`/`bearerSecret`/`hub` untouched — don't widen
  it to a general-purpose node editor, and don't set those two fields via a
  raw `Node { .. }` literal anywhere outside `node_store.rs` itself.
  **Its `grant` parameter is the caller's, and this module never resolves
  one (task #135 P1).** The capability set a first pairing stamps is an
  operator's INTENT — `config.toml`'s `[pairing] defaultGrant`, or the
  `--allow` typed on that commit — so the client resolves it and passes the
  finished list. Reading `config` from inside `node_store` would be a second
  resolution path AND would have to swallow a malformed grants file at the
  one moment that must fail loudly; keep the store a store.
- **`node_store::set_node_via` is the ONE write site for `Node.via` (P-S4),
  a SIBLING to `upsert_paired_node`, never a parameter folded into it.**
  `upsert_paired_node`'s signature is also called from `aoide-server`'s own
  pairing integration tests — a crate outside this field's blast radius —
  so a purely additive setter beside it (mirroring `set_hub`/
  `set_node_allow`'s own precedent) keeps that signature untouched. Don't
  set `Node.via` via a raw `Node { .. }` literal anywhere outside
  `node_store.rs` itself, and don't fold it into `upsert_paired_node`
  without first checking every one of that function's existing callers.
  **A caller passing `None` must mean "nothing to say," never "clear
  it"** — `approve_outbound` (`aoide-client`) only calls `set_node_via` at
  all when the ceremony resolved an actual via; a re-pair that named none
  leaves a previously-recorded `via` (e.g. one `aoide pair`'s hostname arm set) exactly
  as it was, the same untouched-unless-named stance `upsert_paired_node`
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
- **`pairing::derive_reply_sas` (the mutual-code redesign, R1) is a
  SEPARATE derivation from `derive_sas`, never the same code re-shown.**
  Same four fields, same order, same canonicalization — PLUS a leading
  domain-separation tag (`REPLY_SAS_DOMAIN_TAG`, `"aoide-pair-reply"`,
  NUL-separated the same way the other four fields are) so the two codes
  can never coincide even on an identical transcript. Pinned by its own
  `tests::derive_reply_sas_stability_vectors_never_drift` — the same
  "changing the hash, the field order, the separator, the truncation, or
  now the domain tag breaks both boxes identically" stance `derive_sas`'s
  own bullet holds, and the same CONTRACTS.md §6 same-commit requirement.
  Don't collapse the two functions into one with a bool flag — they are
  called from different legs (`approve_inbound` vs. `commit_outbound`) at
  different points in the ceremony, and a shared implementation risks a
  caller passing the wrong flag silently producing the OTHER leg's code.
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
  MUST check `is_some()` first (`aoide-client::pair_watch::reconcile`'s
  own `Pending.sas: Option<..>`, `aoide pair`'s "awaiting reveal"
  refusal) — treating `None` as
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
  separate check-then-insert pair would reopen. Cross-process, EVERY
  load-modify-write of either park file (`park_inbound`/`take_inbound`/
  `reveal_inbound`/`mark_inbound_approved`/`record_inbound_code_try`/
  `list_inbound` and the outbound five) runs under
  `crate::fs::with_stage_lock` — the same flock `mail`'s writer already
  resolves for a `state/` file — so the resident `a2a serve` process and a
  concurrent CLI invocation can never silently drop each other's
  `approved` flag or `tries` increment (#119 review finding 4). A new
  mutator here wraps its whole load-modify-write in `with_stage_lock` the
  same way, never a bare `load → save`. `PARK_LOCK`
  (process-local `static Mutex<()>`, poison-recovering) stays alongside as
  the cap's in-process guarantee: `with_stage_lock` is best-effort by
  contract (a lock hiccup runs the closure unlocked), the mutex is not.
  Outbound entries (`park_outbound`) are operator-created, one per `node
  pair` invocation, and carry no cap.
- **`park_inbound` SUPERSEDES a same-pubkey live entry, never refuses one
  (R3) — the eviction happens under the SAME `PARK_LOCK` acquisition,
  BEFORE the cap check, never a separate check outside it.** A fresh
  request whose `pubkey_hex` matches an entry already parked for this
  approver evicts it first (approved-but-unpolled entries included — the
  superseding request comes from the SAME keyholder, i.e. the requester
  abandoning its own ceremony), so a same-identity retry against a full
  queue still succeeds on the slot its own prior entry frees. The return
  type is `Result<(InboundPairingRequest, Option<String>), String>` — the
  second element is the evicted id, for `aoide-server::a2a::pair_request`
  to audit as a supersede; it is never reported on the wire (CONTRACTS.md
  §6 — a gratuitous existence disclosure to an unauthenticated caller). Any
  new caller of `park_inbound` destructures this tuple; don't collapse it
  back to a bare `InboundPairingRequest` return without carrying the
  evicted id somewhere the caller can still audit it. `park_outbound`
  mirrors the rule on the requester's own side — replaces by id OR by the
  approver's `pubkey_hex`, one live outbound entry per far identity, return
  type unchanged (`Result<(), String>`, no evicted id to report — nothing
  audits the requester's own local file). A cross-direction pair (inbound
  FROM X alongside outbound TO X) is untouched by either rule — the two
  park files never reference each other, and neither mutator should ever
  start doing so.
- **`OutboundPairingRequest.state` defers the requester's own node-record
  commit past the approver's approval — never collapse the two-state
  machine back to an implicit "the poll answered means paired."** An entry
  parks `AwaitingApproval`; `mark_outbound_awaiting_confirm` — Design A,
  task #119, now called from `aoide-client::commands::approve_outbound`'s
  own poll-then-mark step (a CLIENT call, never a server-side wire
  handler; the old `aoide/pairApprove` callback used to trigger this from
  `aoide-server`, but the FUNCTION ITSELF is unchanged) — transitions it to
  `AwaitingConfirm` and nothing else on a pubkey match; no node-store write
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
- **`OutboundPairingRequest.tries` is the exact mirror on the requester's
  own leg (the mutual-code redesign, R1) — same split, same reasoning,
  never merged into `InboundPairingRequest.tries` despite counting the
  same kind of thing.** `record_outbound_code_try` only
  increments-and-persists; `aoide-client::commands::commit_outbound` is
  its ONLY production caller and performs the auto-abort itself via
  `take_outbound`, against the SAME `MAX_CODE_TRIES` constant the inbound
  leg reads. Two fields rather than one shared counter because the two
  legs count mismatches against two DIFFERENT derived codes
  (`derive_sas` vs. `derive_reply_sas`) on two separate park files —
  conflating them would let a wrong guess on one leg burn the other leg's
  budget. Additive `#[serde(default)]`, same discipline.
- **`InboundPairingRequest.self_via` is carried, never validated or parsed,
  by this crate (task #131).** `park_inbound`'s `self_via: Option<&str>`
  param stores whatever `aoide-server::a2a::pair_request` hands it
  straight onto the field with no shape-checking here — the same "only
  ever parsed at dial time, by the caller that actually dials" stance
  every other recorded `via` string in this crate already holds (`Node.via`,
  `OutboundPairingRequest.via`). Don't add a `parse_via` call inside
  `park_inbound` — a malformed claim must never refuse the WHOLE pairing
  request; it only ever matters later, at `aoide-client::commands::
  approve_inbound`'s own commit, and even there a bad string just fails
  that one call the same way a bad `Node.via` already does. Additive
  `#[serde(default, skip_serializing_if = "Option::is_none")]` — a legacy
  record loads `None` and a `None` here never grows the file, same
  discipline `requester_nonce_hex` already holds.
- **`undying::set_undying`'s return value is the on/off TRANSITION, not
  "did anything on disk change" (P-C1, durable-sessions plan).** Re-marking
  an already-undying id refreshes `marked_at` in place and returns `false`;
  unmarking an absent id is a no-op and also returns `false`. Don't fold the
  timestamp refresh into the return value — the `session grant undying`
  command reports this bool verbatim as `changed`, and a `markedAt` bump
  reported as a state change would be misleading (nothing about undying/not
  actually flipped).
- **`undying.json` is written via plain `fs::atomic_write`, never
  `atomic_write_private` — deliberate, not an oversight.** It holds session
  ids, the same class of data `sessions.json`/`nodes.json` already keep
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
- **`advertise` never writes `node_store`, and never will (P-P6).** It
  reaches into `node_store` for exactly one READ (`valid_node_name`, so
  the advertisement's `name` shares the same nickname shape check every
  other node-name field on the wire already holds to) — don't add a write
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
- **`tunnel::dial_url`'s path half MUST come from `node_store::url_path`,
  never a second, independently-written cut of the same url.** The
  ssh-transport plan's §0.4 is the reason: `sign_headers_for_node`
  (`aoide-client`) signs a canonical string built from the URL's path only,
  so a dial url's authority can be rewritten to `127.0.0.1:<local port>`
  with zero effect on what gets signed PROVIDED the path is copied verbatim.
  A future edit that hardcodes `/` or re-parses the path independently would
  silently break every signed call through a tunnel with an opaque
  `-32007` on the far end — `dial_url_never_invents_a_path_it_asserts_
  against_url_path_directly` (`tunnel.rs`) pins this directly, not just by
  eyeballing the two functions' output.
- **`tunnel::record_path`'s two id checks are deliberately DIFFERENT
  strictness, not an oversight.** `key` reuses `node_store::valid_node_name`
  verbatim (it names a node or a `--via` target, the same nickname shape
  everywhere else on the wire). `sessionId` uses this module's own looser
  `is_safe_id` — a session id is not an operator-typed nickname (the default
  shape is `conduct-<pid>-<unix ts>`, and `aoide conduct --id <id>` lets an
  operator override it), so it can't hold to `valid_node_name`'s
  lowercase-alnum-hyphen shape without rejecting real ids. Don't unify the
  two checks "for consistency" — `is_safe_id` still refuses every traversal
  shape `valid_node_name` does (empty, `..`, `/`, a leading `.`), which is
  the actual invariant both exist to hold.

- **`mail::verify_origin_signature` tries the ONE key `node_store` has on
  record for `header.from.node`, never every verified node's key
  (messaging plan P-M2, spec item 3).** This is deliberately NOT
  `a2a::verify_signed_request`'s own pattern (which tries every verified
  node's pubkey to discover WHICH node signed a connection) — origin
  verification already knows the CLAIMED name from the envelope itself, so
  the only question is whether THAT name's own key produced the
  signature. Widening this to a multi-key search "for consistency" with
  the connection-signature path would let any paired node forge mail
  claiming to be a different paired node, which is the exact forgery this
  function exists to rule out. No key on record for that name is a plain
  `false` (`DepositOutcome::UnverifiedOrigin` at the caller), never a
  fall-through to a default identity.

- **`stamp_rung` is called only after the caller's socket write returned
  `Ok` — never before (messaging plan P-M5a-1).** A ring that never
  reached the socket must leave the reader armed for the next trigger (a
  new arming entry, the reader's own Stop hook, or a manual `mail ring`)
  — latching first and writing second would strand a reader that a crash
  or a failed write never actually reached, silent and unrung until the
  next unrelated letter arrives.
- **The mailbase stage lock is held only inside `ring_targets`/
  `stamp_rung`/`enrol_reader`/`armed_names_for_reader` themselves, never
  by a caller across I/O (P-M5a-1; ruling R2).** Each call is a single
  `with_lock` closure measured in milliseconds; a ringer's own socket
  write, and the submit gap it holds, happen OUTSIDE every one of these.
  Don't widen a mailbase lock to cover a socket write "to be safe" — that
  would wedge every other mail command on the box for the length of one
  nudge.
- **`with_ring_lock` is a dedicated, cross-process `.ring.lock` file in
  `mail_dir()` — never the stage lock, and never an in-process mutex
  (P-M5a-2, superseding this bullet's own earlier "a process-wide ring
  mutex" — no such mutex exists; the real serializer is this file).**
  `aoide-conduct`'s `graph::doorbell::ring` wraps its ENTIRE
  select-inject-stamp sequence for one name in this one closure, holding
  it across the real socket connect, write, and submit-keystroke delay —
  the opposite of every stage-lock closure above, which is why it is a
  separate file rather than a wider stage-lock scope. Built on the same
  `fs::lock_path` primitive `try_stage_lock` itself now calls (P-M5a-2
  generalized the one flock-a-path routine both share, rather than
  duplicating it), so the two lock files behave identically (block for
  `LOCK_EX`, `Err` only when the lock file itself cannot be opened or
  created) while never being the same file. The lock is purely a
  serializer, not a policy boundary — that boundary is the resident
  daemon itself: `ring` executes only under `Door::Daemon` (P-M5a-2c),
  so in practice only the daemon process ever takes this lock, plus the
  brief window a daemon restart can overlap old and new processes both
  holding a live copy of `ring`'s call path. Two overlapping rings for
  the same name simply serialize on this file, the second always
  selecting after the first has already stamped; this file does not, by
  itself, stop some other process from opening it and taking the same
  lock — the daemon-only invariant lives in `graph::doorbell`'s own
  callers, not here.
- **The pseudo-reader (a cursor key equal to the mailbox name itself) is
  never a ring target and never counts as enrolled (ruling R1).**
  `ring_targets`/`armed_names_for_reader` both exclude the key `name ==
  reader` outright, and `enrol_reader` refuses to create it. It is the
  identity an unconducted read falls back to, not anybody's terminal —
  counting it toward `enrolled` would suppress the ringer's petname
  fallback for a mailbox nobody has actually claimed.
- **`arms(kind)` is the ONE place that decides which entry kinds ring —
  currently `letter` only.** `ring_targets`/`armed_names_for_reader` call
  it rather than repeating the kind check inline, so a future kind
  joining the arming set (ruling R5: a `fetched` receipt arms the
  origin's readers like a letter; an ordinary `receipt` never does) is a
  one-line change in one function, never a grep-and-fix across every
  caller.
- **`outbox`'s two locks are never conflated (P-M2).** The crate-wide
  stage lock (`with_lock`, wrapping `fs::try_stage_lock`) guards file
  mutations only and is held for microseconds; `.bsy`
  (`try_take_link_lock`, `LOCK_EX|LOCK_NB`) is a SEPARATE, per-node lock a
  drain holds across its entire dial+POST+record cycle. Don't widen the
  stage lock's scope to cover a network call "to be safe" — that would
  wedge every other `aoide` command on the box for the duration of one
  ssh dial. Don't relax `.bsy` to blocking, either — ruling 3 (P-M2 brief)
  is explicit that a busy link is SKIPPED, never queued behind, so one
  wedged drain can never starve every later one.
- **An outbox entry retires ONLY on a valid ack or explicit `mail outbox
  rm` (P-M2) — never auto-evicted, never expired, never capped.**
  `outbox::retire_by_ack` is the "valid ack" half — it trusts its caller
  (`mail::deposit`) to have already proven the ack's origin signature
  genuine, and never re-verifies; don't call it on an unverified envelope.
  A
  `refused: bool` entry (a JSON-RPC admission refusal, distinct from an
  ordinary transport failure) stops a drain from retrying it but still
  does not remove it — the kill-list discipline `undying`/`manifest`
  above hold for their own state applies here too: only an explicit
  human action or a genuine delivery confirmation removes a record.
- **`write_ack_if_absent` gates on PENDING state, never a permanent
  ledger (mail register §26 outbox fix).** A duplicate letter redelivery
  mints a fresh ack via `mail::mint_ack` on every call — the gate lives
  entirely in `outbox::write_ack_if_absent`, which skips the spool only
  when an ack for the same `(node, acked_msgid)` pair is CURRENTLY sitting
  undelivered in that node's outbox, checked and written atomically under
  the crate-wide stage lock. A permanent ledger keyed by `(node,
  acked_msgid)` that never clears was tried first and rejected: it broke
  the spec-mandated behavior that a duplicate whose ack genuinely never
  arrived (the ack's spool entry was already retired/removed some other
  way) must respool — MAIL.md item 5. Don't reintroduce a permanent
  "already acked" ledger in this module without re-checking
  `a2a::a_duplicate_of_a_filed_letter_respools_its_ack`.
- **`has_pending_ack_unlocked` is a marker-file read-plus-one-stat, NEVER a
  directory scan (review round 2 — the fix's first cut walked and parsed
  every file in the node's spool under the crate-wide stage lock on every
  ack deposit; the live osaka spool held 16.5k+ files, so that scan was
  itself a fresh incident in the exact path this fix exists to close).**
  `ack_marker_path(node, acked_msgid)` — `<node>/.ack/<acked_msgid>`,
  content = the pending entry's own msgid, never empty — is written by
  `write_ack_if_absent` in the SAME locked closure as the ack entry it
  covers (entry first, marker second: a crash between the two leaves a
  real entry with no marker, which just risks one harmless extra spool on
  the next redelivery, never a marker with no entry that would block
  respooling forever), and cleared by `remove_entry`, which reads the ONE
  file it is about to delete (never the directory) to learn whether it's
  a receipt-kind entry and, if so, which `acked_msgid` marker to drop
  (falling back to a scan scoped to `.ack/` ONLY, never the node
  directory, on the rare unreadable/unparsable-entry removal — a
  best-effort net for a corrupted file, not the hot path). Every
  entry-removal call site — `mail_wire::drain_node`'s `Delivered`
  confirmation, `mail outbox rm`, `retire_by_ack`'s letter-entry removal
  (a no-op marker-wise, since letters have no marker) — goes through this
  one `remove_entry`, so none of them need their own awareness of the
  marker. Don't reintroduce a directory scan on the deposit path, and
  don't move marker creation ahead of the entry write.
- **The gate self-heals an orphaned marker; an out-of-band mover need not
  touch `.ack/` (review round 3).** `has_pending_ack_unlocked` never
  trusts the marker's mere existence — it reads the msgid the marker
  names and confirms `entry_path(node, that msgid)` still exists before
  answering "pending," deleting the marker on the spot the moment it
  finds one whose entry is gone (an unreadable/malformed marker is
  treated identically). This matters because the planned archive/prune
  step (explicitly out of scope for this pass) is expected to `mv`
  receipt entries straight out of a node's directory with no idea `.ack/`
  exists — it never has to know or care, since the very next deposit
  attempt against that `acked_msgid` discovers and clears the orphan
  itself rather than being silently suppressed forever.
- **Backoff has a ceiling now (`BACKOFF_CEILING_SECS`, 15 min).**
  `back_off` still doubles from `DRAIN_BACKOFF_FLOOR_SECS` on every
  failure, but caps at the ceiling instead of doubling forever — a link
  stuck on a permanent transport failure (a missing `ssh` binary, a dead
  host) settles onto a fixed re-probe schedule rather than backing off
  into hours/days. This is a dedicated constant, not a reuse of
  `aoide_protocol::dialog::SPAWN_BACKOFF_MAX` — that ceiling is sized for
  a respawned process, not an outbox link.

## Extension points

- **A new durable record shape** adds a type to `records` and a read/write
  pair to `fs`/`stage`; existing consumers never touch raw file paths for it.
- **`SessionRecord.sources`** is a general, additive provenance map — not a
  Codex-only field — but carries exactly ONE producer at a time by design
  (P-CX-5, codex seq 228 ruling R3). A second reader wanting to point at ITS
  OWN native source earns its own slice and its own review, never a second
  field or a second map bolted on beside it; that review updates
  CONTRACTS.md §4's `sources` entry in the same commit, same as any other
  wire-shape change.
- **A new SETTABLE config key** — one whose section name and key name are
  both fixed, known ahead of time — is one row in `config::SCHEMA` plus its
  field on the matching `Config` sub-struct (`#[serde(rename)]` when the
  file spelling is camelCase, `#[serde(default = …)]` so an absent key
  still reads its default). Nothing else changes — the validator, the
  `config` listing, and `config set` all pick it up by walking the table. A
  new SECTION lands with the consumer that reads it, never ahead of one,
  and updates CONTRACTS.md §4's `config.toml` subsection in the same
  commit.
- **A new DECLARED-but-not-settable section** — one whose KEYS are
  operator-chosen (a name, a hostname, anything not fixed ahead of time),
  the shape `[mesh.<name>]` established (task #135 P4) — is a field on
  `Config` plus its own struct, validated by a dedicated function `validate`
  calls directly (never a `SCHEMA` row: a `&'static` table cannot enumerate
  keys the operator invents). `config set` cannot reach it —
  `SetRefusal::UnknownKey` refuses any key under that section by name, same
  as a typo — so the ONLY writer is a direct edit to `config.toml`'s text.
  Reading what the declaration implies about live state, and acting on it,
  are the consuming crate's job, never this one's — `aoide_client::mesh`
  reads `[mesh.*]` plus `node_store::load_nodes()` to report drift (`aoide
  mesh`) and to converge it (`aoide mesh pair`); this crate only parses and
  validates the declaration.
  Updates CONTRACTS.md §4's `config.toml` subsection in the same commit,
  same as a settable section.
- **A new CLI command** (this crate has three groups today, `usage`,
  `identity`, and `config`/`config set`) adds a `cmd!`/`register` entry in
  `commands.rs`, wired into the owning app crate's `commands::all()`. The
  pairing ceremony's own CLI commands (`aoide pair`/`pair reject`/`pair
  watch`) live in `aoide-client` instead — this crate exposes the
  `pairing`/`node_store` library only, since the ceremony needs outbound
  HTTP transport this crate never holds. `mail`'s commands (`mail
  send|read|show|mark|rm|outbox|outbox rm|outbox retry`) moved there too at P-M2, for
  the same reason — a command whose handler needs to DIAL another node
  belongs in `aoide-client`, never here, regardless of which crate owns
  the state it reads or writes.

## Docs update required in the same commit

- This `README.md` when a new module or stage-file shape is added.
- `CONTRACTS.md §4`/`§7` when a stage-file or node-registry wire shape
  changes — including `config.toml`'s own subsection when `config::SCHEMA`
  gains or loses a section/key, plus `modules/nucleus/config.nix` when the
  nix authoring front-end's option shape moves with it.
- `CONTRACTS.md §6` when `wire_auth`'s canonical string, header names, or
  pinned vectors change (P-P4).
- `pkgs/aoide/crates/AGENTS.md` for cross-crate invariants (registry order,
  golden discipline) — not restated here.
