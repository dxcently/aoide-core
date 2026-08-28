# aoide-storage

Durable session data + memory persistence: stage-file record shapes, atomic
stage I/O, session/hook upsert ops, the staging/declarative mode marker, and
the peer-federation registry + pull cache (CONTRACTS.md §7). File-first by
decision — no embedded database yet (`docs/architecture/PACKAGE-LAYOUT.md`,
"storage backend" open question).

## Named seams (what it exposes)

- `records`/`fs`/`stage` — the stage-file record shapes and atomic
  read/write I/O every stage consumer (this crate's own `commands`, `conduct`,
  `song`, `conductor`) goes through instead of touching JSON on disk directly.
  Every runtime tree `fs` resolves hangs off ONE root, `fs::root` —
  `$AOIDE_ROOT` (absolute-path-wins), default `<home>/.aoide`, nix-free
  (L-C2, lyra-carrier lane, task #107) — EXCEPT `fs::flake_root`, which
  stays pinned to the dev git checkout (`$AOIDE_FLAKE_ROOT`, default
  `<home>/Aoide`) since that is not a runtime tree. `fs` resolves TWO stage
  roots off that one root, not one (command-defrag lane S1, 2026-08-27,
  CONTRACTS.md §4): `stage_dir` — unchanged, `$AOIDE_ROOT/song/stage/`,
  rice/paint (`livery.json`/`mode.json`, lyra's tree) — and
  `conducting_stage_dir` — new, `$AOIDE_ROOT/state/stage/`, core
  orchestration state (`stage`'s own four path helpers, plus
  `aoide-conduct`'s `herald::herald_path`/`graph::pending_path`). Both honor
  `$AOIDE_STAGE_DIR` (absolute-path-wins) as one combined override, same as
  before the split; `conducting_stage_dir`'s own no-override fallback is
  `state_dir().join("stage")` instead of `stage_dir`'s `song/stage`.
  `conducting_stage_dir`'s first no-override resolution in a process also
  drives `fs::migrate_conducting_stage`: a one-shot, idempotent move of the
  six core files off their pre-split `song/stage/` location, never
  clobbering a fresher `state/stage/` file and never touching a rice file.
  `fs::migrate_root_once` is the SIBLING one-shot migration for the L-C2
  root move itself (a pre-L-C2 host's `~/Aoide/{song/stage,state,log}` into
  the new root's equivalents) — deliberately NOT wired into `fs::root`'s own
  resolution the way `migrate_conducting_stage` is wired into
  `conducting_stage_dir`'s: `root`/`stage_dir`/`state_dir` are reached by
  `with_stage_lock`, the shared lock primitive nearly every stage-file
  writer across the whole workspace routes through regardless of which file
  it is actually touching, so hanging a migration off that path made an
  ordinary `state_dir()`-only test capable of silently migrating the
  operator's real `$HOME` (a live incident during this lane's own
  development). `migrate_root_once` is `pub` and idempotent instead — the
  three real binaries (`aoide`, `aoided`, `lyra`) call it once, explicitly,
  at the top of their own `main()`; see `fs::root`'s own doc for the full
  reasoning. `fs::repo_root` is GONE (its one caller, `aoide-upkeep`'s
  `soundcheck`, now reads `fs::flake_root` directly — a runtime root is not
  a repo, so deriving a checkout path from stage-dir parentage stopped
  making sense the moment the two could diverge). `fs::song_templates_dir`
  (L-C3, same lane) is a THIRD, sibling path seam alongside `root`/
  `flake_root`: the shipped SCORE TEMPLATES dir a repo-less host's `rice
  compose --from <song>` and `aoide-song::widgets`'s registry/manifest
  regeneration both fall back to when `songbook_dir`/`flake_root` have
  nothing. Two tiers — `$AOIDE_SONG_TEMPLATES` (absolute-wins, same
  discipline as every override above), else a sibling of `current_exe()`'s
  directory (`<exe_dir>/../share/lyra/songbook`, gated on that directory
  actually existing) — the same shape `aoide_protocol::bin`'s sibling-binary
  resolver uses, applied to a directory instead of an executable. Returns
  `None` (never a default that might not exist) when neither resolves; the
  caller turns that into a taught error naming both locations.
- `session` — pure session/hook upsert operations.
- `peer_store` — the peer-federation registry + pull cache (CONTRACTS.md §7).
  `Peer` carries two independent, opposite-direction credential fields:
  `tokenFile` (inbound — what a peer presents TO US, read from a local
  file) and `bearerSecret` (outbound — what WE present TO a peer, a
  secrets-broker secret NAME resolved fresh at request time by
  `aoide-client`, task #84). Both are optional and independently settable
  via `peer add`; neither implies the other. `hub` (P-D5,
  `docs/architecture/AOIDED.md`) marks AT MOST ONE registered peer as the
  standing orchestrator address resolution falls back to — additive,
  `#[serde(default)]`, omitted from the wire when `false`
  (`SessionRecord::headless`'s precedent, `records.rs`). `set_hub`/
  `clear_hub` hold the "at most one" and idempotence invariants; nothing
  else writes the field directly. `pubkey`/`verified` (P-P2,
  `docs/architecture/PAIRING.md`, CONTRACTS.md §7's "Peer record" note) are
  the pairing ceremony's own additive fields — set ONLY by
  `upsert_paired_peer`, never by `peer add`; a legacy record predating them
  loads with `pubkey: None`/`verified: false` unchanged.
  `default_peer_name_from_url` sanitizes a bare URL host into the same
  nickname shape `valid_peer_name` requires, for `peer pair request`'s
  no-`--name` default. `url_path` (P-P4) extracts just the path component
  from a peer's `url` (`"http://host:port/foo?x"` → `"/foo"`, `""` when
  none) — the ONE function both `aoide-client`'s signer and
  `aoide-server`'s HTTP request parser derive a wire path from, so a
  signature's canonical string binds to the exact same string on both
  ends. `allows` (P-P3, `docs/architecture/PAIRING.md`
  decision 5) is a CLOSED capability set (`PEER_CAPABILITIES`: `"read"`,
  `"spawn"`) — never a per-capability serde bool scatter — additive,
  empty for every unpaired/legacy peer; `upsert_paired_peer` stamps the
  ceremony's own default (`["read","spawn"]`) the moment a peer FIRST
  becomes verified, and leaves it untouched on a later key rotation (a
  revoked capability survives re-pairing). `set_peer_allow` (`peer allow
  <name> <cap> on|off`'s library half) is the only OTHER writer —
  idempotent, refuses an unknown peer or an unknown capability (the
  capability check runs first). `resolve_peer` (decision 6) is the
  caller-identity ladder the A2A door keys off, returning WHICH `PeerRung`
  matched alongside the `Peer`: a presented bearer against a peer's own
  `token_file` first (`PeerRung::Token`), an origin address against that
  peer's `url` second (`PeerRung::Addr`) — unlike `is_autogated_peer_token`/
  `is_autogated_peer_addr` above, it looks at EVERY registered peer, not
  only `autogate`-marked ones, since resolving WHICH peer is calling is a
  different question from "should this peer skip the pending queue."
  `PeerRung` carries a THIRD variant, `Signature` (P-P4) — the strongest
  rung, never produced by `resolve_peer` itself (it has no access to the
  raw HTTP request a signature needs); it is yielded only by
  `aoide-server::a2a::verify_signed_request`, which resolves the caller BY
  the stored `pubkey` that verifies the request's `X-Aoide-*` signature
  headers (#63 P-ID5: identity is the key; the claimed name is attribution
  only — see `wire_auth` below, CONTRACTS.md §6's P-P4 amendment for the
  full wire shape). None of the three rungs are interchangeable strength:
  `aoide-server`'s spawn arm (`spawn_admitted`) accepts ONLY
  `PeerRung::Signature` — a bare address match carries no possession
  proof, and a bare token match is replayable and identical across every
  request the real peer or an impersonator ever sends; both remain fine
  for attribution/origin-stamping and the ordinary autogate question, just
  never for Spawn. Ambiguity resolves deterministically: `peer add` refuses only a
  duplicate NAME (CONTRACTS.md §7), so two peers can share a URL host or
  hold byte-identical `token_file` contents, and `resolve_peer` then
  answers with whichever matches FIRST in registry (array) order — not
  the last, not random. `via` (P-S4, ssh-transport lane) is the
  `Option<String>` transport marker `aoide-client`'s dial resolution reads
  before every outbound POST to this peer (an `ssh://[user@]host[:port]`
  string, `crate::tunnel::parse_via`'s own shape) — additive,
  `#[serde(default)]`+`skip_serializing_if`, the `hub` discipline verbatim:
  absent for every peer registered before this field existed, and `None`
  means direct dial (today's behavior, unchanged). `set_peer_via` is the
  ONLY writer — a SIBLING to `upsert_paired_peer` rather than a new
  parameter on it, since that function's signature is also called from
  `aoide-server`'s own pairing integration tests, outside this field's
  blast radius.
- `pairing` — the pairing ceremony's own park-and-approve state (P-P2,
  `docs/architecture/PAIRING.md`, CONTRACTS.md §4's `state/peer-pairing-
  inbound.json`/`-outbound.json` subsection): two disk-persisted queues,
  one per direction (`InboundPairingRequest` on the approver, generated by
  `aoide/pairRequest`'s handler; `OutboundPairingRequest` on the requester,
  written by `peer pair request`), keyed by STABLE 8-hex-char ids (never
  `state/stage/pending.json`'s array-position ids — a pairing correlation
  must survive both processes exiting and an async callback arriving
  arbitrarily later). Expiry is swept lazily on every `list_inbound`/
  `list_outbound`/`take_inbound`/`take_outbound` call, never a timer
  (`pairing_timeout_secs`, `AOIDE_PAIRING_TIMEOUT` env, 4-hour default).
  `derive_sas` is the ONE SAS (short authentication string) derivation —
  SHA-256 over the four public transcript values (both pubkeys, both
  nonces, NUL-separated, order-sensitive), pinned by stability test
  vectors so it renders identically on both boxes forever. `derive_commit`
  is a SEPARATE, one-way, untruncated SHA-256 over just a pubkey + a
  nonce — the
  requester commits to its own nonce (`park_inbound`'s `commit_hex`) BEFORE
  ever revealing it (`reveal_inbound`, verified against the parked
  commitment; a mismatch DROPS the entry, a match stores the now-revealed
  `requester_nonce_hex: Option<String>` — `None` until revealed, and a
  caller MUST check that before deriving a SAS). `park_inbound` is capped
  (`pairing_park_cap`, `AOIDE_PAIRING_PARK_CAP` env, default 32,
  check-then-insert under one `PARK_LOCK` acquisition, same discipline
  `aoide-secrets::park::park_if_room` holds); `park_outbound`
  is uncapped (operator-created, one per `peer pair request` call). Every
  mutator of either park file runs its whole load-modify-write under
  `fs::with_stage_lock` — the same flock `inbox::receive` reuses for a
  `state/` file — so the `a2a serve` process and a concurrent CLI never
  race each other's read-modify-write on
  `state/peer-pairing-{inbound,outbound}.json`.
  `OutboundPairingRequest.state` (`AwaitingApproval` → `AwaitingConfirm`,
  `mark_outbound_awaiting_confirm`) defers the REQUESTER's own peer-record
  commit until its own operator confirms a second time, after this
  instance's own `aoide/pairPoll` (Design A, task #119 — REPLACES the old
  `aoide/pairApprove` reverse callback: the requester polls the approver's
  door instead of the approver ever dialing back) comes back `approved` —
  the approver has already committed its own side, purely locally, by
  then — both humans confirm the same code before either end calls itself
  paired. `InboundPairingRequest.approved` (Design A, additive,
  `#[serde(default)]`) is the mirror image on the approver's side: set by
  `mark_inbound_approved` (called ONLY from `aoide-client::commands::approve_inbound`,
  never from a wire handler) once that instance's own operator confirms —
  the entry stays PARKED (never taken) so `aoide/pairPoll` can still find
  and release it, cleaned up only by the ordinary expiry sweep.
  `InboundPairingRequest.tries` (task #120 P3, additive,
  `#[serde(default)]`) counts wrong pairing codes typed against the entry,
  cumulatively across invocations — bumped by `record_inbound_code_try`
  (same `MarkApprovedError` refusal shape), while the auto-deny at 3 is
  the CLI caller's own `take_inbound`, never a state written here. A crash
  between the third increment's save and the deny can persist a value at
  the limit; the approve path denies such an entry up front on next sight,
  so it is never approvable.
  `OutboundPairingRequest.via` (P-S4, additive, `#[serde(default)]`) carries
  the ssh-transport marker THIS instance resolved at request time (an
  explicit `--via`, or `peer invite`'s src_addr-derived default) forward to
  the SEPARATE, later `peer pair approve` invocation that actually commits
  the peer record — the only place that commit happens, so the value has
  nowhere else to ride between the two.
- `mode` — the staging/declarative mode marker, read by `shellbridge`
  (which stays in `conduct`, see that crate's charter-smudge note).
- `ledger` — the durable, append-only session HISTORY (`state/
  session-ledger.jsonl`, under `fs::state_dir` — real disk, never tmpfs;
  P-D8, `docs/architecture/AOIDED.md`'s "L5"). `sessions.json` is the live
  roster; this is what survives its pruning. One `LedgerEntry` line per
  session, written at the exact moment it leaves the roster (`aoide-conduct`
  owns the single shared call site both `session end` and `reap` route
  through — never two independently-written appenders); every field
  serializes unconditionally, unlike `records::SessionRecord`'s additive
  optional fields, since a ledger line is a closed historical shape, not a
  growing live record. `append_ledger_entry`/`read_ledger` are the only
  I/O; a malformed line is skipped on read rather than failing the file.
  `records::Project.autoResume` and `records::SessionRecord.resumedFrom`
  (both additive/v0-safe, `skip_serializing_if`) are this same phase's
  other two wire-shape additions — the daemon's boot-time auto-resume flag
  and the mark a resurrected session's own record carries.
  `records::SessionRecord.origin`/`LedgerEntry.origin` (P-P3,
  `docs/architecture/PAIRING.md` decision 7; write-authority tightened at
  LANE IDENTITY P-ID0, G16/G5, review round 1) are the provenance pair:
  `"peer:<name>"` for a session an identified, paired peer's A2A spawn
  created, additive on the live record (`skip_serializing_if`), always
  present (possibly `null`) on the closed ledger line — `SessionRecord`'s
  own value is projected verbatim into the `LedgerEntry` at exit, the same
  "additive live field, always-serialized ledger field" shape `resumedFrom`
  already set the precedent for, AND `aoide-conduct`'s
  `graph/resurrect.rs::origin_to_carry` now reads the ledger field back on
  revival to carry a LOCAL-class session's own provenance forward onto its
  fresh record (G6 — the ledger wrote `origin` on every exit long before
  anything read it back), REFUSING to carry a `peer:*` shape found there
  (eprintln, never carried) — `state/session-ledger.jsonl` is a plain,
  same-uid-writable, append-only file, so a same-uid process could append a
  line claiming `origin:"peer:X"` and drive the ungated local `aoide
  resurrect`, which has no door and no seal behind it to re-mint that
  authority. `origin` is still attribution, not an authenticated
  credential — the invariant `aoide-conduct`'s `stamp_origin` (`pub`,
  crossing the crate boundary) now holds is by SHAPE, not caller count: a
  `peer:<name>` value may be stamped from exactly one place,
  `aoide-server`'s `a2a::do_spawn`, DIRECTLY on the record from the door
  that authenticated the peer name; every other caller
  (`session_conduct`'s env read, `origin_to_carry`'s ledger read) may
  stamp a LOCAL-CLASS value but refuses a `peer:*` shape from its own
  untrusted source. **This closes the STAMP paths, not the files** — a
  hand-crafted `sessions.json`/ledger line claiming `peer:X` is still a
  readable, unflagged string on disk; nothing here makes the files
  tamper-evident, that is P-ID1 (the daemon-signed credential) minted and
  stored, verified on the per-session control socket's own accept and
  consumed by the send gate as of P-ID2 — the remaining two sockets
  (shellbridge, `aoided`'s own dispatch socket) get a peercred floor of
  their own as of P-ID3 (cross-uid only; see `aoide-conduct`'s own
  README/AGENTS and CONTRACTS.md's identity section for the honest
  accounting of what that does and does not close). A same-uid process
  can still forge a LOCAL-class origin as a raw string, so nothing gates a
  security decision on the field as read off disk — the authenticated form
  is `sealed_id`'s credential (below), whose VERIFIED `originClass` is
  what the send gate and the secrets broker's origin gate (P-ID4,
  `attest`) consume; the consumer NAME presenting a request stays
  unauthenticated either way (a separate, unbuilt axis — CONTRACTS.md's
  identity-lane accounting). What P-ID0 closes: every
  record-STAMP path this codebase drives now refuses a `peer:*` shape it
  didn't mint itself at the door — env AND the unsealed ledger both.
  `records::RestoreSnapshot`/`SessionRecord.restore`/`LedgerEntry.restore`
  (P-C5, durable-sessions plan) are a conducted TERMINAL's continuously-
  captured `{cwd, idle, argv, typed}` snapshot — the SAME `RestoreSnapshot`
  type embedded on both, `origin`'s "additive live field, always-serialized
  ledger field" shape again, except `RestoreSnapshot`'s OWN fields never use
  `skip_serializing_if` in EITHER home, so a populated snapshot reads the
  identical complete shape whichever file it's read from. `idle` is its own
  field rather than inferred from `state`, deliberately: the reap sweep
  overwrites `state` to `"done"` before its ledger write, so idleness would
  otherwise be unrecoverable by the time `ledger_session_exit` runs.
  `aoide-conduct` is the sole writer (its PTY tick, ~1 Hz) and the sole
  reader of `typed`'s raw keystroke stream — this crate only holds the
  shape, never the capture logic.
- `undying` — the undying mark (durable-sessions plan, P-C1; renamed from
  "carry" at command-defrag lane U1, 2026-08-27): `state/undying.json`, the
  set of session ids marked durable so a project's whole undying set can be
  resurrected together (`session grant undying on|off`). Mirrors `peer_store`
  exactly — `load_undying`/`save_undying` tolerate a missing/corrupt file as
  empty and write atomically via `fs::atomic_write` (not
  `atomic_write_private`: a session id is the same class of data
  `sessions.json`/`peers.json` already keep at default mode).
  `set_undying`/`is_undying` are pure list operations; `set_undying` returns
  whether the undying/not-undying TRANSITION changed, and separately
  refreshes `markedAt` on every `on` call including a re-mark of an
  already-undying id. `load_undying` also folds in a one-shot migration off
  the pre-rename `state/carry.json`, idempotent by construction (a cheap
  `exists()` check, no process-wide `Once` needed for a single file) —
  narrated, never a clobber of a fresher `undying.json`.
- `manifest` — a project's own `.aoide/project.json` (v0, command-defrag
  lane U1): host-local SESSION SPECS (`{host, dir, agent, command?}`, `dir`
  always PROJECT-RELATIVE, never a session id or timestamp), so `resurrect`
  (U2) can bring a project's intended sessions up on the host that conducts
  them without a `projects.json` registration first. Distinct from
  `undying` in every way that matters except one — both are host-local,
  neither committed; see this module's own doc for the full contrast.
  `load_manifest`/`save_manifest` are this project root's read/write pair
  (missing file → `None`; unreadable/corrupt → narrated then `None`;
  `save_manifest` refuses an absolute `dir` in any spec BEFORE writing
  anything). `.aoide/` self-ignores on first `save_manifest` into a project
  root (`.gitignore` seeded with `*\n`, never overwritten if one already
  exists) — the manifest never syncs via git the way the project's own
  source does. `resolve_spec_dir` (U2) is the read-side containment guard:
  joins a spec's `dir` onto the project root and normalizes LEXICALLY,
  refusing any `..` that would resolve outside the root. `walk_up` is the
  pure, explicit-`start`-argument discovery seam `resurrect`'s bare mode
  calls: git-style nearest-wins search up through parent directories,
  stopping at the filesystem root — a lexical walk, never realpath-resolving
  (a manifest reached through a symlinked directory is still found; the walk
  never resumes from the symlink's own target ancestry).
- `tunnel` — the ssh tunnel registry (ssh-transport lane, P-S2,
  `docs/architecture/PAIRING.md`'s forthcoming Transport section): a cross-box
  client action that cannot reach a peer's loopback-bound door directly opens
  an ssh `-L` forward and records it at `$XDG_RUNTIME_DIR/aoide/tunnel/
  <sessionId>/<key>.json` (`TUNNEL_VERSION` "0" — two path levels, since
  both components may carry `-` and a flat joined name could collide two
  distinct pairs onto one record), the same runtime-dir
  convention `aoide_conduct::graph::conduct_socket_path` resolves its own
  `session-<id>.sock` into — re-derived here (`runtime_dir`), not imported,
  since this crate sits below `conduct` in the DAG. `parse_via` reads a
  `--via`/`Peer.via` marker (`ssh://[user@]host[:port]`, `ssh` scheme only,
  user and port both optional, a present port bounded `1..=65535`) into a
  `Via`; `default_via` builds one directly from an observed IP + login with
  no string round trip. `dial_url` rewrites a logical peer url's authority to
  `127.0.0.1:<local port>` while preserving BOTH the scheme and the PATH
  verbatim — the path half delegates to `peer_store::url_path` rather than
  re-deriving it, since `sign_headers_for_peer`'s canonical string
  (`aoide-client`) is bound to that exact same path; a divergent cut here
  would make every signed call through the tunnel fail on the far end with an
  opaque `-32007`. `record_path` refuses a traversal-shaped `sessionId` or
  `key` before either ever reaches a path join — `key` through
  `peer_store::valid_peer_name`, `sessionId` through this module's own looser
  `is_safe_id` (a session id is not an operator-typed nickname, so it can't
  reuse `valid_peer_name` verbatim). `save`/`load`/`remove` are the CRUD
  (`atomic_write_private`, `0600` — module doc's own note on why a
  non-secret record still gets that discipline; `load` additionally
  refuses a record whose own fields name a different pair than the path it
  was read from); `list_records` walks only `tunnel/*/*.json`, the same
  `sweep_orphan_sockets` scoping
  (`aoide-conduct::reap`) that lets a sibling convention's files
  (`session-*.sock`, `aoided.sock`) share the same runtime directory without
  ever being mis-parsed. No process is ever spawned here — the ssh child
  itself lives in `aoide-client::tunnel` (P-S3), the same `peer_store`
  (storage) / `commands` (client) split this crate already holds for peer
  transport.
- `takes` — the per-draft take store behind `rice back`/`rice take`.
- `petname`/`display` — the adjective-noun petname mint and its
  render-time-only display grammar.
- `addr` — the pure address resolver (messaging/presence plan, P-C1),
  inverting `display::session_label`'s grammar to turn a typed query back
  into a local session id or a deferred `peer/<rest>` remote query. Zero
  I/O, agnostic of any call site — bare `session`/`--hosts`
  (`aoide-conduct::graph::who`, C2 — the roster core, formerly the standalone
  `who` command) and `send --to` (`aoide-conduct::graph::send`, C3) both call
  `resolve` directly. `resolve_with_hub` (P-D5) composes it with the hub
  preference (`peer_store::Peer.hub`): a hub-designated peer is offered as
  one last, least-specific `Remote` candidate only on `resolve`'s own
  `NotFound` — every earlier precedence tier is untouched. As of P-D5 it is
  a tested library function only; `send --to`'s live call site still
  calls plain `resolve` (the same "land the function, wire a caller later"
  order this module's own tier-5 `peer/<rest>` grammar went through).
- `inbox` — the durable per-host message store (messaging plan P-C6,
  `state/inbox.json`, CONTRACTS.md §4): every message that lands in a local
  session, filed by `conduct`'s `deliver_local` success path — the ONE
  writer that covers a direct `send`, a `--to` local resolve, a
  `pending approve` re-drive, AND the A2A server's `do_inject` (which
  reaches `deliver_local` through the same `session_send` door). Capped at
  200, oldest-drop, atomic writes (`herald::LEDGER_CAP`'s fold-and-cap
  precedent). `context` is an opaque `serde_json::Value` passthrough
  reserved for a future Mneme (memory-manager) integration — v0 never reads
  it.
- `identity` — this instance's lazily-minted ed25519 keypair (pairing
  workstream P-P1, `docs/architecture/PAIRING.md`, CONTRACTS.md §4's
  `state/identity/` subsection): `state/identity/ed25519.key` (the raw
  32-byte private seed, `fs::atomic_write_private`'s 0600 discipline,
  written once) plus a `created_at` sidecar. `Keypair` holds the private
  key and is never `Serialize`/`Deserialize` — `IdentityInfo` (pubkey hex,
  fingerprint, mint time) is the only serializable shape this module
  emits, and a source-scanning test in `identity.rs` mechanically holds
  that boundary. The pairing ceremony (`peer pair`, P-P2) builds on this
  directly (`peer_store`/`pairing` above); the `allows` set + A2A spawn-gate
  flip (P-P3, `peer_store::allows`/`resolve_peer` above) also build on it;
  so does `wire_auth` below (P-P4) — `Keypair::sign`/`Keypair::verify` are
  its ONLY two entry points into `ed25519_dalek`, so neither
  `aoide-client` nor `aoide-server` needs that dependency directly.
- `sealed_id` — the daemon-sealed session credential (LANE IDENTITY P-ID1,
  `docs/architecture/CONTRACTS.md` §4's `seal` field, plan file "LANE
  IDENTITY (#63)"): `SealedIdentity{sessionId, pid, pidStarttime,
  originClass, issuedAt}`, `canonical_seal_string` (the same NUL-separated
  five-field shape `wire_auth::canonical_string` established, but
  **`sessionId`/`originClass` ride VERBATIM — no trim, no case-folding**;
  review fix, since `sessionId` is the session store's own case-sensitive
  primary key and `originClass` is about to be P-ID4's origin-gate lookup
  key, folding either would let a seal minted for one exact identity
  verify against a differently-cased one), and `mint_seal`/`verify_seal` —
  thin wrappers over `wire_auth::sign_hex`/`verify_signature_hex`, so this
  module never touches `ed25519_dalek` directly either. **The signing key
  is NOT `identity::load_or_mint`'s on-disk peer-wire key** — under OQ1-A
  (the plan file's User-answered threat-model question) a same-uid
  attacker can read any file the operator owns, so an on-disk key is not
  secret against it; `identity::mint_ephemeral` (this crate's other new
  P-ID1 entry point) mints a SEPARATE keypair that lives only in the
  calling process's memory, never touching disk, so its secrecy rests on
  process liveness plus Yama `ptrace_scope` instead (see `identity.rs`'s
  own doc on `mint_ephemeral`, and CONTRACTS.md §4's `seal` paragraph, for
  the full reasoning and the Yama-off degrade note). A `pidStarttime` of
  `0` (the documented degrade for a pid that vanished before mint) is
  self-consistent but UNVERIFIABLE against any later live `/proc` read —
  no genuine read is ever `0` — a caller must treat it as "cannot
  revalidate," never as "verified." `records::SessionRecord.seal`/
  `sealedIssuedAt` (both additive, `skip_serializing_if`, one lifecycle —
  always `Some` together) are where a minted seal is stored — stamped by
  `aoide-conduct::graph::session_store::stamp_seal`, this crate's own
  sibling to `stamp_origin`. `sealedIssuedAt` exists because `issuedAt` has
  no live fact a verifier can re-derive it from the way `pidStarttime` does
  (a fresh `/proc` read) — without it, checking a signature means
  brute-forcing every plausible mint instant, which is exactly what this
  module's OWN P-ID1 test suite did before this field existed. **P-ID2 is
  the first phase to read `seal`**: `attest::verify_seal_over` (below)
  reconstructs the exact signed `SealedIdentity` from a record (never
  trusting a stored `pidStarttime`, always a fresh `/proc` read) and calls
  this module's `verify_seal` against the daemon's LIVE public key. This
  module's own test suite (verify TRUE on a genuine seal, FALSE on any
  single tampered field including a case-only-different `sessionId`, FALSE
  under a different keypair) still proves the mechanism in isolation; the
  consumers' tests prove the wiring.
- `attest` — the kernel-attested caller resolution (LANE IDENTITY P-ID4's
  seam lift; bodies moved from `aoide-conduct::graph::{window,identity}`
  and `aoide-client::daemon`, which all delegate here): the bounded
  `/proc` ancestry walk (`pid_ancestry`, self-first/nearest-first) and
  starttime read (`pid_starttime`), `verify_seal_over` (fresh-starttime
  reconstruction — the pid-reuse defense), `attested_session` (the
  verified nearest-ancestor walk the send gate keys on), the daemon
  seal-pubkey channel (`daemon_socket_path`/`connect_bounded`/
  `daemon_seal_pubkey_hex` — a LIVE `ping` round trip, never a file), and
  `attested_caller` — the secrets broker's one-stop: peercred pid →
  verified `(sessionId, originClass)`, `None` = UNIDENTIFIED. Lives here
  because the crate DAG forbids every other shared home (`aoide-secrets`
  may never depend on `aoide-conduct`/`aoide-client`) and every ingredient
  — `records::SessionRecord`, `stage::sessions_path`, `sealed_id`,
  `identity` — already does; resolution only, never a policy decision
  (this crate's `AGENTS.md`).
- `wire_auth` — per-request signed wire authentication for paired peers
  (P-P4, `docs/architecture/PAIRING.md`'s "Wire authentication (paired
  peers)" section, CONTRACTS.md §6's own amendment for the full wire
  shape and pinned vectors). `canonical_string(method, path, timestamp,
  nonce, body)` is the ONE function both ends build independently (never
  a wire-carried canonical string) — five fields, each trimmed+lowercased,
  NUL-separated after every field including the last (P-P2's
  `derive_sas`/`derive_commit` style, reused verbatim), with only the body
  digested (`sha2`) rather than riding the string whole. `sign_hex`/
  `verify_signature_hex` are thin hex-in/hex-out wrappers around
  `identity::Keypair`'s two entry points — neither `aoide-client` nor
  `aoide-server` touches `ed25519_dalek` types directly.
  `signature_skew_secs` (`AOIDE_SIGNATURE_SKEW_SECS` env, 120s default)
  and `within_skew` are the replay guard's timestamp half; the OTHER half
  (the nonce cache) is deliberately NOT here — it is ephemeral,
  process-local, per-`a2a serve` runtime state with no durable file behind
  it at all, unlike everything else this crate persists, so it lives in
  `aoide-server::a2a` next to its one consumer instead (this module's own
  doc comment states the reasoning). `HEADER_PEER`/`HEADER_TIMESTAMP`/
  `HEADER_NONCE`/`HEADER_SIGNATURE` are the four wire header names — always
  present together or not at all, never independently optional.
- `advertise` — the discovery advertisement's wire format and the
  advertise switch (P-P6 + task #120, `docs/architecture/PAIRING.md`'s
  "Discovery (advertise-but-locked)" section, CONTRACTS.md §6's
  "Discovery advertisement" subsection): the one-line
  `{v, name, host, user}` JSON shape `a2a serve` may emit by UDP
  broadcast (`BROADCAST_ADDR`/`PORT`, `255.255.255.255:8711`, pinned here
  so both ends of the wire agree without a handshake — name + ssh hop
  claim ONLY, never a door URL or a key: rendezvous, not
  authentication), every validator a hearer applies BEFORE trusting a
  field (`valid_host`/`valid_user` for bounded metacharacter-free
  shapes, and `MAX_LINE_BYTES` checked on the raw bytes before any JSON
  parse — house rule 4's discipline, an advertisement is untrusted
  network data), and `enabled`/`set_enabled`, the `state/advertise.json`
  switch `aoide peer advertise on|off` flips (default OFF,
  tolerate-missing, atomic write). No socket I/O lives here
  (`aoide-server::discovery` sends, `aoide-client::discover` listens)
  and no write path into `peer_store` — discovery grants nothing, by
  construction, since this module cannot write a peer record even if a
  caller wanted it to.
- `commands` — this crate's CLI commands: `usage` (local token/cost rollup),
  `inbox list|read|clear` (the store above's CLI surface), and `identity`
  (the module above's CLI surface). `peer pair request|pending|approve|
  reject` lives in `aoide-client` instead (outbound transport crosses the
  `client → storage` DAG edge; this crate exposes `pairing`/`peer_store`
  as the library, `client` drives the wire).

## What it consumes

`aoide-protocol` (plus `aoide-test-support` as a dev-dependency), and — as
of P-P1 — `ed25519-dalek`/`getrandom` for `identity`, joined at P-P2 by
`sha2` for `pairing::derive_sas`: sanctioned exceptions to this workspace's
zero-new-deps discipline, scoped to cryptographic primitives specifically
(User ruling 2026-08-25, `docs/architecture/PAIRING.md`'s kill-list and
decision 1; see the workspace `Cargo.toml`'s own comment on those entries
for the version/feature reasoning). It is the second-lowest crate in the
DAG — everything that persists state sits above it.

## How it composes

`client`, `conduct`, `server`, `song`, `conductor`, and both app crates
depend on it for durable state. **Charter smudge**: `takes` and `mode` live
here rather than in a paint-adjacent crate — zero dependency weight, and
`mode` is read by `shellbridge`, which itself stays core-crate-resident in
`conduct` (see `docs/architecture/PACKAGE-LAYOUT.md`, "Charter exceptions").
