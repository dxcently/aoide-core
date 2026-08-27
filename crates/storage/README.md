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
  `fs` resolves TWO stage roots, not one (command-defrag lane S1,
  2026-08-27, CONTRACTS.md §4): `stage_dir` — unchanged, `song/stage/`,
  rice/paint (`livery.json`/`mode.json`, lyra's tree) — and
  `conducting_stage_dir` — new, `state/stage/`, core orchestration state
  (`stage`'s own four path helpers, plus `aoide-conduct`'s
  `herald::herald_path`/`graph::pending_path`). Both honor
  `$AOIDE_STAGE_DIR` (absolute-path-wins) as one combined override, same as
  before the split; `conducting_stage_dir`'s own no-override fallback is
  `state_dir().join("stage")` instead of `stage_dir`'s `song/stage`.
  `conducting_stage_dir`'s first no-override resolution in a process also
  drives `fs::migrate_conducting_stage`: a one-shot, idempotent move of the
  six core files off their pre-split `song/stage/` location, never
  clobbering a fresher `state/stage/` file and never touching a rice file.
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
  `aoide-server::a2a::verify_signed_request`, which authenticates a
  request's `X-Aoide-*` headers against the peer's stored `pubkey` (see
  `wire_auth` below, CONTRACTS.md §6's P-P4 amendment for the full wire
  shape). None of the three rungs are interchangeable strength:
  `aoide-server`'s spawn arm (`spawn_admitted`) accepts ONLY
  `PeerRung::Signature` — a bare address match carries no possession
  proof, and a bare token match is replayable and identical across every
  request the real peer or an impersonator ever sends; both remain fine
  for attribution/origin-stamping and the ordinary autogate question, just
  never for Spawn. Ambiguity resolves deterministically: `peer add` refuses only a
  duplicate NAME (CONTRACTS.md §7), so two peers can share a URL host or
  hold byte-identical `token_file` contents, and `resolve_peer` then
  answers with whichever matches FIRST in registry (array) order — not
  the last, not random.
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
  is uncapped (operator-created, one per `peer pair request` call).
  `OutboundPairingRequest.state` (`AwaitingApproval` → `AwaitingConfirm`,
  `mark_outbound_awaiting_confirm`) defers the REQUESTER's own peer-record
  commit until its own operator confirms a second time, after the
  approver's `aoide/pairApprove` callback already landed and the approver
  has already committed its own side — both humans confirm
  the same code before either end calls itself paired.
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
  `docs/architecture/PAIRING.md` decision 7) are the provenance pair:
  `"peer:<name>"` for a session an identified, paired peer's A2A spawn
  created, additive on the live record (`skip_serializing_if`), always
  present (possibly `null`) on the closed ledger line — `SessionRecord`'s
  own value is projected verbatim into the `LedgerEntry` at exit, the same
  "additive live field, always-serialized ledger field" shape
  `resumedFrom` already set the precedent for. `origin` is attribution,
  not authentication — `aoide-conduct`'s `stamp_origin` takes whatever the
  `AOIDE_SESSION_ORIGIN` env var says, and any same-uid process can set
  that var before running `aoide conduct`, the same ordinary spoofable
  same-user process state `--from`/`AOIDE_SESSION_ID` already are (this
  crate's own `records`/`ledger` section, and CONTRACTS.md's pending-queue
  note); nothing may ever gate on it without upgrading it to an
  authenticated channel first (task #63's lane).
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
- `carry` — the carry mark (durable-sessions plan, P-C1): `state/carry.json`,
  the set of session ids marked durable so a project's whole carried set can
  be resurrected together (`session carry on|off`, a later phase).
  Mirrors `peer_store` exactly — `load_carry`/`save_carry` tolerate a
  missing/corrupt file as empty and write atomically via `fs::atomic_write`
  (not `atomic_write_private`: a session id is the same class of data
  `sessions.json`/`peers.json` already keep at default mode).
  `set_carried`/`is_carried` are pure list operations; `set_carried` returns
  whether the carried/not-carried TRANSITION changed, and separately
  refreshes `markedAt` on every `on` call including a re-mark of an
  already-carried id. Store only for now — no command or consumer is wired
  to it yet.
- `takes` — the per-draft take store behind `rice back`/`rice take`.
- `petname`/`display` — the adjective-noun petname mint and its
  render-time-only display grammar.
- `addr` — the pure address resolver (messaging/presence plan, P-C1),
  inverting `display::session_label`'s grammar to turn a typed query back
  into a local session id or a deferred `peer/<rest>` remote query. Zero
  I/O, agnostic of any call site — `aoide who` (`aoide-conduct::graph::who`,
  C2) and `send --to` (`aoide-conduct::graph::send`, C3) both call
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
- `beacon` — the discovery beacon's wire format (P-P6,
  `docs/architecture/PAIRING.md`'s "Discovery (advertise-but-locked)"
  section, CONTRACTS.md §6's "Discovery beacon" subsection): the one-line
  `{v, name, fpr, url}` JSON shape `a2a serve` may emit on a fixed UDP
  multicast group+port (`GROUP`/`PORT`, `239.255.87.10:8711`, pinned here
  so both ends of the wire agree without a handshake), plus every
  validator a hearer applies BEFORE trusting a field (`valid_fingerprint`
  for the colon-separated display fingerprint shape,
  `valid_url` for `http(s)`-only, and `MAX_LINE_BYTES` checked on the raw
  bytes before any JSON parse — house rule 4's discipline, a beacon is
  untrusted network data). Pure wire format and validators only: no socket
  I/O lives here (`aoide-server::discovery` sends, `aoide-client::discover`
  listens) and no write path into `peer_store` — discovery grants nothing,
  by construction, since this module cannot write a peer record even if a
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
