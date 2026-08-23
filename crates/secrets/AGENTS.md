# AGENTS.md — aoide-secrets

## Invariants

- **A secret's VALUE never appears on a `Serialize`/`Deserialize` type in
  this crate.** `policy::Policy` is still the only such type, and it holds
  no value. P-V2's resolve response and both audit lines are the exact
  place this rule was written down FOR: `broker::handle_resolve` and
  `broker::audit_resolve` build `serde_json::Value`s directly (via the
  `json!` macro) at the point of use, never a named struct with a `value`
  field — check any new `#[derive(Serialize)]` type added to this crate
  against this line before it lands. A value belongs in a client-process
  env var and nowhere else (README's release-to-client flow); `client::
  resolve` extracts it straight out of the reply's `serde_json::Value`
  into a local `String`, never a struct field.
- **Audit happens BROKER-SIDE ONLY** (`broker::audit_resolve`), on every
  resolve attempt, granted or denied. The CLIENT (`client.rs`) never calls
  `aoide_protocol::audit` itself — it only ever learns granted/denied from
  the wire reply. Don't add a second audit call on the client side "for
  completeness"; it would double-log every resolve and the client doesn't
  have the policy-gate reasoning to log honestly anyway.
- **`EventClass::Secret` (the mirrored aoide-log event) forbids
  `untrusted_data`** — enforced in `aoide_protocol::audit::append_audit`
  itself (strips it, `eprintln!`s), not only by this crate's discipline.
  Don't set `untrusted_data` on a Secret-classed `AuditRecord` expecting it
  to ride through; it won't, and the strip is the safety net, not the
  design.
- **`requireTotp` is UNRESOLVABLE only when no enrollment exists on this
  host, never a silent downgrade to a standing grant in either
  direction.** `broker::resolve_gate`/`verify_totp_gate` (P-V3): no
  `totp.secret` -> reject outright, same wording as before P-V3;
  enrolled -> verify the wire's `totp` code (`totp::verify`, `±1` window)
  and consume the matched timestep in the persisted
  `replay::ReplayLedger` — a missing/wrong/already-used code is an
  ordinary denial, the backend never runs. Don't let a `requireTotp`
  policy fall back to treating itself as a standing grant just because an
  enrollment exists; the code (or its absence) is what decides.
- **`put` (P-V4c) is NEVER gated by `requireTotp`, and carries no
  `consumer` field at all.** `broker::put_gate` is a SEPARATE function from
  `resolve_gate` — it never calls `verify_totp_gate`, on ANY policy,
  `requireTotp` or not. This is deliberate, not an oversight: `secrets put`
  is CLI-only/admin-side (`commands::handle_secrets_put`'s `require_cli`
  gate), never agent-facing, so there is no separate consumer identity to
  authorize and no code check to run — see `broker.rs`'s module doc for the
  full reasoning. Don't add a TOTP or consumer check to `put_gate` "for
  symmetry with resolve"; the two ops have different threat models on
  purpose.
- **The "does this secret already have a value" check is BROKER-SIDE ONLY,
  never the client's** (P-67, "warn before overwrite" — the User's own
  live complaint: `put` silently overwrote). `broker::has_value`-backed
  `put_gate` probes existence by running the SAME `get` template `resolve`
  would; the CLIENT never fetches a value to find out (that would be a
  `resolve`-shaped leak on an op that isn't `resolve`) and a client-side
  file peek would break the uid boundary outright (the client doesn't run
  as the secrets uid — it can't see the backing store at all). Don't add a
  client-side existence check "to save a round trip"; the whole point is
  that only the broker is allowed to know.
- **The `put` overwrite refusal is a MACHINE-READABLE flag
  (`"exists":true`), never inferred from `error` text** (P-67). Don't add a
  new `put` denial reason whose message text a caller (or this crate's own
  `client::put`) would need to string-match to distinguish "already has a
  value" from every other kind of denial — a new distinct case gets its
  own flag field the same way, not a string convention.
- **NO CACHE, EVER.** A secret's value exists ONLY between a `get`/`set`
  template's own invocation and the wire write that immediately follows —
  nothing in `broker`/`client`/`backend` may hold a value across requests,
  in memory or on disk, for any reason. `resolve` runs the backend fresh on
  EVERY call so revocation is immediate; don't introduce a warm cache, a
  TTL, or a "remember the last resolve for this secret" optimization —
  that would make revocation lag behind `secrets rm`/backend rotation,
  which is exactly the property this crate exists to hold.
- **ONE VALUE PER SECRET is the contract, not an implementation detail.**
  `policy::Policy` models exactly one backend-fetched value per policy
  entry; a credential with multiple fields is multiple named secrets, each
  its own policy with its own `consumers[]`/`requireTotp` (the `sops`
  preset's per-field JSONPath `key`, README's "Backend presets", already
  shows this). Don't add a multi-field resolve/put op, and don't let a
  single `Policy` grow a second value-bearing field "for convenience" —
  per-field grants and per-field TOTP are the whole point of keeping
  secrets one-per-policy.
- **Per-backend environment is INLINE IN THE TEMPLATE — no structured
  `env` map on `Backend`, ever.** A backend needing `BW_SESSION` or similar
  sets it as part of its own `sh -c` template text. Don't add an `env:
  BTreeMap<String,String>` field to `backend::Backend` "to avoid repeating
  the var in every template" — the whole adapter surface is deliberately
  ONE string per direction (`get`, `set`).
- **`ReplayLedger` keys on timestep ALONE, never on consumer** (ruling,
  Fable, 2026-08-22, P-V1 review escalation — plan file's SECRETS §Policy
  section). The resolve wire's `consumer` field is self-asserted; a
  per-consumer ledger would let one typed code redeem once per invented
  label. Don't reintroduce a consumer dimension to `replay::ReplayLedger`
  without authenticated consumer identity landing first (#51-adjacent,
  not planned).
- **Clock-as-parameter, everywhere.** Every function in `totp`/`replay`
  takes `unix_time`/`timestep`/cutoff as an explicit argument. Nothing in
  `src/` calls `SystemTime::now()` — grep for it before merging a change
  here; a thin wrapper that reads the real clock belongs in V2's broker,
  never inside these pure functions. This is what makes the RFC vectors
  usable as a test suite at all (a fixed `unix_time` input, not "now").
- **Zero algorithmic dependencies.** `sha1`/`hmac`/`totp` are hand-rolled
  on purpose (plan mandate) — do not reach for a `sha1`/`hmac`/`totp-lite`/
  `data-encoding` crate to "simplify" this later; the RFC test vectors are
  the contract that makes the hand-rolled version trustworthy, and the
  whole point is that the secrets broker doesn't carry a supply-chain dependency
  for something ~150 lines of tested Rust does directly. `serde`/
  `serde_json` are the only exception (record-shape (de)serialization, not
  cryptography).
- **RFC vectors are not decorative — a change to `sha1`/`hmac`/`totp` that
  breaks a named RFC test is never "expected," it's a correctness bug.**
  Unlike the golden-snapshot discipline elsewhere in this workspace (where
  a red golden after an intentional command-set change is routine), a red
  RFC vector test here means the hash/HMAC/TOTP math is wrong.
- **`policy::valid_secret_name` is deliberately stricter than
  `aoide_storage::peer_store::valid_peer_name`**, and this crate does NOT
  depend on `aoide-storage` to reuse the looser one — see `policy.rs`'s
  module doc for the exact delta (no leading/trailing hyphen, no `--`
  run). Don't "consolidate" the two without re-deriving why secrets secret
  names are held to a tighter bar (they name on-disk backend-store paths
  under a privileged uid; a peer name only names a JSON cache file).
- **I/O is confined to seven named modules: `broker`, `client`, `store`,
  `backend`, `enroll` (P-V3), `watch` (tracker #71 Part 1), and each
  module's own `#[cfg(test)]` block.** `sha1`/`hmac`/`totp`/`base32`/`uri`/
  `replay`/`policy` stay pure — no `SystemTime::now()`, no socket, no
  `exec`, no reads/writes of secrets home in any of them. This is the P-V2
  narrowing of the old P-V1 rule ("nothing in this crate performs I/O" —
  true then because there were no I/O modules yet), widened once more at
  P-V3 for `enroll`'s `/dev/urandom`/`gethostname`/`qrencode` calls, and
  again for `watch`'s log-tail (`File`/`stat`), socket calls
  (`client::pending`/`approve`/`dismiss`, reused, never duplicated), and
  `SIGINT` handling (`libc::signal`) — the boundary moves as new I/O
  concerns earn their own named module, it does not disappear. `enroll`
  itself never writes a secrets-home FILE directly — that stays `store`'s
  job (`enroll::run` calls `store::save_totp_secret`/`save_replay_ledger`).
  `watch` itself never writes a secrets-home file OR `policy.json` at all
  — it only reads the mirrored aoide log (never the broker's own
  `audit.log`, which is `0700` broker-uid and unreadable from the operator
  side anyway) and speaks the SAME three socket ops `pending`/`approve`/
  `dismiss` already expose, never a new wire op.
- **`watch`'s pure fold (`Event`/`Queue`/`pick_next`/`code_prompt_allowed`)
  holds the SAME clock-as-parameter discipline this crate's `totp`/`replay`
  modules already hold** (invariant above), extended here for the identical
  testability reason: `Queue::apply`/`Queue::reconcile` take an event/
  `Vec<PendingAsk>` and never call `SystemTime::now()` internally — every
  timestamp they fold in (`ts` from the mirrored log's own `AuditRecord`,
  `requestedAt` from `client::pending`'s reply) arrives as a parameter. Only
  `watch::run`'s own outer loop (and its private `unix_now()`) touches the
  real clock, the same "thin wrapper reads the real clock, never the pure
  functions" split `broker.rs`'s own P-N2 tests already establish. Don't
  add a `SystemTime::now()` call inside `Event`/`Queue`/`pick_next`/
  `code_prompt_allowed`/`narrate_event`/`event_to_json` — grep for it
  before merging a change to `watch.rs`'s pure half.
- **`watch`'s tail is a TRIGGER; `client::pending` is the AUTHORITY** — the
  SAME rule P-N2's own README section states for `secrets pending`'s poll,
  extended to this surface: `Queue::reconcile` runs once at `watch::run`
  startup (so a watcher started AFTER an ask parked still converges) and
  again on every parsed event plus a 30s safety tick. Don't let a future
  event kind become load-bearing on its own without a reconcile behind it
  — the mirrored log can miss a line (a truncation between polls, a
  process restart) in a way the broker's own in-memory `ParkRegistry`
  cannot.
- **Every admin verb that reads/writes `policy.json`/`totp.secret` refuses
  the wrong effective uid BEFORE touching the file, never after** (P-V4f,
  the yomi-strix incident, 2026-08-22: plain `sudo aoide secrets add …`
  ran as euid 0, succeeded, and silently reowned `policy.json` to
  `root:root`, bricking the broker and every later admin verb — including
  the correctly-spelled `sudo -u aoide-secrets` retry — until a manual
  `chown`). `home::admin_identity_error(euid, home_owner, home, verb)` is
  the PURE decision (unit-tested on injected uids: matching, root-vs-owner,
  an arbitrary mismatch); `home::admin_identity_check(home, verb)` wires it
  to a real `std::fs::metadata(home)` stat and a real `home::effective_uid`
  (`libc::geteuid`, zero new deps — `libc` is already this crate's
  dependency). `commands::require_admin_identity` calls it right after
  `require_cli` in `add`/`rm`/`grant`/`revoke`/`set-totp`;
  `enroll::run` calls it directly (its real work happens from `cli`'s
  `special` hook, outside `commands.rs`'s own dispatch) — `enroll::show`
  does NOT carry it (read-only, nothing to corrupt), and neither does
  `put`/`exec` (socket-side operator verbs the guard was never meant to
  cover). Root is explicitly a REFUSED case, not a bypass: root can always
  write regardless of file ownership, which is the exact mechanism that
  corrupted `policy.json` in the field. **A not-yet-existing secrets home
  is not an unconditional pass either** (P-V4f follow-up, found on review:
  `store::save_policies`/`store::save_totp_secret` both `create_dir_all`
  the home on first write, so an unguarded root caller hitting a missing
  home would CREATE it `root:root` — the identical bricking symptom,
  just at creation time instead of a reown) — `home::
  admin_identity_error_for_missing_home(euid, home, verb)` is that case's
  own PURE decision (root refused, any other uid passes), and
  `admin_identity_check` falls to it whenever the stat fails, rather than
  passing unconditionally. A non-root uid still creates its own fresh home
  freely (the dev/test tempdir flow, or an explicit `sudo -u aoide-secrets`
  first run per the deployment doc) — only root bootstrapping a missing
  home is refused. Don't add a second, differently-worded identity check
  elsewhere in this crate; these two pure functions plus
  `admin_identity_check`'s dispatch between them are the one gate, and a
  new admin verb that touches `policy.json`/`totp.secret` calls it the
  same way.
- **The automation gate can only ever RELAX `requireTotp`, never tighten
  it** (P-N1). `policy::totp_required(policy, consumer)` is the ONE
  decision point `broker::resolve_gate` routes through — it is `requireTotp
  AND NOT (automation.enabled AND consumer IS IN automation.consumers)`.
  `requireTotp: false` returns `false` from `totp_required` in every
  combination; automation has no ability to IMPOSE a TOTP requirement a
  policy doesn't already carry, only to name specific consumers who skip
  one it does. Don't inline `policy.require_totp` back into `resolve_gate`
  "for clarity" — `totp_required` stayed the ONE call site P-N2's parking
  change routed through (`GateOutcome::NeedsTotp`, invariant below) rather
  than a second ad hoc check growing beside it.
- **`automation.consumers` is checked against the SAME self-asserted
  `consumer` wire field `resolve`'s `consumers[]` already is** (P-N1,
  honesty note mirroring the `ReplayLedger` ruling above, for the
  identical reason). Nothing authenticates the wire's `consumer` field, so
  an automation-open secret is effectively code-free for any local socket
  caller claiming a listed name, until authenticated session identity
  exists (#63-adjacent, not planned). Don't treat `automation` as adding
  any cryptographic boundary beyond what `consumers[]` already has — it's
  a courtesy label on the same self-asserted field, not a stronger one.
- **`Policy::remote` (P-N1) gates NOTHING today — that is deliberate, not
  a gap.** No non-local entry point onto this broker exists yet. This is
  a forward-looking crate invariant, written down now while the field is
  new: **every non-local entry point added later (mesh replication, a
  network door, any future doorway a value could leave this host through)
  MUST refuse a secret whose `remote` is `false` before ever touching its
  backend.** Don't add a mesh/network resolve path that skips this check
  "because it's not implemented as a gate yet" — the field existing with
  no reader yet is exactly what this note exists to close before it
  becomes a live gap the way the automation-consumer self-assertion note
  above already is.
- **A parked ask never stores or touches a value — the same "never store a
  value" rule above, extended to the registry P-N2 adds.** `park::
  ParkedAsk` carries only `secret`/`consumer`/`requested_at` and a private
  send-once channel; `broker::handle_approve` fetches the value fresh
  through the backend ONLY after a code has already validated
  (`verify_totp_gate`, the SAME function an inline `resolve` code uses),
  and sends it straight down that channel — never holding it in the
  registry, never in `approve`'s own wire reply back to the operator.
  Don't add a "cache the value once fetched, in case the connection reads
  slowly" optimization to `ParkedAsk` — the value must exist ONLY inside
  the one send/receive handoff, same as everywhere else in this crate.
- **Three production (non-test) locks exist in this crate tree, all
  poisoned-lock-recovering, all following the SAME convention
  `park::ParkRegistry`'s established first.** Every earlier `Mutex`/
  `RwLock` in this crate was test-only env serialization (`env_lock()`);
  `park::ParkRegistry`'s internal `Mutex` was the first one live code
  touched (P-N2). Thread-per-connection then exposed two more
  read-modify-write sections the old SERIAL accept loop used to serialize
  for free, just by never running two connections' code at once — a
  reviewer-confirmed race, reproduced empirically before the fix (5/20
  iterations of a two-thread test double-granted the same TOTP code):
  `broker::replay_ledger_lock` guards `verify_totp_gate`'s FULL
  load -> record -> prune -> save of the replay ledger, and
  `broker::put_lock` guards `put_gate`'s FULL existence-probe -> store
  (the same newly-exposed TOCTOU shape, one code redeeming twice /
  one overwrite:false put silently losing the race, respectively — both
  fixed in the SAME commit as this note, P-N2 review fix). All three
  locks go through `.lock().unwrap_or_else(|e| e.into_inner())`, never a
  bare `.lock().unwrap()` — a panic inside one connection's own thread
  must never poison every OTHER connection's ability to park/list/
  approve/dismiss/resolve/put, matching this crate's own "one
  connection's failure is contained to that connection" discipline
  (`broker.rs`'s module doc). Neither of the two new locks introduces
  caching — both sections still read fresh from disk every time; the
  lock only serializes the section, never remembers what it read
  (this crate's "NO CACHE, EVER" invariant, unchanged). A future
  production lock elsewhere in this crate follows the SAME recovery
  pattern, not a bare `.unwrap()` — and, per `replay_ledger_lock`/
  `put_lock` being TWO separate locks rather than one shared one, a new
  lock guards exactly the resource it protects rather than reaching for
  one broad "broker file ops" lock that would serialize unrelated
  operations against each other for no reason.
- **`serve`'s accept loop is thread-per-connection, and must never block on
  a parked one (P-N2, hard constraint).** Before this phase the loop called
  `handle_conn` INLINE, serially — safe only because nothing ever blocked
  for long. A parked `resolve` can legitimately hold its connection open
  for the full timeout (default 300s), so `serve` now does
  `std::thread::spawn(move || handle_conn(...))` per accepted connection,
  sharing one `Arc<park::ParkRegistry>`. Don't reintroduce an inline
  `handle_conn` call in the accept loop, and don't add a SECOND kind of
  long-lived wait anywhere in `handle_conn` that isn't routed through
  `park::wait_for_outcome`'s own timeout/completion race — a second
  ad hoc blocking point would need this same accept-loop guarantee
  re-proven from scratch.
- **`resolve_gate` returns a `GateOutcome` (`Granted`/`Denied`/
  `NeedsTotp`), not a bare `Result` (P-N2 — replaced the old
  `(bool, Result<String,String>)` tuple).** `NeedsTotp` is the park
  candidate: `totp_required` is true, an enrollment exists, but no/empty
  code rode the wire — every OTHER `requireTotp`-true-with-no-enrollment
  case is still an immediate `Denied` (unchanged wording), never a park,
  since there is nothing an operator could approve against. Don't collapse
  `NeedsTotp` back into `Denied` "since both come from the same missing-
  code condition" — `handle_resolve` is the ONE call site that branches on
  which variant it got, and that branch is the entire mechanism that turns
  a no-code resolve into a park instead of a refusal.
- **`wait:false` is wire-only — no CLI flag exists, and none should be
  added casually (P-N2).** It exists for a machine caller with no way to
  ever supply a code (this crate's own `README.md`, "Parking a TOTP
  resolve"). Adding a `--no-wait`/`--wait=false` CLI flag would need its
  own justification independent of this one wire escape hatch — don't
  wire one up "since the field already exists" without a caller that
  actually needs it from a terminal.
- **The wire's framing contract is "one request line -> zero or more
  INTERIM lines -> exactly one FINAL reply line" (P-N2c, FIX 1) — not
  "one request, one reply."** An interim line is any line whose object
  carries `"interim":true`; `broker::write_json_line` is the ONE place
  this crate formats a wire line, shared by `handle_conn`'s final-reply
  write and `handle_resolve`'s interim-line write, so a change to the line
  shape can't drift between the two call sites. `client::read_final_reply`
  is the ONE place a reply is read back — it loops, consuming and
  surfacing (`announce_interim`) any interim line, returning only the
  first non-interim line. Don't add a second ad hoc `read_line`+parse
  anywhere in `client.rs`; a new caller of the wire routes through
  `read_final_reply` even if it never expects an interim line today. A
  future mode/op extends the wire with a NEW interim shape or op, never by
  widening `resolve`'s `wait` field (still a plain bool) into something
  richer — `wait` is closed on purpose (invariant below, unchanged from
  P-N2).
- **`approve` MUST re-run the full authorization gate against the ask's
  STORED consumer, immediately before fetching — never trust a code alone
  (P-N2c, FIX 2, hard constraint).** Before this fix, `handle_approve`
  validated only the TOTP code and then fetched by backend/key, so a
  `secrets revoke`/policy edit issued WHILE an ask sat parked did nothing
  to stop that ask's eventual release — and the same gap would have
  silently bypassed the `remote` gate (invariant above) the day a network
  door exists. `broker::authorize_release` re-runs the SAME exists +
  consumers-authorization check `resolve_gate` itself uses; `handle_approve`
  calls it AFTER the code validates (so it is consumed from the replay
  ledger either way — deliberate, see the doc comment) and BEFORE any
  value is fetched. A revoked/removed consumer at that point denies BOTH
  the approver's own reply and the original parked caller's `resolve`
  reply with the identical error, and the ask is removed from the registry
  either way. Don't move a future release-time check to run only against
  the ask's ORIGINAL policy snapshot "since that's what was approved" — the
  whole point is to re-read `policy.json` fresh at release time, the same
  way `resolve`'s own fast path always has.
- **Park ids are nonce-prefixed (`<4-hex-nonce>-<counter>`), never a bare
  counter across a broker restart (P-N2c, FIX 4).** `park::ParkRegistry`
  reads 2 random bytes from `/dev/urandom` once per process start
  (`park::random_nonce`) and prefixes every id it mints that process with
  it; the counter still increments per-ask, unreused, within that process.
  `park::format_id`/`park::parse_id` are the ONE place an id is built or
  parsed — every public `ParkRegistry` method routes through them. This
  exists so a held id from a PREVIOUS broker process can never silently
  address a DIFFERENT ask after a restart (the counter alone restarts at
  1); an id whose nonce doesn't match the CURRENT process is simply
  unknown, the same `"unknown pending id"` error a never-existed id gets.
  Don't reach for `.parse::<u64>()` on a raw id anywhere outside `park.rs`;
  every caller (broker, client, tests) treats an id as an opaque string.
- **A registry-wide park cap bounds memory (P-N2c, FIX 3b),** default 32,
  `AOIDE_SECRETS_PARK_CAP` env override — `park::park_cap()`/
  `park::PARK_CAP_ENV`/`park::DEFAULT_PARK_CAP`, same tolerant-fallback
  shape as `park_timeout()`. `ParkRegistry::park_if_room` is the cap-aware
  entry point (`park` still exists, delegating to `park_if_room(...,
  usize::MAX)`, which cannot refuse) — it checks `len() >= cap` and inserts
  under the SAME lock acquisition, never two separate lock calls, so two
  racing parks can never jointly overrun the cap by one (the same TOCTOU
  discipline the `put_lock`/`replay_ledger_lock` invariant above already
  holds). Beyond the cap, `handle_resolve` returns the SAME immediate
  refusal `wait:false` produces, naming the cap and its env knob. Don't
  make the cap check a separate `len()` call followed by a separate
  `insert` — that reintroduces exactly the TOCTOU this fix exists to close.
- **A connection thread that fails to spawn must drop ONE connection,
  never crash the broker (P-N2c, FIX 3a/3c, hard constraint).** `serve`'s
  accept loop uses the FALLIBLE `std::thread::Builder::new().spawn(...)`,
  never the panicking `std::thread::spawn` — a refused OS thread creation
  (fd/thread-table exhaustion) `eprintln!`s and continues the loop, rather
  than unwinding `serve()` and killing the whole broker process (which,
  under a systemd unit with `StartLimitBurst`, permanently fails the unit
  with no further restart — the exact crash-to-permanent-outage shape this
  fix exists to close). The accept loop's `Err` arm (typically `EMFILE`)
  also sleeps ~250ms before retrying rather than busy-spinning. Don't
  revert to `std::thread::spawn` "since it's simpler" — the fallibility is
  the entire point.
- **`home::secrets_home`/`socket::socket_path` are THE resolution — nothing
  else re-derives a secrets-home or socket path.** `broker::serve`/
  `client::resolve`/`client::run_exec` all take the resolved `&Path` as a
  PARAMETER rather than calling `home`/`socket` internally — this is
  deliberate (keeps them testable against an explicit tempdir/short
  socket path with no env-var mutation) and matches how `cli`'s `special`
  hook calls them: it resolves `home`/`socket` once and passes the result
  in. Don't have `broker`/`client` read the env directly "for
  convenience" — that would silently reintroduce the env-mutation
  test-serialization problem `home`/`socket`'s OWN unit tests already
  need `env_lock` for.
- **`emit_notify` is called ONLY after every lock its outcome depended on
  has already been released (P-N3, hard constraint).** No notification I/O
  happens while holding `park::ParkRegistry`'s internal `Mutex` or
  `broker::replay_ledger_lock` — every call site (`handle_resolve`'s
  `Granted`/`NeedsTotp`-park/`WaitResult::TimedOut` arms, `handle_approve`'s
  success arm, `handle_dismiss`'s found arm) fires only after the
  `ParkRegistry` method or `verify_totp_gate` call that produced its
  id/ask/grant has already returned (their own internal locks are
  acquire-then-release entirely inside those functions, never held across
  the return). Don't add a notify call inside a `_guard = ...lock()...`
  scope; a future call site follows the same rule.
- **`released` fires ONLY on a TOTP-free grant, never on a code-verified
  one (P-N3).** `GateOutcome::Granted`'s `totp_free: bool` field is the ONE
  place this is decided — set once in `resolve_gate` from the SAME
  `totp_required` call that already gated the `if` (never a second policy
  load to re-derive it). A resolve that validated its own inline `--totp`
  code is granted exactly as before but must never notify — the caller
  already knows, they just typed the code. Don't collapse `totp_free`
  back out of `GateOutcome::Granted` "since both grant the same way" — it
  is the only signal `handle_resolve` has to tell the two apart.
- **No dedup or throttle on any notify event, deliberately (P-N3, User
  decision).** Every TOTP-free resolve fires its own `released` line, even
  a tight loop from the same consumer. Don't add a rate limit, a time
  window, or a "same secret+consumer within N seconds" collapse ahead of
  real spam evidence from a live deployment — the same "wait for the field
  to complain" discipline P-V4d/e/f/g were each born from.
- **`aoide-secrets` depends on nothing that could reach the desktop herald
  (P-N3, and stays that way).** `conduct/src/graph/permit.rs`'s summons
  publishes through `crate::herald::publish`/`crate::shellbridge::send_line`
  — both live in `aoide-conduct`, a DIFFERENT crate this crate's own
  `Cargo.toml` does not and must not depend on (`aoide-secrets` depends on
  `aoide-protocol`/`libc`/`serde`/`serde_json` only). Don't add an
  `aoide-conduct` (or `aoide-storage`, or `aoide-client`) dependency to
  reach `herald` "since permit.rs already has the seam" — that crate's own
  shellbridge socket only exists while a desktop session's bridge daemon is
  running, and this broker is meant to run headless as a system service
  with no desktop present at all. A future popup phase reads this crate's
  own emission (`README.md`'s "Broker notifications", the pickup-point
  note) from the OUTSIDE — a new adapter in `aoide-conduct`/`lyra`, never a
  new dependency edge pointing the other way.
- **The `age` backend's identity is minted ONLY from the `put`/SET path,
  NEVER from `get`/GET (P-G1, task #70, hard constraint).**
  `backend::mint_age_identity_if_needed` is called ONLY inside
  `broker::put_gate`'s own critical section (the SAME `put_lock` that
  already guards the existence-probe->store section — one lock, not a
  second one, since a concurrent identity bootstrap has the identical
  TOCTOU shape); `backend::fetch_value` checks for a missing `age.key` and
  returns `missing_age_identity_hint`'s taught error instead of ever
  minting one. Don't add a mint call anywhere on the resolve/GET path
  "for convenience" — a plain read must never have the side effect of
  silently provisioning key material nobody asked for.
- **A backend's OPTIONAL `has` template (P-G1, task #70) is `#[serde(default)]`
  and changes NOTHING for a backend that doesn't carry one.**
  `backend::has_value` runs `Backend::has` when present (treating exit 0
  as "has a value") and falls back to its pre-existing
  `fetch_value(...).is_ok()` probe when absent — byte-identical to every
  `has_value` call before this field existed. Don't make `has` load-bearing
  for a backend that omits it; the fallback is not merely a migration
  shim, it is the PERMANENT behavior for any backend that never adopts
  `has`.
- **`secrets add`'s backend defaults to `age`, not `file`, when
  `--backend` is omitted (P-G1, task #70, DEFAULT FLIP).**
  `commands::DEFAULT_BACKEND` is the ONE place this is decided — an
  ALREADY-recorded policy's `backend` field is never touched by this flip
  (only a brand-new `add` with the flag omitted is affected), and an
  explicit `--backend` still wins outright. Don't special-case an
  "upgrade an old `file` policy to `age`" migration anywhere — this flip
  changes a future default, never a past record.
- **`pass`/`gopass`/`bw`/`sops` are documentation-only presets, and stay
  that way (P-G1, task #70, restated as a crate stance).** `file`/`age`
  are this crate's only SUPPORTED backend implementations — `backend.rs`
  itself still carries no per-backend knowledge of any of the four
  documentation-only presets, and no test in this crate exercises them.
  Don't add code that assumes `pass`/`gopass`/`bw`/`sops` behave a
  particular way (parsing their stdout beyond the generic trim-one-newline
  rule, special-casing their exit codes, etc.) — a preset row in
  "Backend presets" is the full extent of this crate's involvement with
  any of them.
- **`backend::backfill_missing_backends` (P-G2, task #72) only ever ADDS a
  missing built-in BY NAME — it never touches an entry already present,
  built-in or not, and never compares content.** An `age` (or `file`) key
  already in `backends.json` — even one an operator hand-customized under
  that name — is left completely alone; only an ABSENT key gets the
  built-in's default shape inserted. This is the additive backfill the
  P-G1 review fix's own note left open ("An EXISTING deployment's
  `backends.json`... this does NOT backfill" — that invariant above, now
  superseded by this one closing the gap it named). Don't make this
  function overwrite or "repair" an existing entry under a built-in's
  name — presence of the key is the only test, forever.
- **Backfill writes NOTHING when nothing was missing (P-G2, task #72) —
  checked before ever opening a temp file, not merely a same-content
  rewrite.** A `backends.json` that already carries both built-ins must
  come out of `backfill_missing_backends` with its mtime UNCHANGED — don't
  turn this into an unconditional "reserialize and rewrite" that happens
  to produce the same bytes; the write itself must not happen at all when
  the `added` flag stays false.
- **Backfill runs at the SAME startup site as seeding, immediately after
  it, and never instead of it (P-G2, task #72).** `broker::serve` calls
  `seed_default_backends` then `backfill_missing_backends`, both non-fatal
  on error, same posture. Seeding owns the ABSENT-file case exclusively
  (unchanged since P-V4c); backfill owns the EXISTING-file case
  exclusively — on a fresh home, seeding writes both built-ins and the
  backfill call that follows is then a guaranteed no-op (nothing missing).
  Don't merge the two into one function or reorder them; a caller
  (`broker::serve`, and only `broker::serve` — the ONE seeding/backfill
  site) always calls both, in that order.
- **`secrets migrate` is an EXPLICIT, operator-invoked action — never an
  automatic upgrade of an old policy's `backend` field (P-G2, task #72).**
  This does not contradict the DEFAULT-FLIP invariant above ("this flip
  changes a future default, never a past record... don't special-case an
  upgrade migration anywhere") — that invariant forbids `secrets add`'s
  default flip from silently rewriting an EXISTING policy; `secrets
  migrate` is the opposite of silent: a named admin verb an operator runs
  on purpose, against a name they typed, gated by the same admin-identity
  check every other CRUD verb holds. Don't wire anything (a startup hook,
  a `set-totp`/`automate`/`expose` side effect, `backfill_missing_backends`
  itself) to call migrate's logic automatically for any policy — every
  migration is a deliberate, one-secret, operator-typed command.
- **`secrets migrate`'s value NEVER crosses a wire and lives ONLY as a
  local `String` inside `commands::handle_secrets_migrate` (P-G2, task
  #72).** Unlike `put`/`resolve`/`approve`, migrate is a DIRECT-HOME admin
  verb (mirrors `add`/`rm`/`grant` exactly, `commands.rs`'s own door
  taxonomy) — it never touches the broker's unix socket at all, so there
  is no wire reply to keep value-free the way `put`'s/`resolve`'s own
  replies must be; the discipline here is instead that the value never
  becomes an `Outcome` field, an audit line, or an error string, from the
  `backend::fetch_value` call that produces it straight through to the
  `backend::store_value` call that consumes it and drops it.
- **`secrets migrate`'s ordering is: fetch → (maybe mint) → store on the
  TARGET → flip + save `policy.json` → remove the OLD value LAST, and ONLY
  ever in that order (P-G2, task #72, hard constraint).** Any failure
  BEFORE the policy save leaves everything untouched — the old value in
  place, `policy.json` unflipped. Removing the old value only ever happens
  AFTER the policy flip has already durably saved; a removal failure (or a
  source backend this crate can't derive a path for) is reported honestly
  in the success message but never rolls back the already-successful
  migration and never blocks it. Don't reorder this — removing the old
  value before the new one is confirmed stored, or before the policy flip
  is saved, would leave a WINDOW where neither backend has a value the
  policy can resolve.
- **Old-value removal is BUILT-IN-SOURCE-ONLY and PATH-DERIVED, never a
  guess (P-G2, task #72).** `backend::remove_builtin_value` recognizes
  exactly two source backend names — `file` (`<home>/store/<key>`) and
  `age` (`<home>/values/<key>.age`), the SAME paths `FILE_BACKEND_SET`/
  `AGE_BACKEND_SET` themselves write to — and returns `None` for any other
  backend name, built-in or not (a `pass`/`gopass`/`bw`/`sops` row, or an
  operator-custom entry). `<key>` is the policy's own `key` field (what a
  template's `{name}` placeholder substitutes — `backend.rs`'s module
  doc), never the secret's display `name`. Don't add a third built-in path
  here without also adding a real seeded backend for it (`backend.rs`'s
  own "the only backend IMPLEMENTATIONS this crate supports" stance) —
  this function must never derive a path for a backend the crate doesn't
  actually seed and know the on-disk shape of.
- **`secrets migrate` is euid-guarded exactly like `add`/`rm`/`grant`, and
  runs with NO cross-process lock against a concurrently-running broker
  daemon (P-G2, task #72, KNOWN LIMITATION, deliberate, not fixed here).**
  `require_admin_identity(cmd, "migrate")` gates it the same way as every
  other CRUD-shaped admin verb; but because migrate is a direct-home
  op — a separate OS process from `secrets serve`, never the daemon itself
  — it CANNOT take the daemon's own in-process `broker::put_lock` (a
  `static Mutex` is per-process memory; a second process has no way to
  observe or wait on it). A `secrets migrate` racing a live `secrets
  put`/`secrets exec` against the SAME secret via the running daemon is an
  unprotected TOCTOU window, the same class of gap `store::save_policies`'s
  own module doc already accepts for every other admin CRUD verb here
  ("this phase does not lock against a concurrent admin write racing a
  resolve read"). Don't paper over this by acquiring `broker::put_lock`
  from `commands.rs` "for symmetry" — doing so would protect nothing (two
  different `Mutex` instances in two different processes) while implying a
  guarantee that doesn't exist. Closing this for real needs a real
  cross-process primitive (a file lock) this crate does not have today —
  out of scope here, flagged for whoever picks it up next.

## Extension points

- **A new hash/HMAC primitive** (this crate has none planned — SHA-1 is
  fixed by RFC 6238's default and this crate's whole TOTP surface) would
  get its own module beside `sha1`/`hmac`, same zero-dependency rule, same
  RFC-vector-as-test-suite discipline.
- **`secrets enroll` + real TOTP verification LANDED at P-V3** —
  `broker::verify_totp_gate` wires `totp::verify`/`replay::ReplayLedger`
  into `resolve_gate`'s `requireTotp` branch, and `store::
  load_replay_ledger`/`save_replay_ledger` give the ledger its secrets-home
  file.
- **Deployment LANDED at P-V4** — `broker::bind_socket` chmods the socket
  to `0660` on bind (group-connectable is the DESIGN; group OWNERSHIP is
  `modules/nucleus/secrets.nix`'s job via the service's `Group=`, never this
  crate's — see `broker.rs`'s module doc and this file's own invariant
  below). The real `/var/lib/aoide-secrets` path and a real `aoide-secrets`
  system user are provisioned by that nix module (nix-dependent by design
  — root `AGENTS.md`'s HARD CONSTRAINT carves out systemd packaging) or by
  the non-nix `useradd`/`groupadd` path in `README.md`'s "Deployment"
  section (any init, or none — the broker binary itself never gained a nix
  dependency). Only P-V5 (mesh pairing, gated on #51) is still ahead.
- **P-V4d fixed two bugs the first live deployment (yomi-strix) found that
  the sandboxed gates could not see.** `socket::socket_path()`'s default is
  now the fixed `/run/aoide-secrets/secrets.sock` (never derived from
  `home::secrets_home()` — see `socket.rs`'s module doc), so an env-less
  client shell (`aoide secrets exec`/`put` run by hand) resolves the real
  deployed socket with no export needed. `modules/nucleus/secrets.nix`'s
  service gained `path = [ pkgs.bash pkgs.coreutils ]` (a systemd unit's
  default `PATH` carries no `sh`, and every backend template — including
  the built-in `file` backend's own `get`/`set` — runs via `sh -c`) and
  `environment.systemPackages` gained `pkgs.qrencode` (the first live
  `secrets enroll` found it missing from the operator's own shell). Don't
  reintroduce a secrets-home-relative socket default; the whole point of
  P-V4d was that the client and the service must agree on the socket path
  without per-shell env.
- **Backend adapter DOC PRESETS** (`pass`/`gopass`/`bw`/`sops`) landed at
  P-V3 in `README.md`'s "Backend presets" section — `backend.rs` itself is
  unchanged (it never gained backend-specific knowledge, by design). QR-
  code rendering for `secrets enroll`'s URI lives in `enroll::render_qr`
  (`qrencode` shell-out, feature-detected, not a Cargo dependency).
- **The built-in `file` backend + the write half LANDED at P-V4c** —
  `backend::Backend` gained an optional `set` template and the `{home}`
  placeholder (`backend::expand_template`, a single left-to-right scan —
  never a sequential two-pass `.replace()`, module doc); `backend::
  seed_default_backends` seeds `backends.json` with `file` when absent,
  called once from `broker::serve`'s startup (the one seeding site, that
  function's own doc); `broker::handle_put`/`put_gate`/`audit_put` are the
  broker-side `put` op (policy-exists + backend-has-`set` gate only, no
  `requireTotp`, no `consumer`); `client::put`/`run_put` and `commands::
  handle_secrets_put` are the client-side flow, registered as a PLAIN
  handler (not a `special`-hook case — `commands.rs`'s own module doc
  explains why `exec`/`enroll` needed that escape and `put` doesn't). A
  NEW backend preset with its own `set` template follows the exact same
  table-row shape "Backend presets" already documents — no code changes
  needed for one, `file` was the one exception because it ships SEEDED,
  not merely documented.
- **Secrets pairing / mesh replica sharing** (P-V5, gated on #51) is a new
  module beside `broker`, not a growth of `broker`'s own resolve path —
  see the plan's "Mesh sharing" section for the separate loopback channel.
- **The admin-identity guard LANDED at P-V4f** — see the invariant above
  for the shape; the next admin verb that touches `policy.json`/
  `totp.secret` calls `commands::require_admin_identity` (or, if its real
  work lives outside `commands.rs`'s own dispatch the way `enroll::run`'s
  does, `home::admin_identity_check` directly) right after its `require_cli`
  gate, before any read-modify-write.
- **Two live UX gaps closed at P-V4e** — `secrets set-totp <name> on|off`
  (`commands::handle_secrets_set_totp`) flips an existing policy's
  `require_totp` bit through `store::load_policies`/`save_policies`, the
  same round trip `add`/`grant`/`revoke` already use; it is the replacement
  for hand-editing `policy.json` with a `jq` one-liner as the secrets user.
  `secrets enroll --show` (`enroll::show`) reprints an EXISTING
  enrollment's URI/base32/QR through the SAME `enroll::print_enrollment`
  tail `run` uses, calling neither `generate_secret` nor `store::
  save_totp_secret`/`save_replay_ledger` — there is nothing in it that
  could rotate anything. `commands::handle_secrets_enroll` rejects
  `--force`+`--show` together as a usage error; `cli`'s `special` hook
  dispatches to `run` or `show` from the SAME `["secrets", "enroll"]` arm,
  never a second one. A new read-only reprint of some OTHER already-
  persisted secret-adjacent state (not TOTP) follows this same shape: a
  sibling function beside the mutating one, sharing its rendering tail,
  called from the SAME special-hook arm behind a flag, never a new path.
- **Denials name the cause and teach the fix, P-V4g (this commit).**
  `home::describe_home_file_error(home, file, &io_err)` is the ONE seam
  EVERY `policy.json`/`totp.secret`/`totp-replay.json`/`backends.json`
  load/save call site in this crate routes a `PermissionDenied` through —
  not only the admin CRUD verbs (`commands.rs`'s CRUD quintet via its
  local `policy_io_error` wrapper, `enroll::run`/`enroll::show` directly),
  but also the broker's own AGENT-facing gates (`broker::resolve_gate`/
  `put_gate`, reached by `secrets exec`/`put` — the primary agent-facing
  path, and the one the User actually hit live) and `backend::
  load_backends` — the poisoned-file case: the admin-identity guard
  already proved this process's euid owns the secrets HOME directory, but
  an individual file inside it can still be owned by a stale uid from
  before that guard existed, and a bare `format!("policy.json: {e}")` gave
  zero indication why at ANY of those sites, not only the admin ones. It
  teaches `sudo chown --reference=<home> <file>` rather than a literal
  `chown aoide-secrets: ...` — this crate only ever learns uids, never a
  username, and `--reference` sidesteps needing one. Don't add a NEW
  policy.json/backends.json-adjacent read/write path that skips this seam
  "because it's not an admin verb" — the broker gap this note replaces was
  exactly that mistake. `client::describe_connect_error`
  is the client-side sibling: `resolve`/`put`'s `UnixStream::connect`
  failure maps `PermissionDenied` to "this session isn't in
  `aoide-secrets-access` yet" (teaching BOTH `sg aoide-secrets-access -c
  '<cmd>'` and a fresh login — group membership is login-scoped) and
  `NotFound`/`ConnectionRefused` to "the broker isn't running" (teaching
  `systemctl status aoide-secrets-serve` and the `AOIDE_SECRETS_SOCKET`
  override). Both functions are PURE given an injected `io::Error` — no
  real stat/socket needed to unit-test them — and every OTHER
  `io::ErrorKind` rides through unenriched, exactly as before this commit;
  don't widen either match arm to a kind it hasn't been proven to mean.
  Client-side messages only — neither function self-invokes `sudo`/`sg`,
  and neither prompts interactively; they only print what to run. A new
  admin-verb file or a new client socket op reuses these two functions
  rather than hand-rolling a third diagnosis.
- **`secrets put`'s stdin intake grew a tty branch at P-V4e**
  (`client::stdin_is_tty`/`client::read_hidden_line`) — when stdin is a
  terminal, `run_put` prompts on stderr and reads with echo disabled
  (raw `libc::termios`, restored unconditionally, even on a read error)
  instead of requiring a pipe. A piped/redirected stdin is BYTE-IDENTICAL
  to before — `run_put`'s non-tty branch is the original `read_to_string`
  call, untouched. Don't let the tty branch's prompt or trim logic leak
  into the pipe branch "for consistency"; they are deliberately two
  separate code paths with different contracts (a script's piped bytes
  are the value verbatim; a human's typed line loses exactly one trailing
  newline, `client::strip_one_trailing_newline`).
- **`secrets put` warns and confirms before an overwrite, P-67 (this
  commit).** The wire's `put` op gained an optional `overwrite` bool
  (absent means `false`); `broker::put_gate` probes existence via
  `backend::has_value` (just `fetch_value(...).is_ok()` — no new
  per-backend primitive) and refuses with the distinct `{"exists":true}`
  reply when `overwrite` is false and a value already exists, never
  touching the backend's `set` template on that path. `client::put` now
  returns `Result<bool, PutError>` (`bool` = `replaced`,
  `PutError::Exists` = the wire's flag, `PutError::Other` = everything
  else); `client::run_put` takes a `force` bool (the CLI's new `--force`
  flag) that rides as `overwrite` on the FIRST attempt, and on a tty
  `PutError::Exists` refusal, prompts `y/N` and retries with the SAME
  in-memory value + `overwrite:true` on yes — a non-tty stdin gets
  `client::non_tty_exists_message` (a pure function) instead, since there
  is no one to confirm with. `broker::audit_put` carries the same
  `replaced` distinction into both audit logs, names only. A future op
  that could similarly clobber existing state follows this same shape: a
  broker-side existence/state probe, a machine-readable flag on the
  refusal (never string-matched prose), and the client-side confirm/force
  split living in that op's own client function — not a generic
  "confirm before mutation" middleware, since each op's own gate already
  knows its own state.
- **Two per-secret policy gates + their admin verbs landed at P-N1.**
  `Policy` gained `automation: {enabled, consumers[]}` and `remote: bool`,
  both `#[serde(default)]` so an existing `policy.json` predating this
  phase loads cleanly as automation-disabled/empty and `remote: false` —
  see `policy.rs`'s round-trip tests for both the old and new shape.
  `policy::totp_required(policy, consumer)` is the new single decision
  point (invariant above) `broker::resolve_gate` calls instead of reading
  `policy.require_totp` directly. `secrets automate <name> on|off|grant|
  revoke` and `secrets expose <name> on|off` are plain handlers
  (`commands::handle_secrets_automate`/`handle_secrets_expose`) — same
  `require_cli` + `require_admin_identity` gate, same idempotent
  "unchanged" reporting as `set-totp`, appended LAST in `register()`
  (golden 61 -> 63).
- **A `totp_required` `true` result with no code PARKS instead of refusing
  outright, landed at P-N2 (golden 63 -> 66).** `broker::resolve_gate`
  returns `GateOutcome::NeedsTotp` (invariant above) instead of an
  immediate denial when a code is required, enrolled, but absent/empty on
  the wire; `handle_resolve` registers the ask in `park::ParkRegistry` and
  blocks the CONNECTION'S OWN THREAD on `park::wait_for_outcome`, which is
  why `serve`'s accept loop moved to thread-per-connection this phase
  (invariant above — a hard constraint, not a style choice). Three new
  CLI-only, `require_cli`-but-NOT-`require_admin_identity` verbs complete
  or refuse a parked ask over the socket, same operator-side-not-admin-side
  shape `put`/`exec` already draw: `secrets pending` (lists asks, never a
  value), `secrets approve <id> --totp <code>` (validates with the SAME
  `verify_totp_gate` an inline code uses, fetches fresh, releases down the
  ORIGINAL connection — an invalid code leaves the ask parked, ledger
  unburned), `secrets dismiss <id>` (clean refusal to the original caller,
  no code needed). `resolve` gained one optional wire field, `wait`
  (default `true`) — `wait:false` is the wire-only (no CLI flag) escape
  hatch back to the pre-P-N2 immediate refusal. Timeout is
  `AOIDE_SECRETS_PARK_TIMEOUT` (default 300s, env-only — no config-file
  knob exists in this crate for numeric settings, and none was invented for
  this). A future phase adding a code-entry UI (a popup, a notification)
  reads `secrets pending`/calls `secrets approve`/`secrets dismiss` the
  SAME way an operator's terminal does — this phase is explicitly the
  substrate for that, not a preview of it; no UI code lives in this crate.
- **P-N2c (this commit) — four judge-pass fixes on the P-N2 park/approve/
  dismiss lifecycle, all landed together:** the interim-line framing +
  STDERR park announcement (FIX 1, invariant above), `approve`'s release-
  time re-gate against the ask's stored consumer (FIX 2, invariant above,
  hard constraint), the fallible `Builder::spawn` + accept-loop backoff +
  registry-wide park cap (FIX 3a/3b/3c, invariants above), and
  nonce-prefixed ids (FIX 4, invariant above). Two small honesty fixes rode
  the same commit: the dismissed-caller message no longer claims "by an
  operator" (any group member reaching the socket can dismiss, not only an
  operator), and `park::wait_for_outcome`'s doc comment no longer claims
  its lost-race `recv()` is "provably prompt" — a hung backend shell-out
  breaks that promise (see the KNOWN GAP note immediately below), so the
  comment now states the assumption instead of overclaiming it.
- **Broker event notifications LANDED at P-N3.** `emit_notify` (`broker.rs`)
  fires a name-only line for five events (`released`/`parked`/`completed`/
  `dismissed`/`expired`) into the SAME two destinations every `audit_*`
  function already writes to — see `README.md`'s "Broker notifications" for
  the exact shapes and the mechanism reasoning (the `herald`-publish seam
  `conduct/src/graph/permit.rs` uses was checked FIRST and ruled out: it
  lives in `aoide-conduct`, a dependency this crate must not gain — invariant
  above). No adapter tails either destination yet, so this phase is
  emission-only, the identical "substrate now, UI later" relationship P-N2's
  own park/approve/dismiss lifecycle already has to a future popup (P-N2's
  own extension-point note above). The next phase that builds that
  tail/adapter lives in `aoide-conduct`/`lyra`, reading FROM this crate's
  logs — never a new edge pointing the other way.
- **The tail/adapter P-N3 left for a future phase LANDED at tracker #71
  Part 1, IN THIS crate, not `aoide-conduct`/`lyra`** — `watch.rs` (one of
  the seven I/O modules, invariant above) tail-follows the SAME mirrored
  log P-N3 writes to and narrates its five events, plus prompts inline for
  a parked ask when stdin is a terminal. This does NOT contradict the P-N3
  note above ("never a new edge pointing the other way"): `watch` adds NO
  new dependency edge — it lives inside `aoide-secrets` itself and reaches
  `client::pending`/`approve`/`dismiss` the same way `commands.rs` already
  does, never a socket into `aoide-conduct`/`herald`. See `README.md`'s
  "Watching events" section for the full mechanism. **Correction, tracker
  #71 Part 2 (this commit): the graphical popup ALSO landed IN THIS
  crate**, not as an `aoide-conduct`/`lyra`-side subscriber of `secrets
  watch --json` the way this note originally anticipated — see the
  invariant immediately below for why, and `README.md`'s "Popup mode"
  section for the full mechanism.
- **`--popup` (tracker #71 Part 2, this commit) is CORE, not a `lyra`/
  desktop feature, and stays inside `watch.rs` — no new module, no new
  crate dependency.** The root `AGENTS.md`'s own boundary line ("a
  capability that works with only a shell and touches no paint is Aoide")
  is why: `zenity` is a shell-out declared by NAME (`watch::ZENITY_CMD`),
  the SAME feature-detection shape `enroll::render_qr` already uses for
  `qrencode` — it is reachable from ANY shell with `zenity` on `PATH`, not
  only a Quickshell/AoideOS session, so it belongs beside the tty prompt it
  is an alternative to, not in `lyra`. A future RICE-SHAPED popup (matching
  the desktop's own look, replacing zenity's default GTK chrome) would be
  the `lyra`-side consumer of `secrets watch --json` this note originally
  anticipated — `--popup` itself is not that, and does not block it.
  **Codes never touch argv, in this popup path either** — `watch::
  spawn_zenity_entry`'s `Command::new(zenity_cmd).args([...])` carries only
  the dialog's TITLE and TEXT (secret name, consumer, remaining seconds,
  all name-only, `README.md`'s own display-fields rule extended here); the
  typed code arrives back over the CHILD's stdout pipe
  (`run_zenity_entry`'s `child.stdout.take()`), never a command-line
  argument, never a second process, never a temp file. Don't add a
  `--totp`-shaped flag or an intermediate shell wrapper to this spawn path
  that would put a code anywhere argv-visible — `client::approve` is
  called with the code exactly the way the tty prompt already does.
  **Popups are PARKED-ONLY, deliberately (User-flagged default)** —
  `popup_loop` is only ever entered from a `parked` ask picked off the
  SAME `Queue`/`pick_next` the tty prompt uses; `released`/`completed`/
  `dismissed`/`expired` narrate on stdout in every mode (unchanged) but
  never drive a dialog in ANY mode, popup included. Don't wire a second
  event kind into `popup_loop`'s dialog trigger without re-deriving why
  parked-only was chosen (the open Part-1 design question about a toast
  storm from undeduped `released` events, resolved here by simply never
  popping one up).
  **Unlock gating is an OR of two probes, `watch::locked_state`, pure and
  unit-tested with injected `Option<bool>`/`bool` — the two REAL probes
  (`watch::probe_loginctl_locked`/`watch::probe_locker_running`) are thin
  I/O wrappers this function never calls itself**, the same
  clock-as-parameter split `unix_now()` already holds for the rest of this
  module. `probe_locker_running` scans `/proc/<pid>/comm` for a name
  configured by `AOIDE_SECRETS_LOCKER` (default `hyprlock`) — load-bearing,
  not a redundant fallback, since the design doc verified hyprlock 0.9.6
  sets no `LockedHint` at all; `probe_loginctl_locked` is still checked
  first (OR'd, not replaced) so a locker that DOES set `LockedHint` is
  still honored. An unanswerable probe (no session id, no `loginctl`, a
  failed scan) reads as "not locked," never as "locked" — don't flip that
  default; a false negative here only delays a dialog by one poll tick, a
  false positive would silently show a code-entry dialog to whoever is
  physically at a supposedly-locked screen.
  **`watch::popup_action` orders near-expiry ahead of lock-wait, never the
  reverse** — a dialog must not open below [`LOCKOUT_SECS`] EVEN IF the
  screen happens to be unlocked at that instant, and an ask already too
  late to show must never sit "waiting for unlock" either, since that
  would only spend the time that's left doing nothing. Don't reorder this
  check without re-deriving why (the pure `popup_action` unit tests assert
  the ordering directly).
  **A dialog left open for an ask that resolves ELSEWHERE gets killed by
  its EXACT pid** — `watch::run_zenity_entry` holds the `std::process::
  Child` it spawned and calls `child.kill()` on it directly (never a
  re-derived pid from a stored integer, never a name/argv match) the
  moment its own `should_cancel` closure (checking the SAME `Queue` the
  tail thread mutates) reports the ask is gone. Don't replace this with a
  polling check that merely stops WAITING for the child without killing
  it — an orphaned zenity window left open for a completed ask is exactly
  the failure mode this exists to close.
  **`watch::run`'s zenity spawn path takes the binary name as a
  parameter — never a hardcoded `Command::new("zenity")` inline at the
  call site** — production passes the `watch::ZENITY_CMD` constant; this
  crate's OWN tests pass a fake shim script's full path instead, so
  `--popup`'s tests need no `PATH` mutation and no `env_lock` (unlike
  `enroll::render_qr`'s older `PATH`-shim test). Don't inline
  `Command::new("zenity")` into a new call site "since it's just one
  string" — go through the same parameterized functions
  (`spawn_zenity_entry`/`run_zenity_entry`/`zenity_available`) so a future
  test can fake it the same way.
- **The built-in `age` backend + the per-backend `has` template + the
  `secrets add` default flip LANDED at P-G1 (task #70, this commit).**
  `Backend` gained an OPTIONAL `has: Option<String>` field, `#[serde(default)]`
  so an existing `backends.json` predating this phase loads unchanged (see
  the invariant above); `backend::has_value` runs it when present,
  otherwise falls back to its pre-existing `get`-probe behavior byte-for-
  byte. `backend::seed_default_backends` now seeds TWO built-ins, `file`
  (unchanged) and `age` (new) — the SAME seeding site, same "an existing
  `backends.json` is never touched" rule. `age`'s `get`/`set` templates
  (`AGE_BACKEND_GET`/`AGE_BACKEND_SET`, `backend.rs`) shell out to
  `age`/`age-keygen` exactly like `file`'s templates shell out to
  `cat`/`install` — house rule 7, no special-cased Rust reads or writes a
  secret's ciphertext. `backend::mint_age_identity_if_needed` is the ONE
  exception: real Rust I/O (two `age-keygen` shell-outs, not templates)
  that lazily bootstraps `age.key`/`age.recipient` on the FIRST
  `age`-backed `put`, called from `broker::put_gate`'s own `put_lock`
  critical section (never from a `get` path — invariant above) and
  audited as a NAME-ONLY `age-identity-minted` `emit_notify` event
  (`README.md`'s "Broker notifications") — `handle_put` fires it, not
  `put_gate` itself, so it happens with no crate lock held (P-N3's own
  "no lock held" rule, invariant above, extended to this new call site). A
  missing `age`/`age-keygen` binary is a taught error naming the package
  to install (`backend::missing_age_binary_hint`), the same
  "diagnose and teach the fix" idiom `home::describe_home_file_error`/
  `client::describe_connect_error` already hold in this crate — grep
  `describe_`/`missing_age_` for the precedent before hand-rolling a new
  one. `commands::handle_secrets_add`'s `--backend` flag is now OPTIONAL
  (it was a hard requirement before this phase, not merely defaulted),
  defaulting to `age` (`commands::DEFAULT_BACKEND`) — a stored policy's
  `backend` field is untouched either way, only what a BRAND-NEW `add`
  with the flag omitted records. `pass`/`gopass`/`bw`/`sops` stay
  documentation-only presets, restated as an explicit crate stance
  (invariant above): `file`/`age` are the only backend IMPLEMENTATIONS
  this crate supports. No new verb, no wire-op change, no golden-count
  change — this phase is entirely inside the existing `add`/`put`
  surfaces.
- **P-G1 review fix (task #70, this commit): `age`-NAMED is not the same
  as `age`-CONFIGURED.** An existing deployment's `backends.json` predates
  P-G1 (`file` only, no `age` entry — `seed_default_backends` never
  touches an already-present file, invariant above) and `secrets add`'s
  new default (previous bullet) records `backend: "age"` regardless, so a
  brand-new policy on such a home names a backend that isn't configured
  anywhere. Two call sites gained a "is `age` actually known" check ahead
  of anything `age`-specific: `backend::fetch_value` now runs its ordinary
  `unknown backend` lookup BEFORE the missing-identity check — an
  unconfigured `age` policy's GET reports `unknown backend \`age\`` (the
  true cause), never `missing_age_identity_hint`'s "run `secrets put` to
  mint" (actively wrong advice there — `put` hits the identical wall);
  `broker::put_gate` calls the new `backend::backend_is_known(secrets_home,
  "age")` before `mint_age_identity_if_needed`, so a doomed `put` against
  an unconfigured `age` policy never mints a REAL identity (real
  `age-keygen` calls, real `age.key`/`age.recipient` files) before failing
  anyway. This does NOT backfill an existing `backends.json` with the
  `age` entry — that remained the documented, deliberate "seed once, never
  touch an existing file" contract (invariant above) at THIS phase — it
  only made the failure that follows name its true cause instead of a
  misleading age-specific one, and stopped that failure from having a real
  side effect first. **Superseded at P-G2 (task #72, below): the backfill
  gap this bullet names is now closed, additively.**
- **The deployment gap LANDED at P-G1/P-G1-review is CLOSED at P-G2 (task
  #72, this commit), two ways, both additive.** `backend::
  backfill_missing_backends` (invariants above) runs at `broker::serve`'s
  startup immediately after `seed_default_backends` — an EXISTING
  `backends.json` now gains any missing built-in entry by name on every
  broker start, with no operator action, and no entry (built-in or
  custom) already present is ever touched. `secrets migrate <name>
  [--backend <target>]` (`commands::handle_secrets_migrate`, default
  target `age`, `commands::DEFAULT_BACKEND` reused) is the per-secret
  companion: an admin verb (euid-guarded exactly like `add`/`rm`/`grant`,
  direct-home, no socket) that fetches a secret's value via its policy's
  CURRENT backend and stores it via a TARGET backend, flips the policy
  row, and removes the old value when the source is a built-in with a
  derivable path (`backend::remove_builtin_value`) — see the invariants
  above for the exact ordering/removal/locking rules, and `README.md`'s
  "Migrating a secret between backends" for the full flow. Registered
  LAST in `commands::register()` (golden discipline — append, never
  reorder), golden 67 → 68.

**KNOWN GAP, deferred, not fixed by P-N2c:** backend `get`/`set` shell-outs
(`backend::fetch_value`/`store_value`) have NO timeout — a wedged backend
command blocks its calling thread indefinitely. On the `put` path this
means `broker::put_lock` (the invariant above) is held across that
unbounded shell-out, so a single hung `set` template serializes every OTHER
`put` on this broker behind it for as long as the hang lasts (the
`resolve`/`approve` path has no equivalent lock held across its own
backend call, so a hung `get` only blocks that one connection's thread).
This is a documented, deferred gap, not a P-N2c fix — a future phase adding
a shell-out timeout (or narrowing `put_lock`'s critical section to exclude
the backend call, which would need its own TOCTOU analysis) closes it; a
new `put`-path change must not casually widen `put_lock`'s critical
section further without accounting for this already-known cost.

## Docs update required in the same commit

- This `README.md` when a new module, wire shape, or dependency is added.
- `pkgs/aoide/crates/AGENTS.md` for cross-crate invariants (registry
  order, golden discipline, per-crate tests) — not restated here.
- The workspace `Cargo.toml`'s `aoide-secrets` member comment and
  `crates/cli/README.md`'s golden-path count when the verb set changes.
- `CONTRACTS.md §3` (the core schema's command count) and its "Secrets
  wire" subsection (§4, the machine-consumer contract — P-V4c) when the
  wire shape (any op) or file layout changes; that subsection restates
  this crate's own wire docs (`README.md`'s "The wire", `broker.rs`'s
  module doc) for a reader who never opens this crate's Rust — update the
  crate docs FIRST, `CONTRACTS.md` follows in the same commit.
- `lib/vmTest.nix`'s `cmd_count` tripwire and its nearby count-history
  comment when the verb set changes (same commit as the golden snapshot).
