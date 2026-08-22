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
- **I/O is confined to six named modules: `broker`, `client`, `store`,
  `backend`, `enroll` (P-V3), and each module's own `#[cfg(test)]` block.**
  `sha1`/`hmac`/`totp`/`base32`/`uri`/`replay`/`policy` stay pure — no
  `SystemTime::now()`, no socket, no `exec`, no reads/writes of secrets home
  in any of them. This is the P-V2 narrowing of the old P-V1 rule ("nothing
  in this crate performs I/O" — true then because there were no I/O
  modules yet), widened once more at P-V3 for `enroll`'s `/dev/urandom`/
  `gethostname`/`qrencode` calls; the boundary moves as new I/O concerns
  earn their own named module, it does not disappear. `enroll` itself
  never writes a secrets-home FILE directly — that stays `store`'s job
  (`enroll::run` calls `store::save_totp_secret`/`save_replay_ledger`).
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
