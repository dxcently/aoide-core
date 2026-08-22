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

## Docs update required in the same commit

- This `README.md` when a new module, wire shape, or dependency is added.
- `pkgs/aoide/crates/AGENTS.md` for cross-crate invariants (registry
  order, golden discipline, per-crate tests) — not restated here.
- The workspace `Cargo.toml`'s `aoide-secrets` member comment and
  `crates/cli/README.md`'s golden-path count when the verb set changes.
- `CONTRACTS.md §3` (the core schema's command count) and its "Secrets
  wire" subsection (§4, the machine-consumer contract — P-V4c) when the
  wire shape (either op) or file layout changes; that subsection restates
  this crate's own wire docs (`README.md`'s "The wire", `broker.rs`'s
  module doc) for a reader who never opens this crate's Rust — update the
  crate docs FIRST, `CONTRACTS.md` follows in the same commit.
- `lib/vmTest.nix`'s `cmd_count` tripwire and its nearby count-history
  comment when the verb set changes (same commit as the golden snapshot).
