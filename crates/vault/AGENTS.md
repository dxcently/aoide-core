# AGENTS.md — aoide-vault

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
- **`ReplayLedger` keys on timestep ALONE, never on consumer** (ruling,
  Fable, 2026-08-22, P-V1 review escalation — plan file's VAULT §Policy
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
  whole point is that the vault doesn't carry a supply-chain dependency
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
  run). Don't "consolidate" the two without re-deriving why vault secret
  names are held to a tighter bar (they name on-disk backend-store paths
  under a privileged uid; a peer name only names a JSON cache file).
- **I/O is confined to six named modules: `broker`, `client`, `store`,
  `backend`, `enroll` (P-V3), and each module's own `#[cfg(test)]` block.**
  `sha1`/`hmac`/`totp`/`base32`/`uri`/`replay`/`policy` stay pure — no
  `SystemTime::now()`, no socket, no `exec`, no reads/writes of vault home
  in any of them. This is the P-V2 narrowing of the old P-V1 rule ("nothing
  in this crate performs I/O" — true then because there were no I/O
  modules yet), widened once more at P-V3 for `enroll`'s `/dev/urandom`/
  `gethostname`/`qrencode` calls; the boundary moves as new I/O concerns
  earn their own named module, it does not disappear. `enroll` itself
  never writes a vault-home FILE directly — that stays `store`'s job
  (`enroll::run` calls `store::save_totp_secret`/`save_replay_ledger`).
- **`home::vault_home`/`socket::socket_path` are THE resolution — nothing
  else re-derives a vault-home or socket path.** `broker::serve`/
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
  fixed by RFC 6238's default and this vault's whole TOTP surface) would
  get its own module beside `sha1`/`hmac`, same zero-dependency rule, same
  RFC-vector-as-test-suite discipline.
- **`vault enroll` + real TOTP verification LANDED at P-V3** —
  `broker::verify_totp_gate` wires `totp::verify`/`replay::ReplayLedger`
  into `resolve_gate`'s `requireTotp` branch, and `store::
  load_replay_ledger`/`save_replay_ledger` give the ledger its vault-home
  file.
- **Deployment LANDED at P-V4** — `broker::bind_socket` chmods the socket
  to `0660` on bind (group-connectable is the DESIGN; group OWNERSHIP is
  `modules/nucleus/vault.nix`'s job via the service's `Group=`, never this
  crate's — see `broker.rs`'s module doc and this file's own invariant
  below). The real `/var/lib/aoide-vault` path and a real `aoide-vault`
  system user are provisioned by that nix module (nix-dependent by design
  — root `AGENTS.md`'s HARD CONSTRAINT carves out systemd packaging) or by
  the non-nix `useradd`/`groupadd` path in `README.md`'s "Deployment"
  section (any init, or none — the broker binary itself never gained a nix
  dependency). Only P-V5 (mesh pairing, gated on #51) is still ahead.
- **Backend adapter DOC PRESETS** (`pass`/`gopass`/`bw`/`sops`) landed at
  P-V3 in `README.md`'s "Backend presets" section — `backend.rs` itself is
  unchanged (it never gained backend-specific knowledge, by design). QR-
  code rendering for `vault enroll`'s URI lives in `enroll::render_qr`
  (`qrencode` shell-out, feature-detected, not a Cargo dependency).
- **Vault pairing / mesh replica sharing** (P-V5, gated on #51) is a new
  module beside `broker`, not a growth of `broker`'s own resolve path —
  see the plan's "Mesh sharing" section for the separate loopback channel.

## Docs update required in the same commit

- This `README.md` when a new module, wire shape, or dependency is added.
- `pkgs/aoide/crates/AGENTS.md` for cross-crate invariants (registry
  order, golden discipline, per-crate tests) — not restated here.
- The workspace `Cargo.toml`'s `aoide-vault` member comment and
  `crates/cli/README.md`'s golden-path count when the verb set changes.
- `CONTRACTS.md §3` (the core schema's command count) and its vault-home
  pointer note when the wire shape or file layout changes.
