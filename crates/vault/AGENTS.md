# AGENTS.md — aoide-vault

## Invariants

- **A secret's VALUE never appears on a `Serialize`/`Deserialize` type in
  this crate — write this rule now, before it's tested by anything.**
  `policy::Policy` is the only wire-shaped type here at P-V1 and it holds
  no value; the rule exists for V2, where a resolve response and audit
  entries get added under time pressure. Any new `#[derive(Serialize)]`
  type added to this crate must be checked against this line before it
  lands. A value belongs in a client-process env var and nowhere else
  (README's release-to-client flow).
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
- **Nothing in this crate performs I/O outside its own test module.** No
  daemon, no socket, no `exec`, no reads/writes of vault home — those are
  V2. A test's tempdir file write (`replay.rs`/`policy.rs`) proves a
  serialization contract, it is not this crate quietly growing an fs
  dependency.

## Extension points

- **A new hash/HMAC primitive** (this crate has none planned — SHA-1 is
  fixed by RFC 6238's default and this vault's whole TOTP surface) would
  get its own module beside `sha1`/`hmac`, same zero-dependency rule, same
  RFC-vector-as-test-suite discipline.
- **The broker daemon, socket wire, and `vault exec`/`vault serve` verbs**
  (V2) land in a `commands`/`server` module added to this crate (or a
  sibling — TBD at V2 planning), consuming `totp`/`replay`/`policy` as a
  library rather than duplicating any of their logic.
- **Backend adapter templates and `vault enroll` UX** (V3) consume `uri`
  and `base32` as-is; QR-code rendering is a new leaf dependency scoped to
  that phase only (`qrencode` shell-out per the plan, not a new Rust dep).

## Docs update required in the same commit

- This `README.md` when a new module, wire shape, or dependency is added.
- `pkgs/aoide/crates/AGENTS.md` for cross-crate invariants (registry
  order, golden discipline, per-crate tests) — not restated here, and none
  of them apply yet since this crate registers nothing.
- The workspace `Cargo.toml`'s `aoide-vault` member comment, if/when a
  consumer (`aoide-cli`, at P-V2) is added — it currently states plainly
  that nothing depends on this crate.
