# aoide-vault

The pure-logic first slice of Aoide's secrets broker (Workstream VAULT,
`~/.claude/plans/functional-singing-boole.md`'s "Workstream VAULT — Fable
architecture" section). **This crate is not the broker yet** — no daemon, no
unix socket, no CLI verbs, nothing registered in any `Registry`. It is the
math and the types the broker will be built out of, landed first so V2 has
an RFC-vector-tested foundation to wire a socket around instead of
inventing TOTP under daemon-development time pressure.

## What this crate will be (planned, not present)

The eventual broker (`aoide vault serve`) runs as its own uid
(`aoide-vault`), holding a vault home (`/var/lib/aoide-vault`: policy file,
TOTP secret, replay ledger, vault audit log, backend stores) that the
operator's own uid never touches directly. The socket
(`/run/aoide-vault/vault.sock`, group `aoide-vault-access`) is the only
door. **Pathways, not destinations**: nothing here ever holds a secret's
*value* — a client resolves a secret by name over the socket, the broker
release the value directly to that client process, which injects it as an
env var and execs the real command (`Stdio::inherit`, never argv, never any
audit/Outcome/JSON line). This crate owns the piece of that flow that has
no daemon or socket dependency at all: proving a TOTP code is valid, and
the types the policy/replay state will serialize as.

### Release-to-client flow (V2, summarized — not implemented here)

```
agent  -> aoide vault exec --as <consumer> --secret <name>[:VAR] [--totp NNNNNN] -- <cmd>
       -> client (agent uid) connects, sends {op:"resolve", secret, consumer, totp?}
       -> broker (vault uid): policy gate -> totp::verify + replay::ReplayLedger
          (this crate) -> fetch via backend template AS VAULT UID -> release
          value over the socket
       -> client injects env var, Stdio::inherit, execs, returns exit code
```

## Named seams (what it exposes)

- `sha1` — RFC 3174 / FIPS 180-1 SHA-1, hand-rolled.
- `hmac` — RFC 2104 HMAC, specialized to SHA-1, built on `sha1`.
- `totp` — RFC 6238 TOTP over RFC 4226 HOTP truncation, built on `hmac`;
  clock-as-parameter throughout (`unix_time` is always a caller-supplied
  argument, never read from the system clock).
- `base32` — RFC 4648 §6 base32, encode/decode, unpadded by convention but
  padding-tolerant on decode.
- `uri` — `otpauth://` enrollment URI construction (Google Authenticator
  key-uri format), for V3's `vault enroll`.
- `replay` — `ReplayLedger`: the single-use-per-`(consumer, timestep)`
  structure that stops a captured TOTP code from being replayed within its
  validity window. Pure struct + serde; no clock reads.
- `policy` — `Policy` (per-secret `{name, backend, key, requireTotp,
  consumers[], sharedWith[]}`) and `valid_secret_name` (stricter than
  `aoide_storage::peer_store::valid_peer_name` — see the module doc).

## What it consumes

`serde`/`serde_json` only. **Zero algorithmic dependencies** — no `sha1`,
`hmac`, `totp-lite`, or `data-encoding` crate anywhere in this tree; the
plan mandates hand-rolling the hash stack, and the RFC test vectors are
what stand in for trusting a library.

## How it composes

Nothing depends on this crate yet. It joins the workspace `[workspace]
members` (`pkgs/aoide/Cargo.toml`) at P-V1 with a comment explaining that
`aoide-cli` does NOT gain the dependency until P-V2 wires the broker
daemon and `vault exec` client verb around this logic — check that
comment before adding a consumer prematurely.
