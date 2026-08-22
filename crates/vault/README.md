# aoide-vault

Aoide's secrets broker (Workstream VAULT,
`~/.claude/plans/functional-singing-boole.md`'s "Workstream VAULT — Fable
architecture" section). P-V1 landed the pure logic; P-V2 added the broker
daemon, the unix-socket wire, and the client + admin CLI verbs — `aoide
vault serve`/`exec`/`add`/`rm`/`grant`/`revoke`, registered into
`aoide-cli`'s `Registry`. **P-V3 (this commit) adds `vault enroll` and
wires `requireTotp` live**, plus the backend-preset docs below.

`vault enroll` generates a fresh 20-byte secret from `/dev/urandom`,
persists it (`store::save_totp_secret`, `0600`), and prints its
`otpauth://` URI + base32 form to stdout (plus a QR code when `qrencode`
is on `PATH`) — see "TOTP enrollment" below. ONE enrollment per host: a
second `vault enroll` errors unless `--force`, which regenerates the
secret AND resets the replay ledger (old codes, and every already-spent
timestep, stop mattering the moment the secret changes).

A `requireTotp: true` policy is UNRESOLVABLE only when NO enrollment
exists on this host yet — the broker rejects it with "no TOTP enrollment
on this host yet", never a silent standing-grant fallback. Once enrolled,
`broker::resolve_gate` verifies the wire's `totp` code against the
enrolled secret (`±1`-timestep window) and consumes the matched timestep
in a persisted `replay::ReplayLedger` — a missing, wrong, or replayed
code is a denial, same as any other gate failure (the backend never
runs).

## The release-to-client flow (the plan's one subtle decision)

The broker must NOT exec the agent's command: it runs as the vault uid
(wrong cwd/env, and the child would inherit vault privileges). Instead:

```
agent  -> aoide vault exec --as <consumer> --secret <name>[:VAR] [--totp NNNNNN] -- <cmd>
       -> client (agent uid) connects, sends {op:"resolve", secret, consumer, totp?, argv0?}
       -> broker (vault uid): policy gate (name exists, consumer authorized,
          requireTotp -> verify the code against the enrolled secret,
          single-use per timestep) -> fetch via the backend template AS
          VAULT UID -> release the value over the socket
       -> client injects the value as an env var, Stdio::inherit()
          throughout, execs, returns the CHILD's own exit code
```

The value exists ONLY in the client process's env, from `client::resolve`'s
return to the `.env(...)` call — never argv, never an `Outcome`/JSON
envelope, never either audit log (both audit lines are written **broker-
side**, before the value is ever released — see `broker`'s module doc).
Release-to-client is honest, not a leak: a same-uid agent with a valid
code/grant could always read the value once released; the grant/code IS
the gate, not the transport.

## The wire (unix socket, JSON-lines, one request per line, one reply)

```
-> {"op":"resolve","secret":"<name>","consumer":"<consumer>","totp":"<code>"?,"argv0":"<cmd>"?}
<- {"ok":true,"value":"<value>"}                    (granted)
<- {"ok":false,"error":"<value-free message>"}      (denied/error)
```

`totp`/`argv0` are optional. `consumer` is SELF-ASSERTED (the V1 ruling
`replay.rs` carries): the policy's `consumers[]` list is the real gate,
never caller identity. `argv0` (the wrapped command's own argv[0], sent by
`vault exec`) exists purely so the broker's audit lines can name it — the
broker never runs it. `totp` is consulted ONLY when the resolved policy has
`requireTotp: true` (`broker::verify_totp_gate`) — on a policy without it,
`totp` rides the wire unread, same as before P-V3.

The reply is hand-built `serde_json::Value` (`serde_json::json!`), never a
`#[derive(Serialize)]` struct — see "Invariants held" below.

## TOTP enrollment (`vault enroll`, P-V3)

```
$ aoide vault enroll
otpauth://totp/aoide-vault:<hostname>?secret=<base32>&issuer=aoide-vault&algorithm=SHA1&digits=6&period=30
secret (base32): <base32>
(qrencode not found on PATH — scan the URI above by hand, or install qrencode for a QR code)
```

- `enroll::generate_secret` reads 20 raw bytes from `/dev/urandom` — zero
  new deps (no `rand`/`getrandom` crate). `enroll::local_hostname` names
  the enrollment (the `otpauth://` label) via `libc::gethostname`, the SAME
  precedent `aoide_storage::display::local_host_name` uses (this crate
  stays off `aoide-storage` — `policy.rs`'s module doc — so the call is
  repeated, not reached for).
- The secret is persisted RAW (not base32-text) at `<vault_home>/
  totp.secret`, `0600` (`store::save_totp_secret`) — `enroll::run` prints
  the human-facing base32/URI form itself; there's no reason to also
  encode the file this crate reads back.
- ONE enrollment per host: a second `vault enroll` without `--force`
  errors ("TOTP is already enrolled on this host…") without touching
  `totp.secret`. `--force` regenerates the secret AND resets the replay
  ledger (`totp-replay.json`) to empty — timesteps are wall-clock-derived,
  independent of which secret produced the code that consumed one, so a
  stale "already used" entry from before a re-enrollment must never shadow
  a legitimate fresh code from the new secret.
- The URI + base32 secret print DIRECTLY to stdout, never through the
  `Outcome` envelope (this crate's `AGENTS.md`) — `commands::
  handle_vault_enroll` only gates the door (CLI-only, same `require_cli`
  as the CRUD quartet) and records the launch with a secret-free
  `Outcome`; the real work is `enroll::run`, called from `aoide-cli`'s
  `special` hook exactly the way `vault serve`/`exec` already are
  (`aoide-protocol`'s own `AGENTS.md`: the `special` hook is the only
  sanctioned escape from the generic envelope).
- A QR code renders via `qrencode -t ANSIUTF8`, fed the URI over STDIN —
  NEVER argv (`/proc/<pid>/cmdline` is world-readable on Linux, and the
  URI carries the secret). `qrencode`'s absence is feature-detected by the
  spawn itself failing — a one-line hint, never an error.

## Backend presets

`backend.rs`'s `Backends`/`fetch_value` (Named seams, below) know nothing
about any specific secret manager — `backends.json` is a map of named
backend -> ONE `get` command template, and the policy's `key` is
substituted into that template's `{name}` placeholder. These four presets
are DOCUMENTATION, not code — copy the shape that matches your backend
into `backends.json`:

| Backend  | `get` template            | Notes                                            |
|----------|----------------------------|--------------------------------------------------|
| `pass`   | `pass show {name}`         | `key` is the pass-store entry path (`prod/db`).  |
| `gopass` | `gopass show -o {name}`    | `-o` prints the password line only, no metadata. |
| `bw`     | `bw get password {name}`   | `key` is the Bitwarden item's name or id; needs a prior `bw unlock`/`BW_SESSION` in the broker's own environment (vault-uid-owned, per the ownership-trap note below). |
| `sops`   | `sops -d --extract {name} secrets.yaml` | `key` is the FULL `--extract` JSONPath argument sops expects, e.g. `["password"]` — the brackets+quotes are part of the `key` VALUE (so `backend::shell_single_quote` escapes them along with everything else), not written into the template. The `secrets.yaml` path is fixed in the template, not templated — a second sops file needs its own named backend entry, and the vault uid needs the sops decryption key (age/GPG/KMS) set up, per the ownership note below. |

**Never pre-quote `{name}`** — `backend.rs`'s module doc: the substituted
`key` is already shell-single-quote-escaped
(`backend::shell_single_quote`) before it lands in the template, so
`pass show {name}` is correct and `pass show "{name}"` would double-quote
and break. Every template above follows that rule.

Each backend process runs AS THE BROKER'S OWN UID (`backend.rs`'s module
doc), which is what solves the backing-store ownership trap structurally:
the `pass` GPG key, the `bw` session, the `sops` age/GPG key all live
under the vault uid, never the calling agent's — a template above is only
as safe as the vault uid's own access to that backend being scoped
correctly (documentation and deployment concern, P-V4, not this crate's).

## Named seams (what it exposes)

Pure logic (P-V1, unchanged):

- `sha1`/`hmac`/`totp`/`base32`/`uri` — the hand-rolled RFC 2104/3174/4226/
  6238/4648 stack behind TOTP and `otpauth://` URIs.
- `replay` — `ReplayLedger`, single-use-per-TIMESTEP, keyed WITHOUT a
  consumer dimension (see its own module doc for the ruling). Consulted by
  `broker::verify_totp_gate` (P-V3) and persisted via `store`.
- `policy` — `Policy` (per-secret `{name, backend, key, requireTotp,
  consumers[], sharedWith[]}`) and `valid_secret_name`.

Daemon/socket/CLI (P-V2, extended P-V3):

- `home` — `vault_home()`: `$AOIDE_VAULT_HOME` env override, else the
  placeholder default `/var/lib/aoide-vault` (P-V4 is what actually
  provisions that path — see the module doc). Also `secure_dir`/
  `secure_file` (`0700`/`0600`): every `create_dir_all(vault_home)` in this
  crate is immediately followed by `secure_dir`, and every vault-home file
  write locks the file to `0600` after writing — `create_dir_all` alone
  honors the process umask, which would otherwise leave the vault home
  world-searchable.
- `socket` — `socket_path()`: `$AOIDE_VAULT_SOCKET` env override, else
  `vault_home().join("vault.sock")` (deliberately NOT `/run/...` yet — see
  the module doc for why, and the SUN_LEN caution for any caller building
  a socket path by hand).
- `backend` — `Backends`/`Backend` (`backends.json`'s shape: a map of
  named backend -> ONE fetch-command template) and `fetch_value`, which
  substitutes the policy's `key`, SHELL-SINGLE-QUOTE-ESCAPED (never a raw
  `.replace()` — a key with whitespace or an embedded `'` must not be able
  to break the command or escape its argument boundary), into the
  template's `{name}` placeholder, runs it via `sh -c`, and trims exactly
  one trailing newline from stdout. On a failing backend, the returned
  `Err` carries ONLY the exit status — the command's full stderr is
  `eprintln!`'d to the broker's own stderr and never returned, since the
  `Err` string rides the wire reply and both audit lines' `reason` field.
  `pass`/`gopass`/`bw`/`sops` are DOC PRESETS ("Backend presets" above),
  not code — this module has no knowledge of any specific backend.
- `store` — vault-home file persistence, all write-temp-then-rename +
  `home::secure_dir`/`secure_file`: `load_policies`/`save_policies`
  (`policy.json`, P-V2); `load_totp_secret`/`save_totp_secret`
  (`totp.secret`, RAW bytes, P-V3); `load_replay_ledger`/
  `save_replay_ledger` (`totp-replay.json`, P-V3) — reloaded fresh on
  every TOTP-gated resolve attempt rather than cached in the broker
  process, which is also what makes "a restart doesn't resurrect a spent
  code" true for free (the next resolve just re-reads the file).
- `enroll` — `generate_secret`/`local_hostname`/`render_qr` (P-V3's other
  I/O: `/dev/urandom`, `libc::gethostname`, the `qrencode` shell-out) and
  `run` (the full `vault enroll` flow — the entry point for `aoide-cli`'s
  `special` hook, same role `client::run_exec` plays for `vault exec`).
- `broker` — `serve`: the accept loop (`aoide vault serve`'s body), the
  policy gate (`resolve_gate`, plus `verify_totp_gate` for a `requireTotp`
  policy — P-V3), and BOTH audit writes (vault's own `audit.log` in vault
  home + the mirrored aoide log via `EventClass::Secret`) — see its module
  doc for the full wire contract and the "broker-side only" audit
  discipline.
- `client` — `resolve` (one round trip over the socket), `parse_exec_args`
  (pure `Invocation` parsing), `run_exec` (the full `vault exec` flow: the
  entry point for `aoide-cli`'s `special` hook).
- `commands` — `register(&mut Registry)`: SEVEN verbs, ALL CLI-only.
  `serve`/`exec`/`enroll` are door-hint handlers (the real work happens in
  `cli`'s `special` hook, same pattern as `a2a serve`/`conductor`); `add`/
  `rm`/`grant`/`revoke` are policy-CRUD handlers gated the same way
  (`require_cli`) — a non-CLI door (MCP/A2A/Daemon) gets the door-hint
  `Outcome` before `policy.json`/`totp.secret` is ever touched, closing off
  a self-escalation path (`vault grant <secret> <itself>`, or a hostile
  re-enrollment, from an already-connected agent).

## What it consumes

`aoide-protocol` (`Registry`/`Invocation`/`Outcome`/`Door`/`EventClass`/the
audit helpers/the `cmd!`/`arg!`/`flag!` macros), `serde`/`serde_json`,
`libc` (P-V3, new — `enroll::local_hostname`'s `gethostname(2)`, already a
workspace dependency via `aoide-storage`, so nothing new in the lockfile).
**Still zero ALGORITHMIC dependencies** — no `sha1`/`hmac`/`totp-lite`/
`data-encoding` crate anywhere in this tree (this crate's `AGENTS.md`); the
broker socket, the backend shell-out, the exec spawn, and `/dev/urandom`
read are all plain `std`. `qrencode` is a runtime `PATH` shell-out
(feature-detected), never a Cargo dependency.

## How it composes

`aoide-cli` depends on this crate as of P-V2 (`crates/cli/src/commands/
mod.rs::all()` calls `aoide_vault::commands::register`, appended newest;
`crates/cli/src/lib.rs`'s `special` hook wires `vault serve`/`vault exec`/
`vault enroll`, P-V3). The workspace `Cargo.toml` comment on the
`aoide-vault` member is kept current with the verb set in the same commit
as any change.

## Invariants held (see `AGENTS.md` for the full list)

- A secret's VALUE never appears on a `#[derive(Serialize)]`/`Deserialize`
  type anywhere in this crate. `policy::Policy` is still the only such
  type that touches the wire, and it has no value field. The resolve
  reply is hand-built `serde_json::Value`; `client::resolve` reads the
  value straight out of that `Value` into a local `String`. The enrolled
  TOTP secret follows the same rule from a different angle: `enroll::run`
  prints it directly to stdout, never through an `Outcome`.
- Audit happens BROKER-SIDE ONLY, on every resolve attempt (granted or
  denied) — never by the client, which only ever learns granted/denied
  from the wire reply.
- `EventClass::Secret` (the mirror to the aoide audit log) structurally
  forbids `untrusted_data` — enforced in `aoide_protocol::audit::
  append_audit`, not only by convention at the call site.
- TOTP verification (`totp::verify` + `replay::ReplayLedger`) is WIRED
  (P-V3): a `requireTotp` policy is unresolvable only when no enrollment
  exists on this host yet; once enrolled, a missing/wrong/replayed code is
  an ordinary denial, never a silent standing-grant fallback in either
  direction.
