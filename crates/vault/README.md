# aoide-vault

Aoide's secrets broker (Workstream VAULT,
`~/.claude/plans/functional-singing-boole.md`'s "Workstream VAULT — Fable
architecture" section). P-V1 landed the pure logic; **P-V2 (this commit)
adds the broker daemon, the unix-socket wire, and the client + admin CLI
verbs** — `aoide vault serve`/`exec`/`add`/`rm`/`grant`/`revoke`, now
registered into `aoide-cli`'s `Registry`.

**STANDING GRANTS ONLY this phase.** TOTP enrollment (`vault enroll`)
doesn't exist yet, so any policy with `requireTotp: true` is simply
UNRESOLVABLE — the broker rejects it outright with "no TOTP enrollment on
this host yet", never silently falling back to a standing grant.
`vault enroll` and real verification arrive at P-V3/P-V4.

## The release-to-client flow (the plan's one subtle decision)

The broker must NOT exec the agent's command: it runs as the vault uid
(wrong cwd/env, and the child would inherit vault privileges). Instead:

```
agent  -> aoide vault exec --as <consumer> --secret <name>[:VAR] [--totp NNNNNN] -- <cmd>
       -> client (agent uid) connects, sends {op:"resolve", secret, consumer, totp?, argv0?}
       -> broker (vault uid): policy gate (name exists, consumer authorized,
          requireTotp -> reject this phase) -> fetch via the backend
          template AS VAULT UID -> release the value over the socket
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
broker never runs it.

The reply is hand-built `serde_json::Value` (`serde_json::json!`), never a
`#[derive(Serialize)]` struct — see "Invariants held" below.

## Named seams (what it exposes)

Pure logic (P-V1, unchanged):

- `sha1`/`hmac`/`totp`/`base32`/`uri` — the hand-rolled RFC 2104/3174/4226/
  6238/4648 stack behind TOTP and `otpauth://` URIs.
- `replay` — `ReplayLedger`, single-use-per-TIMESTEP, keyed WITHOUT a
  consumer dimension (see its own module doc for the ruling). Not yet
  consulted anywhere — verification is unwired until P-V3/P-V4.
- `policy` — `Policy` (per-secret `{name, backend, key, requireTotp,
  consumers[], sharedWith[]}`) and `valid_secret_name`.

Daemon/socket/CLI (P-V2, new):

- `home` — `vault_home()`: `$AOIDE_VAULT_HOME` env override, else the
  placeholder default `/var/lib/aoide-vault` (P-V4 is what actually
  provisions that path — see the module doc). Also `secure_dir`/
  `secure_file` (`0700`/`0600`): every `create_dir_all(vault_home)` in this
  crate (`broker::serve`, `store::save_policies`) is immediately followed
  by `secure_dir`, and `store::save_policies` locks `policy.json` down to
  `0600` after writing it — `create_dir_all` alone honors the process
  umask, which would otherwise leave the vault home world-searchable.
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
  `pass`/`gopass`/`bw`/`sops` are DOC PRESETS (P-V3), not code — this
  module has no knowledge of any specific backend.
- `store` — `load_policies`/`save_policies`: `policy.json` persistence
  (write-temp-then-rename), the only file I/O `policy::Policy` gains at
  P-V2.
- `broker` — `serve`: the accept loop (`aoide vault serve`'s body), the
  policy gate (`resolve_gate`), and BOTH audit writes (vault's own
  `audit.log` in vault home + the mirrored aoide log via
  `EventClass::Secret`) — see its module doc for the full wire contract
  and the "broker-side only" audit discipline.
- `client` — `resolve` (one round trip over the socket), `parse_exec_args`
  (pure `Invocation` parsing), `run_exec` (the full `vault exec` flow: the
  entry point for `aoide-cli`'s `special` hook).
- `commands` — `register(&mut Registry)`: the six verbs, ALL CLI-only.
  `serve`/`exec` are door-hint handlers (the real work happens in `cli`'s
  `special` hook, same pattern as `a2a serve`/`conductor`); `add`/`rm`/
  `grant`/`revoke` are policy-CRUD handlers gated the same way (`require_
  cli`) — a non-CLI door (MCP/A2A/Daemon) gets the door-hint `Outcome`
  before `policy.json` is ever touched, closing off a self-escalation path
  (`vault grant <secret> <itself>` from an already-connected agent).

## What it consumes

`aoide-protocol` (new at P-V2 — `Registry`/`Invocation`/`Outcome`/`Door`/
`EventClass`/the audit helpers/the `cmd!`/`arg!`/`flag!` macros), `serde`/
`serde_json`. **Still zero ALGORITHMIC dependencies** — no `sha1`/`hmac`/
`totp-lite`/`data-encoding` crate anywhere in this tree (this crate's
`AGENTS.md`); the broker socket, the backend shell-out, and the exec spawn
are all plain `std`.

## How it composes

`aoide-cli` depends on this crate as of P-V2 (`crates/cli/src/commands/
mod.rs::all()` calls `aoide_vault::commands::register`, appended newest;
`crates/cli/src/lib.rs`'s `special` hook wires `vault serve`/`vault exec`).
The workspace `Cargo.toml` comment on the `aoide-vault` member — which used
to say nothing depended on it — is updated in this same commit.

## Invariants held (see `AGENTS.md` for the full list)

- A secret's VALUE never appears on a `#[derive(Serialize)]`/`Deserialize`
  type anywhere in this crate. `policy::Policy` is still the only such
  type that touches the wire, and it has no value field. The resolve
  reply is hand-built `serde_json::Value`; `client::resolve` reads the
  value straight out of that `Value` into a local `String`.
- Audit happens BROKER-SIDE ONLY, on every resolve attempt (granted or
  denied) — never by the client, which only ever learns granted/denied
  from the wire reply.
- `EventClass::Secret` (the mirror to the aoide audit log) structurally
  forbids `untrusted_data` — enforced in `aoide_protocol::audit::
  append_audit`, not only by convention at the call site.
- TOTP verification (`totp::verify` + `replay::ReplayLedger`) stays
  UNWIRED this phase — a `requireTotp` policy is unresolvable, not
  silently downgraded to a standing grant.
