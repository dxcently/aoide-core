# aoide-secrets

Aoide's secrets broker (Workstream SECRETS — renamed from "vault" at P-V4b,
`~/.claude/plans/functional-singing-boole.md`'s "Workstream VAULT — Fable
architecture" section, still titled that in the plan's own historical text).
P-V1 landed the pure logic; P-V2 added the broker
daemon, the unix-socket wire, and the client + admin CLI verbs — `aoide
secrets serve`/`exec`/`add`/`rm`/`grant`/`revoke`, registered into
`aoide-cli`'s `Registry`. P-V3 added `secrets enroll` and wired `requireTotp`
live, plus the backend-preset docs below. **P-V4 (this commit) is
deployment**: `broker::bind_socket` chmods the socket to `0660` on bind,
and the "Deployment" section below covers both the nix module
(`modules/nucleus/secrets.nix`) and the non-nix install path.

`secrets enroll` generates a fresh 20-byte secret from `/dev/urandom`,
persists it (`store::save_totp_secret`, `0600`), and prints its
`otpauth://` URI + base32 form to stdout (plus a QR code when `qrencode`
is on `PATH`) — see "TOTP enrollment" below. ONE enrollment per host: a
second `secrets enroll` errors unless `--force`, which regenerates the
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

The broker must NOT exec the agent's command: it runs as the secrets uid
(wrong cwd/env, and the child would inherit secrets privileges). Instead:

```
agent  -> aoide secrets exec --as <consumer> --secret <name>[:VAR] [--totp NNNNNN] -- <cmd>
       -> client (agent uid) connects, sends {op:"resolve", secret, consumer, totp?, argv0?}
       -> broker (secrets uid): policy gate (name exists, consumer authorized,
          requireTotp -> verify the code against the enrolled secret,
          single-use per timestep) -> fetch via the backend template AS
          SECRETS UID -> release the value over the socket
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
`secrets exec`) exists purely so the broker's audit lines can name it — the
broker never runs it. `totp` is consulted ONLY when the resolved policy has
`requireTotp: true` (`broker::verify_totp_gate`) — on a policy without it,
`totp` rides the wire unread, same as before P-V3.

The reply is hand-built `serde_json::Value` (`serde_json::json!`), never a
`#[derive(Serialize)]` struct — see "Invariants held" below.

## TOTP enrollment (`secrets enroll`, P-V3)

```
$ aoide secrets enroll
otpauth://totp/aoide-secrets:<hostname>?secret=<base32>&issuer=aoide-secrets&algorithm=SHA1&digits=6&period=30
secret (base32): <base32>
(qrencode not found on PATH — scan the URI above by hand, or install qrencode for a QR code)
```

- `enroll::generate_secret` reads 20 raw bytes from `/dev/urandom` — zero
  new deps (no `rand`/`getrandom` crate). `enroll::local_hostname` names
  the enrollment (the `otpauth://` label) via `libc::gethostname`, the SAME
  precedent `aoide_storage::display::local_host_name` uses (this crate
  stays off `aoide-storage` — `policy.rs`'s module doc — so the call is
  repeated, not reached for).
- The secret is persisted RAW (not base32-text) at `<secrets_home>/
  totp.secret`, `0600` (`store::save_totp_secret`) — `enroll::run` prints
  the human-facing base32/URI form itself; there's no reason to also
  encode the file this crate reads back.
- ONE enrollment per host: a second `secrets enroll` without `--force`
  errors ("TOTP is already enrolled on this host…") without touching
  `totp.secret`. `--force` regenerates the secret AND resets the replay
  ledger (`totp-replay.json`) to empty — timesteps are wall-clock-derived,
  independent of which secret produced the code that consumed one, so a
  stale "already used" entry from before a re-enrollment must never shadow
  a legitimate fresh code from the new secret.
- The URI + base32 secret print DIRECTLY to stdout, never through the
  `Outcome` envelope (this crate's `AGENTS.md`) — `commands::
  handle_secrets_enroll` only gates the door (CLI-only, same `require_cli`
  as the CRUD quartet) and records the launch with a secret-free
  `Outcome`; the real work is `enroll::run`, called from `aoide-cli`'s
  `special` hook exactly the way `secrets serve`/`exec` already are
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
| `bw`     | `bw get password {name}`   | `key` is the Bitwarden item's name or id; needs a prior `bw unlock`/`BW_SESSION` in the broker's own environment (secrets-uid-owned, per the ownership-trap note below). |
| `sops`   | `sops -d --extract {name} secrets.yaml` | `key` is the FULL `--extract` JSONPath argument sops expects, e.g. `["password"]` — the brackets+quotes are part of the `key` VALUE (so `backend::shell_single_quote` escapes them along with everything else), not written into the template. The `secrets.yaml` path is fixed in the template, not templated — a second sops file needs its own named backend entry, and the secrets uid needs the sops decryption key (age/GPG/KMS) set up, per the ownership note below. |

**Never pre-quote `{name}`** — `backend.rs`'s module doc: the substituted
`key` is already shell-single-quote-escaped
(`backend::shell_single_quote`) before it lands in the template, so
`pass show {name}` is correct and `pass show "{name}"` would double-quote
and break. Every template above follows that rule.

Each backend process runs AS THE BROKER'S OWN UID (`backend.rs`'s module
doc), which is what solves the backing-store ownership trap structurally:
the `pass` GPG key, the `bw` session, the `sops` age/GPG key all live
under the secrets uid, never the calling agent's — a template above is only
as safe as the secrets uid's own access to that backend being scoped
correctly (documentation and deployment concern, P-V4, not this crate's).

## Deployment (P-V4)

The secrets design's target topology: the broker runs as its OWN system user
`aoide-secrets` (never the operator's uid, never root); secrets home
`/var/lib/aoide-secrets`, `0700`, secrets-uid; socket
`/run/aoide-secrets/secrets.sock`, mode `0660`, group `aoide-secrets-access` (the
operator's uid is a member) — the socket is the ONLY door. The broker
BINARY stays nix-independent (`home.rs`'s module doc); everything below is
packaging, not requirement.

**Socket mode is set in code; socket GROUP is set by deployment.**
`broker::bind_socket` chmods the socket file to `0o660` itself, immediately
after bind (`broker.rs`'s module doc) — `UnixListener::bind` alone honors
the process umask (typically `0755`), which would otherwise leave the
socket WORLD-connectable, and the wire's `consumer` field is SELF-ASSERTED
(same module doc), so a world-connectable socket on a multi-user box would
let any local user resolve any standing-grant secret. That mode is only
meaningful once the socket's GID is the real access group, and that half —
making the broker process's effective group `aoide-secrets-access` so every
file it creates (the socket included) inherits that gid — is deployment's
job, not this crate's: the code sets mode bits, deployment sets identity.

### The nix module (`modules/nucleus/secrets.nix`)

For an Aoide-managed NixOS host: `aoide.secrets.enable = true;` (default
`false`) provisions the `aoide-secrets`/`aoide-secrets-access` groups, the
`aoide-secrets` system user (no login shell, home `/var/lib/aoide-secrets`,
`createHome = false` — `StateDirectory` below owns it instead), and a
SYSTEM `aoide-secrets-serve.service` (`Type = "simple"` — `secrets serve` blocks
forever, so this is right from day one, no oneshot detour; anchored to
`multi-user.target`, no graphical-session dependency) with
`StateDirectory = "aoide-secrets"` (`0700`), `RuntimeDirectory = "aoide-secrets"`
(`0750`), and `AOIDE_SECRETS_HOME`/`AOIDE_SECRETS_SOCKET` set explicitly.
`aoide.secrets.members` (default `[]`) is the list of user names added to
`aoide-secrets-access` — enable alone grants nobody access until a host names
its operator here. No sudo rule is shipped; admin verbs run as the secrets
user by hand (below).

### Any other init (or none) — the non-nix install path

Nothing above is required to run the broker. Manual setup on any Linux
with systemd (or none at all — `aoide secrets serve` is a plain foreground
process; run it under any supervisor, or in a terminal):

```sh
# 1. The broker's own uid/gids.
groupadd --system aoide-secrets
groupadd --system aoide-secrets-access
useradd --system --no-create-home --home-dir /var/lib/aoide-secrets \
        --gid aoide-secrets --shell /usr/sbin/nologin aoide-secrets
usermod -aG aoide-secrets-access <your-operator-user>

# 2. Directories the broker needs (it also re-asserts secrets-home 0700 on
#    every `serve` startup itself — see home.rs's module doc — but the
#    parent dirs and their ownership are this step's job, not the code's).
install -d -o aoide-secrets -g aoide-secrets -m 0700 /var/lib/aoide-secrets
install -d -o aoide-secrets -g aoide-secrets-access -m 0750 /run/aoide-secrets

# 3. Run it (foreground; the unit below is packaging, not requirement).
sudo -u aoide-secrets env \
  AOIDE_SECRETS_HOME=/var/lib/aoide-secrets \
  AOIDE_SECRETS_SOCKET=/run/aoide-secrets/secrets.sock \
  aoide secrets serve
```

A minimal systemd unit for the above (same topology as the nix module's
generated unit, trimmed for a non-nix box — the module additionally sets
`StateDirectory=` and hardening directives like `NoNewPrivileges`/
`ProtectSystem`; the `install -d` step above covers the state dir here):

```ini
# /etc/systemd/system/aoide-secrets-serve.service
[Unit]
Description=Aoide secrets broker (secrets)
After=multi-user.target

[Service]
Type=simple
Restart=on-failure
RestartSec=3s
User=aoide-secrets
Group=aoide-secrets-access
Environment=AOIDE_SECRETS_HOME=/var/lib/aoide-secrets
Environment=AOIDE_SECRETS_SOCKET=/run/aoide-secrets/secrets.sock
ExecStart=/usr/local/bin/aoide secrets serve
RuntimeDirectory=aoide-secrets
RuntimeDirectoryMode=0750

[Install]
WantedBy=multi-user.target
```

`/run/aoide-secrets` is recreated on every start by `RuntimeDirectory=`
(systemd) or by step 2 above (no systemd) — either way, the broker's own
`bind_socket` chmods the socket file inside it to `0660` regardless of
which one provisioned the parent directory.

### Admin verbs

`secrets add|rm|grant|revoke|enroll` mutate `policy.json`/`totp.secret` under
the secrets home, so they run AS the secrets user — no sudo rule is shipped
(nix module or not); the raw form:

```sh
sudo -u aoide-secrets aoide secrets enroll
sudo -u aoide-secrets aoide secrets add <name> --backend <backend> --key <key>
sudo -u aoide-secrets aoide secrets grant <name> <consumer>
```

These pick up the code's own placeholder default
(`/var/lib/aoide-secrets`, `home.rs`) with no extra flags as long as it
matches the deployed path above — `sudo -u aoide-secrets` does not carry the
caller's `AOIDE_SECRETS_HOME`/`AOIDE_SECRETS_SOCKET` env by default, so set
them explicitly on the invocation if a host's paths ever diverge from the
default.

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

- `home` — `secrets_home()`: `$AOIDE_SECRETS_HOME` env override, else the
  placeholder default `/var/lib/aoide-secrets` (P-V4's nix module/non-nix
  install path — "Deployment" above — is what actually provisions that
  path, chowned to the real `aoide-secrets` uid). Also `secure_dir`/
  `secure_file` (`0700`/`0600`): every `create_dir_all(secrets_home)` in this
  crate is immediately followed by `secure_dir`, and every secrets-home file
  write locks the file to `0600` after writing — `create_dir_all` alone
  honors the process umask, which would otherwise leave the secrets home
  world-searchable.
- `socket` — `socket_path()`: `$AOIDE_SECRETS_SOCKET` env override, else
  `secrets_home().join("secrets.sock")` (deliberately NOT `/run/...` yet — see
  the module doc for why, and the SUN_LEN caution for any caller building
  a socket path by hand). P-V4's deployment sets `AOIDE_SECRETS_SOCKET`
  explicitly to `/run/aoide-secrets/secrets.sock`; this function's own default
  never changes.
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
- `store` — secrets-home file persistence, all write-temp-then-rename +
  `home::secure_dir`/`secure_file`: `load_policies`/`save_policies`
  (`policy.json`, P-V2); `load_totp_secret`/`save_totp_secret`
  (`totp.secret`, RAW bytes, P-V3); `load_replay_ledger`/
  `save_replay_ledger` (`totp-replay.json`, P-V3) — reloaded fresh on
  every TOTP-gated resolve attempt rather than cached in the broker
  process, which is also what makes "a restart doesn't resurrect a spent
  code" true for free (the next resolve just re-reads the file).
- `enroll` — `generate_secret`/`local_hostname`/`render_qr` (P-V3's other
  I/O: `/dev/urandom`, `libc::gethostname`, the `qrencode` shell-out) and
  `run` (the full `secrets enroll` flow — the entry point for `aoide-cli`'s
  `special` hook, same role `client::run_exec` plays for `secrets exec`).
- `broker` — `serve`: `bind_socket` (P-V4 — binds, then chmods the socket
  file to `0660`; see "Deployment" above) followed by the accept loop
  (`aoide secrets serve`'s body), the policy gate (`resolve_gate`, plus
  `verify_totp_gate` for a `requireTotp` policy — P-V3), and BOTH audit
  writes (the broker's own `audit.log` in secrets home + the mirrored aoide log
  via `EventClass::Secret`) — see its module doc for the full wire
  contract and the "broker-side only" audit discipline.
- `client` — `resolve` (one round trip over the socket), `parse_exec_args`
  (pure `Invocation` parsing), `run_exec` (the full `secrets exec` flow: the
  entry point for `aoide-cli`'s `special` hook).
- `commands` — `register(&mut Registry)`: SEVEN verbs, ALL CLI-only.
  `serve`/`exec`/`enroll` are door-hint handlers (the real work happens in
  `cli`'s `special` hook, same pattern as `a2a serve`/`conductor`); `add`/
  `rm`/`grant`/`revoke` are policy-CRUD handlers gated the same way
  (`require_cli`) — a non-CLI door (MCP/A2A/Daemon) gets the door-hint
  `Outcome` before `policy.json`/`totp.secret` is ever touched, closing off
  a self-escalation path (`secrets grant <secret> <itself>`, or a hostile
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
mod.rs::all()` calls `aoide_secrets::commands::register`, appended newest;
`crates/cli/src/lib.rs`'s `special` hook wires `secrets serve`/`secrets exec`/
`secrets enroll`, P-V3). The workspace `Cargo.toml` comment on the
`aoide-secrets` member is kept current with the verb set in the same commit
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
