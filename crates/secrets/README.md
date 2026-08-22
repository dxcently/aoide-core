# aoide-secrets

Aoide's secrets broker (Workstream SECRETS — renamed from "vault" at P-V4b,
`~/.claude/plans/functional-singing-boole.md`'s "Workstream VAULT — Fable
architecture" section, still titled that in the plan's own historical text).
P-V1 landed the pure logic; P-V2 added the broker
daemon, the unix-socket wire, and the client + admin CLI verbs — `aoide
secrets serve`/`exec`/`add`/`rm`/`grant`/`revoke`, registered into
`aoide-cli`'s `Registry`. P-V3 added `secrets enroll` and wired `requireTotp`
live, plus the backend-preset docs below. P-V4 was deployment:
`broker::bind_socket` chmods the socket to `0660` on bind, and the
"Deployment" section below covers both the nix module
(`modules/nucleus/secrets.nix`) and the non-nix install path. **P-V4c
(this commit) is the backend build-out**: a built-in `file` backend
(plain `0600` files under the secrets home, expressed entirely through the
template mechanism — see "Backend presets" below), a `{home}` template
placeholder to make that possible, and the write half — an optional
per-backend `set` template plus the new `secrets put <name>` verb (see
"The write flow" below). **P-V4d fixed two deployment bugs the first live
host (yomi-strix) surfaced**: the socket default now resolves to the real
`/run/aoide-secrets/secrets.sock` with no env needed (`socket.rs`'s module
doc), and the broker's own systemd unit gained a `PATH` (`bash`+`coreutils`)
so its `sh -c` backend templates can actually spawn (see "Deployment"
below). The socket wire is now also documented in
`CONTRACTS.md`'s "Secrets wire" subsection as a first-class,
directly-speakable API for non-agent consumers (services, models) — this
file stays the canonical source, `CONTRACTS.md` restates it for a reader
who never opens this crate's Rust. **P-V4e (this commit) closes two live
UX gaps the deployed broker surfaced**: `secrets set-totp <name> on|off`
flips an EXISTING policy's `requireTotp` bit directly — no more hand-editing
`policy.json` with a `jq` one-liner as the broker user — and `secrets enroll
--show` reprints the CURRENT enrollment's `otpauth://` URI/base32/QR without
rotating anything (`--force` still rotates; the two flags are mutually
exclusive). `secrets put` also now prompts on stderr with input hidden when
stdin is a terminal, instead of requiring a pipe — a piped/redirected stdin
is unchanged. **P-V4f (this commit) fixes a THIRD live deployment bug**
(yomi-strix, 2026-08-22): `sudo aoide secrets add …` (plain sudo — euid 0)
used to succeed and silently reown `policy.json` to `root:root`, bricking
the broker and every later admin verb (including the correctly-spelled
`sudo -u aoide-secrets` retry) until a manual `chown`. Every admin verb
that touches `policy.json`/`totp.secret` now refuses outright when the
process's effective uid doesn't own the secrets home, before it ever reads
or writes that file — see "Admin verbs" below and `AGENTS.md`'s matching
invariant for the exact shape.

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

## The write flow (`secrets put`, P-V4c)

The write-side mirror of the flow above, and it goes the OTHER direction —
a value flows CLIENT-to-broker, never released back:

```
operator/service -> aoide secrets put <name>   (value read from STDIN, never argv)
                  -> client (caller uid) connects, sends {op:"put", secret, value}
                     (stdin is a terminal -> prompt on stderr, echo hidden;
                     stdin is piped/redirected -> read straight through, unchanged)
                  -> broker (secrets uid): policy gate (secret has a policy —
                     `put` NEVER auto-creates one, `secrets add` owns that —
                     and its backend has a `set` template) -> pipes `value`
                     to the template's OWN stdin, runs it AS SECRETS UID
                  -> client learns granted/denied from the reply; there is
                     no value in it either way
```

`put` carries NO `consumer` field and is NEVER gated by `requireTotp`
(deliberate): `secrets put` is CLI-only (`commands::handle_secrets_put`'s
`require_cli` gate, same as the policy-admin quartet) and, in deployment,
runs as the secrets uid's own operator (`sudo -u aoide-secrets aoide
secrets put …`, same admin-verb precedent as `add`/`grant` — "Admin verbs"
below) — there is no separate agent-facing "consumer" identity to
authorize, and gating the secrets uid's own operator behind a TOTP code it
would also have to hold is pointless ceremony, not defense in depth. The
value exists ONLY as a local `String` in `client::run_put`, from the
stdin read to the `put()` call that pipes it into the wire request — never
an `Outcome`, never either audit line (both are written broker-side,
name-only, exactly like `resolve`'s — see `broker`'s module doc).

**Stdin intake, P-V4e**: `aoide secrets put <name>` with no pipe now
prompts —

```
$ aoide secrets put db-prod
value for `db-prod` (input hidden):
put secret `db-prod`
```

— the prompt and the post-input newline print to STDERR (stdout stays
clean for scripting), and the terminal's echo is disabled for the read
(`client::read_hidden_line`, raw `libc::termios`, restored unconditionally
afterward — even on a read error). A piped/redirected stdin
(`printf %s hunter2 | aoide secrets put db-prod`, the original shape) is
BYTE-IDENTICAL to before: `client::stdin_is_tty` is false in that case and
`run_put` falls straight through the old `read_to_string` path.

## The wire (unix socket, JSON-lines, one request per line, one reply)

```
-> {"op":"resolve","secret":"<name>","consumer":"<consumer>","totp":"<code>"?,"argv0":"<cmd>"?}
<- {"ok":true,"value":"<value>"}                    (granted)
<- {"ok":false,"error":"<value-free message>"}      (denied/error)

-> {"op":"put","secret":"<name>","value":"<value>"}
<- {"ok":true}                                      (stored)
<- {"ok":false,"error":"<value-free message>"}      (denied/error)
```

`totp`/`argv0` are optional on `resolve`; `put` has neither. `consumer` is
SELF-ASSERTED (the V1 ruling `replay.rs` carries): the policy's
`consumers[]` list is the real gate, never caller identity. `argv0` (the
wrapped command's own argv[0], sent by `secrets exec`) exists purely so the
broker's audit lines can name it — the broker never runs it. `totp` is
consulted ONLY when the resolved policy has `requireTotp: true`
(`broker::verify_totp_gate`) — on a policy without it, or on a `put`
(never checked at all), `totp` rides the wire unread if present, same as
before P-V3.

Both replies are hand-built `serde_json::Value` (`serde_json::json!`),
never a `#[derive(Serialize)]` struct — see "Invariants held" below.

**This wire is a FIRST-CLASS API (P-V4c), not merely `secrets exec`/
`secrets put`'s private implementation detail.** A service (verba
voluntia, an aoide-side Melete model) is meant to connect the socket and
speak these two ops DIRECTLY — no LLM, no `aoide` binary in the loop —
exactly the way `secrets exec`/`secrets put` do internally.
`CONTRACTS.md`'s "Secrets wire" subsection restates this same contract
(transport, both request/reply shapes, every error string, the
group-membership trust model, the `consumer`-self-assertion honesty note)
for a reader who never opens this crate's Rust; THIS section is the
canonical copy — a wire change lands here (and in `broker.rs`'s module
doc) first, `CONTRACTS.md` follows in the same commit.

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
- `secrets enroll --show` (P-V4e) reprints the EXISTING enrollment's URI +
  base32 + QR through the exact same render path, WITHOUT generating or
  rotating anything — `enroll::show` never calls `store::save_totp_secret`/
  `save_replay_ledger`. Errors cleanly ("no TOTP enrollment on this host
  yet…") when nothing is enrolled, rather than silently enrolling one.
  `--force` and `--show` are mutually exclusive (`commands::
  handle_secrets_enroll` rejects the combination as a usage error before
  either reaches `cli`'s `special` hook) — one asks to rotate, the other
  promises not to.
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

`backend.rs`'s `Backends`/`fetch_value`/`store_value` (Named seams, below)
know nothing about any specific secret manager — `backends.json` is a map
of named backend -> a `get` command template (and, P-V4c, an OPTIONAL
`set` template that makes the backend WRITABLE), and the policy's `key` is
substituted into that template's `{name}` placeholder. A template may also
use `{home}` (P-V4c), substituted with `secrets_home` itself, quoted the
SAME way as `{name}`. These presets are DOCUMENTATION, not code — copy the
shape that matches your backend into `backends.json` — with ONE exception:

| Backend  | `get` template            | `set` template | Notes                                            |
|----------|----------------------------|-----------------|--------------------------------------------------|
| `file` **(built-in, P-V4c)** | `cat {home}/store/{name}` | `mkdir -p -m 0700 {home}/store && install -m 0600 /dev/stdin {home}/store/{name}` | The ONE exception — SEEDED automatically into a fresh `backends.json` (below), not merely documented here. Plain `0600` files under `<secrets_home>/store/`, expressed entirely through the template mechanism (house rule 7 — no special-cased Rust reads or writes this backend's bytes). |
| `pass`   | `pass show {name}`         | — | `key` is the pass-store entry path (`prod/db`).  |
| `gopass` | `gopass show -o {name}`    | — | `-o` prints the password line only, no metadata. |
| `bw`     | `bw get password {name}`   | — | `key` is the Bitwarden item's name or id; needs a prior `bw unlock`/`BW_SESSION` in the broker's own environment (secrets-uid-owned, per the ownership-trap note below). |
| `sops`   | `sops -d --extract {name} secrets.yaml` | — | `key` is the FULL `--extract` JSONPath argument sops expects, e.g. `["password"]` — the brackets+quotes are part of the `key` VALUE (so `backend::shell_single_quote` escapes them along with everything else), not written into the template. The `secrets.yaml` path is fixed in the template, not templated — a second sops file needs its own named backend entry, and the secrets uid needs the sops decryption key (age/GPG/KMS) set up, per the ownership note below. |

**`backends.json` is SEEDED with the `file` backend when absent** — the
ONE seeding site is `broker::serve`'s startup (decision recorded in
`broker.rs`'s module doc): the broker is the single long-running process
that ever actually resolves a backend name against a template, so seeding
there guarantees every `resolve`/`put` sees a `backends.json` on disk
without a second seed call at `secrets add`/`secrets put`. **An EXISTING
`backends.json` is never touched** — seeding only ever writes the file
when it is entirely absent.

**Never pre-quote `{name}`/`{home}`** — `backend.rs`'s module doc: both
substitutions are already shell-single-quote-escaped
(`backend::shell_single_quote`) before they land in the template, so
`pass show {name}` / `cat {home}/store/{name}` are correct and
`pass show "{name}"` would double-quote and break. Every template above
follows that rule.

Each backend process (`get` AND `set`) runs AS THE BROKER'S OWN UID
(`backend.rs`'s module doc), which is what solves the backing-store
ownership trap structurally: the `pass` GPG key, the `bw` session, the
`sops` age/GPG key, and the built-in `file` backend's own `store/`
directory all live under the secrets uid, never the calling agent's — a
template above is only as safe as the secrets uid's own access to that
backend being scoped correctly (documentation and deployment concern, P-V4,
not this crate's).

**Per-backend environment is INLINE IN THE TEMPLATE, never a structured
env map** (P-V4c invariant): a backend needing `BW_SESSION` or similar
sets it as part of the `sh -c` command text itself (`BW_SESSION=... bw get
password {name}`) — `backends.json` has no separate `env` field for this
crate to parse, validate, or leak through, and never will; the whole
adapter surface is ONE string per direction (`get`, `set`), by design.

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
user by hand (below). The service's `path` also carries `bash`+`coreutils`
(sh/cat/mkdir/install for the built-in `file` backend's own templates — a
systemd unit's default `PATH` carries no `sh`, so an un-hardened unit can
bind the socket fine and still fail every resolve with "spawning backend
`file`: No such file or directory", found live on the first deployment) and
`environment.systemPackages` gains `qrencode` (so `secrets enroll`'s QR
render succeeds — the first live enrollment attempt found it absent).
**A regular agent-side consumer (`secrets exec`/`secrets put`) needs NO env
set at all on a deployed host** as of P-V4d: `socket::socket_path()`'s own
default now equals the module's `AOIDE_SECRETS_SOCKET` value, so a bare
shell finds the right socket with zero exports. Only the admin verbs below
still need an explicit `sudo -u aoide-secrets` invocation (sudo does not
carry the caller's env).

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

`secrets add|rm|grant|revoke|enroll|set-totp` mutate `policy.json`/
`totp.secret` under the secrets home, so they run AS the secrets user — no
sudo rule is shipped (nix module or not); the raw form:

```sh
sudo -u aoide-secrets aoide secrets enroll
sudo -u aoide-secrets aoide secrets add <name> --backend <backend> --key <key>
sudo -u aoide-secrets aoide secrets grant <name> <consumer>
sudo -u aoide-secrets aoide secrets set-totp <name> on
```

`secrets set-totp <name> on|off` (P-V4e) flips an EXISTING policy's
`requireTotp` bit directly, in place of hand-editing `policy.json` with a
`jq` one-liner — the gap this verb exists to close. Idempotent: re-setting
the state a policy already has reports "unchanged" and writes nothing.

**Running any of these as the wrong user is refused outright, before the
verb ever touches `policy.json`/`totp.secret` (P-V4f).** A mismatched
effective uid — root included, from a plain `sudo` — gets a message
naming the actual home path, the actual owning uid, and the corrective
spelling, e.g.:

```
$ sudo aoide secrets add db-prod --backend file --key db-prod
secrets add must run as the broker user (uid 999, the owner of /var/lib/aoide-secrets) — this process is running as root (uid 0) — plain `sudo` runs as root, and root CAN write here regardless of file ownership, which is exactly what silently corrupts it. Run: sudo -u aoide-secrets aoide secrets add ...
```

This is the fix for the incident above: root COULD always write
`policy.json` regardless of ownership, which is exactly what silently
reowned it. **A secrets home that doesn't exist yet still refuses root**
(found on review, P-V4f follow-up): `store::save_policies`/`store::
save_totp_secret` both create the home directory on their first write, so
an unguarded root caller would have just moved the same bricking bug
earlier — creating a fresh `policy.json`/`totp.secret` owned `root:root`
instead of reowning an existing one. Only a NON-root uid may bootstrap a
missing home (there is genuinely nothing to compare it against yet), so a
first-run `sudo -u aoide-secrets aoide secrets add …` on a fresh host
still works exactly as documented below — a bare `sudo` on that same fresh
host does not.

These pick up the code's own placeholder default
(`/var/lib/aoide-secrets`, `home.rs`) with no extra flags as long as it
matches the deployed path above — `sudo -u aoide-secrets` does not carry the
caller's `AOIDE_SECRETS_HOME`/`AOIDE_SECRETS_SOCKET` env by default, so set
them explicitly on the invocation if a host's paths ever diverge from the
default.

**A `policy.json`/`totp.secret` this euid cannot READ, even though the
admin-identity guard above passed, is the POISONED-FILE case** (the User's
live UX complaint this section answers, 2026-08-22): the guard proves this
process's euid owns the secrets HOME directory, but an individual file
inside it can still be owned by a stale uid from a historical plain-`sudo`
run that predates the guard. `home::describe_home_file_error` is the ONE
seam every admin-verb load/save call site (`commands.rs`'s CRUD quintet,
`enroll::run`/`enroll::show`) routes a `PermissionDenied` `io::Error`
through, rather than the bare `format!("policy.json: {e}")` this crate used
to return — it names the file, shows the owning uid mismatch when a stat is
cheap, and teaches `sudo chown --reference=<home> <file>` (matches the
file's ownership to the secrets home's own without this crate ever
resolving a username, since it only ever learns uids — `effective_uid`'s
whole reason for existing).

**A `put`/`exec` socket-connect failure gets the same treatment on the
client side.** `client::describe_connect_error` maps `UnixStream::connect`'s
`io::Error` into the two live UX gaps the User hit: `PermissionDenied`
means this login session isn't in the `aoide-secrets-access` group yet
(membership is login-scoped — the fix is `sg aoide-secrets-access -c
'<command>'` in the current session, or a fresh login); `NotFound`/
`ConnectionRefused` means nothing is listening at the resolved socket path
at all — the fix is `systemctl status aoide-secrets-serve`, or setting
`AOIDE_SECRETS_SOCKET` if this host's socket lives somewhere else. Both
`client::resolve`/`client::put` route their connect failure through this
one function rather than each hand-rolling the diagnosis.

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
  world-searchable. `effective_uid`/`admin_identity_error`/
  `admin_identity_error_for_missing_home`/`admin_identity_check` (P-V4f)
  are the admin-identity guard: two pure decisions — one for an existing
  home (owner vs. euid), one for a home that doesn't exist yet (root
  refused, any other uid passes, since a write would `create_dir_all` it) —
  both unit-tested on injected uids, and `admin_identity_check`'s live
  wiring to a real stat + a real `geteuid(2)` dispatching between them —
  see `AGENTS.md`'s matching invariant and
  "Admin verbs" above. `describe_home_file_error` (this section's
  "POISONED-FILE case" above) is the sibling diagnosis for a FILE-level
  `PermissionDenied` the guard's own directory-level check can't catch —
  pure given an injected `io::Error`, unit-tested the same way.
- `socket` — `socket_path()`: `$AOIDE_SECRETS_SOCKET` env override, else the
  canonical deployed path `/run/aoide-secrets/secrets.sock` (P-V4d — the
  first live deployment, yomi-strix, found the earlier secrets-home-relative
  default sent an env-less client shell, e.g. a bare `aoide secrets exec`, to
  the wrong path; see the module doc and this file's "Deployment" section
  for the full story, and the SUN_LEN caution for any caller building a
  socket path by hand). P-V4's nix module still sets `AOIDE_SECRETS_SOCKET`
  explicitly on the unit — belt-and-suspenders, not load-bearing anymore —
  and the value MUST equal this function's own default.
- `backend` — `Backends`/`Backend` (`backends.json`'s shape: a map of
  named backend -> a `get` template and an OPTIONAL `set` template, P-V4c)
  and `fetch_value`/`store_value`, which substitute the policy's `key` and
  (P-V4c) `secrets_home` itself (`{home}`), both SHELL-SINGLE-QUOTE-ESCAPED
  (never a raw `.replace()` — a key/home with whitespace or an embedded `'`
  must not be able to break the command or escape its argument boundary)
  via `expand_template`'s single left-to-right scan (module doc — never a
  sequential two-pass replace, which could re-scan already-substituted text
  for the other placeholder). `fetch_value` runs the `get` template via
  `sh -c` and trims exactly one trailing newline from stdout; `store_value`
  (P-V4c) runs the `set` template the same way with `value` piped to ITS
  OWN stdin (never argv) and discards its stdout. On a failing backend
  (either direction), the returned `Err` carries ONLY the exit status — the
  command's full stderr is `eprintln!`'d to the broker's own stderr and
  never returned, since the `Err` string rides the wire reply and both
  audit lines' `reason` field. Also `seed_default_backends` (P-V4c): writes
  the built-in `file` backend into `backends.json` when absent, never when
  one already exists — see "Backend presets" above for the seeding-site
  decision. `pass`/`gopass`/`bw`/`sops` are DOC PRESETS ("Backend presets"
  above), not code — this module has no knowledge of any specific backend;
  `file` is the one backend that ships as SEEDED DATA rather than mere
  documentation, still through the same template mechanism.
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
  entry point for `aoide-cli`'s `special` hook); `put` (P-V4c, one `put`
  round trip over the socket, mirrors `resolve`'s shape) and `run_put`
  (P-V4c, reads the value from THIS process's own stdin then calls `put` —
  the full `secrets put` flow, but a PLAIN function called from
  `commands::handle_secrets_put`, not a `cli`-crate `special`-hook case).
  `describe_connect_error` (this section's "socket-connect failure" case
  above) is the shared connect-error diagnosis both `resolve` and `put`
  route through — pure given an injected `io::Error`, unit-tested without a
  real socket.
- `commands` — `register(&mut Registry)`: NINE verbs, ALL CLI-only.
  `serve`/`exec`/`enroll` are door-hint handlers (the real work happens in
  `cli`'s `special` hook, same pattern as `a2a serve`/`conductor`); `add`/
  `rm`/`grant`/`revoke`/`set-totp` are policy-CRUD handlers gated the same
  way (`require_cli`) — a non-CLI door (MCP/A2A/Daemon) gets the door-hint
  `Outcome` before `policy.json`/`totp.secret` is ever touched, closing off
  a self-escalation path (`secrets grant <secret> <itself>`, or a hostile
  re-enrollment, from an already-connected agent). Those same five also
  call `require_admin_identity` (P-V4f) right after `require_cli` — the
  wrong effective uid gets refused before the file is ever touched too, see
  "Admin verbs" above. `put` (P-V4c) is gated
  the SAME way (`require_cli`) but is NOT special-cased like `exec`/
  `enroll` — see `commands.rs`'s own module doc for why its wire reply
  carrying no value at all makes that unnecessary. `set-totp` (P-V4e)
  follows `put`'s shape too — a plain handler, no wire, no value, appended
  newest.

## What it consumes

`aoide-protocol` (`Registry`/`Invocation`/`Outcome`/`Door`/`EventClass`/the
audit helpers/the `cmd!`/`arg!`/`flag!` macros), `serde`/`serde_json`,
`libc` (P-V3, new — `enroll::local_hostname`'s `gethostname(2)`, already a
workspace dependency via `aoide-storage`, so nothing new in the lockfile;
P-V4e reuses the same dependency for `client::stdin_is_tty`'s `isatty(2)`
and `client::read_hidden_line`'s `tcgetattr`/`tcsetattr` — no new crate).
**Still zero ALGORITHMIC dependencies** — no `sha1`/`hmac`/`totp-lite`/
`data-encoding` crate anywhere in this tree (this crate's `AGENTS.md`); the
broker socket, the backend shell-out, the exec spawn, and `/dev/urandom`
read are all plain `std`. `qrencode` is a runtime `PATH` shell-out
(feature-detected), never a Cargo dependency.

## How it composes

`aoide-cli` depends on this crate as of P-V2 (`crates/cli/src/commands/
mod.rs::all()` calls `aoide_secrets::commands::register`, appended newest;
`crates/cli/src/lib.rs`'s `special` hook wires `secrets serve`/`secrets exec`/
`secrets enroll` — P-V4e's `--show` rides the SAME `secrets enroll` arm, no
second one — `secrets put`, P-V4c, deliberately does NOT join that hook,
see `commands.rs`'s module doc; neither does `secrets set-totp`, P-V4e, for
the same reason `put` doesn't — a plain handler, no value on the wire). The workspace `Cargo.toml`
comment on the `aoide-secrets` member is kept current with the verb set in
the same commit as any change.

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
- **NO CACHE, EVER** (P-V4c, written down as a crate invariant): a
  secret's value exists ONLY between a `get`/`set` template's own
  invocation and the wire write that follows it — nothing in `broker`/
  `client`/`backend` holds a value across requests, in memory or on disk,
  for any reason (not a warm cache, not a TTL, not a "the last resolve for
  this secret"). `resolve` runs the backend fresh on EVERY call, so
  revocation (removing a consumer, `secrets rm`, rotating the backing
  value) is immediate — the very next resolve sees it, never a stale
  cached answer. This is also why `policy.json`/`totp-replay.json` are
  reloaded fresh from disk on every gated attempt rather than held in the
  broker process (`store`'s module doc) — the same "no cached state"
  discipline, restated here as the crate-wide rule it actually is.
- **ONE VALUE PER SECRET** (P-V4c, written down as the contract
  `policy::Policy`'s shape already implies): a "secret" in this crate's
  vocabulary is exactly one policy entry — one `{name, backend, key,
  requireTotp, consumers[], sharedWith[]}` — pointing at exactly one
  backend-fetched value. A credential with multiple fields (a
  username+password pair, a multi-key JSON blob) is modeled as MULTIPLE
  named secrets, each its own policy with its own `consumers[]`/
  `requireTotp`, never one policy resolving to a multi-field structure —
  the `sops` preset's JSONPath `key` (`["password"]`, "Backend presets"
  above) already shows this shape: a second field of the same
  `secrets.yaml` gets its OWN backend entry, `["username"]`, not a second
  key inside one resolve. There is no multi-field resolve op on the wire,
  and none is planned — per-field grants and per-field TOTP are the whole
  point.
- **Per-backend environment is INLINE IN THE TEMPLATE** (P-V4c, "Backend
  presets" above) — `sh -c` IS the environment mechanism; there is no
  structured `env` map anywhere in `Backend`'s shape, and none is planned.
