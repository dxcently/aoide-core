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
invariant for the exact shape. **P-67 (this commit) closes the live UX gap
the User hit next**: `secrets put` used to silently overwrite an existing
value. `put`'s wire op gained an optional `overwrite` field (P-V4c's `put`,
extended, not a new op); the broker now refuses an overwrite attempt with a
machine-readable `{"exists":true}` reply unless `overwrite:true` rides the
wire, and `secrets put` gained a `--force` flag that sets it — on a tty
without `--force`, the refusal becomes a `y/N` confirmation instead of a
hard stop. See "The write flow" below for the full flow and
`CONTRACTS.md`'s "Secrets wire" subsection for the wire-compat notes.
**P-N1 (this commit) adds two per-secret policy gates and their admin
verbs**: `automation` (`{enabled, consumers[]}`) lets an operator name
consumers that resolve a `requireTotp`-gated secret WITHOUT a code —
`secrets automate <name> on|off|grant|revoke` — while every other caller
stays gated exactly as before (see "The automation gate" below,
`policy::totp_required` for the exact decision, and its honesty caveat:
the consumers it lists are checked against the SAME self-asserted
`consumer` wire field every other gate in this crate already trusts, or
doesn't); `remote` (default `false`) is a per-secret reachability flag
with NO behavior change yet — `secrets expose <name> on|off` — that every
future non-local entry point onto this broker must check before releasing
a value (see "Remote reachability" below). **P-N2 (this commit) parks a
`requireTotp` resolve with no code instead of refusing it outright**: the
requesting connection now WAITS (default 300s, `AOIDE_SECRETS_PARK_TIMEOUT`
to change it) while the ask is completed from a SEPARATE connection —
`secrets pending`/`secrets approve <id> --totp <code>`/`secrets dismiss
<id>` — or the timeout elapses. This is what moved [`broker::serve`] from
a single-threaded serial accept loop to thread-per-connection (a parked
connection must never stall every other client behind it on `accept(2)`) —
see "Parking a TOTP resolve" below for the full lifecycle. A resolve WITH
a code is completely unchanged; the wire's new `wait:false` field restores
the pre-P-N2 immediate refusal for a caller that can't type a code.

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

## The write flow (`secrets put`, P-V4c; warn-before-overwrite, P-67)

The write-side mirror of the flow above, and it goes the OTHER direction —
a value flows CLIENT-to-broker, never released back:

```
operator/service -> aoide secrets put <name> [--force]   (value read from STDIN, never argv)
                  -> client (caller uid) connects, sends
                     {op:"put", secret, value, overwrite:<bool>?}
                     (stdin is a terminal -> prompt on stderr, echo hidden;
                     stdin is piped/redirected -> read straight through, unchanged)
                  -> broker (secrets uid): policy gate (secret has a policy —
                     `put` NEVER auto-creates one, `secrets add` owns that)
                     -> IF overwrite is false/absent AND the secret already
                     has a stored value (probed via the backend's OWN `get`
                     template, broker-side only) -> refuse with the distinct
                     {"exists":true} reply, backend never touched
                     -> ELSE (no existing value, or overwrite:true): backend
                     has a `set` template -> pipes `value` to the template's
                     OWN stdin, runs it AS SECRETS UID
                  -> client learns granted/denied (and, on success, whether
                     it REPLACED an existing value) from the reply; there is
                     no value in it either way
```

**Warn before overwrite (P-67)** — the User's own complaint: `put`
overwrote a secret with an existing value silently. The existence check is
BROKER-SIDE, never the client's: the client must never fetch the value to
find out (that would be a `resolve`-shaped leak on an op that isn't
`resolve`), and a client-side file peek is structurally impossible anyway —
the client doesn't run as the secrets uid, so it can't see the backing
store. `crate::backend::has_value` is the probe: it just runs the SAME
`get` template `resolve` would and treats success as "has a value" — every
`get` template's contract already IS "exit 0 with the value on stdout when
it exists, non-zero otherwise" ("Backend presets" below), so there is no
new per-backend primitive and no special-casing of the built-in `file`
backend.

On a tty, `client::run_put` turns the broker's `exists` refusal into a
`y/N` confirmation (`secret \`<name>\` already has a stored value —
overwrite? [y/N]`, default No, read from the SAME stdin the value came
from) — a yes re-sends the value ALREADY held in memory with
`overwrite:true`, never asking the caller to retype it; a no or EOF aborts
with an "unchanged" message. On a piped/non-interactive stdin there is no
one to ask, so the refusal teaches the fix instead:
`printf %s <value> | aoide secrets put <name> --force`. `secrets put
<name> --force` sends `overwrite:true` on the very FIRST attempt, skipping
the confirmation on a tty too. A `put` on a secret with no stored value is
unaffected either way — no prompt, no warning, same as before this
feature. The success message says which happened ("stored" a new value vs.
"replaced" an existing one), and `broker::audit_put`'s `replaced` field
carries the same distinction into both audit logs (names only, never the
value).

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

## The wire (unix socket, JSON-lines, one request line, zero-or-more interim, one final reply)

**Framing (P-N2c, FIX 1):** write ONE request line; read zero or more
INTERIM lines (`"interim":true`) followed by exactly one FINAL reply line
(no `interim` field, or `interim` absent/false). Today the only interim
line is `resolve`'s park announcement below — a future op/mode extends the
wire with a new interim shape or a new `op`, never by widening `wait` (see
below) into something richer.

```
-> {"op":"resolve","secret":"<name>","consumer":"<consumer>","totp":"<code>"?,"argv0":"<cmd>"?,"wait":<bool>?}
<- {"interim":true,"parked":true,"id":"<id>","timeoutSecs":<N>}   (INTERIM,
                                                      only when this resolve
                                                      parks — P-N2c FIX 1;
                                                      never on the fast path)
<- {"ok":true,"value":"<value>"}                    (granted — immediately,
                                                      or after a park completes)
<- {"ok":false,"error":"<value-free message>"}      (denied/error/timeout/dismissed)

-> {"op":"put","secret":"<name>","value":"<value>","overwrite":<bool>?}
<- {"ok":true,"replaced":<bool>}                    (stored — `replaced`
                                                      says whether an
                                                      existing value was
                                                      clobbered, P-67)
<- {"ok":false,"exists":true,"error":"<message>"}   (P-67: refused — the
                                                      secret already has a
                                                      stored value and
                                                      `overwrite` was
                                                      false/absent)
<- {"ok":false,"error":"<value-free message>"}      (denied/error)

-> {"op":"pending"}
<- {"ok":true,"pending":[{"id":"<id>","secret":"<name>","consumer":"<consumer>","requestedAt":<unix-seconds>},...]}

-> {"op":"approve","id":"<id>","totp":"<code>"}
<- {"ok":true}                                      (code valid — the VALUE
                                                      releases down the
                                                      ORIGINAL parked
                                                      connection, never here)
<- {"ok":false,"error":"<value-free message>"}      (unknown id / invalid or
                                                      missing code — the ask
                                                      STAYS parked either way)

-> {"op":"dismiss","id":"<id>"}
<- {"ok":true}                                       (the parked caller gets
                                                       a clean "dismissed"
                                                       refusal)
<- {"ok":false,"error":"unknown pending id `<id>`"}
```

`client::resolve` (`secrets exec`/`secrets get`) consumes any interim line
itself and never surfaces it on stdout — a park prints ONE line to STDERR
instead: `parked as ask <id> — complete with: aoide secrets approve <id>
--totp <code>  (or dismiss <id>); times out in <N>s`, so an interactive
caller learns its own ask id immediately rather than watching a silent hang
that is indistinguishable from a wedged broker for up to
`AOIDE_SECRETS_PARK_TIMEOUT` seconds.

`totp`/`argv0`/`wait` are optional on `resolve` (`wait` defaults to `true`
— see "Parking a TOTP resolve" below); `put` has neither, but gained
`overwrite` at P-67 (also optional — absent means `false`, same shape as
`resolve`'s own optional fields). `consumer` is SELF-ASSERTED (the V1
ruling `replay.rs` carries): the policy's `consumers[]` list is the real
gate, never caller identity. `argv0` (the wrapped command's own argv[0],
sent by `secrets exec`) exists purely so the broker's audit lines can name
it — the broker never runs it. `totp` is consulted ONLY when the resolved
policy has `requireTotp: true` (`broker::verify_totp_gate`) — on a policy
without it, or on a `put` (never checked at all), `totp` rides the wire
unread if present, same as before P-V3. The `exists` flag on a denied
`put` is what a consumer of this wire checks — never string-matching the
`error` text — to tell "already has a value" apart from every other
denial.

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

## Parking a TOTP resolve (P-N2)

Before this phase, `resolve` on a `requireTotp` secret with no code was an
immediate refusal — the caller had exactly the 30-second window of one TOTP
code to notice the prompt, switch to an authenticator, and retry, or lose
the race. P-N2 replaces that with a PARK: the ask waits, held open on its
own connection, until an operator completes it or a timeout elapses.

```
agent  -> aoide secrets exec --as m --secret db-prod -- psql        (no --totp)
       -> client connects, sends {op:"resolve", secret:"db-prod", consumer:"m"}
       -> broker: totp_required(policy, "m") is true, no code on the wire
          -> registers {id, secret:"db-prod", consumer:"m", requestedAt}
             in the in-memory ParkRegistry, THIS connection's thread blocks
             — no value is ever fetched, stored, or held anywhere yet

operator -> aoide secrets pending                          (a SEPARATE connection)
         <- [{"id":"3f2a-3","secret":"db-prod","consumer":"m","requestedAt":...}]
         -> aoide secrets approve 3f2a-3 --totp 123456       (a THIRD connection)
         -> broker: verify_totp_gate("123456") — SAME RFC 6238 verify +
            replay ledger an inline `--totp` code uses
            -> valid: re-run the FULL authorization gate (exists + consumer
               authorized, P-N2c FIX 2, see below) against the ask's STORED
               consumer BEFORE fetching — then fetch fresh through the
               backend, send it down the ORIGINAL (first) connection's own
               channel
            -> invalid/expired/used: the ask STAYS parked, ledger UNBURNED
               — approve replies {"ok":false,"error":...} to the operator,
               the agent's connection keeps waiting
            -> valid code but the re-gate now denies (revoked mid-park):
               BOTH the operator's approve reply and the agent's original
               resolve reply get the SAME denial; the ask is removed either
               way, never left dangling

       <- the agent's ORIGINAL resolve call finally returns
          {"ok":true,"value":"<value>"} — approve's own reply never
          carried it
```

**The value never exists anywhere until the ask resolves.** Parking stores
only `{id, secret name, consumer, requestedAt}` — never a value, never a
partial fetch — the SAME "never store or park a value" invariant every
other verb in this crate holds (`AGENTS.md`). `approve` fetches fresh,
through the backend, only after a code has already validated, then sends
it down the channel the original `resolve` call is blocked reading —
`approve`'s own wire reply to the operator carries no `value` field at all.

**Three ways out**, all removing the ask from the registry:
- `secrets approve <id> --totp <code>` — a valid code releases the value to
  the original caller; an invalid one leaves the ask parked, unburned.
- `secrets dismiss <id>` — the original caller gets a clean "dismissed"
  refusal, no code needed.
- Timeout (default 300s, `AOIDE_SECRETS_PARK_TIMEOUT` env override) — the
  original caller's refusal names the timeout, the env knob, AND both
  completion paths (`secrets approve`/an inline `--totp` retry), since a
  stale id at that point would only mislead (`broker::park_timeout_message`).

**`wait:false` is the wire-only escape hatch** for a caller that has no way
to ever supply a code and would rather fail fast than tie up a connection
for up to 5 minutes — no CLI flag exists for it (this section's own
"first-class API" framing), only a direct socket speaker can send it.
Absent/`true` (the default) parks; `false` reproduces the EXACT pre-P-N2
refusal string, byte for byte.

**Concurrency — the accept loop never blocks on a parked connection.**
Before P-N2, [`broker::serve`]'s accept loop called `handle_conn` INLINE,
serially — safe only because nothing ever blocked for long. A park can
legitimately hold a connection open for the full timeout, so `serve` now
spawns one thread PER connection; a parked connection blocks only its own
thread, and every other connection (an unrelated `resolve`, a `put`, a
`pending` poll) is admitted and served normally the entire time one sits
parked. `AGENTS.md`'s own invariant list has the poisoned-lock convention
this introduced (the crate's first production, non-test, lock).

**Review fix, same commit as the fix below in git history: two
read-modify-write sections the serial accept loop used to serialize for
free needed an EXPLICIT lock once connections stopped running one at a
time.** `verify_totp_gate`'s replay-ledger load→record→prune→save, and
`put_gate`'s existence-probe→store, are each now held under their own
process-wide `Mutex<()>` (`broker::replay_ledger_lock`/`broker::put_lock`)
for the full critical section — without it, two threads racing the SAME
valid TOTP code could both load the ledger before either saved and both
grant (breaking single-use), and two concurrent `overwrite:false` puts
could both pass the existence probe before either stored. Both follow the
SAME poisoned-lock-recovery convention `ParkRegistry`'s lock set. See
"Invariants held" below for the full three-lock inventory.

**`approve` re-gates authorization at release time (P-N2c, FIX 2).** Before
this fix, `handle_approve` discarded the ask's stored consumer and
`fetch_secret_value` loaded policy only far enough to find the
backend/key — so a `secrets revoke` issued WHILE an ask sat parked did
nothing to stop that ask's release (up to `AOIDE_SECRETS_PARK_TIMEOUT`
seconds of revocation-hole), and the same gap would silently have bypassed
the `remote` gate once a network door exists. The fix (`broker::
authorize_release`) re-runs the SAME exists + consumers-authorization check
`resolve` itself uses, against the ask's ORIGINAL stored consumer, AFTER
the TOTP code validates but BEFORE any value is fetched. **Honesty note:**
the code is consumed from the replay ledger regardless of which way the
re-gate comes out — a burned code on a denied release is the deliberate
trade (a reusable code on a denial path is worse), documented here so it is
never mistaken for a bug.

**Ids are nonce-prefixed, not a bare counter (P-N2c, FIX 4).** An id has
the shape `<4-hex-nonce>-<counter>` (`ParkRegistry::new` reads 2 bytes from
`/dev/urandom` once per broker process start; the counter still increments
per-ask, unreused, within that process). A bare restart-then-reuse counter
could let a held id silently approve a DIFFERENT ask after a broker
restart — the nonce makes a stale id from a previous process simply
unknown (the same `"unknown pending id"` error a never-existed id gets)
rather than accidentally routable to a same-numbered ask under a new
process.

**A registry-wide park cap bounds memory (P-N2c, FIX 3b),** default 32,
`AOIDE_SECRETS_PARK_CAP` env override — `park::park_cap()`, same
tolerant-fallback shape as `park_timeout()`. Beyond the cap, a codeless
`resolve` gets the immediate `wait:false`-shaped refusal (never a park),
naming the cap and its env knob. `ParkRegistry::park_if_room` checks
`len() >= cap` and inserts under the SAME lock acquisition — never two
separate lock calls — so two racing threads can never jointly overrun the
cap by one (the same TOCTOU discipline `put_lock`/`replay_ledger_lock`
already hold).

**The broker survives thread-creation failure and fd exhaustion (P-N2c,
FIX 3a/3c) instead of dying permanently.** `serve`'s accept loop used to
call `std::thread::spawn`, which PANICS if the OS refuses to create a
thread — that panic unwinds `serve()` itself, killing the broker process;
under a systemd unit with `StartLimitBurst`, enough of these in a row marks
the unit permanently failed with no further restart attempts, a crash that
never repairs itself. The loop now uses the fallible `std::thread::Builder
::new().spawn(...)`: on `Err`, it `eprintln!`s and drops that ONE
connection, leaving the broker itself untouched. The accept loop's `Err`
arm (typically `EMFILE`, too many open files) also gained a ~250ms sleep
before retrying — without it, a broker at the fd ceiling busy-spins the
accept loop at 100% CPU instead of waiting out the transient exhaustion.

## The automation gate (`secrets automate`, P-N1)

A policy's `automation` field (`{enabled: bool, consumers: [name, ...]}`,
absent on an existing `policy.json` loads as `{enabled: false, consumers:
[]}` — identical behavior to before this field existed) lets an operator
name specific consumers that resolve `requireTotp`-gated secrets WITHOUT a
fresh code, while every other caller stays gated exactly as before. It can
only ever RELAX `requireTotp`, never tighten it: a policy with
`requireTotp: false` is unaffected by `automation` in every combination.

`policy::totp_required(policy, consumer)` is the ONE decision point
`broker::resolve_gate` routes through (replacing what used to be a bare
`if policy.require_totp`) — the gate order is now:

```
exists -> consumer authorized (unchanged) -> totp_required(policy, consumer) -> fetch
```

where `totp_required` is `requireTotp AND NOT (automation.enabled AND
consumer IS IN automation.consumers)`. Consumer names in
`automation.consumers` are matched EXACTLY, the same validation
([`policy::valid_secret_name`]) as every other name this crate holds —
`secrets automate <name> grant <consumer>` checks it before the name ever
lands in `policy.json`.

`secrets automate <name> on|off` flips `automation.enabled`;
`secrets automate <name> grant|revoke <consumer>` edits
`automation.consumers` — both idempotent (`set-totp`'s own precedent):
re-flipping the same state, or granting/revoking a consumer already
in/out of the list, reports "unchanged" and writes nothing.

**Honesty note (mirrors the replay-ledger ruling below, for the identical
reason):** the wire's `consumer` field is SELF-ASSERTED — nothing
authenticates it (this crate's `AGENTS.md`, `CONTRACTS.md`'s "Secrets
wire" honesty note). `automation.consumers` is checked against that SAME
self-asserted field, so an automation-open secret is effectively
CODE-FREE for any local socket caller claiming a listed consumer name,
until authenticated session identity exists (#63-adjacent, not planned
here). Automation is a courtesy label on top of the real boundary (socket
group membership), not a cryptographic one, exactly like `consumers[]`
itself — don't reach for `automation` as a way to "still be safe without
TOTP" against a hostile co-tenant of the same socket group; it isn't.

## Remote reachability (`secrets expose`, P-N1)

`policy.json` also carries a `remote` boolean (default `false`; absent on
an existing file loads as `false`). **NO behavior change today** — there
is no non-local entry point onto this broker yet (no mesh replication, no
network door) — this field exists so an operator can PRE-DECLARE which
secrets are meant to ever leave this host, ahead of one landing. It is a
crate invariant (`AGENTS.md`): every non-local entry point added later
MUST refuse a secret whose `remote` is `false` before ever touching its
backend. `secrets expose <name> on|off` flips it, same idempotency
discipline as `set-totp`/`automate`.

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

`secrets add|rm|grant|revoke|enroll|set-totp|automate|expose` mutate
`policy.json`/`totp.secret` under the secrets home, so they run AS the
secrets user — no sudo rule is shipped (nix module or not); the raw form:

```sh
sudo -u aoide-secrets aoide secrets enroll
sudo -u aoide-secrets aoide secrets add <name> --backend <backend> --key <key>
sudo -u aoide-secrets aoide secrets grant <name> <consumer>
sudo -u aoide-secrets aoide secrets set-totp <name> on
sudo -u aoide-secrets aoide secrets automate <name> on
sudo -u aoide-secrets aoide secrets automate <name> grant <consumer>
sudo -u aoide-secrets aoide secrets expose <name> on
```

`secrets set-totp <name> on|off` (P-V4e) flips an EXISTING policy's
`requireTotp` bit directly, in place of hand-editing `policy.json` with a
`jq` one-liner — the gap this verb exists to close. Idempotent: re-setting
the state a policy already has reports "unchanged" and writes nothing.

`secrets automate <name> on|off` (P-N1) flips the policy's `automation.
enabled` bit; `secrets automate <name> grant|revoke <consumer>` edits
`automation.consumers` (checked with the same [`valid_secret_name`]
validation as every other name in this crate). Both are idempotent the
same way `set-totp` is — a state already in place, or a consumer already
granted/revoked, reports "unchanged" and never rewrites `policy.json`. See
"The automation gate" below for what this field actually does at resolve
time, and its honesty caveat.

`secrets expose <name> on|off` (P-N1) flips the policy's `remote` bit —
same idempotency discipline as `set-totp`/`automate`. **No behavior
change today**: no non-local entry point onto this broker exists yet, so
`remote` currently gates nothing — see "Remote reachability" below for
the invariant it exists to enforce once one lands.

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

**A `policy.json`/`totp.secret`/`backends.json` this euid cannot READ, even
though the admin-identity guard above passed, is the POISONED-FILE case**
(the User's live UX complaint this section answers, 2026-08-22): the guard
proves this process's euid owns the secrets HOME directory, but an
individual file inside it can still be owned by a stale uid from a
historical plain-`sudo` run that predates the guard. `home::
describe_home_file_error` is the ONE seam EVERY `policy.json`/
`totp.secret`/`totp-replay.json`/`backends.json` load/save call site in
this crate routes a `PermissionDenied` `io::Error` through — not only the
admin CRUD verbs (`commands.rs`'s CRUD quintet via its `policy_io_error`
wrapper, `enroll::run`/`enroll::show`), but also the broker's own
AGENT-facing gates (`broker::resolve_gate`/`put_gate`, reached by `secrets
exec`/`put` — the primary agent-facing path, and the exact one the User
hit live) and `backend::load_backends` — rather than the bare
`format!("policy.json: {e}")` this crate used to return at each of those
sites. It names the file, shows the owning uid mismatch when a stat is
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
  consumers[], sharedWith[], automation, remote}`, `automation`/`remote`
  added P-N1) and `valid_secret_name`. `totp_required(policy, consumer)`
  (P-N1) is the ONE decision point behind "is a TOTP code required for
  this resolve" — see "The automation gate" below.
- `park` (P-N2, id scheme + cap P-N2c) — `ParkRegistry` (the in-memory
  parked-ask registry, `Mutex<BTreeMap<id, ParkedAsk>>` + an `AtomicU64`
  monotonic per-process counter, never reused within one broker process's
  lifetime, PLUS a `nonce: String` — 2 random bytes from `/dev/urandom`
  read once in `ParkRegistry::new`), `park_timeout`
  (`AOIDE_SECRETS_PARK_TIMEOUT` env override, default 300s — no
  config-file knob exists in the secrets home for this, env-only),
  `park_cap`/`PARK_CAP_ENV`/`DEFAULT_PARK_CAP` (P-N2c FIX 3b:
  `AOIDE_SECRETS_PARK_CAP` env override, default 32, same tolerant-fallback
  shape as `park_timeout`), and `wait_for_outcome` (the completion/timeout
  race, `mpsc::Receiver::recv_timeout` plus a re-check against the registry
  to close the race where a timeout and a late approval land at nearly the
  same instant — see its own module doc, softened P-N2c to state the
  backend-shell-out assumption rather than claim it "provably" holds).
  Never stores or touches a value — a `ParkedAsk` carries only
  `secret`/`consumer`/`requestedAt` and a private send-once channel.
  `format_id`/`parse_id` (P-N2c FIX 4) are the ONE place an id is built or
  read — every public method (`park`/`park_if_room`/`peek`/`take`/
  `remove_only`/`list`) routes an id through them, so `<nonce>-<counter>`
  is never assembled or parsed twice. `park` still exists (delegates to
  `park_if_room(..., usize::MAX)`, which cannot refuse); `park_if_room` is
  the cap-aware entry point `handle_resolve` actually calls, checking
  `len() >= cap` and inserting under the SAME lock acquisition (no
  separate check-then-insert) so two racing parks can never jointly
  overrun the cap by one.

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
  documentation, still through the same template mechanism. `has_value`
  (P-67) is the existence probe behind "warn before overwrite" — just
  `fetch_value(...).is_ok()`, since a `get` template's own contract already
  IS "exit 0 with the value on stdout when it exists" for every backend
  above; no new per-backend primitive, no special-casing of `file`.
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
  (`aoide secrets serve`'s body — **thread-per-connection as of P-N2**,
  changed from a single-threaded serial loop so a parked connection never
  stalls anyone queued behind it, see "Parking a TOTP resolve" above; P-N2c
  FIX 3a/3c hardened it further — `std::thread::Builder::new().spawn(...)`
  instead of the panic-on-failure `std::thread::spawn`, so a refused thread
  drops only that ONE connection (`eprintln!` + continue) rather than
  unwinding `serve()` and killing the broker process; the `Err` arm also
  gained a ~250ms sleep before retrying, so fd exhaustion (`EMFILE`) backs
  off instead of busy-spinning the accept loop at 100% CPU), the policy
  gate (`resolve_gate`, plus `verify_totp_gate` for a `requireTotp`
  policy — P-V3; P-N2 changed `resolve_gate`'s return into a `GateOutcome`
  enum — `Granted`/`Denied`/`NeedsTotp` — so its callers can tell "denied"
  and "park candidate" apart, where the old signature only had a
  `Result`), and BOTH audit writes (the broker's own `audit.log` in
  secrets home + the mirrored aoide log via `EventClass::Secret`) — see
  its module doc for the full wire contract and the "broker-side only"
  audit discipline. `write_json_line` (P-N2c) is the ONE place this crate
  formats a wire line — shared by `handle_conn`'s final-reply write and
  `handle_resolve`'s new interim-line write, so both stay byte-for-byte
  the same shape; `handle_line` now takes a trailing `interim_out: &mut
  impl Write` that only `handle_resolve` ever writes through (module doc).
  `put_gate` (P-V4c, extended P-67) returns a
  `PutOutcome` (`Granted { replaced }` / `DeniedExists` / `Denied(reason)`)
  rather than a plain `Result` — `handle_put` maps that onto the wire's
  `replaced`/`exists` fields, and `audit_put` carries the same `replaced`
  distinction into both audit logs (names only, never the value) — see
  "The write flow" (README) and this module's own doc for the full P-67
  shape. `handle_pending`/`handle_approve`/`handle_dismiss` (P-N2) are the
  three new op handlers — `handle_approve` peeks the ask (read-only) BEFORE
  validating a code, so an invalid code never removes it, and only `take`s
  it once a code has already validated and been consumed by the replay
  ledger; P-N2c FIX 2 added `authorize_release` (re-runs exists +
  consumers-authorization against the ask's STORED consumer, AFTER the code
  validates/burns but BEFORE any fetch — a revoked-mid-park consumer denies
  both the approver's reply and the original parked caller's reply, and the
  ask is removed either way) — `handle_approve` calls it right after
  `take`. `audit_park`/`audit_approve`/`audit_dismiss` are the matching
  name-only audit functions, same two-destination shape as `audit_resolve`/
  `audit_put`; the dismissed-caller message no longer claims "by an
  operator" (P-N2c honesty fix — any group member reaching the socket can
  dismiss).
- `client` — `resolve` (one round trip over the socket, now via
  `read_final_reply` — P-N2c FIX 1: loops reading lines, consuming and
  `announce_interim`-ing any `"interim":true` line, returning the first
  non-interim line as the reply; `announce_interim` is what prints the
  `parked as ask <id> — complete with: ...` line to STDERR, never stdout,
  and only for the `"parked":true` interim shape — a future interim shape
  a caller doesn't recognize is silently consumed, never surfaced or
  fatal), `parse_exec_args`
  (pure `Invocation` parsing), `run_exec` (the full `secrets exec` flow: the
  entry point for `aoide-cli`'s `special` hook); `put` (P-V4c, one `put`
  round trip over the socket, mirrors `resolve`'s shape; P-67: takes an
  `overwrite` bool, returns `Result<bool, PutError>` where the `bool` is
  `replaced` and `PutError::Exists` is the wire's distinct `{"exists":true}`
  refusal, never inferred from `error` prose) and `run_put` (P-V4c, reads
  the value from THIS process's own stdin then calls `put` — the full
  `secrets put` flow, but a PLAIN function called from
  `commands::handle_secrets_put`, not a `cli`-crate `special`-hook case;
  P-67: takes a `force` bool — the CLI's `--force` — and, on a tty
  `PutError::Exists` refusal, prompts `y/N` and retries with
  `overwrite:true` on yes, never asking the caller to retype the value).
  `describe_connect_error` (this section's "socket-connect failure" case
  above) is the shared connect-error diagnosis both `resolve` and `put`
  route through — pure given an injected `io::Error`, unit-tested without a
  real socket. `non_tty_exists_message` (P-67) is the pure message builder
  behind the non-interactive "refuses and teaches `--force`" path — testable
  without faking a tty. `pending`/`approve`/`dismiss` (P-N2) are one-shot
  socket round trips mirroring `resolve`/`put`'s own shape — `PendingAsk`
  (id/secret/consumer/requestedAt, no value field at all) is `pending`'s
  return type; `approve`/`dismiss` return `Result<(), String>` — neither
  arm of either can carry a value, since the wire replies they read never
  have one.
- `commands` — `register(&mut Registry)`: FOURTEEN verbs, ALL CLI-only.
  `serve`/`exec`/`enroll` are door-hint handlers (the real work happens in
  `cli`'s `special` hook, same pattern as `a2a serve`/`conductor`); `add`/
  `rm`/`grant`/`revoke`/`set-totp`/`automate`/`expose` are policy-CRUD
  handlers gated the same way (`require_cli`) — a non-CLI door (MCP/A2A/
  Daemon) gets the door-hint `Outcome` before `policy.json`/`totp.secret` is
  ever touched, closing off a self-escalation path (`secrets grant <secret>
  <itself>`, or a hostile re-enrollment, from an already-connected agent).
  Those same seven also call `require_admin_identity` (P-V4f) right after
  `require_cli` — the wrong effective uid gets refused before the file is
  ever touched too, see "Admin verbs" above. `put` (P-V4c) is gated
  the SAME way (`require_cli`) but is NOT special-cased like `exec`/
  `enroll` — see `commands.rs`'s own module doc for why its wire reply
  carrying no value at all makes that unnecessary. `set-totp` (P-V4e)
  follows `put`'s shape too — a plain handler, no wire, no value. `automate`/
  `expose` (P-N1) follow the SAME shape as `set-totp` — plain handlers, no
  wire op of their own (both only edit `policy.json`, the same file
  `resolve`/`put` already read), same idempotent "unchanged" reporting.
  `pending`/`approve`/`dismiss` (P-N2, appended newest, LAST in
  `register()`) are `require_cli`-only like `put` — deliberately NOT
  `require_admin_identity`-gated, since they never touch `policy.json`,
  only the broker's in-memory `ParkRegistry` over the socket, the same
  operator-side-but-not-admin-side distinction `put`/`exec` already draw.

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
see `commands.rs`'s module doc; neither does `secrets set-totp`, P-V4e, nor
`secrets automate`/`secrets expose`, P-N1, nor `secrets pending`/`secrets
approve`/`secrets dismiss`, P-N2, for the same reason `put` doesn't — plain
handlers, no value on the wire). The workspace `Cargo.toml`
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
- **A parked ask never stores or touches a value** (P-N2, same "NO CACHE,
  EVER" spirit as above, restated for the registry this phase adds): a
  `ParkedAsk` holds only `secret`/`consumer`/`requestedAt` and a private
  channel — `approve` fetches fresh through the backend only AFTER a code
  has already validated, and sends it straight down that channel; nothing
  in `park`/`broker` ever holds a value across the wait.
- **Three production, non-test locks exist in this crate tree, all
  poisoned-lock-recovering** (`.lock().unwrap_or_else(|e| e.into_inner())`,
  never a bare `.unwrap()`): `park::ParkRegistry`'s internal `Mutex` was
  the first (P-N2 — every earlier `Mutex`/`RwLock` use was test-only env
  serialization); thread-per-connection then exposed two more
  read-modify-write sections the old serial accept loop used to serialize
  implicitly, just by never running two connections' code at once — a
  reviewer-confirmed race (empirically reproduced, ~5/20 iterations
  double-granting the same TOTP code before the fix). `broker::
  replay_ledger_lock` now guards `verify_totp_gate`'s full
  load→record→prune→save of the replay ledger, and `broker::put_lock`
  guards `put_gate`'s full existence-probe→store — two SEPARATE locks,
  since `put` and `resolve`/`approve` guard different files and there is
  no reason for one to block the other. A panic inside one connection's
  own thread must never poison every OTHER connection's ability to
  park/list/approve/dismiss/resolve/put, matching this crate's existing
  "one connection's failure never touches another's" discipline
  (`broker.rs`'s own module doc). Neither new lock caches anything — both
  sections still read fresh from disk on every call, same "NO CACHE,
  EVER" invariant as always; the lock only serializes the section.
