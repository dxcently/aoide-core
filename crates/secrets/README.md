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
**P-N3 (this commit) fires a NAME-ONLY notification on every notable broker
event** — `released` (a TOTP-free grant: `requireTotp:false`, or an
automation-skip), `parked`, `completed` (a successful `approve`),
`dismissed`, and `expired` (a park timing out) — so the desktop can surface
secret activity, and so a future popup has the park lifecycle's own
`released`/`parked`/`completed`/`dismissed`/`expired` signal to key off of.
See "Broker notifications" below for the exact shapes, the mechanism this
phase chose (and the one it didn't), and the no-dedup decision.

**`secrets watch` (this commit, tracker #71 Part 1) is the terminal
completion surface P-N2's own doc named as its eventual consumer**: a
foreground, line-mode verb that tail-follows the mirrored log, narrates
every P-N3 event, and — on a terminal — prompts inline for a parked ask
(approve with a hidden code, dismiss, or ignore). `--json` emits one event
object per line, the pickup point a future graphical popup (tracker #71
Part 2) subscribes to instead of re-tailing the log itself. See "Watching
events" below for the full mechanism.

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

**P-G1 (task #70, this commit) adds a SECOND seeded built-in backend,
`age`, beside `file` — and makes it the new `secrets add` default.**
`age` stores each secret as an age-encrypted `0600` file under
`<secrets_home>/values/`, decrypted with an identity this crate LAZILY
MINTS on the first `age`-backed `put` (`age.key`/`age.recipient`,
`age-keygen`, both `0600`) — never on a `get`, which is a taught error
instead if no identity exists yet. See "Backend presets" below for the
exact templates and the mint/taught-error mechanism, and "The write flow"
above for where the mint slots into `put`'s existing gate. **Backends also
gained an OPTIONAL `has` template** (task #70): a third, `#[serde(default)]`
template slot beside `get`/`set` that `has_value` runs directly when
present (exit 0 = has a value) instead of falling back to a `get`-and-
discard probe — absent on an old `backends.json`, so every file written
before this phase loads and behaves identically. **`aoide`'s own two
built-in stores (`file`, `age`) are the only backend IMPLEMENTATIONS this
crate supports today** — `pass`/`gopass`/`bw`/`sops` remain
DOCUMENTATION-ONLY presets ("Backend presets" below): copy the shape into
`backends.json` by hand, but integrating with any of those tools is
unsupported, untested territory this crate makes no promise about.
**DEFAULT FLIP:** `secrets add` with no `--backend` flag now records `age`
(previously `--backend` was a hard REQUIREMENT, not a defaulted flag, at
all) — an existing policy's already-recorded `backend` field is untouched
either way; only a brand-new `add` with the flag omitted is affected.

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

## Broker notifications (P-N3)

Every notable broker event fires a NAME-ONLY notification, so a desktop can
surface secret activity — and so a future popup phase (the code-entry UI
P-N2's own doc already named as this substrate's eventual consumer) has a
signal to key off of, not just `secrets pending`'s poll. Five events, the
task's own exact shapes:

```
released:  {"event":"released", "secret", "consumer"}            — a TOTP-free grant
parked:    {"event":"parked", "id", "secret", "consumer", "timeoutSecs"}
completed: {"event":"completed", "id", "secret", "consumer"}      — a successful approve
dismissed: {"event":"dismissed", "id", "secret", "consumer"}
expired:   {"event":"expired", "id", "secret", "consumer"}        — a park that timed out
```

**P-G1 (task #70) adds a SIXTH event, `age-identity-minted`, through the
SAME `emit_notify` mechanism** — `{"event":"age-identity-minted"}`, fired
from `handle_put` exactly once, the first time an `age`-backed `put`
lazily mints `age.key`/`age.recipient` ("Backend presets" above). Carries
no `secret`/`consumer`/`id` at all — the identity is host-level, not tied
to any one secret — so it is INVISIBLE to `secrets watch`/`--popup`'s own
event parser (`watch::parse_notify_line` requires both `secret` and
`consumer` on every event it recognizes; this one has neither, so it is
silently skipped there, exactly like any other unrecognized `event` kind
already is) — a deliberate scope cut, not an oversight: task #70 asked
only for the audit line, not a new `watch` narration.

`released` fires ONLY on a TOTP-free grant — `requireTotp:false`, or an
automation-skip (P-N1's `automation.enabled` + a listed consumer) — never on
a resolve that validated its own inline `--totp` code: the caller just typed
the code themselves, there is nothing for a desktop popup to tell them.
`GateOutcome::Granted`'s `totp_free` field (`broker.rs`) is the ONE place
this distinction is recorded, right where `resolve_gate` already decides
`totp_required` — see `broker.rs`'s own doc on that variant.

**No dedup, no throttle — deliberate (User decision, this phase).** Every
TOTP-free resolve fires its own `released` line, even a hundred calls in a
tight loop from the same consumer. Revisit only with real spam evidence from
a live deployment (the same "wait for the field to complain" discipline this
crate's other UX fixes — P-V4d/e/f/g — were all born from); no rate limit,
window, or "same secret+consumer within N seconds" collapsing is planned
ahead of that evidence.

**Mechanism chosen, and the one this phase did NOT take.** `conduct/src/
graph/permit.rs` (a DIFFERENT crate, `aoide-conduct`) publishes its own
desktop summons through `crate::herald::publish` → `crate::shellbridge::
send_line` — a unix-socket call into the shellbridge daemon that owns
`song/stage/herald.json`, the file the Quickshell herald widget actually
draws from. That seam was the first one this phase checked, and it is NOT
reachable from here: `aoide-secrets`'s own `Cargo.toml` depends on nothing
but `aoide-protocol`/`libc`/`serde`/`serde_json` — no `aoide-storage`, no
`aoide-conduct` — and `herald`/`shellbridge` both live in `aoide-conduct`
(a "charter smudge" its own `AGENTS.md` names explicitly). Reaching them
would mean a NEW `aoide-secrets` → `aoide-conduct` dependency edge, which
this phase's brief ruled out (`pkgs/aoide/crates/AGENTS.md`'s "no
cross-crate copying" — the fix for a missing seam is widening what's
already `pub`, not duplicating logic in, and reaching an unrelated crate is
worse than either); it would also be a step backward across the aoide/AoideOS
boundary from the root `AGENTS.md` (house rule 7's "delete every `.qml`"
test): the shellbridge socket only exists while a desktop session's bridge
daemon is running, but this broker is meant to run headless, as a system
service, with no desktop present at all (`socket::socket_path`'s own
`/run/aoide-secrets/secrets.sock`, entirely independent of `$XDG_RUNTIME_DIR/
aoide/shellbridge.sock`).

No adapter on the `aoide-conduct`/`lyra` side currently tails the mirrored
aoide log (`~/Aoide/log`) and republishes anything from it into `herald`
either — `aoide-client`'s adapter skeleton (`crates/client/src/adapter.rs`)
subscribes to `EventClass::{Audit,Gate,Rice,Content,Notification}` but has
no `Secret` case at all, and no other crate in this workspace tails that
file live.

**THREE destinations as of P-G4 (task #77 — the `ProtectHome` fix, see
below).** `emit_notify` writes the SAME `payload` verbatim to all three: the
broker's own structured `<secrets_home>/audit.log` (`append_own_log` —
`tail -f <secrets_home>/audit.log` shows the five event shapes above exactly
as written), the mirrored aoide log (`EventClass::Secret`, `command:
"secrets.notify"`, `status` = the event kind, `message` = the same payload
JSON stringified — `tail -f ~/Aoide/log | grep secrets.notify` is the
cross-host-readable audit-trail half, UNCHANGED by P-G4), and NOW the
broker-owned **events feed** (`append_events_feed`, `socket::events_path` —
default a sibling of the broker's own socket, e.g.
`/run/aoide-secrets/events.jsonl` next to `secrets.sock`; env override
`AOIDE_SECRETS_EVENTS`). All three writes are best-effort: a notification
must never fail or block the resolve/approve/dismiss it rides alongside, so
every one of `append_own_log`/`aoide_protocol::audit`/`append_events_feed`'s
own errors is `eprintln!`d and swallowed, the SAME posture every `audit_*`
function already holds — and, like every other notify write, NEVER runs
while a crate lock is held (see below).

**Why a third destination, and why it lives beside the socket rather than
under the operator's home.** The deployed broker unit runs with
`ProtectHome=true` (`modules/nucleus/secrets.nix`) — its best-effort mirror
into `~/Aoide/log` silently fails there, so `secrets watch` (below) received
ZERO event lines in the field and fell back to its 30s pending-reconcile
tick for every popup (found live on yomi-strix, 2026-08-23). A path beside
the broker's own socket sits inside the directory the unit already owns and
writes to (`RuntimeDirectory=`/`/run`), so it is reachable under
`ProtectHome=true` exactly the way the socket itself already is. Created
`0640` with an explicit `chmod` right after the file is first created (never
left to the process umask) — the deployed unit's `Group=
aoide-secrets-access` makes group-read exactly the socket's own audience.
Events are ephemeral cues on a `/run`-backed tmpfs, not a second audit trail
— capped at 1 MiB (`broker::EVENTS_MAX_BYTES`); past the cap, the next
append truncates the file to empty first rather than rotating it, and
`watch::Follower::poll`'s own `len() < pos` branch (already needed for a
broker restart replacing the file) is what makes that truncation
transparent to a live tail. The mirrored `~/Aoide/log` write is UNCHANGED —
it still serves the audit trail; only `secrets watch`'s own tail moved off
it (below).

**The popup phase's pickup point is `aoide secrets watch --json`
(tracker #71 Part 1)** — see "Watching events" below. It tails the
broker-owned events feed (P-G4; the mirrored `~/Aoide/log` through P-N3),
the same way `secrets pending` already polls the in-memory `ParkRegistry` —
a `parked` line is the exact trigger `secrets pending`'s own poll would
eventually see, just pushed instead of pulled, and delivered in about a
second instead of up to 30. A future GRAPHICAL popup (a `lyra`/desktop
consumer, tracker #71 Part 2) reads `secrets watch --json`'s stdout stream
directly rather than re-deriving this tail itself — this emission plus
`watch`'s own tail/reconcile loop are the substrate, the same relationship
P-N2's park/approve/dismiss lifecycle already has to that UI.

`emit_notify` (`broker.rs`) is the ONE function that builds and writes a
notify line — every call site (`handle_resolve`'s `Granted`/`NeedsTotp`/
`WaitResult::TimedOut` arms, `handle_approve`'s success arm,
`handle_dismiss`'s found arm) calls it only AFTER the crate lock its own
outcome depended on has already been released (`park::ParkRegistry`'s
internal `Mutex`, or `broker::replay_ledger_lock`) — see `emit_notify`'s own
doc comment for the exact "no lock held" accounting at each site;
`append_events_feed` inherits the same guarantee rather than re-earning it.

## Watching events (`secrets watch`, tracker #71 Part 1)

`aoide secrets watch` is a foreground, line-mode terminal surface — the
"delete every `.qml`" proof for the code-entry-popup design (root
`AGENTS.md` house rule 7): the whole capability is reachable with nothing
but a shell. **As of P-G4 (task #77) it tail-follows the broker-owned
events feed** (`socket::events_path` — default a sibling of the broker's
own socket, env override `AOIDE_SECRETS_EVENTS`; see "Broker notifications"
above for why) **from EOF** (`crate::watch::Follower` — delta reads only,
`stat(2)` once a second, reopening at 0 whenever the file has shrunk, which
covers both a broker restart replacing the file and the feed's own 1 MiB
truncate-in-place cap). Through P-N3 this tailed the mirrored `~/Aoide/log`
instead, filtering `class:"secret", command:"secrets.notify"` lines — that
mirror silently went dark under the deployed broker's `ProtectHome=true`
unit, delivering nothing until the reconcile tick below caught up, up to
30s late; corrected at P-G4, see "Broker notifications" above for the live
incident. `watch::parse_notify_line` now parses the events feed's bare
`{"event": "<kind>", ...}` payload lines directly — no wrapper, no
`message`-as-JSON-string indirection — and narrates every one of the five
broker events (`released`/`parked`/`completed`/`dismissed`/`expired`,
"Broker notifications" above). `client::pending` remains the AUTHORITY —
the tail never is — so `crate::watch::Queue::reconcile` runs once at
startup (so a watcher started AFTER an ask parked still sees it) and again
on every event plus a 30s safety tick that is now purely a RECONCILIATION
BACKSTOP (a missed line, a completion from another terminal, or a broker
restart) rather than the primary delivery path — a parked ask surfaces
through the feed in about a second, not up to 30. An ask `reconcile`
discovers with no matching `parked` line has no `timeoutSecs` to go on —
the wire's `pending` reply never carries one — so its countdown is
`park::park_timeout()` used as an ESTIMATE, marked with a `~` prefix in the
prompt so the operator knows it's a guess. On a brand-new host where the
broker hasn't emitted anything since boot, the events feed may not exist
yet at `secrets watch` startup — `watch::wait_for_follower`'s
`NotFound`-poll narrates once and waits, the same "wait, don't exit 1"
shape this held for the mirrored log through P-N3.

```
$ aoide secrets watch
watching secret events — ^C to leave (parked asks stay parked)

  19:04:11  released    aws-ci → melete   (no code required)
  19:06:02  parked      db-prod → claude   ask 3f2a-3   times out in 5m00s

┌ ask 3f2a-3 ─ db-prod ← claude ─ asked 19:06:02 ─ 4m41s left
│ [a] approve (enter code)   [d] dismiss the ask   [i] ignore (stays parked)
└ > a
  code for `db-prod` (input hidden): ······
  ✓ approved 3f2a-3 — value released to the waiting caller
```

**On a terminal** (`client::stdin_is_tty`, and `--json` absent), each
parked ask prompts inline, one at a time, FIFO by `requestedAt` (the ask
closest to expiry prompts first) — a second ask arriving mid-prompt is
narrated immediately and counted as "queued", never double-prompted (a code
typed into the wrong ask would be spent for nothing). The three keys are
read as a LINE (`a⏎`), never raw single-key — no cbreak/raw mode, no
terminal-state restoration risk, works over ssh and with a piped stdin:
- `[a]` opens a hidden-input code prompt (`client::read_hidden_line`,
  reused VERBATIM — the code goes straight to `client::approve`, NEVER
  argv) — a wrong code narrates `the ask is STILL PARKED, nothing was
  spent` and re-opens the same prompt (no retry cap; the park's own
  timeout is the bound).
- `[d]` calls `client::dismiss` — the ask is GONE, the waiting caller gets
  a clean refusal.
- `[i]` ignores the ask FOR THIS SESSION ONLY — it stays parked,
  completable from any terminal, and still narrates when it completes or
  expires (never a blindfold).

**Near-expiry lockout: 10 seconds** (`crate::watch::LOCKOUT_SECS`),
enforced twice — a code prompt refuses to OPEN below the threshold, and the
remaining time is re-checked again AFTER the code is read but BEFORE
`client::approve` is called, so a code typed right at the boundary is
discarded unspent rather than raced against the broker's own backend
shell-out — bounded since task #74 (`AOIDE_SECRETS_BACKEND_TIMEOUT`,
default 10s, "Bounded backend shell-outs" below) but still not
instantaneous, so this double-check remains load-bearing.

**Non-tty stdin, or `--json`: narration only, no prompts, ever** — `aoide
secrets watch | tee` and a systemd unit both behave. `--json` emits one
JSON object per line, flushed per line — the seam any other consumer (a
script, a future desktop adapter) subscribes to instead of re-tailing the
log itself. (Tracker #71 Part 2's own popup phase landed IN THIS crate,
not as a separate `lyra`-side subscriber of this stream — see "Popup mode"
below.)

```
$ aoide secrets watch --json
{"event":"parked","id":"3f2a-3","secret":"db-prod","consumer":"claude","timeoutSecs":300,"requestedAt":1787441132,"expiresAt":1787441432,"ts":1787441132}
{"event":"completed","id":"3f2a-3","secret":"db-prod","consumer":"claude","ts":1787441159}
{"event":"released","secret":"aws-ci","consumer":"melete","ts":1787441171}
```

`released`/`completed`/`dismissed`/`expired` carry no `id`-adjacent extras
beyond what "Broker notifications" already documents, plus the top-level
`ts` every line carries (the mirrored log's own `AuditRecord.ts`); `parked`
additionally carries `requestedAt`/`expiresAt` (`ts` and `ts + timeoutSecs`)
so a subscriber never has to compute a deadline from a wall-clock delta
itself. **Never in this shape, ever: a secret value** — same rule as every
other wire/log shape in this crate.

`aoide secrets watch` is CLI-only (`require_cli`, same door gate as
`pending`/`approve`/`dismiss`) but NOT an admin/euid verb — it touches no
`policy.json`, only the mirrored log (read-only) and the broker's in-memory
registry over the existing socket ops. Socket errors while reconciling
(the broker not running, or restarting) print the taught connect error
(`client::describe_connect_error`) and the watcher keeps tailing the log
regardless — the broker may come back. Clean exit on Ctrl-C (a SIGINT
handler sets a flag the tail loop notices within its next 1s poll) or on
stdin EOF during a prompt; either way, the parting line names how many asks
are still parked: `left the watcher — N ask(s) still parked; complete with
aoide secrets approve <id> --totp <code>`.

**Startup: waits for the log, rather than exiting 1, if it's not there yet**
(review rider). On a brand-new host `secrets watch` may start before the
broker has written its first line to `~/Aoide/log` — `watch::
wait_for_follower` polls once a second and narrates the wait exactly ONCE
(`waiting for the log to appear at <path>`) rather than failing immediately;
Ctrl-C during the wait exits cleanly. Any OTHER open error (a permission
problem, for example) still fails immediately — only "the file doesn't
exist yet" waits.

**Narration timestamps are UTC**, always — `hms()` renders the mirrored
log's own `AuditRecord.ts` (unix seconds) as `HH:MM:SS` with no local-zone
conversion, on every line, in every mode (tty prompt, popup narration, and
the plain pipe path alike).

**After an async narration line interrupts an open tty prompt, the FULL
prompt frame reprints underneath it** — header, the `[a]`/`[d]`/`[i]`
options line (or the `CLOSED` variant), and the `└ > ` entry marker, never
just the bare header (review rider — the "1.3 Signal flow" ASCII above
already showed the full block reprinted this way; a stray header-only line
with no visible options would be confusing on its own).

## Popup mode (`secrets watch --popup`, tracker #71 Part 2)

`aoide secrets watch --popup` is the same watcher loop, `--json` and the
socket ops unchanged, with one swap: a parked ask surfaces as a
`zenity --entry --hide-text` dialog instead of the terminal's `[a]`/`[d]`/
`[i]` prompt — the terminal path (narration, `pending`/`approve`/`dismiss`
from ANOTHER window) still works exactly as before, `--popup` only changes
how THIS process itself offers to complete an ask.

```
$ aoide secrets watch --popup
watching secret events — ^C to leave (parked asks stay parked)
  19:06:02  parked      db-prod → claude   ask 3f2a-3   times out in 5m00s
[a zenity --entry --hide-text dialog opens: "code for `db-prod` ← claude · 287s left",
 with an extra "Dismiss ask" button beside OK/Cancel]
```

- **The typed code rides the CHILD's own stdout pipe straight into
  `client::approve` — never argv.** `zenity`'s own argv (`Command::new`'s
  `args`) carries only the dialog's TITLE and TEXT, both name-only (secret
  name, consumer, remaining seconds) — never a code, never a value. Grep
  the spawn call yourself (`watch::spawn_zenity_entry`) if in doubt.
- **Wrong code**: a brief `zenity --error` shows, then the SAME ask's entry
  dialog re-opens — the ask stays parked, the replay ledger unburned, same
  as the tty path's own wrong-code retry.
- **Cancel/close the dialog = IGNORE** (same session-only semantics as the
  tty prompt's `[i]`) — the ask stays parked, completable from any other
  terminal. The dialog's extra **"Dismiss ask" button** maps to
  `client::dismiss` — a real refusal, never confused with a Cancel: the two
  are always a different button, worded differently, exactly the design's
  own "never adjacent, never share a word" rule for `[d]` vs `[i]`.
- **Unlock-gated.** Before opening a dialog, `watch::is_locked` ORs two
  signals: `loginctl show-session <id> -p LockedHint --value` (skipped
  entirely when `$XDG_SESSION_ID` is unset; an unanswerable probe reads as
  "not locked," never as "locked") OR'd with a `/proc` scan for a named
  locker PROCESS, `AOIDE_SECRETS_LOCKER` (default `hyprlock` — the design
  doc verified hyprlock 0.9.6 sets no `LockedHint`, so this half is
  load-bearing on this rig, not a redundant fallback). While locked, the
  loop holds the dialog and re-polls once a second; once unlocked it opens
  the dialog — but ONLY if the near-expiry rule below still allows it.
- **Near-expiry: no dialog opens below the SAME 10-second lockout**
  (`watch::LOCKOUT_SECS`) the tty prompt refuses `[a]` below — checked
  BEFORE showing (a locked-then-expiring ask is skipped, never shown late)
  and RE-CHECKED after the dialog returns, before the code is sent (the
  same double-enforcement "Near-expiry lockout" above documents for the
  tty path).
- **If the ask completes/expires elsewhere while its dialog sits open**,
  `watch::run_zenity_entry` kills that dialog's EXACT child — the
  `std::process::Child` handle it already holds, never a re-derived pid,
  never a name match — and narrates `ask <id> resolved elsewhere while its
  popup was open`.
- **`released`/`completed`/`dismissed`/`expired` are SUPPRESSED as
  popups** — parked-only is the default (User-flagged): every mode
  narrates all five events on stdout regardless, but only a `parked` event
  ever drives a dialog. A tight automation loop firing many `released`
  events therefore narrates a scrolling terminal, never a toast storm of
  dialogs.
- **`zenity` is a runtime shell-out declared BY NAME — zero new Cargo
  dependencies** (the plugin philosophy, root `AGENTS.md` house rule 7;
  same feature-detection shape `enroll::render_qr` already uses for
  `qrencode`). Missing at `--popup` startup: a taught error naming BOTH
  fixes (`install zenity`, or drop `--popup` and run plain `secrets
  watch`), clean exit 1 — checked once, before the tail thread or the
  socket reconcile ever starts.
- **`--popup` works over a non-tty stdin** (dialogs replace prompts, so
  there's nothing for stdin to drive) — **`--popup`+`--json` is a usage
  error** (`commands::handle_secrets_watch`, before `watch::run` is ever
  reached): the two modes both own "how a parked ask gets completed" and
  can't both drive it.
- **`watch::run`'s zenity spawn path takes the binary name as a
  parameter** (`watch::ZENITY_CMD` in production, `"zenity"`) rather than
  hardcoding `Command::new("zenity")` — this is what lets this crate's own
  tests stand in a fake shim script (a tempdir executable that echoes a
  fixed code, or a fixed exit code) WITHOUT mutating `PATH` (unlike
  `enroll::render_qr`'s older PATH-shim test, which needs `env_lock`
  because `PATH` is process-global); see `watch.rs`'s own test section for
  the exact shape.

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

## Bounded backend shell-outs (task #74)

Every `get`/`set`/`has` template execution — every call this crate makes
through `backend::fetch_value`/`store_value`/`has_value` — now runs through
ONE shared, bounded spawn path, `backend::run_backend_command`. Before this
phase there was no bound at all (this file used to document it as a KNOWN
GAP, `AGENTS.md`): a wedged template blocked its calling thread forever,
and on the `put` path that thread was holding `broker::put_lock` the whole
time, serializing every OTHER `put` on this broker behind the one hang —
the exact live-shaped failure this phase closes.

`AOIDE_SECRETS_BACKEND_TIMEOUT` (seconds, default **10**) bounds the wait —
read fresh on every shell-out, never cached, same tolerant-fallback parsing
as `AOIDE_SECRETS_PARK_TIMEOUT`: a blank or unparsable value falls back to
the default rather than disabling the bound. A template still running past
the deadline has its WHOLE PROCESS GROUP `SIGKILL`ed (never just the
immediate `sh` — a pipeline the template itself forked, e.g. `age -d ... |
something`, would otherwise survive as orphans) and reaped (`Child::wait`,
never a zombie left behind); the caller gets a taught error naming the
backend, the operation (`get`/`set`/`has`), and the env knob — **never the
template text**, which can't carry a secret value in the first place (a
`set` template's `value` only ever reaches its child over stdin, never
interpolated into the command string `expand_template` builds). The wait
itself is wall-clock via polling `Child::try_wait` — never a per-child
watchdog thread, never `SIGALRM` — with stdout/stderr drained
NON-BLOCKINGLY while polling (rather than only after the child exits), so a
template that happens to write more than one pipe buffer's worth of output
can't deadlock against the timeout mechanism itself.

A hung `get`/`resolve` only ever blocks its own connection's thread
(`broker.rs`'s module doc — no lock is held across that call); a hung
`has`-probe (P-67's "warn before overwrite" existence check) degrades to
"no stored value" on timeout, the same tolerant fallback it already held
for a spawn failure or a non-zero exit — the SET attempt that follows hits
the identical hang and correctly fails with a real timeout error there, so
nothing is silently overwritten on a mere probe timeout. Behavior for a
well-behaved template is unchanged under the default knob — this phase
only bounds the wait, it never slows down the common case.

**P-G3 review fix: the ONE non-template shell-out this crate makes is
bounded too.** `backend::mint_age_identity_if_needed`'s two `age-keygen`
calls (the `age` backend's lazy identity bootstrap — a plain argv exec,
never a `sh -c` template, so it never went through `run_backend_command`)
originally ran through a plain blocking `Command::output()`, missed by the
task #74 bound above even though minting happens inside the SAME
`put_lock` critical section a hung `set` template used to wedge. The
poll/drain/kill/reap loop `run_backend_command` uses internally is now its
own function, `backend::wait_bounded` (generic over an already-spawned
child — no backend name, no op, no command string), so `age-keygen`'s own
caller, `backend::run_age_keygen`, bounds it the identical way without
duplicating the loop. `run_backend_command`'s own external behavior is
unchanged by this refactor.

## Backend presets

`backend.rs`'s `Backends`/`fetch_value`/`store_value` (Named seams, below)
know nothing about any specific secret manager — `backends.json` is a map
of named backend -> a `get` command template, an OPTIONAL `set` template
(P-V4c) that makes the backend WRITABLE, and an OPTIONAL `has` template
(P-G1, task #70) that answers "does this secret already have a value" more
cheaply/honestly than re-running `get` and discarding its stdout — the
policy's `key` is substituted into a template's `{name}` placeholder, and
a template may also use `{home}` (P-V4c), substituted with `secrets_home`
itself, quoted the SAME way as `{name}`. `has` is `#[serde(default)]`:
absent on a `backends.json` written before this field existed, and
`has_value` falls back to its pre-existing `get`-probe behavior byte-for-
byte in that case. These presets are DOCUMENTATION, not code — copy the
shape that matches your backend into `backends.json` — with TWO
exceptions:

| Backend  | `get` template            | `set` template | `has` template | Notes                                            |
|----------|----------------------------|-----------------|-----------------|--------------------------------------------------|
| `file` **(built-in, P-V4c)** | `cat {home}/store/{name}` | `mkdir -p -m 0700 {home}/store && install -m 0600 /dev/stdin {home}/store/{name}` | `test -f {home}/store/{name}` (P-G1) | An EXCEPTION — SEEDED automatically into a fresh `backends.json` (below), not merely documented here. Plain `0600` files under `<secrets_home>/store/`, expressed entirely through the template mechanism (house rule 7 — no special-cased Rust reads or writes this backend's bytes). Its `has` template is a cheap `test -f` rather than re-running `cat` and discarding the value — no behavior change, since a `0600` file's existence already implied a value under the old `get`-probe fallback too. |
| `age` **(built-in, P-G1, task #70)** | `age -d -i {home}/age.key {home}/values/{name}.age` | `mkdir -p -m 0700 {home}/values && age -e -R {home}/age.recipient -o {home}/values/{name}.age && chmod 0600 {home}/values/{name}.age` | `test -f {home}/values/{name}.age` | The SECOND exception — also SEEDED. Age-encrypted `0600` files under `<secrets_home>/values/`; `secrets add`'s own new DEFAULT backend (above). The identity (`{home}/age.key`/`{home}/age.recipient`) is LAZILY MINTED by `backend::mint_age_identity_if_needed` on the first `age`-backed `put` — real Rust I/O, not a template (same one-time-bootstrap shape `enroll`'s TOTP-secret generation already uses), audited as a name-only `age-identity-minted` broker notify event ("Broker notifications" above). **Never minted on `get`** — a missing `age.key` there is a taught error (`backend::missing_age_identity_hint`), never an auto-mint. A missing `age`/`age-keygen` binary on `PATH`, for either template OR the mint itself, is ALSO a taught error naming the package to install (`backend::missing_age_binary_hint`) — never a bare "exited 127". |
| `pass`   | `pass show {name}`         | — | — | `key` is the pass-store entry path (`prod/db`).  |
| `gopass` | `gopass show -o {name}`    | — | — | `-o` prints the password line only, no metadata. |
| `bw`     | `bw get password {name}`   | — | — | `key` is the Bitwarden item's name or id; needs a prior `bw unlock`/`BW_SESSION` in the broker's own environment (secrets-uid-owned, per the ownership-trap note below). |
| `sops`   | `sops -d --extract {name} secrets.yaml` | — | — | `key` is the FULL `--extract` JSONPath argument sops expects, e.g. `["password"]` — the brackets+quotes are part of the `key` VALUE (so `backend::shell_single_quote` escapes them along with everything else), not written into the template. The `secrets.yaml` path is fixed in the template, not templated — a second sops file needs its own named backend entry, and the secrets uid needs the sops decryption key (age/GPG/KMS) set up, per the ownership note below. |

**`aoide`'s own two built-in stores, `file` and `age`, are the only
backend IMPLEMENTATIONS this crate supports as of P-G1 (task #70).**
`pass`/`gopass`/`bw`/`sops` remain exactly what they always were —
DOCUMENTATION-ONLY presets, copy-paste shapes for a `backends.json` you
maintain by hand — but this crate makes no support promise about actually
integrating with any of them: no tests exercise them, no code path knows
their quirks, and a live problem with one is the operator's own to debug.
Reach for `age` (encrypted, no external tool) or `file` (plaintext, purely
local) first; only add a `pass`/`gopass`/`bw`/`sops` row if you already run
that tool and accept it as unsupported territory.

**`backends.json` is SEEDED with BOTH built-in backends (`file`, `age`)
when absent** — the ONE seeding site is `broker::serve`'s startup
(decision recorded in `broker.rs`'s module doc): the broker is the single
long-running process that ever actually resolves a backend name against a
template, so seeding there guarantees every `resolve`/`put` sees a
`backends.json` on disk without a second seed call at `secrets add`/
`secrets put`. **An EXISTING `backends.json` is never touched BY SEEDING**
— seeding only ever writes the file when it is entirely absent. **P-G2
(task #72) adds an additive sibling, right after seeding in the SAME
startup call:** `backend::backfill_missing_backends` acts on an EXISTING
file, adding whichever built-in (`file`/`age`) is missing BY NAME — never
touching an entry, built-in or custom, already present — and skipping the
write entirely when nothing was missing. See "Migrating a secret between
backends" below for the per-secret companion this pairs with.

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

## Migrating a secret between backends (`secrets migrate`, P-G2, task #72)

`secrets migrate <name> [--backend <target>]` (target defaults to `age`)
moves ONE secret's already-stored value from its policy's CURRENT backend
to a TARGET backend, then flips the policy's own `backend` field —
`backend::backfill_missing_backends`'s per-secret companion (above): where
backfill closes the GAP (a backend the policy names but `backends.json`
never configured), migrate is what an operator runs to actually ACT on a
secret once it's closed, or to move any secret between any two configured
backends for any other reason.

```
operator -> aoide secrets migrate db-prod --backend age
         -> policy gate (same admin door as add/rm/grant: CLI-only,
            euid-guarded — "Admin verbs" below)
         -> fetch the value via the policy's CURRENT backend
         -> store it via the TARGET backend (may lazily mint the target's
            age identity, the SAME `backend::mint_age_identity_if_needed`
            put_gate already uses — reused, never duplicated)
         -> flip policy.backend to the target and save policy.json
         -> remove the OLD value, ONLY if the source backend is a built-in
            whose value path this crate can derive on its own
         <- reports what happened, including whether the old value was
            actually removed
```

**Admin verb, direct-home — mirrors `add`/`rm`/`grant` exactly, not
`put`/`exec`'s socket round trip** (`commands.rs`'s own door taxonomy):
`require_cli` + `require_admin_identity` gate it before anything touches
`policy.json`, same euid-ownership refusal (root explicitly included) the
whole CRUD/`set-totp`/`automate`/`expose` quartet-plus already holds. It
does **not** go through the running broker's socket at all — like
`add`/`rm`/`grant`, it reads/writes `policy.json` (and, here, a backend's
own value file) directly as whatever uid invokes it, normally `sudo -u
aoide-secrets aoide secrets migrate ...` in deployment.

**Ordering is safety-critical, and deliberately asymmetric with removal**:
the new ciphertext is fetched and durably stored via the TARGET backend
BEFORE `policy.json`'s `backend` field ever flips; the OLD value is removed
LAST, strictly after the policy save has already succeeded. Any failure
before the policy flip — a fetch failure, a store failure, a policy-save
failure — leaves EVERYTHING untouched: the old value in place, the policy
unflipped, no partial state. Once the flip has landed, the secret is fully
migrated even if the old-value cleanup that follows fails or is skipped —
cleanup is best-effort tidiness, never load-bearing for correctness.

**Old-value removal only ever happens for a built-in SOURCE backend whose
value path this crate can derive without asking its own template**
(`backend::remove_builtin_value`): `file` → `<home>/store/<key>`, `age` →
`<home>/values/<key>.age` — the SAME paths `FILE_BACKEND_SET`/
`AGE_BACKEND_SET` themselves write to. `<key>` here is the policy's own
`key` field (the value a template's `{name}` placeholder substitutes —
`backend.rs`'s module doc — not the secret's display `name`, which can
differ). A source backend that ISN'T one of these two built-ins (a
`pass`/`gopass`/`bw`/`sops` row, or any operator-custom entry) is left
completely untouched — this crate has no way to know where such a backend
keeps its own bytes — and the success message says so plainly rather than
silently doing nothing.

**Idempotent and refusal-clean, matching this crate's other admin verbs**:
migrating a secret to the backend it's already on is a no-op that reports
exactly that (house rule: report what changed, never `.changed(...)` on a
write that never happened) — no fetch, no store, no policy write. A secret
with no policy is a clean `no policy for secret` error. A MISSING value
under the source backend (the fetch step fails — including the exact
"unconfigured `age`" gap this phase's own backfill half closes for future
secrets, but a secret already pointed at a backend that still isn't
configured) is a clean refusal: nothing is mutated, the policy keeps
naming its original (unreachable) backend, and the operator is told to fix
the source first.

**The moved value exists ONLY as a local `String` inside
`commands::handle_secrets_migrate`**, from `backend::fetch_value`'s return
to `backend::store_value`'s own argument — never an `Outcome` field, never
argv, never logged. **Audit is name-only**, the same discipline every
other value-adjacent audit line in this crate holds: one
`EventClass::Secret` line (`command: "secrets.migrate"`, `status`
`migrated`/`unchanged`/`refused`) naming the secret, source backend, and
target backend — never the value, never the key.

**No lock against a live broker (KNOWN LIMITATION, `AGENTS.md`).** `migrate`
runs as a separate OS process from `secrets serve` and cannot take the
daemon's own in-process `put_lock` — a `migrate` racing a `put`/`exec`
against the SAME secret through a concurrently-running broker is an
unprotected window (the same class of gap this crate's admin CRUD verbs
already accept for `policy.json`, `store.rs`'s own module doc). Run it
against a secret you know isn't being written concurrently.

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

**The events feed (P-G4, task #77) needs NO nix change either.**
`socket::events_path`'s default is a sibling of the resolved socket path —
`/run/aoide-secrets/events.jsonl` next to `secrets.sock` — so it lands
inside the SAME `RuntimeDirectory = "aoide-secrets"` the module above
already provisions, with no new `AOIDE_SECRETS_EVENTS` export needed on
either the broker or `secrets watch`'s side. This is what fixed the
`ProtectHome=true` gap live: the mirrored `~/Aoide/log` write is under the
operator's home, which that setting blocks; a path inside `RuntimeDirectory`
is not.

**Open deployment gap, flagged not fixed here (P-G1, task #70 — this
crate's own hard constraint forbids touching `.nix` files; the unit-path
packaging is the orchestrator's, root `AGENTS.md`):** the service's `path`
above does NOT yet carry `pkgs.age` — `age`/`age-keygen` are absent from
the nix module's `PATH` the same way `bash`/`coreutils` were absent before
the fix documented two paragraphs up. Since `age` is now `secrets add`'s
DEFAULT backend, a fresh nix-deployed broker will fail every `age`-backed
`get`/`set`/mint with the taught "`age`/`age-keygen` CLI on PATH" error
(`backend::missing_age_binary_hint`) until `modules/nucleus/secrets.nix`'s
`path` gains `pkgs.age` in a follow-up commit — the SAME fix shape the
`bash`/`coreutils`/`qrencode` additions above already are, just not yet
made for this new default.

**A second, related deployment gap, reporting fixed at P-G1 review (task
#70), CLOSED at P-G2 (task #72, this commit).** An EXISTING deployment's
`backends.json` predates P-G1 (`file` only, no `age` entry — seeding never
touches an already-present file, "Backend presets" above), and `secrets
add`'s new default records `backend: "age"` on a brand-new policy
regardless. P-G1 review made the resulting `get`/`put` against that policy
report the true cause, `unknown backend \`age\`` (`backend::fetch_value`/
`broker::put_gate` both confirm `age` is an actually-configured backend
before doing anything `age`-specific, rather than assuming the name implies
the seeded built-in) instead of the misleading "run `secrets put` to mint"
hint, and stopped a doomed `put` from minting a real identity first — but
left the underlying gap itself open: there was still no path that added the
`age`/`has` entries to an already-existing `backends.json`.

**P-G2 closes it two ways, both additive.** First, automatically: every
broker startup, `broker::serve` now calls `backend::
backfill_missing_backends(secrets_home)` immediately after
[`seed_default_backends`] — where seeding only ever acts on an ABSENT
`backends.json`, backfill acts on an EXISTING one, adding whichever
built-in entry (`file`/`age`) is missing BY NAME and never touching an
entry — built-in or hand-customized, even one an operator wrote under the
name `age` or `file` themselves — that's already present. A `backends.json`
that already carries both built-ins is not rewritten at all (no gratuitous
mtime churn); every other row (`pass`/`gopass`/`bw`/`sops` presets, any
operator-named custom backend) rides through byte-for-byte. This alone
means a broker restarted after upgrading past P-G1 self-heals its
`backends.json` with no operator action — the "delete `backends.json` and
lose your custom rows" workaround above is retired.

Second, per-secret: `secrets migrate <name> [--backend <target>]`
(`commands::handle_secrets_migrate`, default target `age`) moves ONE
secret's already-stored VALUE from its policy's current backend to the
target backend, then flips the policy row — so an existing secret sitting
on a policy that named `age` before `age` was actually configured (or one
an operator wants to move off `file` onto `age`, or off any backend onto
another) can actually be acted on, not merely reported on. See "Migrating a
secret between backends" below for the full flow.

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

`secrets add|rm|grant|revoke|enroll|set-totp|automate|expose|migrate` mutate
`policy.json`/`totp.secret` (and, for `migrate`, a backend's own value file)
under the secrets home, so they run AS the secrets user — no sudo rule is
shipped (nix module or not); the raw form:

```sh
sudo -u aoide-secrets aoide secrets enroll
sudo -u aoide-secrets aoide secrets add <name> --key <key> [--backend <backend>]  # defaults to `age`
sudo -u aoide-secrets aoide secrets grant <name> <consumer>
sudo -u aoide-secrets aoide secrets set-totp <name> on
sudo -u aoide-secrets aoide secrets automate <name> on
sudo -u aoide-secrets aoide secrets automate <name> grant <consumer>
sudo -u aoide-secrets aoide secrets expose <name> on
sudo -u aoide-secrets aoide secrets migrate <name> [--backend <target>]  # defaults to `age`
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
  named backend -> a `get` template, an OPTIONAL `set` template (P-V4c),
  and an OPTIONAL `has` template (P-G1, task #70)) and `fetch_value`/
  `store_value`, which substitute the policy's `key` and (P-V4c)
  `secrets_home` itself (`{home}`), both SHELL-SINGLE-QUOTE-ESCAPED (never
  a raw `.replace()` — a key/home with whitespace or an embedded `'` must
  not be able to break the command or escape its argument boundary) via
  `expand_template`'s single left-to-right scan (module doc — never a
  sequential two-pass replace, which could re-scan already-substituted text
  for the other placeholder). `fetch_value`/`store_value`/`has_value`'s
  `run_has_template` all route through `run_backend_command` (task #74,
  "Bounded backend shell-outs" above) — the ONE place this crate actually
  spawns `sh -c`, bounded by `backend_timeout()`
  (`AOIDE_SECRETS_BACKEND_TIMEOUT`), killing and reaping the child's whole
  process group on a timeout. `fetch_value` trims exactly one trailing
  newline from the returned stdout; `store_value` (P-V4c) pipes `value` to
  the template's OWN stdin (never argv) and discards its stdout. On a
  failing backend (either direction, or a timeout), the returned `Err`
  carries ONLY the exit status (or the timeout message) — the
  command's full stderr is `eprintln!`'d to the broker's own stderr and
  never returned, since the `Err` string rides the wire reply and both
  audit lines' `reason` field; exit 127 (`sh -c`'s universal "command not
  found") from the built-in `age` backend specifically is enriched into
  `missing_age_binary_hint`'s taught error instead (P-G1). Also
  `seed_default_backends`: writes the two built-in backends, `file`
  (P-V4c) and `age` (P-G1, task #70), into `backends.json` when absent,
  never when one already exists — see "Backend presets" above for the
  seeding-site decision. `pass`/`gopass`/`bw`/`sops` are DOC PRESETS
  ("Backend presets" above), not code — this module has no knowledge of
  any specific backend; `file`/`age` are the two backends that ship as
  SEEDED DATA rather than mere documentation, still through the same
  template mechanism. `has_value` (P-67, extended P-G1) is the existence
  probe behind "warn before overwrite" — when a backend carries a `has`
  template it runs THAT and reports its exit status (`run_has_template`);
  otherwise it falls back to its pre-existing `fetch_value(...).is_ok()`
  probe, unchanged from before `has` existed, since a `get` template's own
  contract already IS "exit 0 with the value on stdout when it exists" for
  every backend above. `mint_age_identity_if_needed` (P-G1) is the `age`
  backend's ONE-TIME identity bootstrap — `age-keygen` twice (the key, then
  `-y` for its recipient), both locked to `0600` — real Rust I/O, not a
  template, the same precedent `enroll`'s TOTP-secret generation already
  sets; called ONLY from `broker::put_gate`'s own critical section, never
  from a `get` path (a missing identity there is `missing_age_identity_hint`,
  a taught error, never an auto-mint).
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
  dismiss). `emit_notify` (P-N3) is the one function every notify call site
  routes through — see "Broker notifications" above for the exact shapes
  and the two destinations it writes (the SAME `append_own_log`/
  `aoide_protocol::audit` primitives every `audit_*` function already
  uses); `GateOutcome::Granted` grew a `totp_free: bool` field (set once, in
  `resolve_gate`, from the SAME `totp_required` call that already gated the
  `if`) so `handle_resolve` can tell a TOTP-free grant apart from a
  code-verified one without a second policy load.
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
  ever touched too, see "Admin verbs" above. **`add`'s `--backend` flag is
  now OPTIONAL, defaulting to `age` when omitted (P-G1, task #70, DEFAULT
  FLIP)** — `handle_secrets_add`'s own `DEFAULT_BACKEND` constant; an
  explicit `--backend` still wins, and an ALREADY-recorded policy's
  `backend` field is never touched by this flip, only what a brand-new
  `add` records. `put` (P-V4c) is gated
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
