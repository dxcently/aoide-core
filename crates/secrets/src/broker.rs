//! The broker daemon (`aoide secrets serve`): a unix-socket JSON-lines
//! server, ONE request per line, ONE reply per line — the shellbridge
//! precedent (`aoide_conduct::shellbridge`, read and matched deliberately
//! per the phase brief) for everything EXCEPT the connection model itself.
//!
//! **Connection model: thread-per-connection (P-N2, this commit — CHANGED
//! from a single-threaded serial accept loop).** Before this phase,
//! [`serve`]'s `for conn in listener.incoming()` called [`handle_conn`]
//! INLINE, so one slow/blocked connection stalled every other client
//! queued behind it on `accept(2)`. That was safe only because nothing here
//! ever blocked for long. P-N2 breaks that: a TOTP-gated `resolve` with no
//! code now PARKS (see below) and can legitimately hold its connection open
//! for the FULL park timeout (default 300s, [`crate::park::park_timeout`]).
//! [`serve`] now spawns ONE THREAD PER CONNECTION
//! (`std::thread::spawn(move || handle_conn(...))`), so a parked connection
//! blocks only its own thread — the accept loop keeps admitting new
//! connections, and an unrelated `resolve`/`put`/`pending` on a different
//! connection completes normally while another sits parked. Every failure
//! is still contained per-connection (a malformed line, an unknown op, a
//! dropped connection, even a panic inside one `handle_conn` thread ends
//! only that one connection — never the service, never another connection's
//! own thread); see `park.rs`'s module doc for why the shared
//! [`crate::park::ParkRegistry`] recovers from a poisoned lock rather than
//! propagating a panic across threads.
//!
//! **Thread-per-connection also exposed two read-modify-write sections that
//! the old serial accept loop used to serialize FOR FREE, just by never
//! running two connections' code at the same time (P-N2 review fix, this
//! commit).** [`verify_totp_gate`]'s replay-ledger load -> record -> prune
//! -> save, and [`put_gate`]'s existence-probe -> store, are each now
//! wrapped in their own process-wide [`std::sync::Mutex<()>`]
//! ([`replay_ledger_lock`], [`put_lock`]) held across the FULL critical
//! section — without it, two threads racing the SAME valid TOTP code could
//! both load the ledger before either saved, each `record()` against a
//! private copy, and both succeed (one code redeeming a secret TWICE,
//! breaking the single-use guarantee); symmetrically, two concurrent
//! `overwrite:false` puts could both pass the existence probe before either
//! stored. Both locks recover from a poisoned lock the SAME way
//! [`crate::park::ParkRegistry`]'s does (`park.rs`'s own module doc is the
//! precedent this follows) — `.lock().unwrap_or_else(|e| e.into_inner())`,
//! never a bare `.unwrap()`, so a panic inside one connection's thread can
//! never wedge every other connection's TOTP verification or put. Neither
//! lock introduces caching — the ledger and the backend's own stored value
//! are still read fresh from disk every time; the lock only serializes the
//! section, it never remembers what it read.
//!
//! Wire (`resolve`/`put`/`pending`/`approve`/`dismiss`):
//! ```text
//! -> {"op":"resolve","secret":"<name>","consumer":"<consumer>","totp":"<code>"?,"argv0":"<cmd>"?,"wait":<bool>?}
//! <- {"ok":true,"value":"<value>"}                    (granted — immediately, or after a park completes)
//! <- {"ok":false,"error":"<value-free message>"}      (denied/error/timeout/dismissed)
//!
//! -> {"op":"put","secret":"<name>","value":"<value>","overwrite":<bool>?}
//! <- {"ok":true,"replaced":<bool>}                    (stored — `replaced`
//!                                                       tells whether a
//!                                                       previous value was
//!                                                       clobbered)
//! <- {"ok":false,"exists":true,"error":"<message>"}   (P-67: refused —
//!                                                       `overwrite` was
//!                                                       false/absent and
//!                                                       the secret ALREADY
//!                                                       has a stored value)
//! <- {"ok":false,"error":"<value-free message>"}      (denied/error)
//!
//! -> {"op":"pending"}
//! <- {"ok":true,"pending":[{"id":"<id>","secret":"<name>","consumer":"<consumer>","requestedAt":<unix-seconds>,"peerUid":<uid-or-null>},...]}
//!
//! -> {"op":"approve","id":"<id>","totp":"<code>"}
//! <- {"ok":true}                                      (code valid — the
//!                                                       VALUE releases down
//!                                                       the ORIGINAL parked
//!                                                       connection, never
//!                                                       in this reply)
//! <- {"ok":false,"error":"<value-free message>"}      (unknown id / invalid
//!                                                       or missing code —
//!                                                       the ask STAYS
//!                                                       parked on an
//!                                                       invalid/missing
//!                                                       code)
//!
//! -> {"op":"dismiss","id":"<id>"}
//! <- {"ok":true}                                       (the parked caller
//!                                                       gets a clean
//!                                                       "dismissed" refusal)
//! <- {"ok":false,"error":"unknown pending id `<id>`"}
//! <- {"ok":false,"error":"<peer-uid-mismatch refusal>"} (task #73 — the
//!                                                       dismissing
//!                                                       connection's own
//!                                                       peer uid is
//!                                                       neither the ask's
//!                                                       stamped peer uid
//!                                                       nor the broker's
//!                                                       own; the ask stays
//!                                                       parked, untouched)
//! ```
//! `totp`/`argv0`/`wait` are optional on `resolve`; `overwrite` is optional
//! on `put` — ABSENT MEANS `false` (P-67, wire compatibility: an old client
//! sending no `overwrite` field still gets the tightened "exists" refusal
//! from a new broker on a second `put`, which is the deliberate behavior
//! change this feature makes — see `client.rs`'s module doc for the full
//! wire-compat note). `wait` (P-N2) ABSENT MEANS `true` — a resolve that
//! would otherwise park now DOES park by default; `wait:false` restores the
//! pre-P-N2 immediate `"...no totp code was provided"` refusal, for machine
//! callers that structurally cannot type a code and would rather fail fast
//! (documented in `CONTRACTS.md`'s "Secrets wire" subsection — wire-only,
//! no CLI flag). `consumer` is SELF-ASSERTED
//! (the plan's V1 ruling, `crate::replay`'s module doc): the policy's
//! `consumers[]` list is the real gate, not caller identity. This repo-wide
//! machine-consumer contract (every op, every error string, the
//! group-membership trust model) is ALSO documented in `CONTRACTS.md`'s
//! "Secrets home" section — services (verba voluntia, Melete-side models)
//! are meant to speak this wire directly, no LLM in the loop; `secrets
//! exec`/`secrets put`/`secrets pending`/`secrets approve`/`secrets
//! dismiss` are convenience wrappers over the same ops, not the only door
//! onto them.
//!
//! **Kernel-truth peer identity (task #73, this commit).** The paragraph
//! above is about the wire's `consumer` field, which STAYS self-asserted —
//! #73 does not change that. What it adds is a SEPARATE, orthogonal fact
//! this crate did not have before: `handle_conn` reads `SO_PEERCRED`
//! ([`crate::peercred::peer_cred`]) once, at connection start, and threads
//! it into every op handler on that connection — the connecting process's
//! REAL uid, verified by the kernel, independent of anything the wire
//! request itself claims. A parked ask is stamped with the requesting
//! connection's peer uid at park time (`park::ParkedAsk::peer_uid`'s own
//! doc), shown (additively) in `pending`'s reply, and is the ONE fact
//! [`handle_dismiss`] gates a decision on — see that function's own doc.
//! Every resolve/park/approve/dismiss/put audit line also carries the
//! acting connection's peer uid alongside the pre-existing self-asserted
//! name, for the identical reason: a kernel fact recorded next to a
//! self-asserted one, never conflated with it. A `SO_PEERCRED` read
//! failure is treated as an UNIDENTIFIED connection (`None`) — never a
//! panic, never a fabricated uid; every decision keyed on it fails CLOSED
//! on `None`, not open.
//!
//! **Parking a TOTP-gated resolve (P-N2, this commit).** Today (before this
//! phase) a `resolve` for a `requireTotp`-gated secret with no code was an
//! ordinary denial. Now: [`resolve_gate`] returns [`GateOutcome::NeedsTotp`]
//! for that exact case (enrollment exists, code absent/empty, a code WOULD
//! be checked if present) — [`handle_resolve`] registers a
//! [`crate::park::ParkedAsk`] in the shared [`crate::park::ParkRegistry`]
//! and blocks THIS connection's own thread on [`crate::park::
//! wait_for_outcome`] until one of three things happens:
//! - `secrets approve <id> --totp <code>` ([`handle_approve`]) validates
//!   the code with the SAME [`verify_totp_gate`] a fast-path `resolve`
//!   would use (same RFC 6238 verify, same single-use-per-timestep replay
//!   ledger — a code is consumed identically either way), fetches the value
//!   fresh (`fetch_secret_value`, NEVER cached from park time — the value
//!   is never stored anywhere before this moment, `park.rs`'s module doc),
//!   and sends it down the channel to the parked connection — `approve`'s
//!   OWN reply to the approver never carries the value, only `{"ok":true}`.
//!   An INVALID/expired/already-used/missing code leaves the ask exactly
//!   where it was (`ParkRegistry::peek`, never `take`, on that path) — the
//!   operator can retry.
//! - `secrets dismiss <id>` ([`handle_dismiss`]) resolves the ask with no
//!   code at all — the parked connection gets a clean "dismissed" refusal.
//! - [`crate::park::park_timeout`] elapses first (default 300s,
//!   `AOIDE_SECRETS_PARK_TIMEOUT` to change it) — the parked connection gets
//!   a refusal naming the timeout, the knob, and both completion paths
//!   (inline `--totp` on a fresh resolve, or `secrets approve`); the ask is
//!   removed.
//!
//! Audit gains three new event kinds alongside the unchanged `secrets.
//! resolve`/`secrets.put` ones (module doc's audit section, below): a
//! `secrets.resolve` "parked" line at park time
//! ([`audit_park`]), a `secrets.approve` line per approve attempt
//! ([`audit_approve`]), and a `secrets.dismiss` line per dismiss attempt
//! ([`audit_dismiss`]) — all name-only, same discipline as every other
//! audit line in this module. The ask's EVENTUAL grant/deny (approved,
//! dismissed, or timed out) still fires the pre-existing [`audit_resolve`]
//! exactly as an immediate resolve always has — parking only inserts a
//! wait in the middle, it does not change what gets audited at the end.
//!
//! **An automation-open listed consumer NEVER parks** — `resolve_gate`'s
//! `totp_required` check (P-N1) already routes those straight to
//! [`GateOutcome::Granted`]/`Denied`, before the no-code/park branch is
//! ever reached; nothing about this phase changes that.
//!
//! **`put` carries NO `consumer` field and is never gated by
//! `requireTotp`** (P-V4c, deliberate): `secrets put` is CLI-only
//! (`commands::handle_secrets_put`'s `require_cli` gate) and, in
//! deployment, runs AS THE SECRETS UID's own operator (`sudo -u
//! aoide-secrets aoide secrets put …`, same admin-command precedent as
//! `add`/`grant` — README's "Admin commands" section) — there is no separate
//! "consumer" identity to authorize the way `resolve`'s agent-facing
//! callers need, and a code check would be gating the secrets uid against
//! itself. [`put_gate`] therefore checks ONLY that a policy exists for the
//! named secret (`put` never auto-creates one — `secrets add` owns policy
//! creation, same as before P-V4c) and that its backend has a `set`
//! template; it never touches `policy.require_totp` or `verify_totp_gate`
//! at all.
//!
//! **P-67 ("warn before overwrite"): `put_gate` also probes existence
//! BEFORE storing.** When the wire's `overwrite` field is false/absent AND
//! `crate::backend::has_value` reports the secret already has a value, the
//! gate refuses with the DISTINCT `{"exists":true}` reply above — a
//! machine-readable flag, never a string a caller would have to pattern-
//! match out of `error`'s prose — and the backend's `set` template never
//! runs. The existence probe happens BROKER-SIDE only: the client never
//! fetches a value to check this (that would violate the release-to-client
//! discipline for an op that isn't even `resolve`), and a client-side file
//! peek is impossible anyway — the client doesn't run as the secrets uid.
//! `has_value` is just `fetch_value(...).is_ok()` (`backend.rs`'s own
//! doc) — running the `get` template broker-side is fine here because,
//! same as every other backend call in this module, the value never
//! leaves this process.
//!
//! **The automation gate (P-N1) can only ever RELAX `requireTotp`, never
//! tighten it.** [`resolve_gate`]'s TOTP branch is gated by
//! `crate::policy::totp_required(policy, consumer)`, not `policy.
//! require_totp` directly — that function's own doc has the full decision
//! table; the short version is: a policy's automation is OPEN
//! (`automation.enabled`) and `consumer` is one of the names LISTED in
//! `automation.consumers` skips the code entirely for THAT consumer, every
//! other caller (automation closed, or open but unlisted) is gated exactly
//! as before this field existed. Gate order: exists ->
//! consumers-authorization -> remote-origin (below) -> `totp_required` ->
//! fetch.
//!
//! **The origin gate (LANE IDENTITY P-ID4) — the first real consumer of
//! the sealed session credential.** After exists/consumers and BEFORE the
//! TOTP/automation branch, [`resolve_gate`] checks the CALLER's attested
//! provenance: [`handle_resolve`] resolves the connection's kernel-truth
//! `SO_PEERCRED` pid through `aoide_storage::attest::attested_caller`
//! (real `/proc` ancestry -> sealed session -> seal verified against the
//! daemon's LIVE `ping`-fetched public key, fresh-starttime pid-reuse
//! defense included — never anything the wire asserts) and hands the
//! result in as a parameter, clock-discipline style. A caller whose sealed
//! session is REMOTE-ORIGIN (`originClass` `peer:*` — a session a remote
//! peer created) is refused unless the secret's `allowRemoteOrigin` policy
//! bit (default OFF, `secrets allow-remote-origin <name> on` to opt in) is
//! set; the refusal ([`denied_remote_origin_message`]) names the flag, the
//! session, and its origin. Sitting BEFORE the TOTP branch means a refused
//! remote-origin caller never parks and never reaches approve — no
//! re-check needed on the approve path. **The boundary, exactly:** this
//! gate NARROWS positively-attested remote-origin sessions; it does not
//! authenticate local ones. An UNIDENTIFIED caller (no sealed session in
//! its ancestry, an unreachable daemon, an unreadable roster — and, in the
//! packaged cross-uid deployment where the broker runs as the
//! `aoide-secrets` system user, EVERY caller, since the operator's daemon
//! socket and `sessions.json` are both unreachable cross-uid) is NOT
//! refused by this gate: same-uid honesty (OQ1-A) means local unidentified
//! callers were always admitted, and refusing them here would break every
//! legitimate non-session caller while stopping no same-uid attacker (who
//! could always detach from its ancestry). `consumer` therefore STAYS
//! self-asserted — consumer-name authentication is a separate, unbuilt
//! axis — and the three policy axes stay distinct: `remote` (may this
//! secret be served through a NON-LOCAL entry point), `automation` (may a
//! listed consumer skip TOTP), `allowRemoteOrigin` (may a session a REMOTE
//! PEER created resolve this secret locally).
//!
//! **`requireTotp` is wired live (P-V3).** [`resolve_gate`] rejects it
//! outright ONLY when no `secrets enroll` has ever run on this host
//! (`crate::store::load_totp_secret` returns `None`) — a clear "no TOTP
//! enrollment" error, same wording as before P-V3. Once enrolled, a
//! `requireTotp` policy verifies the wire's `totp` code against the
//! enrolled secret (`crate::totp::verify`, `±1`-timestep window) and
//! consumes the matched timestep in a [`crate::replay::ReplayLedger`]
//! persisted via `crate::store::load_replay_ledger`/`save_replay_ledger`
//! (this crate's `AGENTS.md` ruling: keyed on timestep ALONE, never
//! consumer) — a missing/wrong/already-used code is a denial, exactly
//! like every other gate failure below: the backend never runs, both
//! audit lines fire with a value-free (and CODE-free — the typed code is
//! untrusted input, never echoed) reason. The ledger is reloaded fresh
//! from disk on every TOTP-gated attempt rather than cached across
//! connections (no in-memory broker state at all, matching how policies
//! are already handled) — which is also what makes "a broker restart must
//! not resurrect a spent code" true for free: the very next resolve after
//! a restart re-reads the same file.
//!
//! `resolve_gate`'s clock is a PARAMETER (`now_unix`), not a `SystemTime::
//! now()` call inside it — [`handle_resolve`] and [`handle_approve`] (P-N2)
//! are the two places in this module that read the real clock
//! (`aoide_protocol::audit::now_secs()`) and hand it in, so `resolve_gate`/
//! `verify_totp_gate` stay exactly as deterministically testable as
//! `crate::totp`/`crate::replay` themselves (this crate's `AGENTS.md`,
//! "clock-as-parameter, everywhere" — the broker is where the real-clock
//! wrapper is allowed to live, and these are those two wrappers).
//!
//! **Audit, broker-side only** (this crate's `AGENTS.md`): every resolve
//! attempt is logged HERE — never by the client, which only ever learns
//! granted/denied from the wire reply — to TWO places: the broker's own
//! append-only log in secrets home (`audit.log`, hand-built
//! `serde_json::Value` via the `json!` macro, never a named
//! `#[derive(Serialize)]` struct with a reusable field a value could land
//! on) and the mirrored aoide audit log via `aoide_protocol::audit` with
//! `EventClass::Secret`. Both carry secret name + consumer + argv0 (if the
//! client sent one) + granted/denied + a value-free reason — NEVER the
//! value, which exists only as this module's own local `String` between
//! the backend fetch and the `{"ok":true,"value":...}` line write (or, on a
//! park, between `fetch_secret_value`'s return inside [`handle_approve`]
//! and the `ParkOutcome::Approved` send — still never persisted, `park.rs`'s
//! module doc). [`audit_park`]/[`audit_approve`]/[`audit_dismiss`] (P-N2)
//! follow the identical two-destination, name-only shape.
//!
//! **The socket is chmod'd to `0660` immediately after bind** (P-V4,
//! deployment). `UnixListener::bind` alone honors the process umask, so
//! the socket's mode is whatever the ambient umask happens to yield —
//! under the common `022` that's `0755`, which (since `connect(2)` on an
//! `AF_UNIX` socket requires WRITE permission) is actually unreachable for
//! the intended access GROUP, while under a loose umask (`002`/`000`, a
//! hand-run non-nix box) it drifts toward group- or world-connectable —
//! and the wire's `consumer` field is SELF-ASSERTED (this module's own
//! doc, above), so an over-open socket means any local user could resolve
//! any standing-grant secret. The explicit chmod replaces that
//! umask-dependent lottery with the one deliberate mode either way.
//! `0660` (owner + group rw, no other bits) is the
//! DESIGN, not a tightened-as-far-as-possible default: the socket is
//! deliberately GROUP-connectable, not owner-only, because the whole point
//! is that ordinary operator-uid agents (members of the access group) can
//! reach it. [`bind_socket`] sets only the MODE bits (`0o660` literal, the
//! group-connectable design point — contrast [`crate::home::secure_file`]'s
//! `0o600`, which is the wrong mode HERE on purpose). Group OWNERSHIP —
//! making the socket's gid the real `aoide-secrets-access` group — is
//! deployment's job, not this crate's: P-V4's nix module sets the
//! `aoide-secrets-serve` unit's `Group=aoide-secrets-access`, so every file the
//! broker process creates (including this socket) inherits that gid from
//! the process's own primary/effective group. This module only ever touches
//! the mode bits.

use crate::park::{AskOrigin, ParkOutcome, ParkRegistry, WaitResult};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Bind `socket_path`: create its parent dir if absent, remove a stale
/// socket file first (single-owner path per host, same precedent as
/// `shellbridge::run`), bind, then chmod the socket file to `0660`
/// (module doc — group-connectable is the DESIGN, group OWNERSHIP is
/// deployment's job). Split out of [`serve`] so a test can exercise the
/// bind-and-secure step directly without entering the forever-loop accept
/// body.
fn bind_socket(socket_path: &Path) -> std::io::Result<UnixListener> {
    if let Some(parent) = socket_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

/// Bind `socket_path` and serve `resolve`/`put`/`pending`/`approve`/
/// `dismiss` requests forever. Creates `secrets_home` if absent and locks
/// it down to `0700` (bounce-fix item 3, P-V2 review — `create_dir_all`
/// alone honors the process umask, which would leave `policy.json`/
/// `backends.json` world-readable). **Seeds `backends.json` with the
/// built-in `file` backend when absent** (P-V4c, `crate::backend::
/// seed_default_backends`) — this is the ONE seeding site (decision
/// recorded here, not duplicated at `secrets add`/`secrets put`): `serve`
/// is the single long-running process that ever actually resolves a
/// backend name against a `get`/`set` template (both the CLI's `secrets
/// exec` and the new `secrets put` reach a backend only by round-tripping
/// through THIS process over the socket), so seeding here guarantees every
/// such attempt sees a `backends.json` on disk without a second seed call
/// anywhere else. A seeding failure is logged and NON-fatal — an existing
/// or hand-authored `backends.json` (or none at all, for a host that only
/// ever uses non-`file` backends) is still a perfectly servable broker.
/// **Immediately after, backfills any built-in the file is MISSING** (P-G2,
/// task #72, `crate::backend::backfill_missing_backends`) — additive only,
/// never touching an entry (built-in or custom) already present by name;
/// this is what closes the deployment gap a pre-P-G1 `backends.json` (or a
/// hand-edited one predating `has`) would otherwise leave open forever,
/// same non-fatal-failure posture as seeding. Only returns on a bind/
/// permission failure — a running broker never returns `Ok`.
///
/// **ONE [`ParkRegistry`] for the whole broker's lifetime** (P-N2),
/// wrapped in an `Arc` and cloned into every spawned connection thread
/// (module doc's thread-per-connection change) — every connection must
/// share the SAME registry, since an `approve`/`dismiss`/`pending` arriving
/// on one connection has to see (and resolve) an ask parked by a totally
/// different connection.
pub fn serve(secrets_home: &Path, socket_path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(secrets_home)?;
    crate::home::secure_dir(secrets_home)?;
    if let Err(e) = crate::backend::seed_default_backends(secrets_home) {
        eprintln!("[aoide/secrets] could not seed the default `file`/`age` backends into backends.json: {e}");
    }
    // P-G2 (task #72): the additive sibling of the seeding call above — an
    // EXISTING `backends.json` (the far more common live case) gains
    // whichever built-in entry it's missing, by name, never touching an
    // entry — built-in or custom — that's already there. A no-op on a
    // fresh home (seeding just created both) and on an already-complete
    // file (no write at all — `backend::backfill_missing_backends`'s own
    // doc). Non-fatal, same posture as the seeding call it follows.
    if let Err(e) = crate::backend::backfill_missing_backends(secrets_home) {
        eprintln!("[aoide/secrets] could not backfill missing built-in backends into backends.json: {e}");
    }
    let listener = bind_socket(socket_path)?;

    let home = secrets_home.to_path_buf();
    // P-G4 (task #77): resolved ONCE here, from the ALREADY-resolved
    // `socket_path` parameter — never re-derived per connection, same
    // "resolve once, pass as parameter" discipline `home`/`parked` already
    // follow in this loop (`AGENTS.md`).
    let events_path = crate::socket::events_path(socket_path);
    let parked = Arc::new(ParkRegistry::new());
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let home = home.clone();
                let events_path = events_path.clone();
                let parked = Arc::clone(&parked);
                // FIX 3a (P-N2c, deploy blocker): `std::thread::spawn`
                // PANICS if the OS refuses to create a thread (e.g. the
                // process is already at its thread/fd limit) — that panic
                // would unwind straight out of this accept loop, killing
                // `serve` itself, which systemd would then restart into
                // the SAME resource exhaustion until `StartLimitBurst`
                // gives up and the unit goes `failed` PERMANENTLY. Use the
                // fallible `Builder::spawn` and, on `Err`, drop just this
                // one connection (log + `continue`) — the broker keeps
                // accepting everyone else, same "one connection's failure
                // never touches another's" discipline this module doc
                // already holds for every other per-connection failure.
                if let Err(e) = std::thread::Builder::new()
                    .spawn(move || handle_conn(&home, &events_path, stream, &parked))
                {
                    eprintln!("[aoide/secrets] could not spawn a connection thread (dropping this connection): {e}");
                }
            }
            Err(e) => {
                eprintln!("[aoide/secrets] accept error (continuing): {e}");
                // FIX 3c: a short backoff before retrying — without it, an
                // fd-exhaustion condition (EMFILE) that keeps `accept(2)`
                // failing immediately turns this loop into a tight busy
                // spin, burning a full CPU core while making the
                // exhaustion strictly worse (this loop's own fds count
                // against the same limit). 250ms is short enough that a
                // transient, immediately-recovering error costs nothing a
                // human would notice, and long enough to stop the spin.
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
        }
    }
    Ok(())
}

/// Handle ONE client connection, on its OWN thread (module doc, P-N2): read
/// newline-delimited JSON requests and reply to each. A read error (dropped
/// connection) ends only this connection; nothing here can unwind into
/// `serve`'s accept loop OR into any other connection's own thread. A
/// `resolve` that parks (`handle_resolve`) blocks THIS thread only, for as
/// long as `crate::park::park_timeout()` allows — every other connection's
/// `handle_conn` thread is unaffected.
fn handle_conn(secrets_home: &Path, events_path: &Path, stream: UnixStream, parked: &ParkRegistry) {
    // #73: read SO_PEERCRED ONCE, at connection start, and thread the same
    // value into every op this connection sends — never re-read per line
    // (the peer identity of an already-accepted connection cannot change
    // mid-stream, and re-reading would just be wasted syscalls). `None`
    // when the read fails (`peercred::peer_cred`'s own "unidentified, never
    // a panic" contract) — every handler below already treats an absent
    // peer uid as "cannot be authorized," never as "trust it."
    let peer = crate::peercred::peer_cred(&stream);
    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("[aoide/secrets] could not clone connection: {e}");
            return;
        }
    };
    let reader = BufReader::new(stream);
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let reply = handle_line(secrets_home, events_path, &line, parked, &mut writer, peer);
        if write_json_line(&mut writer, &reply).is_err() {
            break;
        }
    }
}

/// Write ONE JSON value as a newline-terminated wire line — the ONE place
/// this crate formats a reply/interim line for the socket (module doc's
/// framing contract), shared by [`handle_conn`]'s own final-reply write and
/// [`handle_resolve`]'s interim-line write (P-N2c) so both stay byte-for-
/// byte the same shape.
fn write_json_line(writer: &mut impl Write, value: &Value) -> std::io::Result<()> {
    let mut out = value.to_string();
    out.push('\n');
    writer.write_all(out.as_bytes())
}

/// Parse and dispatch ONE wire line. Pure with respect to the wire framing
/// (all I/O — policy load, backend fetch, audit, parking — happens inside
/// the individual `handle_*` functions) EXCEPT for `interim_out`
/// (P-N2c): [`handle_resolve`] is the only handler that ever writes through
/// it, to send the interim `{"interim":true,"parked":true,...}` line the
/// INSTANT an ask parks (module doc's "framing contract" — the whole reason
/// this parameter exists: without it, `secrets exec` hangs for up to the
/// full park timeout with zero indication whether it parked or the broker
/// wedged). Every other handler ignores it entirely. Malformed JSON or an
/// unknown `op` always gets a FINAL reply line, never a silently dropped
/// connection (unlike shellbridge's fire-and-forget commands, a secrets
/// client is BLOCKED waiting on this reply).
fn handle_line(
    secrets_home: &Path,
    events_path: &Path,
    line: &str,
    parked: &ParkRegistry,
    interim_out: &mut impl Write,
    peer: Option<crate::peercred::PeerCred>,
) -> Value {
    let req: Value = match serde_json::from_str(line.trim()) {
        Ok(v) => v,
        Err(_) => return json!({"ok": false, "error": "malformed request: not valid JSON"}),
    };
    match req.get("op").and_then(Value::as_str) {
        Some("resolve") => handle_resolve(secrets_home, events_path, &req, parked, interim_out, peer),
        Some("put") => handle_put(secrets_home, events_path, &req, peer),
        Some("pending") => handle_pending(parked),
        Some("approve") => handle_approve(secrets_home, events_path, parked, &req, peer),
        Some("dismiss") => handle_dismiss(secrets_home, events_path, parked, &req, peer),
        Some("admin") => handle_admin(secrets_home, &req, peer),
        Some(other) => json!({"ok": false, "error": format!("unknown op `{other}`")}),
        None => json!({"ok": false, "error": "malformed request: missing `op`"}),
    }
}

/// Render a peer uid for a taught error message or an audit line — `None`
/// (an unidentified connection, `peercred::peer_cred`'s own doc) prints as
/// `"unidentified"` rather than a bare blank, so a human reading `audit.log`
/// or a refusal never mistakes it for uid 0 or an omitted field.
fn peer_uid_display(peer_uid: Option<u32>) -> String {
    peer_uid.map(|u| u.to_string()).unwrap_or_else(|| "unidentified".to_string())
}

/// Capture a parking ask's [`AskOrigin`] — ONCE, right here, at the SAME
/// park-time instant `peer_uid` itself is stamped (`AskOrigin`'s own doc on
/// why this can never be deferred to render time: the pid can exit and be
/// reused). An unidentified connection (`peer: None`, `peercred::peer_cred`
/// itself already failed) still gets a hostname — this broker's own host is
/// knowable regardless of who's asking — but no username/pid/comm, since
/// there is no kernel-truth pid to read either from.
fn capture_origin(peer: Option<crate::peercred::PeerCred>) -> AskOrigin {
    AskOrigin {
        username: peer.and_then(|p| crate::peercred::username_for_uid(p.uid)),
        pid: peer.map(|p| p.pid),
        comm: peer.and_then(|p| crate::peercred::read_comm(p.pid)),
        hostname: Some(crate::enroll::local_hostname()),
    }
}

/// The ONE place an [`AskOrigin`] is rendered onto the wire (the `parked`
/// events-feed line, `pending`'s reply, `audit_park`'s own record) —
/// `null` per field when unknown, the SAME "always present, null when
/// absent" shape `peerUid`/`reason` already hold, so a caller need not
/// special-case "field absent" vs "field null."
fn origin_to_json(origin: &AskOrigin) -> Value {
    json!({
        "username": origin.username,
        "pid": origin.pid,
        "comm": origin.comm,
        "hostname": origin.hostname,
    })
}

/// `resolve` — the fast path is UNCHANGED (module doc): a code present, or
/// no TOTP gate at all, resolves/denies immediately exactly as before P-N2.
/// The new branch is [`GateOutcome::NeedsTotp`]: `wait` (default `true`,
/// module doc) parks the connection via [`ParkRegistry::park`]/
/// [`crate::park::wait_for_outcome`]; `wait:false` restores the pre-P-N2
/// immediate refusal. **P-N2c:** the instant a park is registered, an
/// INTERIM line (`{"interim":true,"parked":true,"id":...,"timeoutSecs":...}`)
/// writes down `interim_out` BEFORE this function blocks on
/// `wait_for_outcome` — a write failure here (the caller already hung up)
/// is swallowed, not propagated: the park proceeds regardless, since a
/// gone caller learning its own id is moot but the ask itself is still a
/// legitimate parked state an operator could dismiss.
fn handle_resolve(
    secrets_home: &Path,
    events_path: &Path,
    req: &Value,
    parked: &ParkRegistry,
    interim_out: &mut impl Write,
    peer: Option<crate::peercred::PeerCred>,
) -> Value {
    let secret = req.get("secret").and_then(Value::as_str).unwrap_or("").to_string();
    let consumer = req.get("consumer").and_then(Value::as_str).unwrap_or("").to_string();
    let argv0 = req.get("argv0").and_then(Value::as_str).map(str::to_string);
    let totp = req.get("totp").and_then(Value::as_str).map(str::to_string);
    let wait = req.get("wait").and_then(Value::as_bool).unwrap_or(true);
    let peer_uid = peer.map(|p| p.uid);
    // Optional, self-asserted, DISPLAY-ONLY context for why this ask exists
    // — named `ask_reason` (not `reason`) purely to avoid shadowing this
    // function's own many `reason` locals (the DENIAL text each `Denied`/
    // `WaitResult` arm below builds) — never gates anything, only ever rides
    // into the park registry / `pending` reply / `parked` event for a
    // surface to show a human (`park::ParkedAsk::reason`'s own doc).
    let ask_reason = req.get("reason").and_then(Value::as_str).map(str::to_string);

    if secret.is_empty() || consumer.is_empty() {
        return json!({"ok": false, "error": "malformed request: `secret` and `consumer` are required"});
    }

    // The one real-clock read in this function — see module doc. The
    // caller's attested origin is resolved here too, once per resolve
    // (LANE IDENTITY P-ID4) — like the clock, an impure read taken at the
    // edge and handed into the deterministic gate as a parameter.
    let now_unix = aoide_protocol::audit::now_secs();
    let caller = attested_caller_origin(peer);
    match resolve_gate(
        secrets_home,
        &secret,
        &consumer,
        totp.as_deref(),
        now_unix,
        caller.as_ref().map(|(s, o)| (s.as_str(), o.as_str())),
    ) {
        GateOutcome::Granted { value, totp_free } => {
            audit_resolve(secrets_home, &secret, &consumer, argv0.as_deref(), true, None, peer_uid);
            // P-N3: notify only the TOTP-free grant (`requireTotp:false`, or
            // an automation-skip) — a resolve that validated its own inline
            // `--totp` code needs no desktop notice, the caller just typed
            // it themselves. Fired AFTER `audit_resolve` (no lock held by
            // either call) — see `emit_notify`'s own doc.
            if totp_free {
                emit_notify(
                    secrets_home,
                    events_path,
                    "released",
                    json!({"event": "released", "secret": secret, "consumer": consumer}),
                );
            }
            json!({"ok": true, "value": value})
        }
        GateOutcome::Denied(reason) => {
            audit_resolve(secrets_home, &secret, &consumer, argv0.as_deref(), false, Some(&reason), peer_uid);
            json!({"ok": false, "error": reason})
        }
        GateOutcome::NeedsTotp => {
            if !wait {
                let reason = "requireTotp is set but no totp code was provided".to_string();
                audit_resolve(secrets_home, &secret, &consumer, argv0.as_deref(), false, Some(&reason), peer_uid);
                return json!({"ok": false, "error": reason});
            }
            let cap = crate::park::park_cap();
            // #73: the requesting connection's own kernel-truth peer uid is
            // stamped onto the ask right here, at park time — the ONE fact
            // `handle_dismiss` later checks a dismisser's own peer uid
            // against (`park::ParkedAsk::peer_uid`'s own doc).
            // Captured NOW, once, never re-read later (`AskOrigin`'s own
            // doc: the pid can exit and be reused long before this ask
            // resolves or a dialog renders it).
            let origin = capture_origin(peer);
            let Some((id, rx)) =
                parked.park_if_room(&secret, &consumer, now_unix, cap, peer_uid, ask_reason.as_deref(), origin.clone())
            else {
                // FIX 3b: at the registry-wide cap — the SAME immediate
                // refusal `wait:false` gives, plus a hint naming the
                // cap/knob, rather than growing an unbounded thread queue
                // (module doc's "read-modify-write... never block" is
                // about connections, not about this being unbounded).
                let reason = format!(
                    "requireTotp is set but no totp code was provided, and the pending-ask queue is full \
                     ({cap} parked already — {} to raise it); retry with an inline `--totp <code>`, or once \
                     an operator clears a pending ask",
                    crate::park::PARK_CAP_ENV
                );
                audit_resolve(secrets_home, &secret, &consumer, argv0.as_deref(), false, Some(&reason), peer_uid);
                return json!({"ok": false, "error": reason});
            };
            audit_park(secrets_home, &id, &secret, &consumer, peer_uid, ask_reason.as_deref(), &origin);
            let timeout = crate::park::park_timeout();
            // P-N3: the popup's future trigger — fired once per park, right
            // alongside `audit_park`, no lock held (`park_if_room` already
            // returned). `reason` (additive) rides straight from the wire's
            // own optional field into this event, unmodified — the ONE
            // place a caller-supplied ask reason enters the events feed a
            // popup/tty surface later reads (`ParkedAsk::reason`'s own doc).
            emit_notify(
                secrets_home,
                events_path,
                "parked",
                json!({
                    "event": "parked",
                    "id": id,
                    "secret": secret,
                    "consumer": consumer,
                    "timeoutSecs": timeout.as_secs(),
                    "reason": ask_reason,
                    "origin": origin_to_json(&origin),
                }),
            );
            // P-N2c FIX 1: announce the park BEFORE blocking — a write
            // failure here (the caller already hung up) is swallowed, not
            // propagated (this function's own doc): the ask stays
            // legitimately parked either way.
            let interim = json!({"interim": true, "parked": true, "id": id, "timeoutSecs": timeout.as_secs()});
            let _ = write_json_line(interim_out, &interim);
            match crate::park::wait_for_outcome(parked, &id, rx, timeout) {
                WaitResult::Approved(value) => {
                    audit_resolve(secrets_home, &secret, &consumer, argv0.as_deref(), true, None, peer_uid);
                    json!({"ok": true, "value": value})
                }
                WaitResult::Denied(reason) => {
                    audit_resolve(secrets_home, &secret, &consumer, argv0.as_deref(), false, Some(&reason), peer_uid);
                    json!({"ok": false, "error": reason})
                }
                WaitResult::Dismissed => {
                    // FIX small-honesty: no actor claim — ANY group member
                    // holding a valid socket connection can dismiss, not
                    // necessarily "an operator" in any privileged sense.
                    let reason = "the pending TOTP ask was dismissed before a code was provided".to_string();
                    audit_resolve(secrets_home, &secret, &consumer, argv0.as_deref(), false, Some(&reason), peer_uid);
                    json!({"ok": false, "error": reason})
                }
                WaitResult::TimedOut => {
                    let reason = park_timeout_message(&secret, timeout.as_secs());
                    audit_resolve(secrets_home, &secret, &consumer, argv0.as_deref(), false, Some(&reason), peer_uid);
                    emit_notify(
                        secrets_home,
                        events_path,
                        "expired",
                        json!({"event": "expired", "id": id, "secret": secret, "consumer": consumer}),
                    );
                    json!({"ok": false, "error": reason})
                }
            }
        }
    }
}

/// The timeout refusal's exact wording — a pure function so it's testable
/// without actually waiting out a real timeout (task requirement: name the
/// timeout, the knob, and BOTH completion paths). Deliberately does NOT
/// name the now-removed ask's id: by the time this fires the id is already
/// gone from the registry, and `secrets approve <that-id>` would just get
/// "unknown pending id" — a stale id would mislead, not help.
fn park_timeout_message(secret: &str, timeout_secs: u64) -> String {
    format!(
        "the pending TOTP ask for `{secret}` timed out after {timeout_secs}s ({} to change the default) — \
         resolve again with an inline `--totp <code>`, or approve the next ask before it expires with \
         `aoide secrets approve <id> --totp <code>`",
        crate::park::PARK_TIMEOUT_ENV
    )
}

/// `pending` (P-N2) — list every parked ask. Never carries a value (module
/// doc); never errors (an empty queue is `{"ok":true,"pending":[]}`, same
/// tolerant shape `graph pending list` already holds). Not audited — a mere
/// read of in-memory state, same precedent `graph pending list` sets (that
/// command doesn't audit either). **`peerUid` (task #73) is an ADDITIVE
/// field over the pre-#73 wire shape** — the kernel-truth `SO_PEERCRED` uid
/// stamped on each ask at park time (`null` when it couldn't be read),
/// alongside the pre-existing self-asserted `consumer` name — an old client
/// that doesn't know this field simply ignores it, per this crate's own
/// wire-compatibility discipline (`AGENTS.md`).
fn handle_pending(parked: &ParkRegistry) -> Value {
    let pending: Vec<Value> = parked
        .list()
        .into_iter()
        .map(|(id, secret, consumer, requested_at, peer_uid, reason, origin)| {
            json!({
                "id": id,
                "secret": secret,
                "consumer": consumer,
                "requestedAt": requested_at,
                "peerUid": peer_uid,
                // Additive over the pre-this-phase shape (`peerUid`'s own
                // precedent, task #73) — `null` per field when unknown.
                "reason": reason,
                "origin": origin_to_json(&origin),
            })
        })
        .collect();
    json!({"ok": true, "pending": pending})
}

/// Re-run the `exists` + `consumer authorized` half of the policy gate
/// against the ask's STORED consumer, immediately before a value is ever
/// fetched for release (P-N2c FIX 2 — reviewer-confirmed gap). Before this
/// fix, [`handle_approve`] jumped straight from a validated code to
/// [`fetch_secret_value`], never re-checking authorization — a `secrets
/// revoke`/`secrets rm` issued WHILE an ask sat parked did NOT stop the
/// eventual release (up to the full park timeout's worth of revocation
/// lag), and the same gap would have silently bypassed a future `remote`
/// gate the moment one exists. Mirrors [`resolve_gate`]'s own
/// exists/authorized checks exactly (identical error strings, so a caller
/// sees the same wording whether the fast path or the parked path denied
/// it) but never touches TOTP — the code has already validated by the
/// time this runs.
fn authorize_release(secrets_home: &Path, secret: &str, consumer: &str) -> Result<(), String> {
    let policies = crate::store::load_policies(secrets_home)
        .map_err(|e| crate::home::describe_home_file_error(secrets_home, &crate::store::policy_path(secrets_home), &e))?;
    let policy = policies.iter().find(|p| p.name == secret).ok_or_else(|| "secret not found".to_string())?;
    let authorized = policy.consumers.is_empty() || policy.consumers.iter().any(|c| c == consumer);
    if !authorized {
        return Err("consumer not authorized for this secret".to_string());
    }
    Ok(())
}

/// `approve <id> --totp <code>` (P-N2, re-gated P-N2c): validate the code
/// with the SAME [`verify_totp_gate`] a fast-path `resolve` uses (same RFC
/// 6238 verify, same single-use replay ledger — the code is consumed
/// identically either way), re-run [`authorize_release`] against the ask's
/// STORED consumer, then fetch the value fresh and release it down the
/// ORIGINAL parked connection. This function's OWN reply to the approver
/// never carries the value — only `{"ok":true}` or a value-free
/// `{"ok":false,"error":...}`.
///
/// **Two-step lookup, deliberately** (module doc): [`ParkRegistry::peek`]
/// first (read-only) so an INVALID/expired/already-used/missing code
/// leaves the ask exactly where it was — [`ParkRegistry::take`] only
/// happens AFTER a code has already validated (and been consumed by the
/// replay ledger), at which point the ask must be resolved one way or
/// another (approved, or denied — a policy removed/revoked while parked,
/// module doc on [`authorize_release`], or the rare case where the value
/// can no longer be fetched at all); it can never be left parked past that
/// point, since the code that would be needed to try again has already
/// been spent. **The code is burned either way, honestly documented**: a
/// revoked-but-still-parked ask still consumes the approver's code even
/// though the release is then denied — the code validated the APPROVER'S
/// identity/possession, which is a real event regardless of what the
/// re-gate decides next; it is not un-spent just because authorization
/// changed underneath it a moment later.
fn handle_approve(
    secrets_home: &Path,
    events_path: &Path,
    parked: &ParkRegistry,
    req: &Value,
    peer: Option<crate::peercred::PeerCred>,
) -> Value {
    let approver_uid = peer.map(|p| p.uid);
    let id = req.get("id").and_then(Value::as_str).unwrap_or("").to_string();
    if id.is_empty() {
        return json!({"ok": false, "error": "malformed request: `id` is required"});
    }
    let Some((secret, consumer, _ask_peer_uid)) = parked.peek(&id) else {
        let reason = format!("unknown pending id `{id}`");
        audit_approve(secrets_home, &id, None, false, &reason, approver_uid);
        return json!({"ok": false, "error": reason});
    };

    let totp = req.get("totp").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty());
    let Some(code) = totp else {
        let reason = "malformed request: `totp` is required".to_string();
        audit_approve(secrets_home, &id, Some(&secret), false, &reason, approver_uid);
        return json!({"ok": false, "error": reason});
    };

    // The one real-clock read in this function — see module doc.
    let now_unix = aoide_protocol::audit::now_secs();
    if let Err(e) = verify_totp_gate(secrets_home, Some(code), now_unix) {
        // Invalid/expired/already-used code: the ask STAYS parked (task
        // requirement) — never `take`n on this path.
        audit_approve(secrets_home, &id, Some(&secret), false, &e, approver_uid);
        return json!({"ok": false, "error": e});
    }

    // The code is now valid AND consumed — the ask must resolve one way or
    // another from here, never stay parked.
    let Some(ask) = parked.take(&id) else {
        let reason = format!("pending ask `{id}` no longer exists (it may have timed out or been dismissed)");
        audit_approve(secrets_home, &id, Some(&secret), false, &reason, approver_uid);
        return json!({"ok": false, "error": reason});
    };

    // FIX 2: re-gate authorization against the ask's STORED consumer
    // BEFORE ever fetching a value — a revocation while parked must stop
    // the release, not just a future one.
    if let Err(e) = authorize_release(secrets_home, &secret, &consumer) {
        ask.send(ParkOutcome::Denied(e.clone()));
        audit_approve(secrets_home, &id, Some(&secret), false, &e, approver_uid);
        return json!({"ok": false, "error": e});
    }

    match fetch_secret_value(secrets_home, &secret) {
        Ok(value) => {
            ask.send(ParkOutcome::Approved(value));
            audit_approve(secrets_home, &id, Some(&secret), true, "", approver_uid);
            // P-N3: fired once, on the approver's own side — the ORIGINAL
            // parked caller's `resolve` return (`WaitResult::Approved` in
            // `handle_resolve`) does not fire a second one for the same
            // lifecycle event.
            emit_notify(
                secrets_home,
                events_path,
                "completed",
                json!({"event": "completed", "id": id, "secret": secret, "consumer": consumer}),
            );
            json!({"ok": true})
        }
        Err(e) => {
            ask.send(ParkOutcome::Denied(e.clone()));
            audit_approve(secrets_home, &id, Some(&secret), false, &e, approver_uid);
            json!({"ok": false, "error": e})
        }
    }
}

/// Fetch `secret`'s value fresh through its policy's backend — the SAME
/// lookup [`resolve_gate`]'s own granted path performs, reused here rather
/// than duplicated (task requirement: "NEVER store or park a value; the
/// fetch happens only after successful completion"). Never called before a
/// code has already validated.
fn fetch_secret_value(secrets_home: &Path, secret: &str) -> Result<String, String> {
    let policies = crate::store::load_policies(secrets_home)
        .map_err(|e| crate::home::describe_home_file_error(secrets_home, &crate::store::policy_path(secrets_home), &e))?;
    let policy = policies.iter().find(|p| p.name == secret).ok_or_else(|| "secret not found".to_string())?;
    crate::backend::fetch_value(secrets_home, &policy.backend, &policy.key)
}

/// **#73: who may `dismiss` a parked ask** — the dismissing connection's own
/// kernel-truth `SO_PEERCRED` uid must match the ask's STAMPED `peer_uid`
/// (from park time, `park::ParkedAsk::peer_uid`'s own doc), OR the broker's
/// own effective uid (`home::effective_uid()` — the operator/admin path:
/// the broker process's own uid can always clear a parked ask, the same
/// "this process's uid decides" precedent `home::admin_identity_check`
/// already holds for the direct-home admin commands). Pure — no I/O, so it's
/// unit-tested directly with injected uids, no real socket/process needed.
///
/// **Fail closed on any missing kernel fact — never fail open.** An
/// UNIDENTIFIED dismisser (`dismisser_uid: None`, `SO_PEERCRED` read
/// failed on the DISMISSING connection) is NEVER authorized, even against
/// an ask whose own `peer_uid` is also `None` — there is nothing to prove a
/// match against, so the safe default is refusal, not a pass. An
/// UNIDENTIFIED ask (`ask_peer_uid: None` — the ORIGINAL `resolve`
/// connection's own peer cred could not be read at park time) can still be
/// dismissed by the broker's own uid (the operator path never depended on
/// matching the ask's uid to begin with), but by no ordinary caller — again,
/// nothing to match.
fn dismiss_authorized(dismisser_uid: Option<u32>, ask_peer_uid: Option<u32>, broker_euid: u32) -> bool {
    match dismisser_uid {
        Some(uid) if uid == broker_euid => true,
        Some(uid) => ask_peer_uid == Some(uid),
        None => false,
    }
}

/// The taught error a refused `dismiss` (task #73) gets — names BOTH uids
/// (task requirement) so an operator immediately sees why the refusal fired
/// rather than having to go correlate `audit.log` by hand.
fn dismiss_refused_message(id: &str, dismisser_uid: Option<u32>, ask_peer_uid: Option<u32>, broker_euid: u32) -> String {
    format!(
        "dismiss `{id}` refused: this connection's peer uid ({}) is neither the ask's own peer uid ({}) nor \
         the broker's own uid ({broker_euid}) — only the original caller or the broker's own operator (uid \
         {broker_euid}) may dismiss it",
        peer_uid_display(dismisser_uid),
        peer_uid_display(ask_peer_uid),
    )
}

/// `dismiss <id>` (P-N2; peer-uid-gated, task #73): resolve a parked ask
/// with no code at all — the parked connection gets a clean "dismissed"
/// refusal, the dismisser gets `{"ok":true}`. An unknown id is a taught
/// error naming it explicitly (task requirement).
///
/// **#73: authorization is checked BEFORE the ask is ever taken off the
/// registry** ([`ParkRegistry::peek`], read-only — the same "peek first,
/// take only once resolved" shape [`handle_approve`] already holds for an
/// invalid code): a REFUSED dismiss leaves the ask exactly where it was,
/// dismissable by its rightful owner or the broker's own operator, rather
/// than being silently consumed by an unauthorized caller's failed attempt.
fn handle_dismiss(
    secrets_home: &Path,
    events_path: &Path,
    parked: &ParkRegistry,
    req: &Value,
    peer: Option<crate::peercred::PeerCred>,
) -> Value {
    let dismisser_uid = peer.map(|p| p.uid);
    let id = req.get("id").and_then(Value::as_str).unwrap_or("").to_string();
    if id.is_empty() {
        return json!({"ok": false, "error": "malformed request: `id` is required"});
    }
    let Some((secret, _consumer, ask_peer_uid)) = parked.peek(&id) else {
        let reason = format!("unknown pending id `{id}`");
        audit_dismiss(secrets_home, &id, "", false, Some(&reason), dismisser_uid);
        return json!({"ok": false, "error": reason});
    };

    let broker_euid = crate::home::effective_uid();
    if !dismiss_authorized(dismisser_uid, ask_peer_uid, broker_euid) {
        let reason = dismiss_refused_message(&id, dismisser_uid, ask_peer_uid, broker_euid);
        // The ask itself is left exactly where it was — never `take`n on
        // this path, same "refused = untouched" shape an invalid `approve`
        // code already holds.
        audit_dismiss(secrets_home, &id, &secret, false, Some(&reason), dismisser_uid);
        return json!({"ok": false, "error": reason});
    }

    match parked.take(&id) {
        Some(ask) => {
            let secret = ask.secret.clone();
            let consumer = ask.consumer.clone();
            ask.send(ParkOutcome::Dismissed);
            audit_dismiss(secrets_home, &id, &secret, true, None, dismisser_uid);
            emit_notify(
                secrets_home,
                events_path,
                "dismissed",
                json!({"event": "dismissed", "id": id, "secret": secret, "consumer": consumer}),
            );
            json!({"ok": true})
        }
        None => {
            // Lost a race against a concurrent approve/dismiss/timeout
            // between the `peek` above and this `take` — the SAME "unknown
            // pending id" shape a never-existed id already gets, since the
            // ask is genuinely gone by now.
            let reason = format!("unknown pending id `{id}`");
            audit_dismiss(secrets_home, &id, "", false, Some(&reason), dismisser_uid);
            json!({"ok": false, "error": reason})
        }
    }
}

/// `put` (P-V4c): stores `value` through the named secret's backend `set`
/// template. No `consumer` field on this op, no TOTP gate — see module doc
/// for why (CLI-only, admin-side). The value exists here ONLY as this
/// function's own local read of `req`'s `value` field, handed straight to
/// [`put_gate`]/`crate::backend::store_value`; it never lands anywhere
/// else in this function (not the returned `Value`, not either audit line
/// — [`audit_put`] is name-only by construction, same as `audit_resolve`).
///
/// **P-67:** also reads `overwrite` (absent/false when missing — wire
/// compat, module doc). [`put_gate`]'s [`PutOutcome`] maps onto three wire
/// shapes: `Granted { replaced }` -> `{"ok":true,"replaced":replaced}`;
/// `DeniedExists` -> `{"ok":false,"exists":true,"error":...}` (the
/// machine-readable refusal); `Denied(reason)` -> the ordinary
/// `{"ok":false,"error":reason}`, unchanged from before this feature.
fn handle_put(secrets_home: &Path, events_path: &Path, req: &Value, peer: Option<crate::peercred::PeerCred>) -> Value {
    let secret = req.get("secret").and_then(Value::as_str).unwrap_or("").to_string();
    let value = req.get("value").and_then(Value::as_str).unwrap_or("").to_string();
    let overwrite = req.get("overwrite").and_then(Value::as_bool).unwrap_or(false);
    let peer_uid = peer.map(|p| p.uid);

    if secret.is_empty() {
        return json!({"ok": false, "error": "malformed request: `secret` is required"});
    }

    let outcome = put_gate(secrets_home, &secret, &value, overwrite);
    let (granted, reply, reason, replaced, minted) = match &outcome {
        PutOutcome::Granted { replaced, minted } => {
            (true, json!({"ok": true, "replaced": replaced}), None, Some(*replaced), *minted)
        }
        PutOutcome::DeniedExists => {
            let msg = format!("secret `{secret}` already has a stored value");
            (false, json!({"ok": false, "error": msg, "exists": true}), Some(msg), None, false)
        }
        PutOutcome::Denied(reason) => {
            (false, json!({"ok": false, "error": reason}), Some(reason.clone()), None, false)
        }
    };
    audit_put(secrets_home, &secret, granted, reason.as_ref(), replaced, peer_uid);
    // P-G1 (task #70): fired AFTER `put_gate` has already returned — its own
    // `put_lock` guard is a local var that dropped when the function
    // returned, so no lock is held here (the SAME "no lock held" rule
    // `emit_notify`'s own doc/AGENTS.md hold for every other call site).
    if minted {
        emit_notify(secrets_home, events_path, "age-identity-minted", json!({"event": "age-identity-minted"}));
    }
    reply
}

/// Task #79's admin-op peer-cred gate: an `{op:"admin"}` request is
/// accepted ONLY when the CONNECTING process's own uid is the broker's own
/// effective uid — reuses [`home::admin_identity_error`]'s exact wording
/// (root's extra "plain `sudo` runs as root" clause included) by treating
/// the peer's uid as that function's "process euid" argument and the
/// broker's own euid as its "home owner" argument, so a refusal here
/// teaches the IDENTICAL fix the direct-write path's
/// [`crate::commands::require_admin_identity`] already teaches — this is
/// deliberately the same identity check aimed at two different processes,
/// never a second wording for it. Root (uid 0) is refused exactly the way
/// [`home::admin_identity_error`] already refuses it — there is nothing
/// admin-op-specific to add. An unidentified connection (`peer_uid` is
/// `None` — the ucred read failed) is refused outright, the SAME
/// fail-closed default [`dismiss_authorized`] holds: there is no uid to
/// compare, so the safe answer is refusal, never a permissive fallback.
fn admin_gate(peer_uid: Option<u32>, secrets_home: &Path, subcommand: &str) -> Option<String> {
    let broker_euid = crate::home::effective_uid();
    match peer_uid {
        Some(uid) => crate::home::admin_identity_error(uid, broker_euid, secrets_home, subcommand),
        None => Some(format!(
            "secrets {subcommand} over the broker socket must come from an IDENTIFIED connection — this connection's \
             peer uid could not be determined (SO_PEERCRED read failed), so it is refused the same way a \
             mismatched uid would be. Run: sudo -u aoide-secrets aoide secrets {subcommand} ..."
        )),
    }
}

/// The `{op:"admin", command:...}` op family (task #79): the live daemon
/// becomes the single writer for `policy.json`/backend-store mutation, with
/// the SAME commands `commands.rs`'s direct-home CRUD quintet always
/// exposed (`add`/`rm`/`grant`/`revoke`/`set-totp`/`automate`/`expose`/
/// `allow-remote-origin`/`migrate`) — this function is the ONE place any of
/// them executes over
/// the socket, gated by [`admin_gate`] before a single byte of `policy.json`
/// is touched, and run inside [`put_lock`]'s critical section (the SAME
/// lock a `put` already serializes under — one process, one writer, one
/// lock guarding every read-modify-write this crate makes) so a `secrets
/// add` racing a live `secrets put` against the same secret can no longer
/// interleave (`AGENTS.md`'s pre-#79 KNOWN LIMITATION, closed by this
/// function for the daemon-running case — see that file's rewritten
/// section for what remains open: no daemon + two concurrent direct-write
/// admin processes, since THAT case never reaches this function at all).
/// Every command's actual mutation lives in [`crate::admin`], never
/// duplicated here — this function only parses the wire's typed fields
/// into that module's typed arguments and shapes the reply; argument
/// VALIDATION (name shape, `on`/`off` spelling) is `commands.rs`'s job on
/// the way IN (a malformed field reaching this function is a client bug,
/// not a human mistyping a terminal command), so an admin op with a
/// missing/malformed field gets a plain domain error from [`crate::admin`],
/// never a second usage-error vocabulary grown here.
fn handle_admin(secrets_home: &Path, req: &Value, peer: Option<crate::peercred::PeerCred>) -> Value {
    let peer_uid = peer.map(|p| p.uid);
    let Some(subcommand) = req.get("command").and_then(Value::as_str) else {
        return json!({"ok": false, "error": "malformed request: `command` is required"});
    };
    if let Some(reason) = admin_gate(peer_uid, secrets_home, subcommand) {
        audit_admin(secrets_home, subcommand, "", false, Some(&reason), peer_uid);
        return json!({"ok": false, "error": reason});
    }

    let str_field = |k: &str| req.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let bool_field = |k: &str| req.get(k).and_then(Value::as_bool).unwrap_or(false);
    let strs_field = |k: &str| {
        req.get(k)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect::<Vec<_>>())
            .unwrap_or_default()
    };

    let name = str_field("name");
    let result: Result<crate::admin::AdminOutcome, String> = {
        // `put_lock`'s critical section covers exactly the mutation call —
        // never the audit write that follows (P-N3's "no lock held across
        // I/O" discipline, `audit_put`'s own call shape: `put_gate`
        // acquires+releases internally, `handle_put` audits only after it
        // returns).
        let _guard = put_lock().lock().unwrap_or_else(|e| e.into_inner());
        match subcommand {
            "add" => crate::admin::add(secrets_home, &name, &str_field("backend"), &str_field("key"), bool_field("requireTotp"), strs_field("consumers")),
            "rm" => crate::admin::rm(secrets_home, &name),
            "grant" => crate::admin::grant(secrets_home, &name, &str_field("consumer")),
            "revoke" => crate::admin::revoke(secrets_home, &name, &str_field("consumer")),
            "set-totp" => crate::admin::set_totp(secrets_home, &name, str_field("state") == "on"),
            "expose" => crate::admin::expose(secrets_home, &name, str_field("state") == "on"),
            "allow-remote-origin" => {
                crate::admin::allow_remote_origin(secrets_home, &name, str_field("state") == "on")
            }
            "automate" => match str_field("action").as_str() {
                "on" => crate::admin::automate_toggle(secrets_home, &name, true),
                "off" => crate::admin::automate_toggle(secrets_home, &name, false),
                "grant" => crate::admin::automate_consumer(secrets_home, &name, &str_field("consumer"), true),
                "revoke" => crate::admin::automate_consumer(secrets_home, &name, &str_field("consumer"), false),
                other => Err(format!("malformed request: unknown automate action `{other}`")),
            },
            "migrate" => {
                let target = req.get("target").and_then(Value::as_str).unwrap_or("age").to_string();
                // `audit_admin` below is deliberately command-generic (no
                // structured source-backend field) — the real backend
                // name, when `crate::admin::migrate` knew one, is already
                // folded into `MigrateError`'s own message text.
                crate::admin::migrate(secrets_home, aoide_protocol::Door::Daemon, &name, &target)
                    .map(|(outcome, ..)| outcome)
                    .map_err(|e| e.message)
            }
            other => Err(format!("malformed request: unknown value in the `command` field: `{other}`")),
        }
    };

    match result {
        Ok(outcome) => {
            audit_admin(secrets_home, subcommand, &name, true, None, peer_uid);
            json!({"ok": true, "message": outcome.message, "changed": outcome.changed})
        }
        Err(e) => {
            audit_admin(secrets_home, subcommand, &name, false, Some(&e), peer_uid);
            json!({"ok": false, "error": e})
        }
    }
}

/// Task #79: ONE generic audit line for every `{op:"admin"}` mutation
/// executed over the broker socket — the socket path has no OTHER audit
/// mechanism at all (unlike the CLI direct-write path, which keeps its own
/// pre-existing generic per-command dispatch audit, plus `migrate`'s own
/// richer `commands::audit_migrate` line, both entirely unchanged by this
/// phase), so this is the one place a broker-routed admin mutation is ever
/// recorded. Deliberately command-generic (never a per-command bespoke message
/// the way `commands::audit_migrate`'s `source -> target` detail is) —
/// `name` is empty when a request never got far enough to know one (a
/// missing `command`, an `admin_gate` refusal before any field was read).
fn audit_admin(secrets_home: &Path, subcommand: &str, name: &str, granted: bool, reason: Option<&String>, peer_uid: Option<u32>) {
    let record = json!({
        "ts": aoide_protocol::audit::now_secs(),
        "op": "admin",
        "command": subcommand,
        "name": name,
        "peerUid": peer_uid,
        "granted": granted,
        "reason": reason,
    });
    if let Err(e) = append_own_log(secrets_home, &record) {
        eprintln!("[aoide/secrets] could not write the secrets audit log: {e}");
    }

    let status = if granted { "granted" } else { "denied" };
    let puid = peer_uid_display(peer_uid);
    let message = match reason {
        Some(r) => format!("admin {subcommand} `{name}` (peer uid {puid}): {status} ({r})"),
        None => format!("admin {subcommand} `{name}` (peer uid {puid}): {status}"),
    };
    let _ = aoide_protocol::audit(
        &aoide_protocol::default_audit_log(),
        aoide_protocol::Door::Daemon,
        aoide_protocol::EventClass::Secret,
        &format!("secrets.admin.{subcommand}"),
        status,
        &message,
    );
}

/// Outcome of the `put` policy gate + existence probe + backend store
/// (P-67, "warn before overwrite"): `Denied` is the pre-existing shape
/// (policy/backend problems, unchanged); `DeniedExists` is the NEW
/// machine-readable refusal — `overwrite` was false and
/// `crate::backend::has_value` found the secret already has a stored
/// value; `Granted { replaced, minted }` distinguishes a first-ever store
/// from an overwrite (`replaced`) so the audit line and the client's own
/// success message can say which happened, and (P-G1, task #70) whether
/// THIS put lazily minted a fresh `age` identity (`minted`) so
/// [`handle_put`] knows whether to fire the "age identity minted" notify
/// event.
#[derive(Debug)]
enum PutOutcome {
    Granted { replaced: bool, minted: bool },
    DeniedExists,
    Denied(String),
}

/// Serializes `put_gate`'s existence-probe -> store critical section (P-N2
/// review fix, this commit) — see the module doc's "read-modify-write
/// sections" paragraph for why thread-per-connection made this necessary
/// (it was implicitly serialized for free under the old single-threaded
/// accept loop) and `park::ParkRegistry`'s own module doc for the
/// poisoned-lock-recovery precedent this follows. A SEPARATE lock from
/// [`replay_ledger_lock`] — `put` and `resolve`/`approve` guard different
/// files (a backend's own stored value vs. `totp-replay.json`), so there is
/// no reason for a slow put to block an unrelated TOTP verification or vice
/// versa.
fn put_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    &LOCK
}

/// The `put` policy gate + existence probe + backend store, in one place —
/// mirrors [`resolve_gate`]'s shape. `put` never auto-creates a policy
/// (`secrets add` owns policy creation, module doc) and never checks
/// `requireTotp` (module doc): a missing policy or a backend with no `set`
/// template are both ordinary, value-free denials — the backend is never
/// invoked on either. **P-67:** when `overwrite` is false and
/// `crate::backend::has_value` reports an existing value, the backend's
/// `set` template is never invoked either — the existence probe (a `get`
/// template run) is the only backend call on that path. **P-N2 review
/// fix:** the probe and the store are held under [`put_lock`] for the
/// FULL critical section — two `overwrite:false` puts racing on separate
/// connections must never both pass the probe before either stores (the
/// same newly-exposed TOCTOU shape [`verify_totp_gate`]'s replay ledger
/// had, module doc). The probe itself still reads the backend fresh every
/// time — the lock serializes, it never caches.
///
/// **P-G1 (task #70): a `policy.backend == "age"` put also lazily mints
/// this host's age identity first**, inside the SAME [`put_lock`] critical
/// section (a concurrent identity bootstrap has the identical TOCTOU shape
/// the existence-probe->store section already needed a lock for — one
/// lock, not a second one, since both races share this function's own
/// critical section already). `crate::backend::mint_age_identity_if_needed`
/// is checked BY BACKEND NAME rather than made a property every backend
/// gets — this is a SECOND named exception beside `file`'s own seeded-data
/// status ("Backend presets", `README.md`), not a general mechanism.
///
/// **The `put_lock` critical section's worst-case wait is up to FOUR
/// `AOIDE_SECRETS_BACKEND_TIMEOUT`s, not one (judge fix, this commit —
/// corrected from an undercounted "one timeout" framing elsewhere in this
/// crate's docs).** Every shell-out inside this section is bounded
/// individually (`backend::run_backend_command`/`backend::wait_bounded`,
/// task #74/P-G3), but a first-ever `age`-backed `put` can chain up to
/// FOUR of them sequentially before this function returns: minting calls
/// `age-keygen` TWICE (`mint_age_identity_if_needed`'s own key-then-
/// recipient calls, each independently bounded via `backend::
/// run_age_keygen`), then the existence probe runs a `has`/`get` template
/// once (`backend::has_value`), then — on the store path — the `set`
/// template runs once more (`backend::store_value`). Each hop is bounded
/// on its own, so the whole section can never hang forever, but "bounded"
/// here means "up to 4x the knob," never "one timeout total" — a caller
/// (or an operator raising `AOIDE_SECRETS_BACKEND_TIMEOUT`) should size
/// around the worst case, not the per-call one.
fn put_gate(secrets_home: &Path, secret: &str, value: &str, overwrite: bool) -> PutOutcome {
    let policies = match crate::store::load_policies(secrets_home) {
        Ok(p) => p,
        Err(e) => {
            return PutOutcome::Denied(crate::home::describe_home_file_error(
                secrets_home,
                &crate::store::policy_path(secrets_home),
                &e,
            ))
        }
    };
    let Some(policy) = policies.iter().find(|p| p.name == secret) else {
        return PutOutcome::Denied("secret not found".to_string());
    };

    let _guard = put_lock().lock().unwrap_or_else(|e| e.into_inner());

    // P-G1 review fix (task #70): `age`-named does not by itself mean
    // "configured" — an existing deployment's `backends.json` can predate
    // this phase and carry no `age` entry at all, and `secrets add`'s new
    // default records `backend: "age"` regardless. Confirming
    // `backend_is_known` first means such a `put` still correctly fails
    // below with `unknown backend \`age\`` (from `has_value`/
    // `store_value`), but without first minting a REAL identity for a
    // backend that was never going to work.
    let minted = if policy.backend == "age" && crate::backend::backend_is_known(secrets_home, "age") {
        match crate::backend::mint_age_identity_if_needed(secrets_home) {
            Ok(minted) => minted,
            Err(e) => return PutOutcome::Denied(e),
        }
    } else {
        false
    };

    let already_has_value = crate::backend::has_value(secrets_home, &policy.backend, &policy.key);
    if already_has_value && !overwrite {
        return PutOutcome::DeniedExists;
    }
    match crate::backend::store_value(secrets_home, &policy.backend, &policy.key, value) {
        Ok(()) => PutOutcome::Granted { replaced: already_has_value, minted },
        Err(e) => PutOutcome::Denied(e),
    }
}

/// Timesteps kept in the replay ledger beyond the oldest one a `±1`-window
/// `totp::verify` could still match — a generous buffer (not a tight `±1`)
/// so a slightly-delayed save can never prune the very timestep
/// [`verify_totp_gate`] just recorded. Pure bound, no clock read.
const REPLAY_RETENTION_STEPS: u64 = 4; // ~2 minutes at the 30s step

/// [`resolve_gate`]'s three-way decision (P-N2, widened from the old
/// `(bool, Result<String, String>)` pair specifically to carry the new
/// PARK-candidate case — `policy.rs`'s own `totp_required` doc anticipated
/// exactly this change: "a follow-up phase (P-N2) turns a no-code `true`
/// result into a PARK instead of a flat refusal, and this is the one place
/// that phase changes"). `NeedsTotp` is returned ONLY when a code would
/// otherwise be checked (enrollment exists) and none was given — when no
/// enrollment exists at all, this is still an immediate [`GateOutcome::
/// Denied`] (module doc: parking would be pointless, since nobody could
/// ever complete an approve without an enrolled secret).
enum GateOutcome {
    /// `totp_free` (P-N3) is `true` exactly when [`crate::policy::
    /// totp_required`] said no code was ever needed for this resolve
    /// (`requireTotp:false`, or an automation-skip) — the ONE case
    /// [`handle_resolve`] fires a `released` notify event for. A resolve
    /// that DID validate an inline `--totp` code also reaches this variant
    /// (the fast path is otherwise unchanged, module doc) but with
    /// `totp_free: false`, so it is never mistaken for the TOTP-free case.
    Granted { value: String, totp_free: bool },
    Denied(String),
    NeedsTotp,
}

/// The policy gate + backend fetch, in one place. `now_unix` is the
/// caller's clock read (module doc's clock-as-parameter discipline) — this
/// function and everything it calls stay deterministic given the same
/// inputs. `totp` is treated as absent when blank/whitespace-only, same as
/// an outright missing field (task requirement: "no (or empty) totp
/// field"). `caller` (LANE IDENTITY P-ID4) is the connection's
/// POSITIVELY-attested sealed session, `(sessionId, originClass)`, resolved
/// by [`handle_resolve`] via [`attested_caller_origin`] and handed in as a
/// parameter for the same reason the clock is — this function stays
/// deterministic and exhaustively table-testable; `None` means
/// UNIDENTIFIED, which the origin check below deliberately does not touch.
fn resolve_gate(
    secrets_home: &Path,
    secret: &str,
    consumer: &str,
    totp: Option<&str>,
    now_unix: u64,
    caller: Option<(&str, &str)>,
) -> GateOutcome {
    let policies = match crate::store::load_policies(secrets_home) {
        Ok(p) => p,
        Err(e) => {
            return GateOutcome::Denied(crate::home::describe_home_file_error(
                secrets_home,
                &crate::store::policy_path(secrets_home),
                &e,
            ))
        }
    };
    let Some(policy) = policies.iter().find(|p| p.name == secret) else {
        return GateOutcome::Denied("secret not found".to_string());
    };
    let authorized = policy.consumers.is_empty() || policy.consumers.iter().any(|c| c == consumer);
    if !authorized {
        return GateOutcome::Denied("consumer not authorized for this secret".to_string());
    }
    // The origin gate (LANE IDENTITY P-ID4): after exists/consumers, before
    // TOTP/automation — a caller whose SEALED session is remote-origin
    // (`peer:*`) is refused unless this secret opted in, so a remote-origin
    // caller can never even reach the park/approve machinery for a secret
    // that hasn't admitted it. Keys ONLY on a POSITIVELY-attested remote
    // origin (module doc's "The origin gate" section states the boundary
    // exactly): `caller == None` — unidentified — falls through untouched.
    if let Some((session_id, origin)) = caller {
        if origin.starts_with("peer:") && !policy.allow_remote_origin {
            return GateOutcome::Denied(denied_remote_origin_message(secret, session_id, origin));
        }
    }
    // P-N3: recorded once, up front, so the eventual `Granted` variant can
    // say honestly whether a code was ever checked — `totp_required` itself
    // is already the ONE decision point (`AGENTS.md`), this just carries its
    // answer forward to the grant.
    let totp_free = !crate::policy::totp_required(policy, consumer);
    if !totp_free {
        let code = totp.map(str::trim).filter(|s| !s.is_empty());
        match code {
            None => {
                // No code — either a park candidate (enrollment exists, a
                // code WOULD be checked if present) or, when nothing has
                // ever enrolled this host, the same immediate refusal
                // `verify_totp_gate` has always given for that case.
                return match crate::store::load_totp_secret(secrets_home) {
                    Ok(Some(_)) => GateOutcome::NeedsTotp,
                    Ok(None) => GateOutcome::Denied(
                        "requireTotp is set but no TOTP enrollment exists on this host yet".to_string(),
                    ),
                    Err(e) => GateOutcome::Denied(format!("totp.secret: {e}")),
                };
            }
            Some(code) => {
                if let Err(e) = verify_totp_gate(secrets_home, Some(code), now_unix) {
                    return GateOutcome::Denied(e);
                }
            }
        }
    }
    match crate::backend::fetch_value(secrets_home, &policy.backend, &policy.key) {
        Ok(value) => GateOutcome::Granted { value, totp_free },
        Err(e) => GateOutcome::Denied(e),
    }
}

/// The origin-gate refusal's exact wording (LANE IDENTITY P-ID4) — a pure
/// function so the taught message is testable without a live daemon or a
/// sealed roster. Names the SECRET, the caller's sealed session + origin
/// (kernel-attested facts, never wire-asserted ones), and the exact flag +
/// command that opts the secret in. Value-free by construction, same as
/// every other refusal in this module.
fn denied_remote_origin_message(secret: &str, session_id: &str, origin: &str) -> String {
    format!(
        "this caller's session `{session_id}` is remote-origin (`{origin}`) and secret `{secret}` \
         does not admit remote-origin callers — its allowRemoteOrigin flag is off (the default); \
         an operator can opt this secret in with `aoide secrets allow-remote-origin {secret} on`"
    )
}

/// Resolve the connecting peer's POSITIVELY-attested sealed session (LANE
/// IDENTITY P-ID4): kernel-truth `SO_PEERCRED` pid -> real `/proc`
/// ancestry -> sealed session record -> seal verified against the daemon's
/// LIVE public key, all via `aoide_storage::attest::attested_caller` (ONE
/// implementation, shared with `aoide-conduct`'s send gate — that module's
/// doc has the DAG argument and the fresh-starttime pid-reuse defense).
/// `None` on ANY missing link — an unidentified connection (`peer: None`),
/// an unreachable daemon, an unreadable roster, no verifying ancestor —
/// and `None` always means UNIDENTIFIED: the origin gate ignores it, per
/// the module doc's stated boundary. In the packaged cross-uid deployment
/// (the broker as the `aoide-secrets` system user) both the operator's
/// daemon socket and their `sessions.json` are unreachable, so THIS
/// resolves `None` for every caller there — the gate bites wherever the
/// broker runs as the operator's own uid (`attest`'s module doc carries
/// the same honesty note from the other side).
fn attested_caller_origin(peer: Option<crate::peercred::PeerCred>) -> Option<(String, String)> {
    aoide_storage::attest::attested_caller(peer?.pid)
}

/// Serializes [`verify_totp_gate`]'s ENTIRE replay-ledger load -> record ->
/// prune -> save critical section (P-N2 review fix, this commit — a
/// CONFIRMED race, reproduced by a two-thread test iterated ~20x before
/// this lock existed). See the module doc's "read-modify-write sections"
/// paragraph: the old single-threaded accept loop serialized this for
/// free just by never running two connections' code at once; P-N2's move
/// to thread-per-connection removed that, so without an explicit lock two
/// threads racing the SAME valid code could each load the ledger before
/// either saved, each `record()` a private copy, and both succeed — one
/// code redeeming a `requireTotp` secret TWICE. Recovers from a poisoned
/// lock the same way [`crate::park::ParkRegistry`]'s own lock does
/// (`park.rs`'s module doc is the precedent) — a panic inside one
/// connection's thread must never wedge every other connection's TOTP
/// verification. The ledger is still loaded fresh from disk on every call
/// (this crate's "NO CACHE, EVER" invariant, `AGENTS.md`) — this lock only
/// serializes the section, it never remembers what it read.
fn replay_ledger_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    &LOCK
}

/// The `requireTotp` half of [`resolve_gate`]. No enrollment on this host
/// -> unresolvable (unchanged wording from before P-V3). Enrolled -> a
/// fresh `±1`-window code, single-use per TIMESTEP via the persisted
/// [`crate::replay::ReplayLedger`] (this crate's `AGENTS.md` ruling: keyed
/// on timestep alone, never consumer). Every error string here is
/// value-free AND code-free by construction: the caller-typed `totp`
/// string is untrusted input (module doc) and is never interpolated into
/// any returned message, only parsed/compared. **P-N2 review fix:** the
/// ledger's load/record/prune/save is held under [`replay_ledger_lock`]
/// for its full extent — see that function's own doc.
fn verify_totp_gate(secrets_home: &Path, totp: Option<&str>, now_unix: u64) -> Result<(), String> {
    let secret = match crate::store::load_totp_secret(secrets_home) {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Err("requireTotp is set but no TOTP enrollment exists on this host yet".to_string())
        }
        Err(e) => return Err(format!("totp.secret: {e}")),
    };
    let Some(code_str) = totp else {
        return Err("requireTotp is set but no totp code was provided".to_string());
    };
    let Ok(code) = code_str.trim().parse::<u32>() else {
        return Err("malformed totp code".to_string());
    };
    let Some(step) = crate::totp::verify(&secret, code, now_unix, crate::totp::DEFAULT_WINDOW) else {
        return Err("totp code invalid or expired".to_string());
    };

    let _guard = replay_ledger_lock().lock().unwrap_or_else(|e| e.into_inner());
    let mut ledger = match crate::store::load_replay_ledger(secrets_home) {
        Ok(l) => l,
        Err(e) => return Err(format!("totp-replay.json: {e}")),
    };
    if !ledger.record(step) {
        return Err("totp code already used".to_string());
    }
    ledger.prune_before(crate::totp::timestep(now_unix).saturating_sub(REPLAY_RETENTION_STEPS));
    if let Err(e) = crate::store::save_replay_ledger(secrets_home, &ledger) {
        return Err(format!("writing totp-replay.json: {e}"));
    }
    Ok(())
}

fn own_audit_log_path(secrets_home: &Path) -> PathBuf {
    secrets_home.join("audit.log")
}

fn append_own_log(secrets_home: &Path, record: &Value) -> std::io::Result<()> {
    let path = own_audit_log_path(secrets_home);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    let mut line = record.to_string();
    line.push('\n');
    f.write_all(line.as_bytes())
}

/// The events feed's size cap (P-G4, task #77): events are ephemeral cues
/// on a `/run`-backed tmpfs, not an audit trail (that's still
/// `own_audit_log_path`/the mirrored `~/Aoide/log`, both unbounded and
/// unrotated by design) — 1 MiB is comfortably past anything a live
/// watcher needs to have caught up on, and no rotation machinery exists or
/// is needed: past the cap, [`append_events_feed`] simply truncates the
/// file to empty before writing the new line, which `watch::Follower::
/// poll`'s own `len() < pos` branch already treats as a truncation/
/// rotation and reopens from 0 (confirmed by reading `watch.rs` directly —
/// see that function's doc comment).
const EVENTS_MAX_BYTES: u64 = 1024 * 1024;

/// The events feed's create mode (P-G4, task #77): `0640` — group-read,
/// no world access, never left to the process umask, since the deployed
/// unit's `Group=aoide-secrets-access` makes group-read exactly the
/// socket's own audience.
const EVENTS_CREATE_MODE: u32 = 0o640;

/// Append ONE event line to the broker-owned events feed (P-G4, task
/// #77) — the live-proven fix for `ProtectHome=true`: the deployed broker
/// unit cannot write into the operator's `~/Aoide/log` (`emit_notify`'s
/// mirror there silently fails under that sandboxing), so `secrets watch`
/// received zero event lines and fell back to its 30s pending-reconcile
/// tick for every popup (found live on yomi-strix, 2026-08-23). This feed
/// lives beside the broker's own socket — inside the directory the
/// broker's unit already owns (`socket::events_path`'s own doc) — so it is
/// reachable under the SAME sandboxing that already lets the socket itself
/// bind there.
///
/// **Delegates its mechanics to [`aoide_protocol::feed::FeedWriter`] as of
/// P-D1** (`docs/architecture/AOIDED.md`'s "L1 — the event bus" section) —
/// this function is now the thin, secrets-specific caller: it supplies
/// `events_path`, [`EVENTS_MAX_BYTES`], and [`EVENTS_CREATE_MODE`], and
/// `FeedWriter::append` does the create/cap-truncate/chmod-once/write-line
/// work. Best-effort, always, exactly like [`append_own_log`]/
/// `emit_notify`'s own two existing destinations — a failure inside
/// `FeedWriter::append` is `eprintln!`'d and swallowed there, never
/// propagated back here, so a notification write must never fail or block
/// the resolve it rides with (`emit_notify`'s own doc, unchanged by this
/// move). **MUST be called with no crate lock held**, the identical rule
/// `emit_notify` itself already holds — this function is only ever reached
/// FROM `emit_notify`, so it inherits that guarantee rather than
/// re-earning it.
fn append_events_feed(events_path: &Path, payload: &Value) {
    aoide_protocol::feed::FeedWriter::new(events_path.to_path_buf(), EVENTS_MAX_BYTES, EVENTS_CREATE_MODE).append(payload);
}

/// Write BOTH audit lines for one resolve attempt (module doc). Name-only,
/// by construction: nothing passed here is ever the secret's value.
/// **`peer_uid` (task #73) rides alongside the self-asserted `consumer`
/// name — kernel-truth via `SO_PEERCRED`, read once at connection start
/// (`handle_conn`'s own doc), `None` when it couldn't be read. Honesty
/// note, restated from `peercred.rs`'s own module doc: this does NOT make
/// `consumer` itself authenticated — it is a separate fact recorded
/// alongside it, not a replacement for it.**
fn audit_resolve(
    secrets_home: &Path,
    secret: &str,
    consumer: &str,
    argv0: Option<&str>,
    granted: bool,
    reason: Option<&String>,
    peer_uid: Option<u32>,
) {
    let record = json!({
        "ts": aoide_protocol::audit::now_secs(),
        "secret": secret,
        "consumer": consumer,
        "peerUid": peer_uid,
        "argv0": argv0,
        "granted": granted,
        "reason": reason,
    });
    if let Err(e) = append_own_log(secrets_home, &record) {
        eprintln!("[aoide/secrets] could not write the secrets audit log: {e}");
    }

    let status = if granted { "granted" } else { "denied" };
    let message = match reason {
        Some(r) => format!(
            "secret `{secret}` for consumer `{consumer}` (peer uid {}): {status} ({r})",
            peer_uid_display(peer_uid)
        ),
        None => {
            format!("secret `{secret}` for consumer `{consumer}` (peer uid {}): {status}", peer_uid_display(peer_uid))
        }
    };
    let _ = aoide_protocol::audit(
        &aoide_protocol::default_audit_log(),
        aoide_protocol::Door::Daemon,
        aoide_protocol::EventClass::Secret,
        "secrets.resolve",
        status,
        &message,
    );
}

/// Write BOTH audit lines for one `put` attempt — the `put` mirror of
/// [`audit_resolve`], same two destinations (the broker's own `audit.log`
/// + the mirrored `EventClass::Secret` aoide-log line), same name-only
/// discipline. No `consumer`/`argv0` fields — `put`'s wire request carries
/// neither (module doc). `replaced` (P-67) is `Some(bool)` only on a
/// GRANTED put — names only, never a value, same as everything else this
/// function writes — so the audit trail can say "replaced" vs "stored new"
/// without re-deriving it from the reason string.
fn audit_put(
    secrets_home: &Path,
    secret: &str,
    granted: bool,
    reason: Option<&String>,
    replaced: Option<bool>,
    peer_uid: Option<u32>,
) {
    let record = json!({
        "ts": aoide_protocol::audit::now_secs(),
        "op": "put",
        "secret": secret,
        "peerUid": peer_uid,
        "granted": granted,
        "reason": reason,
        "replaced": replaced,
    });
    if let Err(e) = append_own_log(secrets_home, &record) {
        eprintln!("[aoide/secrets] could not write the secrets audit log: {e}");
    }

    let status = if granted { "granted" } else { "denied" };
    let puid = peer_uid_display(peer_uid);
    let message = match (reason, replaced) {
        (Some(r), _) => format!("put `{secret}` (peer uid {puid}): {status} ({r})"),
        (None, Some(true)) => format!("put `{secret}` (peer uid {puid}): {status} (replaced existing value)"),
        (None, Some(false)) => format!("put `{secret}` (peer uid {puid}): {status} (stored new value)"),
        (None, None) => format!("put `{secret}` (peer uid {puid}): {status}"),
    };
    let _ = aoide_protocol::audit(
        &aoide_protocol::default_audit_log(),
        aoide_protocol::Door::Daemon,
        aoide_protocol::EventClass::Secret,
        "secrets.put",
        status,
        &message,
    );
}

/// Write BOTH audit lines for one `resolve` that PARKED (P-N2) — fired
/// once, at park time, from [`handle_resolve`]. The ask's EVENTUAL
/// grant/deny (approved, dismissed, or timed out) still fires
/// [`audit_resolve`] separately, exactly as an immediate resolve always
/// has (module doc) — this is an ADDITIONAL line marking the park itself,
/// not a replacement for that one. Name-only, same discipline as every
/// other audit call in this module — carries the ask's `id` so the two
/// lines (park, then eventual resolution) can be correlated by a human
/// reading `audit.log`, never a code or value.
fn audit_park(
    secrets_home: &Path,
    id: &str,
    secret: &str,
    consumer: &str,
    peer_uid: Option<u32>,
    reason: Option<&str>,
    origin: &AskOrigin,
) {
    let record = json!({
        "ts": aoide_protocol::audit::now_secs(),
        "op": "park",
        "id": id,
        "secret": secret,
        "consumer": consumer,
        "peerUid": peer_uid,
        // Additive, same "display-only, self-asserted/best-effort" posture
        // `argv0` already holds on `audit_resolve`'s own record — never a
        // value.
        "reason": reason,
        "origin": origin_to_json(origin),
    });
    if let Err(e) = append_own_log(secrets_home, &record) {
        eprintln!("[aoide/secrets] could not write the secrets audit log: {e}");
    }
    let message = format!(
        "secret `{secret}` for consumer `{consumer}` (peer uid {}): parked (id `{id}`, awaiting a TOTP code)",
        peer_uid_display(peer_uid)
    );
    let _ = aoide_protocol::audit(
        &aoide_protocol::default_audit_log(),
        aoide_protocol::Door::Daemon,
        aoide_protocol::EventClass::Secret,
        "secrets.resolve",
        "parked",
        &message,
    );
}

/// Write BOTH audit lines for one `approve` attempt (P-N2) — the
/// APPROVER's own side of the interaction, distinct from [`audit_resolve`]'s
/// eventual line on the PARKED caller's side. `secret` is `None` only for
/// an unknown id (nothing to name). Never carries the typed code (untrusted
/// input, module doc) or the released value.
fn audit_approve(secrets_home: &Path, id: &str, secret: Option<&str>, granted: bool, reason: &str, peer_uid: Option<u32>) {
    let record = json!({
        "ts": aoide_protocol::audit::now_secs(),
        "op": "approve",
        "id": id,
        "secret": secret,
        "peerUid": peer_uid,
        "granted": granted,
        "reason": if reason.is_empty() { Value::Null } else { Value::String(reason.to_string()) },
    });
    if let Err(e) = append_own_log(secrets_home, &record) {
        eprintln!("[aoide/secrets] could not write the secrets audit log: {e}");
    }
    let status = if granted { "granted" } else { "denied" };
    let puid = peer_uid_display(peer_uid);
    let message = match secret {
        Some(s) if !reason.is_empty() => format!("approve `{id}` for secret `{s}` (approver peer uid {puid}): {status} ({reason})"),
        Some(s) => format!("approve `{id}` for secret `{s}` (approver peer uid {puid}): {status}"),
        None => format!("approve `{id}` (approver peer uid {puid}): {status} ({reason})"),
    };
    let _ = aoide_protocol::audit(
        &aoide_protocol::default_audit_log(),
        aoide_protocol::Door::Daemon,
        aoide_protocol::EventClass::Secret,
        "secrets.approve",
        status,
        &message,
    );
}

/// Write BOTH audit lines for one `dismiss` attempt (P-N2) — mirrors
/// [`audit_approve`]'s shape. `secret` is `""` only for an unknown id.
fn audit_dismiss(secrets_home: &Path, id: &str, secret: &str, granted: bool, reason: Option<&str>, peer_uid: Option<u32>) {
    let record = json!({
        "ts": aoide_protocol::audit::now_secs(),
        "op": "dismiss",
        "id": id,
        "secret": if secret.is_empty() { Value::Null } else { Value::String(secret.to_string()) },
        "peerUid": peer_uid,
        "granted": granted,
        "reason": reason,
    });
    if let Err(e) = append_own_log(secrets_home, &record) {
        eprintln!("[aoide/secrets] could not write the secrets audit log: {e}");
    }
    let status = if granted { "dismissed" } else { "denied" };
    let puid = peer_uid_display(peer_uid);
    let message = match reason {
        Some(r) => format!("dismiss `{id}` (peer uid {puid}): {status} ({r})"),
        None if !secret.is_empty() => format!("dismiss `{id}` for secret `{secret}` (peer uid {puid}): {status}"),
        None => format!("dismiss `{id}` (peer uid {puid}): {status}"),
    };
    let _ = aoide_protocol::audit(
        &aoide_protocol::default_audit_log(),
        aoide_protocol::Door::Daemon,
        aoide_protocol::EventClass::Secret,
        "secrets.dismiss",
        status,
        &message,
    );
}

/// Emit one broker EVENT (P-N3, not to be confused with the `audit_*`
/// functions above): the five notable outcomes — `released`, `parked`,
/// `completed`, `dismissed`, `expired` — a future desktop popup needs to
/// hear about. `payload` is the EXACT name-only JSON shape that future
/// consumer reads (`{"event": "<kind>", "secret", "consumer", "id"?,
/// "timeoutSecs"?}` — never a value, same discipline every other record in
/// this module already holds).
///
/// THREE destinations as of P-G4 (task #77): the broker's own structured
/// `audit.log` (`append_own_log`/`own_audit_log_path`, so `tail -f
/// <secrets_home>/audit.log` shows the raw event JSON verbatim), the
/// mirrored aoide log (`EventClass::Secret`, command `secrets.notify`,
/// status = `kind` — `tail -f ~/Aoide/log | grep secrets.notify` is the
/// cross-host-readable half, kept for the audit trail), and NOW the
/// broker-owned events feed (`append_events_feed`, `events_path` —
/// `socket::events_path`'s own doc has the ProtectHome reasoning). The
/// first two are UNCHANGED from P-N3; `secrets watch`'s own tail moved
/// OFF the mirrored log and onto this third destination exclusively
/// (`watch.rs`'s module doc) — the mirror stays for the audit trail, it is
/// simply no longer what the watcher reads. See `README.md`'s "Broker
/// notifications" section for the full pickup-point note.
///
/// **Best-effort, always** (task requirement): a notification must never
/// fail or block the resolve it rides alongside. All three writes are
/// `eprintln!`/swallowed exactly like every `audit_*` function's own `if
/// let Err(e) = ...` above — never a `?`, never a panic.
///
/// **MUST be called with no crate lock held** (`AGENTS.md`'s three-lock
/// inventory — `replay_ledger_lock`, `put_lock`, `ParkRegistry`'s own
/// internal `Mutex`). Every call site above already satisfies this: each
/// one fires after the park-registry call that produced its `id`/`ask` has
/// already returned (that call's own internal lock is acquired and released
/// entirely inside `ParkRegistry`'s own methods), and after
/// `verify_totp_gate`'s `replay_ledger_lock` guard (a block-scoped
/// `_guard`) has already gone out of scope. A future call site follows the
/// same rule: emit only once every lock this event's own outcome depended
/// on has already been released. `append_events_feed` inherits this same
/// guarantee (its own doc) rather than re-earning it.
fn emit_notify(secrets_home: &Path, events_path: &Path, kind: &str, payload: Value) {
    if let Err(e) = append_own_log(secrets_home, &payload) {
        eprintln!("[aoide/secrets] could not write the secrets notify log: {e}");
    }
    append_events_feed(events_path, &payload);
    let message = payload.to_string();
    let _ = aoide_protocol::audit(
        &aoide_protocol::default_audit_log(),
        aoide_protocol::Door::Daemon,
        aoide_protocol::EventClass::Secret,
        "secrets.notify",
        kind,
        &message,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    fn tmp_home(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aoide-secrets-broker-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A peer identity matching the broker's OWN effective uid — task
    /// #73's `dismiss_authorized` always admits the broker's own euid
    /// regardless of an ask's stamped `peer_uid` (invariant: `dismiss_
    /// authorized_always_admits_the_brokers_own_euid`). This is the
    /// cleanup identity every pre-#73 test that dismisses its own parked
    /// ask (never itself testing peer-uid gating) uses — an `None` peer
    /// there would now be a genuinely unidentified dismisser, refused by
    /// the fail-closed rule even against an ask whose own `peer_uid` is
    /// also `None`.
    fn operator_peer() -> Option<crate::peercred::PeerCred> {
        Some(crate::peercred::PeerCred { uid: crate::home::effective_uid(), gid: 0, pid: 0 })
    }

    fn seed(home: &Path, policies: &[Policy]) {
        crate::store::save_policies(home, policies).unwrap();
        let backends = serde_json::json!({ "scratch": { "get": "printf %s {name}" } });
        std::fs::write(crate::backend::backends_path(home), serde_json::to_vec(&backends).unwrap()).unwrap();
    }

    /// A fixed "now" for every test that doesn't specifically exercise TOTP
    /// timing — deterministic, never `SystemTime::now()`.
    const NOW: u64 = 1_700_000_000;

    /// Unpacks [`GateOutcome`] into the PRE-P-N2 `(granted, Result<value,
    /// error>)` tuple shape most of this suite's existing assertions were
    /// written against — same precedent [`put_outcome_as_result`] already
    /// sets for [`PutOutcome`]. `NeedsTotp` collapses to a placeholder
    /// `Err` here (its own distinct shape — the whole point of P-N2 — is
    /// exercised directly via `matches!(outcome, GateOutcome::NeedsTotp)`
    /// by the tests that actually need to tell it apart from an ordinary
    /// denial; every OTHER test in this suite predates P-N2 and never
    /// exercises a policy shape that can produce `NeedsTotp` at all).
    fn gate_outcome_as_result(outcome: GateOutcome) -> (bool, Result<String, String>) {
        match outcome {
            GateOutcome::Granted { value, .. } => (true, Ok(value)),
            GateOutcome::Denied(e) => (false, Err(e)),
            GateOutcome::NeedsTotp => (false, Err("needs a totp code (would park)".to_string())),
        }
    }

    #[test]
    fn unknown_secret_is_denied_with_a_clear_reason() {
        let home = tmp_home("unknown");
        seed(&home, &[]);
        let (granted, result) = gate_outcome_as_result(resolve_gate(&home, "nope", "m", None, NOW, None));
        assert!(!granted);
        assert_eq!(result.unwrap_err(), "secret not found");
        std::fs::remove_dir_all(&home).ok();
    }

    /// The wire-level counterpart to `commands.rs`'s
    /// `a_policy_json_this_euid_cannot_read_gets_the_chown_reference_hint`:
    /// `secrets exec`/`put` are the primary AGENT-facing path, and a
    /// poisoned `policy.json` reaches them through `resolve_gate`/
    /// `put_gate`, not the admin CRUD quintet — this is the exact incident
    /// this whole feature answers, so both gates must teach the fix, not
    /// just `commands.rs`'s `add`/`rm`/`grant`/`revoke`/`set-totp`. Skipped
    /// under a root test runner (root reads `0000` files fine, so the
    /// denial this test depends on wouldn't happen).
    #[test]
    fn an_unreadable_policy_json_teaches_the_chown_reference_fix_on_both_gates() {
        if crate::home::effective_uid() == 0 {
            return;
        }
        let home = tmp_home("unreadable-policy");
        seed(&home, &[Policy::new("t", "scratch", "k")]);

        use std::os::unix::fs::PermissionsExt;
        let path = crate::store::policy_path(&home);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

        let (resolve_granted, resolve_result) = gate_outcome_as_result(resolve_gate(&home, "t", "m", None, NOW, None));
        let (put_granted, put_result) = put_outcome_as_result(put_gate(&home, "t", "irrelevant", false));

        // Restore before any assertion could early-return and leave the
        // tempdir's cleanup unable to remove an unreadable file.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert!(!resolve_granted);
        let resolve_err = resolve_result.unwrap_err();
        assert!(resolve_err.to_lowercase().contains("permission denied"), "{resolve_err}");
        assert!(resolve_err.contains("chown --reference="), "{resolve_err}");
        assert!(resolve_err.contains(&path.display().to_string()), "{resolve_err}");

        assert!(!put_granted);
        let put_err = put_result.unwrap_err();
        assert!(put_err.contains("chown --reference="), "{put_err}");

        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn consumer_not_in_the_list_is_denied() {
        let home = tmp_home("wrongconsumer");
        let mut p = Policy::new("t", "scratch", "stored-value");
        p.consumers = vec!["m".to_string()];
        seed(&home, &[p]);
        let (granted, result) = gate_outcome_as_result(resolve_gate(&home, "t", "someone-else", None, NOW, None));
        assert!(!granted);
        assert!(result.unwrap_err().contains("not authorized"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn empty_consumers_list_means_any_consumer() {
        let home = tmp_home("anyconsumer");
        let p = Policy::new("t", "scratch", "stored-value");
        seed(&home, &[p]);
        let (granted, result) = gate_outcome_as_result(resolve_gate(&home, "t", "whoever", None, NOW, None));
        assert!(granted);
        assert_eq!(result.unwrap(), "stored-value");
        std::fs::remove_dir_all(&home).ok();
    }

    // ── the origin gate (LANE IDENTITY P-ID4) ────────────────────────────

    /// A POSITIVELY-attested remote-origin caller on a DEFAULT secret
    /// (allowRemoteOrigin off) is refused — before TOTP ever enters the
    /// picture — with the taught message naming the flag, the session, and
    /// its origin. The backend never runs.
    #[test]
    fn a_remote_origin_caller_is_refused_on_a_default_secret() {
        let home = tmp_home("origin-deny");
        seed(&home, &[Policy::new("t", "scratch", "stored-value")]);
        let (granted, result) = gate_outcome_as_result(resolve_gate(
            &home, "t", "m", None, NOW,
            Some(("remote-orch", "peer:sakaki")),
        ));
        assert!(!granted);
        let err = result.unwrap_err();
        assert!(err.contains("allowRemoteOrigin"), "the refusal names the flag: {err}");
        assert!(err.contains("remote-orch"), "the refusal names the session: {err}");
        assert!(err.contains("peer:sakaki"), "the refusal names the origin: {err}");
        assert!(err.contains("secrets allow-remote-origin t on"), "the refusal teaches the opt-in: {err}");
        std::fs::remove_dir_all(&home).ok();
    }

    /// The opt-in admits the same remote-origin caller — and sits BEFORE
    /// the TOTP branch, so with no TOTP gate the value releases normally.
    #[test]
    fn allow_remote_origin_on_admits_a_remote_origin_caller() {
        let home = tmp_home("origin-optin");
        let mut p = Policy::new("t", "scratch", "stored-value");
        p.allow_remote_origin = true;
        seed(&home, &[p]);
        let (granted, result) = gate_outcome_as_result(resolve_gate(
            &home, "t", "m", None, NOW,
            Some(("remote-orch", "peer:sakaki")),
        ));
        assert!(granted);
        assert_eq!(result.unwrap(), "stored-value");
        std::fs::remove_dir_all(&home).ok();
    }

    /// The gate keys ONLY on a `peer:*` origin: a LOCAL-origin attested
    /// caller and an UNIDENTIFIED one (`None` — the module doc's stated
    /// boundary: this gate narrows remote-origin sessions, it does not
    /// authenticate local ones) both resolve exactly as before P-ID4.
    #[test]
    fn local_origin_and_unidentified_callers_are_untouched_by_the_origin_gate() {
        let home = tmp_home("origin-local");
        seed(&home, &[Policy::new("t", "scratch", "stored-value")]);

        let (granted, result) = gate_outcome_as_result(resolve_gate(
            &home, "t", "m", None, NOW,
            Some(("local-orch", "local")),
        ));
        assert!(granted, "a local-origin attested caller is admitted");
        assert_eq!(result.unwrap(), "stored-value");

        let (granted, result) = gate_outcome_as_result(resolve_gate(&home, "t", "m", None, NOW, None));
        assert!(granted, "an unidentified caller is admitted — this gate never authenticates locals");
        assert_eq!(result.unwrap(), "stored-value");
        std::fs::remove_dir_all(&home).ok();
    }

    /// Gate ORDER: exists/consumers still win over the origin check — an
    /// unauthorized consumer gets the consumers refusal, not the origin
    /// one, even when the caller is remote-origin; and a remote-origin
    /// refusal on a `requireTotp` secret fires BEFORE any park/TOTP path
    /// (the refusal is immediate, never `NeedsTotp`).
    #[test]
    fn origin_gate_sits_after_consumers_and_before_totp() {
        let home = tmp_home("origin-order");
        let mut listed = Policy::new("t", "scratch", "k");
        listed.consumers = vec!["m".to_string()];
        let mut totp_gated = Policy::new("t2", "scratch", "k2");
        totp_gated.require_totp = true;
        seed(&home, &[listed, totp_gated]);

        let (granted, result) = gate_outcome_as_result(resolve_gate(
            &home, "t", "someone-else", None, NOW,
            Some(("remote-orch", "peer:sakaki")),
        ));
        assert!(!granted);
        assert_eq!(result.unwrap_err(), "consumer not authorized for this secret");

        match resolve_gate(&home, "t2", "m", None, NOW, Some(("remote-orch", "peer:sakaki"))) {
            GateOutcome::Denied(reason) => {
                assert!(reason.contains("allowRemoteOrigin"), "{reason}");
            }
            GateOutcome::NeedsTotp => panic!("a refused remote-origin caller must never park"),
            GateOutcome::Granted { .. } => panic!("must be denied"),
        }
        std::fs::remove_dir_all(&home).ok();
    }

    /// The FULL plumbing, end to end through `handle_line` (LANE IDENTITY
    /// P-ID4): a real sealed roster on disk (`AOIDE_STAGE_DIR`), a fake
    /// daemon serving the REAL minting key's pubkey over `ping`
    /// (`AOIDE_DAEMON_SOCKET`), and a connection whose kernel-truth
    /// peercred pid is this very process — attested as remote-origin, the
    /// resolve is refused; re-seal the roster under a STALE starttime and
    /// the caller degrades to UNIDENTIFIED (the pid-reuse defense holding
    /// through the new call path) and is admitted again.
    #[test]
    fn handle_resolve_refuses_an_attested_remote_origin_caller_end_to_end() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_audit = std::env::var("AOIDE_AUDIT_LOG").ok();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_sock = std::env::var("AOIDE_DAEMON_SOCKET").ok();

        let home = tmp_home("origin-e2e");
        std::env::set_var("AOIDE_AUDIT_LOG", home.join("mirrored-aoide-log"));
        let stage = home.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        seed(&home, &[Policy::new("t", "scratch", "stored-value")]);

        let kp = aoide_storage::identity::mint_ephemeral().unwrap();
        let me = std::process::id() as i32;
        let starttime = aoide_storage::attest::pid_starttime(me).unwrap();
        let seal_over = |st: u64| {
            let sid = aoide_storage::sealed_id::SealedIdentity {
                session_id: "remote-orch".to_string(),
                pid: me,
                pid_starttime: st,
                origin_class: "peer:sakaki".to_string(),
                issued_at: 1_700_000_000,
            };
            aoide_storage::records::SessionRecord {
                session_id: "remote-orch".to_string(),
                state: "idle".to_string(),
                pid: Some(me as u32),
                origin: Some("peer:sakaki".to_string()),
                seal: Some(aoide_storage::sealed_id::mint_seal(&kp, &sid)),
                sealed_issued_at: Some(1_700_000_000),
                ..Default::default()
            }
        };
        let write_roster = |rec| {
            let roster = aoide_storage::records::SessionsFile {
                schema_version: "0".to_string(),
                sessions: vec![rec],
            };
            aoide_storage::stage::write_stage(&aoide_storage::stage::sessions_path(), &roster).unwrap();
        };
        write_roster(seal_over(starttime));

        // A one-shot fake daemon per connection attempt, serving the REAL
        // minting key's pubkey.
        let sock = home.join("aoided.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let pubkey = kp.info().pubkey_hex;
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                let _ = reader.read_line(&mut line);
                let reply = json!({"ok": true, "daemon": "aoided", "sealPubkeyHex": pubkey});
                let mut w = stream;
                let _ = w.write_all(format!("{reply}\n").as_bytes());
            }
        });
        std::env::set_var("AOIDE_DAEMON_SOCKET", &sock);

        let peer = Some(crate::peercred::PeerCred {
            uid: crate::home::effective_uid(),
            gid: 0,
            pid: me,
        });
        let req = r#"{"op":"resolve","secret":"t","consumer":"m"}"#;
        let reply = handle_line(&home, &home.join("events.jsonl"), req, &ParkRegistry::new(), &mut Vec::new(), peer);
        assert_eq!(reply["ok"], false, "{reply}");
        let err = reply["error"].as_str().unwrap();
        assert!(err.contains("allowRemoteOrigin"), "{err}");
        assert!(err.contains("peer:sakaki"), "{err}");

        // Pid-reuse defense through the new call path: a roster whose seal
        // was minted over a STALE starttime no longer attests — the caller
        // is UNIDENTIFIED and the same resolve is admitted.
        write_roster(seal_over(starttime + 1));
        let reply = handle_line(&home, &home.join("events.jsonl"), req, &ParkRegistry::new(), &mut Vec::new(), peer);
        assert_eq!(reply["ok"], true, "{reply}");
        assert_eq!(reply["value"], "stored-value");

        match saved_audit {
            Some(v) => std::env::set_var("AOIDE_AUDIT_LOG", v),
            None => std::env::remove_var("AOIDE_AUDIT_LOG"),
        }
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        match saved_sock {
            Some(v) => std::env::set_var("AOIDE_DAEMON_SOCKET", v),
            None => std::env::remove_var("AOIDE_DAEMON_SOCKET"),
        }
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn require_totp_is_unresolvable_with_no_enrollment_on_this_host() {
        let home = tmp_home("totp-noenroll");
        let mut p = Policy::new("t", "scratch", "stored-value");
        p.require_totp = true;
        seed(&home, &[p]);
        // No `totp.secret` written — nothing has enrolled this host yet.
        let (granted, result) = gate_outcome_as_result(resolve_gate(&home, "t", "m", Some("123456"), NOW, None));
        assert!(!granted);
        assert!(result.unwrap_err().contains("no TOTP enrollment"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn a_granted_resolve_fetches_through_the_named_backend() {
        let home = tmp_home("granted");
        let mut p = Policy::new("t", "scratch", "stored-value");
        p.consumers = vec!["m".to_string()];
        seed(&home, &[p]);
        let (granted, result) = gate_outcome_as_result(resolve_gate(&home, "t", "m", None, NOW, None));
        assert!(granted);
        assert_eq!(result.unwrap(), "stored-value");
        std::fs::remove_dir_all(&home).ok();
    }

    // ── requireTotp, enrolled (P-V3) ────────────────────────────────────

    /// Seeds an enrollment (`totp.secret`) alongside the usual policy/
    /// backend fixture. Returns the raw secret bytes so a test can derive
    /// a code from them via `crate::totp` directly.
    fn seed_enrolled(home: &Path, mut p: Policy) -> Vec<u8> {
        p.require_totp = true;
        seed(home, &[p]);
        let secret = b"a-twenty-byte-totp-s".to_vec();
        assert_eq!(secret.len(), 20);
        crate::store::save_totp_secret(home, &secret).unwrap();
        secret
    }

    /// Time-sensitivity discipline (phase brief): derive the TIMESTEP
    /// first, then the code for exactly that step — never `totp6(secret,
    /// now)` against a live clock, which could straddle a boundary between
    /// computing the code and the assertion running.
    fn code_for_now(secret: &[u8], now: u64) -> String {
        let step = crate::totp::timestep(now);
        crate::totp::format6(crate::totp::hotp(secret, step, crate::totp::DIGITS))
    }

    #[test]
    fn enrolled_and_correct_code_is_granted_and_runs_the_backend() {
        let home = tmp_home("totp-granted");
        let mut p = Policy::new("t", "scratch", "stored-value");
        p.consumers = vec!["m".to_string()];
        let secret = seed_enrolled(&home, p);
        let code = code_for_now(&secret, NOW);

        let (granted, result) = gate_outcome_as_result(resolve_gate(&home, "t", "m", Some(&code), NOW, None));
        assert!(granted, "{result:?}");
        assert_eq!(result.unwrap(), "stored-value");
        std::fs::remove_dir_all(&home).ok();
    }

    /// P-N2: enrolled + `requireTotp` + no code no longer means an
    /// immediate denial — it's now the PARK candidate (`GateOutcome::
    /// NeedsTotp`); `broker::handle_resolve` is what turns that into an
    /// actual park (or, with `wait:false`, this exact old denial string —
    /// see the wire-level `wait_false_...` test below for that half).
    #[test]
    fn enrolled_with_no_code_needs_totp_a_park_candidate_not_an_immediate_denial() {
        let home = tmp_home("totp-missingcode");
        let p = Policy::new("t", "scratch", "stored-value");
        seed_enrolled(&home, p);

        let outcome = resolve_gate(&home, "t", "m", None, NOW, None);
        assert!(matches!(outcome, GateOutcome::NeedsTotp), "expected NeedsTotp");
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn enrolled_with_the_wrong_code_is_denied() {
        let home = tmp_home("totp-wrongcode");
        let p = Policy::new("t", "scratch", "stored-value");
        let secret = seed_enrolled(&home, p);
        let correct = code_for_now(&secret, NOW);
        // Any 6-digit code that isn't the correct one.
        let wrong_num: u32 = (correct.parse::<u32>().unwrap() + 1) % 1_000_000;
        let wrong = crate::totp::format6(wrong_num);

        let (granted, result) = gate_outcome_as_result(resolve_gate(&home, "t", "m", Some(&wrong), NOW, None));
        assert!(!granted);
        assert!(result.unwrap_err().contains("invalid or expired"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn a_malformed_totp_code_is_denied_without_panicking() {
        let home = tmp_home("totp-malformed");
        let p = Policy::new("t", "scratch", "stored-value");
        seed_enrolled(&home, p);

        let (granted, result) = gate_outcome_as_result(resolve_gate(&home, "t", "m", Some("not-a-number"), NOW, None));
        assert!(!granted);
        assert!(result.unwrap_err().contains("malformed"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn the_same_code_used_twice_is_denied_the_second_time_replay() {
        let home = tmp_home("totp-replay");
        // Empty consumers list = any consumer — so BOTH calls clear the
        // authorization check, isolating the replay/ledger behavior this
        // test is actually about (a consumer mismatch would deny the
        // second call for the WRONG reason).
        let p = Policy::new("t", "scratch", "stored-value");
        let secret = seed_enrolled(&home, p);
        let code = code_for_now(&secret, NOW);

        let (first_granted, first_result) = gate_outcome_as_result(resolve_gate(&home, "t", "m", Some(&code), NOW, None));
        assert!(first_granted, "{first_result:?}");

        // A second, DIFFERENT claimed consumer doesn't matter — the ledger
        // keys on timestep alone (this crate's AGENTS.md ruling: the
        // resolve wire's `consumer` field is self-asserted, so a
        // per-consumer ledger would let one typed code redeem once per
        // invented label).
        let (second_granted, second_result) = gate_outcome_as_result(resolve_gate(&home, "t", "someone-else-entirely", Some(&code), NOW, None));
        assert!(!second_granted);
        assert!(second_result.unwrap_err().contains("already used"));
        std::fs::remove_dir_all(&home).ok();
    }

    /// The ledger persistence requirement, exercised directly against
    /// `resolve_gate`: a SEPARATE call — standing in for "after a broker
    /// restart", since `resolve_gate` never caches the ledger in memory —
    /// still refuses the timestep an earlier call consumed, because the
    /// only state connecting the two calls is the file on disk.
    #[test]
    fn a_spent_code_stays_spent_across_a_simulated_broker_restart() {
        let home = tmp_home("totp-restart");
        let mut p = Policy::new("t", "scratch", "stored-value");
        p.consumers = vec!["m".to_string()];
        let secret = seed_enrolled(&home, p);
        let code = code_for_now(&secret, NOW);

        let (granted, _) = gate_outcome_as_result(resolve_gate(&home, "t", "m", Some(&code), NOW, None));
        assert!(granted);

        // Nothing here reuses any in-process state from the call above —
        // this is exactly what a fresh broker process would do.
        let ledger_after_restart = crate::store::load_replay_ledger(&home).unwrap();
        let step = crate::totp::timestep(NOW);
        assert!(ledger_after_restart.is_used(step), "the ledger file must have the spent timestep");

        let (granted_again, result_again) = gate_outcome_as_result(resolve_gate(&home, "t", "m", Some(&code), NOW, None));
        assert!(!granted_again);
        assert!(result_again.unwrap_err().contains("already used"));
        std::fs::remove_dir_all(&home).ok();
    }

    /// Every TOTP denial path must short-circuit BEFORE the backend ever
    /// runs — same "positive control" discipline as `tests/e2e.rs`'s
    /// backend-invoked marker.
    #[test]
    fn totp_denial_paths_never_invoke_the_backend() {
        let home = tmp_home("totp-marker");
        let marker = home.join("backend-invoked-marker");
        let mut p = Policy::new("t", "scratch", "stored-value");
        p.require_totp = true;
        p.consumers = vec!["m".to_string()];
        seed(&home, &[p]);
        let secret = b"a-twenty-byte-totp-s".to_vec();
        crate::store::save_totp_secret(&home, &secret).unwrap();
        // Overwrite the fixture backend so it touches a marker before
        // producing output — same technique as `tests/e2e.rs`.
        let backends = serde_json::json!({
            "scratch": { "get": format!("touch {} && printf %s {{name}}", marker.display()) }
        });
        std::fs::write(crate::backend::backends_path(&home), serde_json::to_vec(&backends).unwrap()).unwrap();

        let code = code_for_now(&secret, NOW);
        let wrong_num: u32 = (code.parse::<u32>().unwrap() + 1) % 1_000_000;
        let wrong = crate::totp::format6(wrong_num);

        // No code (now a PARK candidate, P-N2 — never an immediate denial,
        // but still must never touch the backend), wrong code, replay
        // (after one legitimate grant) — every one of these must leave the
        // marker untouched.
        let outcome = resolve_gate(&home, "t", "m", None, NOW, None);
        assert!(matches!(outcome, GateOutcome::NeedsTotp), "expected NeedsTotp");
        assert!(!marker.exists(), "backend ran on a needs-totp (would-park) case");

        let (granted, _) = gate_outcome_as_result(resolve_gate(&home, "t", "m", Some(&wrong), NOW, None));
        assert!(!granted);
        assert!(!marker.exists(), "backend ran on a wrong-code denial");

        let (granted, _) = gate_outcome_as_result(resolve_gate(&home, "t", "m", Some(&code), NOW, None));
        assert!(granted, "the legitimate code should be granted (and now the marker DOES exist)");
        assert!(marker.exists(), "positive control: the backend must run on a granted resolve");
        std::fs::remove_file(&marker).unwrap();

        let (granted, _) = gate_outcome_as_result(resolve_gate(&home, "t", "m", Some(&code), NOW, None));
        assert!(!granted, "the same code must be denied the second time (replay)");
        assert!(!marker.exists(), "backend ran on a replay denial");

        std::fs::remove_dir_all(&home).ok();
    }

    // ── automation gate (P-N1) ──────────────────────────────────────────

    /// The end-to-end proof `crate::policy::totp_required`'s own unit
    /// tests can't give alone: a `requireTotp` policy whose automation is
    /// OPEN and lists the calling consumer resolves through the REAL
    /// broker gate with no `totp` field on the wire at all.
    #[test]
    fn automation_open_and_listed_consumer_resolves_without_a_totp_code() {
        let home = tmp_home("automation-open");
        let mut p = Policy::new("t", "scratch", "stored-value");
        p.require_totp = true;
        p.automation.enabled = true;
        p.automation.consumers = vec!["m".to_string()];
        // No `secrets enroll` on this host at all — proves the code path
        // never even reaches `verify_totp_gate` (which would deny with "no
        // TOTP enrollment" otherwise).
        seed(&home, &[p]);

        let (granted, result) = gate_outcome_as_result(resolve_gate(&home, "t", "m", None, NOW, None));
        assert!(granted, "{result:?}");
        assert_eq!(result.unwrap(), "stored-value");
        std::fs::remove_dir_all(&home).ok();
    }

    /// The same policy, an UNLISTED consumer — still gated, exactly as
    /// before this field existed (no enrollment on this host, so the
    /// denial is the "no TOTP enrollment" one).
    #[test]
    fn automation_open_but_unlisted_consumer_is_still_gated() {
        let home = tmp_home("automation-unlisted");
        let mut p = Policy::new("t", "scratch", "stored-value");
        p.require_totp = true;
        p.automation.enabled = true;
        p.automation.consumers = vec!["m".to_string()];
        seed(&home, &[p]);

        let (granted, result) = gate_outcome_as_result(resolve_gate(&home, "t", "someone-else", None, NOW, None));
        assert!(!granted);
        assert!(result.unwrap_err().contains("no TOTP enrollment"));
        std::fs::remove_dir_all(&home).ok();
    }

    /// Automation CLOSED (the default) — the exact same policy shape minus
    /// `enabled`, still fully gated for the consumer that would have been
    /// listed had it been open.
    #[test]
    fn automation_disabled_is_gated_exactly_like_before_this_field_existed() {
        let home = tmp_home("automation-closed");
        let mut p = Policy::new("t", "scratch", "stored-value");
        p.require_totp = true;
        p.automation.consumers = vec!["m".to_string()]; // listed, but NOT enabled
        seed(&home, &[p]);

        let (granted, result) = gate_outcome_as_result(resolve_gate(&home, "t", "m", None, NOW, None));
        assert!(!granted);
        assert!(result.unwrap_err().contains("no TOTP enrollment"));
        std::fs::remove_dir_all(&home).ok();
    }

    // ── socket permissions (P-V4) ───────────────────────────────────────

    #[test]
    fn bind_socket_chmods_the_socket_file_to_0660() {
        let home = tmp_home("sockmode");
        let socket_path = home.join("secrets.sock");
        let listener = bind_socket(&socket_path).unwrap();
        let mode = std::fs::metadata(&socket_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660, "secrets socket must be group-connectable (0660), got {mode:o}");
        drop(listener);
        std::fs::remove_dir_all(&home).ok();
    }

    // ── wire framing (handle_line) ──────────────────────────────────────

    #[test]
    fn malformed_json_gets_a_reply_not_a_dropped_connection() {
        let home = tmp_home("malformed");
        let reply = handle_line(&home, &home.join("events.jsonl"), "not json at all", &ParkRegistry::new(), &mut Vec::new(), None);
        assert_eq!(reply["ok"], false);
        assert!(reply["error"].as_str().unwrap().contains("not valid JSON"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn missing_op_is_a_clear_error() {
        let home = tmp_home("missingop");
        let reply = handle_line(&home, &home.join("events.jsonl"), r#"{"secret":"t","consumer":"m"}"#, &ParkRegistry::new(), &mut Vec::new(), None);
        assert_eq!(reply["ok"], false);
        assert!(reply["error"].as_str().unwrap().contains("missing `op`"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn unknown_op_is_a_clear_error() {
        let home = tmp_home("unknownop");
        let reply = handle_line(&home, &home.join("events.jsonl"), r#"{"op":"explode"}"#, &ParkRegistry::new(), &mut Vec::new(), None);
        assert_eq!(reply["ok"], false);
        assert!(reply["error"].as_str().unwrap().contains("unknown op"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn resolve_with_missing_fields_is_malformed() {
        let home = tmp_home("missingfields");
        let reply = handle_line(&home, &home.join("events.jsonl"), r#"{"op":"resolve","secret":"t"}"#, &ParkRegistry::new(), &mut Vec::new(), None);
        assert_eq!(reply["ok"], false);
        assert!(reply["error"].as_str().unwrap().contains("required"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn a_full_resolve_line_round_trips_the_value() {
        // `handle_line` -> `handle_resolve` -> `audit_resolve` writes the
        // MIRRORED aoide audit log too, via `aoide_protocol::
        // default_audit_log()` — redirect it into this test's own tempdir
        // (`env_lock`, restored after) so the test never touches the real
        // `~/Aoide/log`. The broker's OWN `audit.log` lives under `home`
        // regardless, no redirection needed for that half.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_AUDIT_LOG").ok();
        let home = tmp_home("fullline");
        std::env::set_var("AOIDE_AUDIT_LOG", home.join("mirrored-aoide-log"));

        let p = Policy::new("t", "scratch", "stored-value");
        seed(&home, &[p]);
        let reply = handle_line(&home, &home.join("events.jsonl"), r#"{"op":"resolve","secret":"t","consumer":"m"}"#, &ParkRegistry::new(), &mut Vec::new(), None);
        assert_eq!(reply["ok"], true);
        assert_eq!(reply["value"], "stored-value");

        match saved {
            Some(v) => std::env::set_var("AOIDE_AUDIT_LOG", v),
            None => std::env::remove_var("AOIDE_AUDIT_LOG"),
        }
        std::fs::remove_dir_all(&home).ok();
    }

    /// Bounce-fix item 1 (P-V2 review), full path: a backend that dumps a
    /// sentinel to stderr and fails must not leak that sentinel through
    /// EITHER audit line OR the wire reply — `backend::fetch_value` already
    /// proves the `Err` string is clean in isolation; this proves the
    /// guarantee survives all the way through `handle_line` ->
    /// `audit_resolve`'s `reason` field on both logs.
    #[test]
    fn a_backend_stderr_sentinel_never_reaches_the_wire_reply_or_either_audit_log() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_AUDIT_LOG").ok();
        let home = tmp_home("stderrleak");
        std::env::set_var("AOIDE_AUDIT_LOG", home.join("mirrored-aoide-log"));

        let p = Policy::new("t", "scratch", "stored-value");
        crate::store::save_policies(&home, &[p]).unwrap();
        let backends = serde_json::json!({
            "scratch": { "get": "printf 'SENTINEL-STDERR-XYZ' 1>&2; exit 1" }
        });
        std::fs::write(crate::backend::backends_path(&home), serde_json::to_vec(&backends).unwrap()).unwrap();

        let reply = handle_line(&home, &home.join("events.jsonl"), r#"{"op":"resolve","secret":"t","consumer":"m"}"#, &ParkRegistry::new(), &mut Vec::new(), None);
        assert_eq!(reply["ok"], false);
        let wire_error = reply["error"].as_str().unwrap();
        assert!(!wire_error.contains("SENTINEL"), "wire reply leaked stderr: {wire_error}");

        let own_log = std::fs::read_to_string(own_audit_log_path(&home)).unwrap();
        assert!(!own_log.contains("SENTINEL"), "the broker's own audit.log leaked stderr: {own_log}");

        let mirrored_log = std::fs::read_to_string(home.join("mirrored-aoide-log")).unwrap();
        assert!(!mirrored_log.contains("SENTINEL"), "mirrored aoide audit log leaked stderr: {mirrored_log}");

        match saved {
            Some(v) => std::env::set_var("AOIDE_AUDIT_LOG", v),
            None => std::env::remove_var("AOIDE_AUDIT_LOG"),
        }
        std::fs::remove_dir_all(&home).ok();
    }

    // ── `put` (P-V4c) ────────────────────────────────────────────────────

    fn seed_with_set(home: &Path, policies: &[Policy], get: &str, set: &str) {
        crate::store::save_policies(home, policies).unwrap();
        let backends = serde_json::json!({ "scratch": { "get": get, "set": set } });
        std::fs::write(crate::backend::backends_path(home), serde_json::to_vec(&backends).unwrap()).unwrap();
    }

    /// Unpacks [`PutOutcome`] into the pre-P-67 `(granted, Result<replaced,
    /// error>)` tuple shape most of this suite's existing assertions were
    /// written against — keeps those readable without a `match` at every
    /// call site. `DeniedExists` collapses to a plain `Err` here (its own
    /// distinct shape is exercised directly by the P-67 tests below).
    fn put_outcome_as_result(outcome: PutOutcome) -> (bool, Result<bool, String>) {
        match outcome {
            PutOutcome::Granted { replaced, .. } => (true, Ok(replaced)),
            PutOutcome::DeniedExists => (false, Err("secret already has a stored value".to_string())),
            PutOutcome::Denied(reason) => (false, Err(reason)),
        }
    }

    #[test]
    fn put_on_an_unknown_secret_is_denied_and_never_invokes_a_backend() {
        let home = tmp_home("put-unknown");
        seed(&home, &[]);
        let (granted, result) = put_outcome_as_result(put_gate(&home, "nope", "irrelevant", false));
        assert!(!granted);
        assert_eq!(result.unwrap_err(), "secret not found");
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn put_on_a_backend_with_no_set_template_is_a_clean_error() {
        let home = tmp_home("put-noset");
        let p = Policy::new("t", "scratch", "k");
        seed(&home, &[p]); // `seed`'s fixture backend has only `get`.
        // `overwrite: true` — `seed`'s fixture `get` (`printf %s {name}`)
        // always succeeds, so an `overwrite: false` attempt would hit the
        // NEW `DeniedExists` path first; forcing `overwrite` here is what
        // keeps this test actually exercising the missing-`set`-template
        // error, same as before P-67.
        let (granted, result) = put_outcome_as_result(put_gate(&home, "t", "irrelevant", true));
        assert!(!granted);
        assert!(result.unwrap_err().contains("no `set` template"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn a_granted_put_writes_through_the_named_backends_set_template() {
        let home = tmp_home("put-granted");
        let out = home.join("out.txt");
        let p = Policy::new("t", "scratch", "k");
        seed_with_set(&home, &[p], &format!("cat {}", out.display()), &format!("cat > {}", out.display()));

        let (granted, result) = put_outcome_as_result(put_gate(&home, "t", "the-stored-value", false));
        assert!(granted, "{result:?}");
        assert_eq!(result.unwrap(), false, "the store dir starts empty — this is a NEW store, not a replace");
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "the-stored-value");
        std::fs::remove_dir_all(&home).ok();
    }

    /// `put` never checks `requireTotp` — even a policy with it set is
    /// storable without any code at all (module doc: put is CLI-only/
    /// admin-side, not agent-facing).
    #[test]
    fn put_ignores_require_totp_entirely() {
        let home = tmp_home("put-ignorestotp");
        let out = home.join("out.txt");
        let mut p = Policy::new("t", "scratch", "k");
        p.require_totp = true;
        seed_with_set(&home, &[p], &format!("cat {}", out.display()), &format!("cat > {}", out.display()));

        let (granted, result) = put_outcome_as_result(put_gate(&home, "t", "value-with-no-totp-anywhere", false));
        assert!(granted, "{result:?}");
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "value-with-no-totp-anywhere");
        std::fs::remove_dir_all(&home).ok();
    }

    // ── the built-in `age` backend (P-G1, task #70) ─────────────────────

    /// Same feature-detection idiom `backend.rs`'s own age tests use — a
    /// spawn attempt, not a `PATH` scan — so this test skips with a
    /// printed reason on a box without `age`/`age-keygen` rather than
    /// failing.
    fn age_tools_available() -> bool {
        let age_keygen = std::process::Command::new("age-keygen").arg("--version").output();
        let age = std::process::Command::new("age").arg("--version").output();
        matches!(age_keygen, Ok(o) if o.status.code().is_some()) && matches!(age, Ok(o) if o.status.code().is_some())
    }

    /// `handle_put` (via [`put_gate`]) lazily mints the age identity on the
    /// FIRST `age`-backed put and fires the "age identity minted" notify
    /// event through the SAME two destinations every other `emit_notify`
    /// call writes to; a SECOND put through the same identity (even for a
    /// different secret) must never mint or notify again.
    #[test]
    fn a_put_on_an_age_backed_secret_mints_the_identity_once_and_notifies_only_then() {
        if !age_tools_available() {
            eprintln!(
                "skipping a_put_on_an_age_backed_secret_mints_the_identity_once_and_notifies_only_then: \
                 age/age-keygen not found on PATH"
            );
            return;
        }
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("put-age-mint-notify");
        crate::backend::seed_default_backends(&home).unwrap();
        crate::store::save_policies(&home, &[Policy::new("t", "age", "t")]).unwrap();
        let parked = ParkRegistry::new();

        with_redirected_audit_log(&home, || {
            let reply =
                handle_line(&home, &home.join("events.jsonl"), r#"{"op":"put","secret":"t","value":"the-stored-value"}"#, &parked, &mut Vec::new(), None);
            assert_eq!(reply["ok"], true, "{reply}");
        });

        let own_lines = own_log_lines(&home);
        let ev = find_notify_event(&own_lines, "age-identity-minted");
        assert!(!ev.to_string().contains("the-stored-value"), "the notify event leaked the value: {ev}");
        let mirrored_lines = mirrored_log_lines(&home);
        let mirrored = find_mirrored_notify(&mirrored_lines, "age-identity-minted");
        assert!(!mirrored.to_string().contains("the-stored-value"), "{mirrored}");

        // A second put — a DIFFERENT secret, same already-minted identity —
        // must not mint or notify a second time.
        crate::store::save_policies(&home, &[Policy::new("t", "age", "t"), Policy::new("t2", "age", "t2")]).unwrap();
        with_redirected_audit_log(&home, || {
            let reply =
                handle_line(&home, &home.join("events.jsonl"), r#"{"op":"put","secret":"t2","value":"another-value"}"#, &parked, &mut Vec::new(), None);
            assert_eq!(reply["ok"], true, "{reply}");
        });
        let mint_events = own_log_lines(&home)
            .iter()
            .filter(|l| l.get("event").and_then(Value::as_str) == Some("age-identity-minted"))
            .count();
        assert_eq!(mint_events, 1, "the identity must be minted exactly once across both puts");

        std::fs::remove_dir_all(&home).ok();
    }

    /// P-G1 review fix (task #70): on an EXISTING deployment whose
    /// `backends.json` predates this phase (`file` only, no `age` entry —
    /// see `backend.rs`'s sibling test for the identical GET-side gap), a
    /// policy recorded via `secrets add`'s new age-default records
    /// `backend: "age"` even though `age` isn't configured anywhere on
    /// disk. `put_gate` must not mint a REAL identity — real
    /// `age-keygen` calls, real `age.key`/`age.recipient` files written to
    /// this secrets home — for a `put` that is doomed to fail with
    /// "unknown backend `age`" the instant `has_value`/`store_value` look
    /// the name up. Uses a fake `age-keygen` shim (this crate's own
    /// `enroll.rs` precedent for a PATH-shimmed external tool) so this
    /// runs deterministically with no real `age` install and no
    /// `age_tools_available()` skip.
    #[test]
    fn put_never_mints_an_age_identity_for_a_backend_not_configured_in_backends_json() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("put-age-unconfigured-no-mint");
        std::fs::create_dir_all(&home).unwrap();
        // Pre-P-G1 shape: `file` only, no `age` entry at all.
        std::fs::write(
            crate::backend::backends_path(&home),
            br#"{"file":{"get":"cat {home}/store/{name}","set":"install -m 0600 /dev/stdin {home}/store/{name}"}}"#,
        )
        .unwrap();
        crate::store::save_policies(&home, &[Policy::new("t", "age", "t")]).unwrap();

        use std::os::unix::fs::PermissionsExt;
        // A fake `age-keygen` that would succeed if ever invoked — proves
        // a REAL mint attempt, not merely a missing-binary short-circuit.
        let shim_dir = std::env::temp_dir().join(format!(
            "aoide-secrets-broker-test-age-keygen-shim-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&shim_dir).unwrap();
        let shim = shim_dir.join("age-keygen");
        std::fs::write(
            &shim,
            "#!/bin/sh\nif [ \"$1\" = \"-y\" ]; then echo age1fakerecipient > \"$3\"; else echo AGE-SECRET-KEY-1FAKE > \"$2\"; fi\n",
        )
        .unwrap();
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        let saved_path = std::env::var("PATH").ok();
        std::env::set_var("PATH", format!("{}:{}", shim_dir.display(), saved_path.clone().unwrap_or_default()));

        let outcome = put_gate(&home, "t", "the-stored-value", false);

        match saved_path {
            Some(p) => std::env::set_var("PATH", p),
            None => std::env::remove_var("PATH"),
        }

        assert!(
            matches!(&outcome, PutOutcome::Denied(e) if e == "unknown backend `age`"),
            "expected Denied(\"unknown backend `age`\"), got {outcome:?}"
        );
        assert!(
            !home.join("age.key").exists(),
            "put_gate must not mint a real identity for a backend `backends.json` never configured"
        );
        assert!(!home.join("age.recipient").exists());

        std::fs::remove_dir_all(&home).ok();
        std::fs::remove_dir_all(&shim_dir).ok();
    }

    // ── overwrite (P-67, "warn before overwrite") ───────────────────────

    #[test]
    fn put_gate_on_an_existing_value_without_overwrite_is_a_distinct_exists_denial_and_leaves_the_value_unchanged() {
        let home = tmp_home("put-exists-denied");
        let out = home.join("out.txt");
        let p = Policy::new("t", "scratch", "k");
        seed_with_set(&home, &[p], &format!("cat {}", out.display()), &format!("cat > {}", out.display()));

        // Store a first value directly (bypassing the gate) so the probe
        // has something to find.
        std::fs::write(&out, "original-value").unwrap();

        let outcome = put_gate(&home, "t", "attempted-overwrite", false);
        assert!(matches!(outcome, PutOutcome::DeniedExists), "expected DeniedExists, got a different outcome");
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "original-value", "a denied put must never touch the store");
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn put_gate_with_overwrite_true_replaces_an_existing_value() {
        let home = tmp_home("put-overwrite-granted");
        let out = home.join("out.txt");
        let p = Policy::new("t", "scratch", "k");
        seed_with_set(&home, &[p], &format!("cat {}", out.display()), &format!("cat > {}", out.display()));
        std::fs::write(&out, "original-value").unwrap();

        let (granted, result) = put_outcome_as_result(put_gate(&home, "t", "new-value", true));
        assert!(granted, "{result:?}");
        assert_eq!(result.unwrap(), true, "an existing value was overwritten — `replaced` must be true");
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "new-value");
        std::fs::remove_dir_all(&home).ok();
    }

    // ── bounded backend shell-outs (task #74) ───────────────────────────

    /// The scenario `AGENTS.md`'s KNOWN GAP note named directly: a hung
    /// `set` template used to hold `put_lock` for as long as the hang
    /// lasted, wedging every OTHER `put` on this broker behind it. With
    /// the backend choke point now bounded (`backend::run_backend_command`,
    /// task #74), `put_gate` — the function that actually acquires and
    /// releases `put_lock` — must return within the timeout instead of
    /// hanging: a fresh secret with no existing value, so `put_gate` runs
    /// straight through the existence probe into the `set` template that
    /// hangs, all under the SAME `put_lock` critical section the KNOWN GAP
    /// note describes.
    #[test]
    fn a_hung_set_template_no_longer_wedges_put_lock_forever() {
        let home = tmp_home("put-hung-set-bounded");
        let p = Policy::new("t", "scratch", "k");
        seed_with_set(&home, &[p], "false", "sleep 60");

        let saved = std::env::var(crate::backend::BACKEND_TIMEOUT_ENV).ok();
        std::env::set_var(crate::backend::BACKEND_TIMEOUT_ENV, "1");
        let start = std::time::Instant::now();
        let outcome = put_gate(&home, "t", "the-value", false);
        let elapsed = start.elapsed();
        match saved {
            Some(v) => std::env::set_var(crate::backend::BACKEND_TIMEOUT_ENV, v),
            None => std::env::remove_var(crate::backend::BACKEND_TIMEOUT_ENV),
        }

        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "put_gate against a hung set template took {elapsed:?} — put_lock was not freed in bounded time"
        );
        assert!(
            matches!(&outcome, PutOutcome::Denied(e) if e.contains("timed out")),
            "expected a timeout denial, got {outcome:?}"
        );
        std::fs::remove_dir_all(&home).ok();
    }

    /// A second `put_gate` call, run immediately after the hung one above
    /// returns, must not itself see any lingering effect of the first —
    /// proving `put_lock` was genuinely released, not merely that the
    /// first call's own thread gave up waiting on it.
    #[test]
    fn put_lock_is_free_for_the_next_caller_right_after_a_timeout() {
        let home = tmp_home("put-lock-freed-for-next-caller");
        let out = home.join("out.txt");
        let p1 = Policy::new("hangs", "hangs", "k");
        let p2 = Policy::new("t", "scratch", "k");
        crate::store::save_policies(&home, &[p1, p2]).unwrap();
        let backends = serde_json::json!({
            "hangs": { "get": "false", "set": "sleep 60" },
            "scratch": { "get": format!("cat {}", out.display()), "set": format!("cat > {}", out.display()) },
        });
        std::fs::write(crate::backend::backends_path(&home), serde_json::to_vec(&backends).unwrap()).unwrap();

        let saved = std::env::var(crate::backend::BACKEND_TIMEOUT_ENV).ok();
        std::env::set_var(crate::backend::BACKEND_TIMEOUT_ENV, "1");
        let first = put_gate(&home, "hangs", "irrelevant", false);
        let (granted, result) = put_outcome_as_result(put_gate(&home, "t", "second-caller-value", false));
        match saved {
            Some(v) => std::env::set_var(crate::backend::BACKEND_TIMEOUT_ENV, v),
            None => std::env::remove_var(crate::backend::BACKEND_TIMEOUT_ENV),
        }

        assert!(matches!(first, PutOutcome::Denied(_)), "the hung put must be denied, not granted: {first:?}");
        assert!(granted, "the second, unrelated put must succeed once put_lock is freed: {result:?}");
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "second-caller-value");
        std::fs::remove_dir_all(&home).ok();
    }

    /// The SAME `put_lock`-freed proof as the two tests above, but for the
    /// OTHER unbounded shell-out `put_gate` could run inside its critical
    /// section (P-G3 review fix): a first `age`-backed put with no existing
    /// identity has to mint one FIRST, inside `put_lock` (module doc, "a
    /// `policy.backend == \"age\"` put also lazily mints... inside the SAME
    /// `put_lock` critical section"). A PATH-shimmed hanging `age-keygen`
    /// (no real `age` binary needed — same shim technique `backend.rs`'s own
    /// `age-keygen` timeout test uses) proves that hang is now ALSO bounded,
    /// and that `put_lock` is free for a second, unrelated put right after —
    /// closing the exact gap a hung mint would otherwise have reopened.
    #[test]
    fn a_hung_age_keygen_mint_no_longer_wedges_put_lock_forever() {
        let shim_dir = std::env::temp_dir().join(format!(
            "aoide-secrets-broker-age-keygen-shim-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&shim_dir).unwrap();
        let shim = shim_dir.join("age-keygen");
        std::fs::write(&shim, "#!/bin/sh\nsleep 60\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("put-hung-mint-bounded");
        let out = home.join("out.txt");
        let p_age = Policy::new("mints", "age", "k");
        let p_scratch = Policy::new("t", "scratch", "k");
        crate::store::save_policies(&home, &[p_age, p_scratch]).unwrap();
        // A REAL `age` entry (never seeded via `age-keygen` here — this
        // exercises the mint path, which is what must be bounded), plus an
        // ordinary `scratch` backend for the second, unrelated caller.
        let backends = serde_json::json!({
            "age": { "get": "cat {home}/values/{name}.age", "set": "cat > {home}/values/{name}.age" },
            "scratch": { "get": format!("cat {}", out.display()), "set": format!("cat > {}", out.display()) },
        });
        std::fs::write(crate::backend::backends_path(&home), serde_json::to_vec(&backends).unwrap()).unwrap();

        let saved_path = std::env::var("PATH").ok();
        let new_path = format!("{}:{}", shim_dir.display(), saved_path.clone().unwrap_or_default());
        std::env::set_var("PATH", &new_path);
        let saved_timeout = std::env::var(crate::backend::BACKEND_TIMEOUT_ENV).ok();
        std::env::set_var(crate::backend::BACKEND_TIMEOUT_ENV, "1");

        let start = std::time::Instant::now();
        let first = put_gate(&home, "mints", "irrelevant", false);
        let elapsed = start.elapsed();
        let (granted, result) = put_outcome_as_result(put_gate(&home, "t", "second-caller-value", false));

        match saved_path {
            Some(p) => std::env::set_var("PATH", p),
            None => std::env::remove_var("PATH"),
        }
        match saved_timeout {
            Some(v) => std::env::set_var(crate::backend::BACKEND_TIMEOUT_ENV, v),
            None => std::env::remove_var(crate::backend::BACKEND_TIMEOUT_ENV),
        }

        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "put_gate against a hung age-keygen mint took {elapsed:?} — put_lock was not freed in bounded time"
        );
        assert!(matches!(&first, PutOutcome::Denied(_)), "the hung mint must be denied, not granted: {first:?}");
        assert!(!home.join("age.key").exists(), "a hung mint must never leave a half-written identity behind");
        assert!(granted, "the second, unrelated put must succeed once put_lock is freed: {result:?}");
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "second-caller-value");

        std::fs::remove_dir_all(&home).ok();
        std::fs::remove_dir_all(&shim_dir).ok();
    }

    /// The wire-level version of the two tests above, through `handle_line`
    /// — this is the deliverable's own end-to-end proof: a first `put`
    /// stores; a second `put` (no `overwrite`) is refused with the
    /// `exists` flag and leaves the stored value untouched; a third `put`
    /// with `overwrite:true` replaces it.
    #[test]
    fn a_full_put_overwrite_cycle_round_trips_through_handle_line() {
        let home = tmp_home("put-overwrite-wire");
        let out = home.join("out.txt");
        let p = Policy::new("t", "scratch", "k");
        seed_with_set(&home, &[p], &format!("cat {}", out.display()), &format!("cat > {}", out.display()));

        // 1. Empty -> stores, `replaced` is false.
        let first = handle_line(&home, &home.join("events.jsonl"), r#"{"op":"put","secret":"t","value":"first-value"}"#, &ParkRegistry::new(), &mut Vec::new(), None);
        assert_eq!(first["ok"], true, "{first}");
        assert_eq!(first["replaced"], false, "{first}");
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "first-value");

        // 2. Existing, no `overwrite` -> the distinct `exists` refusal, and
        //    the stored value is UNCHANGED.
        let second = handle_line(&home, &home.join("events.jsonl"), r#"{"op":"put","secret":"t","value":"attempted-overwrite"}"#, &ParkRegistry::new(), &mut Vec::new(), None);
        assert_eq!(second["ok"], false, "{second}");
        assert_eq!(second["exists"], true, "the refusal must be machine-readable via `exists`, not error prose: {second}");
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "first-value", "a refused put must never touch the store");

        // 3. Existing, `overwrite: true` -> replaced, `replaced` is true.
        let third = handle_line(&home, &home.join("events.jsonl"), r#"{"op":"put","secret":"t","value":"second-value","overwrite":true}"#, &ParkRegistry::new(), &mut Vec::new(), None);
        assert_eq!(third["ok"], true, "{third}");
        assert_eq!(third["replaced"], true, "{third}");
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "second-value");

        std::fs::remove_dir_all(&home).ok();
    }

    /// Wire compatibility (task requirement): an absent `overwrite` field
    /// is read exactly like `overwrite: false` — an old client's request
    /// line, sent against a new broker, still gets the tightened refusal on
    /// a second `put`.
    #[test]
    fn an_absent_overwrite_field_behaves_exactly_like_false() {
        let home = tmp_home("put-overwrite-absent");
        let out = home.join("out.txt");
        let p = Policy::new("t", "scratch", "k");
        seed_with_set(&home, &[p], &format!("cat {}", out.display()), &format!("cat > {}", out.display()));
        std::fs::write(&out, "original-value").unwrap();

        let with_false = handle_line(&home, &home.join("events.jsonl"), r#"{"op":"put","secret":"t","value":"x","overwrite":false}"#, &ParkRegistry::new(), &mut Vec::new(), None);
        let without_field = handle_line(&home, &home.join("events.jsonl"), r#"{"op":"put","secret":"t","value":"x"}"#, &ParkRegistry::new(), &mut Vec::new(), None);
        assert_eq!(with_false, without_field, "an explicit `overwrite:false` and an absent field must match byte-for-byte");
        assert_eq!(with_false["exists"], true, "{with_false}");
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn a_full_put_line_round_trips_through_handle_line_with_no_value_in_the_reply() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_AUDIT_LOG").ok();
        let home = tmp_home("put-fullline");
        std::env::set_var("AOIDE_AUDIT_LOG", home.join("mirrored-aoide-log"));

        let out = home.join("out.txt");
        let p = Policy::new("t", "scratch", "k");
        seed_with_set(&home, &[p], &format!("cat {}", out.display()), &format!("cat > {}", out.display()));

        let reply = handle_line(&home, &home.join("events.jsonl"), r#"{"op":"put","secret":"t","value":"stored-value"}"#, &ParkRegistry::new(), &mut Vec::new(), None);
        assert_eq!(reply["ok"], true);
        assert!(reply.get("value").is_none(), "put's reply must never carry a value: {reply}");
        assert_eq!(reply["replaced"], false, "the store starts empty — this is a new store, not a replace: {reply}");
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "stored-value");

        match saved {
            Some(v) => std::env::set_var("AOIDE_AUDIT_LOG", v),
            None => std::env::remove_var("AOIDE_AUDIT_LOG"),
        }
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn put_with_a_missing_secret_field_is_malformed() {
        let home = tmp_home("put-missingfields");
        let reply = handle_line(&home, &home.join("events.jsonl"), r#"{"op":"put","value":"x"}"#, &ParkRegistry::new(), &mut Vec::new(), None);
        assert_eq!(reply["ok"], false);
        assert!(reply["error"].as_str().unwrap().contains("required"));
        std::fs::remove_dir_all(&home).ok();
    }

    /// The sentinel test (P-V4c phase brief): a put of a sentinel value,
    /// forced through BOTH failure paths (missing policy, missing `set`
    /// template), must leave the sentinel out of the wire reply AND both
    /// audit logs on every single attempt.
    #[test]
    fn put_sentinel_value_never_leaks_on_missing_policy_or_missing_set_template() {
        const SENTINEL: &str = "SENTINEL-PUT-VALUE-XYZ";
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_AUDIT_LOG").ok();
        let home = tmp_home("put-sentinel");
        std::env::set_var("AOIDE_AUDIT_LOG", home.join("mirrored-aoide-log"));

        // ── failure 1: no policy at all for this secret ────────────────
        seed(&home, &[]);
        let reply = handle_line(&home, &home.join("events.jsonl"), &format!(r#"{{"op":"put","secret":"nope","value":"{SENTINEL}"}}"#), &ParkRegistry::new(), &mut Vec::new(), None);
        assert_eq!(reply["ok"], false);
        assert!(!reply.to_string().contains(SENTINEL), "wire reply leaked the sentinel: {reply}");

        // ── failure 2: policy exists, but its backend has no `set` ─────
        // `overwrite: true` forces past the NEW existence-probe path
        // (`seed`'s fixture `get` always succeeds) so this still exercises
        // the missing-`set`-template denial specifically, same as before
        // P-67.
        let p = Policy::new("t", "scratch", "k");
        seed(&home, &[p]); // `seed`'s fixture backend is get-only.
        let reply =
            handle_line(&home, &home.join("events.jsonl"), &format!(r#"{{"op":"put","secret":"t","value":"{SENTINEL}","overwrite":true}}"#), &ParkRegistry::new(), &mut Vec::new(), None);
        assert_eq!(reply["ok"], false);
        assert!(!reply.to_string().contains(SENTINEL), "wire reply leaked the sentinel: {reply}");

        let own_log = std::fs::read_to_string(own_audit_log_path(&home)).unwrap();
        assert!(!own_log.contains(SENTINEL), "the broker's own audit.log leaked the sentinel:\n{own_log}");
        assert!(own_log.contains("\"op\":\"put\""), "{own_log}");

        let mirrored_log = std::fs::read_to_string(home.join("mirrored-aoide-log")).unwrap();
        assert!(!mirrored_log.contains(SENTINEL), "mirrored aoide audit log leaked the sentinel:\n{mirrored_log}");

        match saved {
            Some(v) => std::env::set_var("AOIDE_AUDIT_LOG", v),
            None => std::env::remove_var("AOIDE_AUDIT_LOG"),
        }
        std::fs::remove_dir_all(&home).ok();
    }

    // ── parking (P-N2) ───────────────────────────────────────────────────
    //
    // `handle_resolve` now BLOCKS the calling thread when a resolve parks,
    // so every test below that exercises a genuine park spawns it on its
    // own thread (`std::thread::scope`, no `'static` bound needed) and
    // completes the ask from the main thread against the SAME
    // `ParkRegistry` — this proves the actual blocking/wakeup mechanism,
    // not just the pure `GateOutcome::NeedsTotp` decision the tests above
    // already cover. Every test that calls `handle_line` for `resolve`/
    // `approve`/`dismiss` triggers this module's own audit calls
    // (`audit_park`/`audit_resolve`/`audit_approve`/`audit_dismiss`), which
    // write to `AOIDE_AUDIT_LOG` — same discipline the pre-P-N2 tests above
    // already hold individually (`crate::env_lock()` + a redirected path,
    // never the real `~/Aoide/log`).

    fn unix_now() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
    }

    /// Redirect `AOIDE_AUDIT_LOG` into `home`'s own tempdir for the
    /// duration of `f`, restoring it after — the shared helper every
    /// `handle_line`-driven test below wraps its body in. Caller still
    /// holds `crate::env_lock()` for the whole test (the SAME lock guards
    /// `AOIDE_SECRETS_PARK_TIMEOUT` where a test also touches that).
    fn with_redirected_audit_log<T>(home: &Path, f: impl FnOnce() -> T) -> T {
        let saved = std::env::var("AOIDE_AUDIT_LOG").ok();
        std::env::set_var("AOIDE_AUDIT_LOG", home.join("mirrored-aoide-log"));
        let result = f();
        match saved {
            Some(v) => std::env::set_var("AOIDE_AUDIT_LOG", v),
            None => std::env::remove_var("AOIDE_AUDIT_LOG"),
        }
        result
    }

    /// `wait:false` restores the pre-P-N2 immediate refusal (task
    /// requirement) — no thread, no blocking, no ask ever created.
    #[test]
    fn resolve_with_wait_false_gets_the_old_immediate_refusal_and_never_parks() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("wait-false");
        let p = Policy::new("t", "scratch", "stored-value");
        seed_enrolled(&home, p);
        let parked = ParkRegistry::new();

        with_redirected_audit_log(&home, || {
            let reply = handle_line(&home, &home.join("events.jsonl"), r#"{"op":"resolve","secret":"t","consumer":"m","wait":false}"#, &parked, &mut Vec::new(), None);
            assert_eq!(reply["ok"], false);
            assert_eq!(
                reply["error"], "requireTotp is set but no totp code was provided",
                "wait:false must reproduce the EXACT pre-P-N2 refusal string: {reply}"
            );
        });
        assert!(parked.list().is_empty(), "wait:false must never create a parked ask");
        std::fs::remove_dir_all(&home).ok();
    }

    /// The deliverable's own end-to-end proof at the wire level: a
    /// `resolve` with no code PARKS (default `wait`), `secrets pending`
    /// sees it, `secrets approve <id> --totp <code>` releases the value
    /// down the ORIGINAL parked connection's own reply (never the
    /// approver's), and the approver's own reply carries no value at all.
    #[test]
    fn park_then_approve_releases_the_value_to_the_original_caller_only() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("park-approve");
        let mut p = Policy::new("t", "scratch", "stored-value");
        p.consumers = vec!["m".to_string()];
        let secret = seed_enrolled(&home, p);
        let parked = ParkRegistry::new();

        with_redirected_audit_log(&home, || {
            let resolved = std::thread::scope(|scope| {
                let resolve_handle =
                    scope.spawn(|| handle_line(&home, &home.join("events.jsonl"), r#"{"op":"resolve","secret":"t","consumer":"m"}"#, &parked, &mut Vec::new(), None));

                let mut id = None;
                for _ in 0..200 {
                    let list = parked.list();
                    if let Some((pid, secret, consumer, _, _, _, _)) = list.into_iter().next() {
                        assert_eq!(secret, "t");
                        assert_eq!(consumer, "m");
                        id = Some(pid);
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                let id = id.expect("the resolve did not park in time");

                let code = code_for_now(&secret, unix_now());
                let approve_req = format!(r#"{{"op":"approve","id":"{id}","totp":"{code}"}}"#);
                let approve_reply = handle_line(&home, &home.join("events.jsonl"), &approve_req, &parked, &mut Vec::new(), None);
                assert_eq!(approve_reply["ok"], true, "{approve_reply}");
                assert!(
                    approve_reply.get("value").is_none(),
                    "the approver's own reply must never carry the value: {approve_reply}"
                );

                resolve_handle.join().unwrap()
            });

            assert_eq!(resolved["ok"], true, "{resolved}");
            assert_eq!(resolved["value"], "stored-value");
        });
        assert!(parked.list().is_empty(), "the ask must be gone once resolved");
        std::fs::remove_dir_all(&home).ok();
    }

    /// `secrets dismiss <id>` — the parked caller gets a clean refusal, the
    /// dismisser gets `{"ok":true}`.
    #[test]
    fn park_then_dismiss_refuses_the_parked_caller_cleanly() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("park-dismiss");
        let p = Policy::new("t", "scratch", "stored-value");
        seed_enrolled(&home, p);
        let parked = ParkRegistry::new();

        with_redirected_audit_log(&home, || {
            std::thread::scope(|scope| {
                let resolve_handle =
                    scope.spawn(|| handle_line(&home, &home.join("events.jsonl"), r#"{"op":"resolve","secret":"t","consumer":"m"}"#, &parked, &mut Vec::new(), None));

                let mut id = None;
                for _ in 0..200 {
                    if let Some((pid, ..)) = parked.list().into_iter().next() {
                        id = Some(pid);
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                let id = id.expect("the resolve did not park in time");

                let dismiss_reply = handle_line(&home, &home.join("events.jsonl"), &format!(r#"{{"op":"dismiss","id":"{id}"}}"#), &parked, &mut Vec::new(), operator_peer());
                assert_eq!(dismiss_reply["ok"], true, "{dismiss_reply}");

                let resolved = resolve_handle.join().unwrap();
                assert_eq!(resolved["ok"], false);
                assert!(resolved["error"].as_str().unwrap().to_lowercase().contains("dismissed"), "{resolved}");
            });
        });
        assert!(parked.list().is_empty());
        std::fs::remove_dir_all(&home).ok();
    }

    /// P-N2c FIX 2, the reviewer-confirmed authorization gap: a `secrets
    /// revoke` issued WHILE an ask sits parked must stop the eventual
    /// release, not just the next one. Parks a resolve, edits
    /// `policy.json` DIRECTLY (the same write `commands::
    /// handle_secrets_revoke` would perform) to drop "m" from the
    /// secret's `consumers[]` while the ask is still parked, then
    /// approves with a genuinely VALID code — both the approver and the
    /// original parked caller must see the denial, and the ask must be
    /// gone from the registry afterward (never left dangling parked).
    #[test]
    fn park_then_revoke_the_consumer_then_approve_denies_the_parked_caller() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("park-revoke-then-approve");
        let mut p = Policy::new("t", "scratch", "stored-value");
        p.consumers = vec!["m".to_string()];
        let secret = seed_enrolled(&home, p);
        let parked = ParkRegistry::new();

        with_redirected_audit_log(&home, || {
            std::thread::scope(|scope| {
                let resolve_handle =
                    scope.spawn(|| handle_line(&home, &home.join("events.jsonl"), r#"{"op":"resolve","secret":"t","consumer":"m"}"#, &parked, &mut Vec::new(), None));

                let mut id = None;
                for _ in 0..200 {
                    if let Some((pid, ..)) = parked.list().into_iter().next() {
                        id = Some(pid);
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                let id = id.expect("the resolve did not park in time");

                // The revocation: "m" is no longer listed (a non-empty
                // list WITHOUT "m" — an empty list would mean "any
                // consumer," the opposite of what a revoke means).
                let mut revoked = Policy::new("t", "scratch", "stored-value");
                revoked.require_totp = true;
                revoked.consumers = vec!["someone-else".to_string()];
                crate::store::save_policies(&home, &[revoked]).unwrap();

                let code = code_for_now(&secret, unix_now());
                let approve_reply =
                    handle_line(&home, &home.join("events.jsonl"), &format!(r#"{{"op":"approve","id":"{id}","totp":"{code}"}}"#), &parked, &mut Vec::new(), None);
                assert_eq!(approve_reply["ok"], false, "{approve_reply}");
                assert_eq!(approve_reply["error"], "consumer not authorized for this secret", "{approve_reply}");
                assert!(
                    approve_reply.get("value").is_none(),
                    "a denied approve must never carry a value: {approve_reply}"
                );

                let resolved = resolve_handle.join().unwrap();
                assert_eq!(resolved["ok"], false, "{resolved}");
                assert_eq!(
                    resolved["error"], "consumer not authorized for this secret",
                    "the ORIGINAL parked caller must see the SAME re-gate denial: {resolved}"
                );
            });
        });
        assert!(parked.list().is_empty(), "a denied-on-re-gate ask must be gone, never left dangling parked");
        std::fs::remove_dir_all(&home).ok();
    }

    /// P-N2c FIX 3b: at the registry-wide park cap, a codeless resolve
    /// gets the SAME immediate refusal `wait:false` would (never a park),
    /// with a hint naming the cap and its env knob — the queue never grows
    /// past `AOIDE_SECRETS_PARK_CAP`.
    #[test]
    fn a_codeless_resolve_at_the_park_cap_is_refused_immediately_and_never_parks() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_cap = std::env::var(crate::park::PARK_CAP_ENV).ok();
        std::env::set_var(crate::park::PARK_CAP_ENV, "1");

        let home = tmp_home("park-cap");
        let p = Policy::new("t", "scratch", "stored-value");
        seed_enrolled(&home, p);
        let parked = ParkRegistry::new();

        with_redirected_audit_log(&home, || {
            std::thread::scope(|scope| {
                // Fills the ONE slot the cap allows.
                let first_handle =
                    scope.spawn(|| handle_line(&home, &home.join("events.jsonl"), r#"{"op":"resolve","secret":"t","consumer":"m"}"#, &parked, &mut Vec::new(), None));
                let mut id = None;
                for _ in 0..200 {
                    if let Some((pid, ..)) = parked.list().into_iter().next() {
                        id = Some(pid);
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                let id = id.expect("the first resolve did not park in time");
                assert_eq!(parked.list().len(), 1);

                // A SECOND codeless resolve, at cap 1, must be refused
                // immediately — same connection thread, so this call
                // itself must NOT block.
                let second_reply =
                    handle_line(&home, &home.join("events.jsonl"), r#"{"op":"resolve","secret":"t","consumer":"m"}"#, &parked, &mut Vec::new(), None);
                assert_eq!(second_reply["ok"], false, "{second_reply}");
                let err = second_reply["error"].as_str().unwrap();
                assert!(err.contains("queue is full"), "{err}");
                assert!(err.contains(crate::park::PARK_CAP_ENV), "must name the knob: {err}");
                assert_eq!(parked.list().len(), 1, "the cap refusal must never grow the queue");

                // Clean up the still-parked first ask so its thread returns.
                let dismissed = handle_line(&home, &home.join("events.jsonl"), &format!(r#"{{"op":"dismiss","id":"{id}"}}"#), &parked, &mut Vec::new(), operator_peer());
                assert_eq!(dismissed["ok"], true, "{dismissed}");
                let _ = first_handle.join().unwrap();
            });
        });

        match saved_cap {
            Some(v) => std::env::set_var(crate::park::PARK_CAP_ENV, v),
            None => std::env::remove_var(crate::park::PARK_CAP_ENV),
        }
        std::fs::remove_dir_all(&home).ok();
    }

    /// P-N2c FIX 1, over a REAL connection (`UnixStream::pair`, not a
    /// direct `handle_line` call): a parking resolve must put TWO lines on
    /// the wire — the interim `{"interim":true,"parked":true,...}` line
    /// first, then (once dismissed here, to keep the test fast) the final
    /// reply — proving `handle_conn`'s own write path, not just
    /// `handle_resolve`'s return value, honors the "zero-or-more interim,
    /// exactly one final" framing (module doc; `CONTRACTS.md`).
    #[test]
    fn park_over_a_real_connection_writes_the_interim_line_then_the_final_reply() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("park-interim-two-lines");
        let p = Policy::new("t", "scratch", "stored-value");
        seed_enrolled(&home, p);
        let parked = Arc::new(ParkRegistry::new());

        with_redirected_audit_log(&home, || {
            let (client_end, server_end) = UnixStream::pair().expect("socketpair");
            let home_for_conn = home.clone();
            let events_for_conn = home.join("events.jsonl");
            let parked_for_conn = Arc::clone(&parked);
            let conn_handle = std::thread::spawn(move || {
                handle_conn(&home_for_conn, &events_for_conn, server_end, &parked_for_conn)
            });

            let mut writer = client_end.try_clone().expect("clone client end");
            writer
                .write_all(b"{\"op\":\"resolve\",\"secret\":\"t\",\"consumer\":\"m\"}\n")
                .unwrap();
            let mut reader = BufReader::new(client_end);

            // Line 1: the interim park announcement.
            let mut line1 = String::new();
            reader.read_line(&mut line1).expect("reading the interim line");
            let interim: Value = serde_json::from_str(line1.trim()).expect("interim line must be JSON");
            assert_eq!(interim["interim"], true, "{interim}");
            assert_eq!(interim["parked"], true, "{interim}");
            let id = interim["id"].as_str().expect("interim carries the ask id").to_string();
            assert!(interim["timeoutSecs"].as_u64().is_some(), "{interim}");

            // Resolve it so the connection's second (final) line arrives
            // without waiting out the real timeout.
            let dismissed = handle_line(&home, &home.join("events.jsonl"), &format!(r#"{{"op":"dismiss","id":"{id}"}}"#), &parked, &mut Vec::new(), operator_peer());
            assert_eq!(dismissed["ok"], true, "{dismissed}");

            // Line 2: the final reply — exactly one, and it is NOT interim.
            let mut line2 = String::new();
            reader.read_line(&mut line2).expect("reading the final reply line");
            let final_reply: Value = serde_json::from_str(line2.trim()).expect("final line must be JSON");
            assert!(
                final_reply.get("interim").is_none(),
                "the second line must be the FINAL reply, not another interim: {final_reply}"
            );
            assert_eq!(final_reply["ok"], false, "{final_reply}");
            assert!(final_reply["error"].as_str().unwrap().to_lowercase().contains("dismissed"), "{final_reply}");

            // `handle_conn`'s read loop blocks on the NEXT line until EOF —
            // drop the client side FIRST so the server sees the connection
            // close and `handle_conn` returns; otherwise this join hangs
            // forever (both ends alive, neither expecting more data).
            drop(reader);
            drop(writer);
            conn_handle.join().unwrap();
        });
        assert!(parked.list().is_empty());
        std::fs::remove_dir_all(&home).ok();
    }

    /// Task requirement: an invalid code leaves the ask PARKED (never
    /// removed) and never burns the replay ledger — proven by a wrong code
    /// first, then the CORRECT code still working afterward on the SAME ask.
    #[test]
    fn approve_with_an_invalid_code_leaves_the_ask_parked_and_the_ledger_unburned() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("park-invalidcode");
        let p = Policy::new("t", "scratch", "stored-value");
        let secret = seed_enrolled(&home, p);
        let parked = ParkRegistry::new();

        with_redirected_audit_log(&home, || {
            std::thread::scope(|scope| {
                let resolve_handle =
                    scope.spawn(|| handle_line(&home, &home.join("events.jsonl"), r#"{"op":"resolve","secret":"t","consumer":"m"}"#, &parked, &mut Vec::new(), None));

                let mut id = None;
                for _ in 0..200 {
                    if let Some((pid, ..)) = parked.list().into_iter().next() {
                        id = Some(pid);
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                let id = id.expect("the resolve did not park in time");

                // A wrong code: denied, but the ask must still be there.
                let wrong = handle_line(&home, &home.join("events.jsonl"), &format!(r#"{{"op":"approve","id":"{id}","totp":"000000"}}"#), &parked, &mut Vec::new(), None);
                assert_eq!(wrong["ok"], false, "{wrong}");
                assert_eq!(parked.list().len(), 1, "an invalid code must leave the ask parked");

                // The REAL correct code now completes it.
                let code = code_for_now(&secret, unix_now());
                let right = handle_line(&home, &home.join("events.jsonl"), &format!(r#"{{"op":"approve","id":"{id}","totp":"{code}"}}"#), &parked, &mut Vec::new(), None);
                assert_eq!(right["ok"], true, "{right}");

                let resolved = resolve_handle.join().unwrap();
                assert_eq!(resolved["ok"], true, "{resolved}");
                assert_eq!(resolved["value"], "stored-value");
            });
        });
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn approve_on_an_unknown_id_is_a_taught_error() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("approve-unknown");
        let parked = ParkRegistry::new();
        with_redirected_audit_log(&home, || {
            let reply = handle_line(&home, &home.join("events.jsonl"), r#"{"op":"approve","id":"9","totp":"123456"}"#, &parked, &mut Vec::new(), None);
            assert_eq!(reply["ok"], false);
            assert!(reply["error"].as_str().unwrap().contains("unknown pending id `9`"), "{reply}");
        });
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn dismiss_on_an_unknown_id_is_a_taught_error() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("dismiss-unknown");
        let parked = ParkRegistry::new();
        with_redirected_audit_log(&home, || {
            let reply = handle_line(&home, &home.join("events.jsonl"), r#"{"op":"dismiss","id":"9"}"#, &parked, &mut Vec::new(), None);
            assert_eq!(reply["ok"], false);
            assert!(reply["error"].as_str().unwrap().contains("unknown pending id `9`"), "{reply}");
        });
        std::fs::remove_dir_all(&home).ok();
    }

    // ── #73: peer-uid-gated dismiss ─────────────────────────────────────
    //
    // A real socketpair's SO_PEERCRED always reports THIS test process's
    // own euid on either end — there is no way to fabricate a genuinely
    // different uid without a second real user. So these tests construct
    // the ask's stamped `peer_uid` directly via `ParkRegistry::
    // park_if_room` (never through a live `resolve` that parks) and hand
    // `handle_dismiss`/`handle_line` a directly-constructed `PeerCred` for
    // the dismissing side — both are ordinary function parameters, no
    // socket needed either way.

    /// `dismiss_authorized` (the pure decision) — every combination the
    /// task requirement names, no I/O.
    #[test]
    fn dismiss_authorized_matches_the_asks_own_peer_uid() {
        assert!(dismiss_authorized(Some(1000), Some(1000), 0));
        assert!(!dismiss_authorized(Some(1000), Some(1001), 0), "a different peer uid must be refused");
    }

    #[test]
    fn dismiss_authorized_always_admits_the_brokers_own_euid() {
        // The broker's own operator uid may dismiss ANY ask, regardless of
        // who parked it — including one whose own peer_uid is unidentified.
        assert!(dismiss_authorized(Some(4242), Some(1000), 4242));
        assert!(dismiss_authorized(Some(4242), None, 4242));
    }

    #[test]
    fn dismiss_authorized_fails_closed_on_an_unidentified_dismisser() {
        // No kernel fact to check the dismisser against — refuse, never
        // pass, even when the ask's own peer_uid is ALSO unidentified (a
        // coincidental "both unknown" is not a match).
        assert!(!dismiss_authorized(None, Some(1000), 4242));
        assert!(!dismiss_authorized(None, None, 4242));
    }

    #[test]
    fn dismiss_refused_message_names_both_uids() {
        let msg = dismiss_refused_message("3f2a-1", Some(1001), Some(1000), 0);
        assert!(msg.contains("1001"), "{msg}");
        assert!(msg.contains("1000"), "{msg}");
        assert!(msg.contains("3f2a-1"), "{msg}");
    }

    #[test]
    fn dismiss_refused_message_spells_unidentified_not_a_blank() {
        let msg = dismiss_refused_message("id", None, Some(1000), 0);
        assert!(msg.contains("unidentified"), "{msg}");
    }

    /// End-to-end: an ask stamped with one peer uid, dismissed by a
    /// DIFFERENT (directly-constructed) peer uid, is refused — and the ask
    /// stays parked, exactly like an invalid `approve` code leaves it
    /// parked (never silently consumed by a failed unauthorized attempt).
    #[test]
    fn dismiss_by_a_mismatched_peer_uid_is_refused_and_the_ask_stays_parked() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("dismiss-wrong-peer-uid");
        let parked = ParkRegistry::new();
        let real_euid = unsafe { libc::geteuid() };
        // Sentinel uids deliberately far from this test process's own real
        // euid (which would otherwise coincidentally satisfy the
        // broker-euid bypass in `dismiss_authorized`).
        let owner_uid = real_euid.wrapping_add(10_000);
        let wrong_uid = real_euid.wrapping_add(20_000);
        let (id, _rx) = parked.park_if_room("t", "m", NOW, usize::MAX, Some(owner_uid), None, AskOrigin::default()).unwrap();

        with_redirected_audit_log(&home, || {
            let wrong_peer = Some(crate::peercred::PeerCred { uid: wrong_uid, gid: 0, pid: 0 });
            let reply = handle_line(
                &home,
                &home.join("events.jsonl"),
                &format!(r#"{{"op":"dismiss","id":"{id}"}}"#),
                &parked,
                &mut Vec::new(),
                wrong_peer,
            );
            assert_eq!(reply["ok"], false, "{reply}");
            let err = reply["error"].as_str().unwrap();
            assert!(err.contains(&owner_uid.to_string()), "{err}");
            assert!(err.contains(&wrong_uid.to_string()), "{err}");
        });
        // Refused — the ask is untouched, still parked.
        assert!(parked.peek(&id).is_some(), "a refused dismiss must leave the ask parked");
        std::fs::remove_dir_all(&home).ok();
    }

    /// The matching half: dismissing with the SAME peer uid the ask was
    /// stamped with succeeds.
    #[test]
    fn dismiss_by_the_asks_own_matching_peer_uid_succeeds() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("dismiss-matching-peer-uid");
        let parked = ParkRegistry::new();
        let real_euid = unsafe { libc::geteuid() };
        let owner_uid = real_euid.wrapping_add(30_000);
        let (id, _rx) = parked.park_if_room("t", "m", NOW, usize::MAX, Some(owner_uid), None, AskOrigin::default()).unwrap();

        with_redirected_audit_log(&home, || {
            let matching_peer = Some(crate::peercred::PeerCred { uid: owner_uid, gid: 0, pid: 0 });
            let reply = handle_line(
                &home,
                &home.join("events.jsonl"),
                &format!(r#"{{"op":"dismiss","id":"{id}"}}"#),
                &parked,
                &mut Vec::new(),
                matching_peer,
            );
            assert_eq!(reply["ok"], true, "{reply}");
        });
        assert!(parked.peek(&id).is_none(), "a granted dismiss must remove the ask");
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn approve_missing_totp_is_a_malformed_request_and_leaves_the_ask_parked() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("approve-missingtotp");
        let p = Policy::new("t", "scratch", "stored-value");
        seed_enrolled(&home, p);
        let parked = ParkRegistry::new();
        let (id, _rx) = parked.park("t", "m", NOW);

        with_redirected_audit_log(&home, || {
            let reply = handle_line(&home, &home.join("events.jsonl"), &format!(r#"{{"op":"approve","id":"{id}"}}"#), &parked, &mut Vec::new(), None);
            assert_eq!(reply["ok"], false);
            assert!(reply["error"].as_str().unwrap().contains("`totp` is required"), "{reply}");
        });
        assert_eq!(parked.list().len(), 1, "a missing code must leave the ask parked");
        std::fs::remove_dir_all(&home).ok();
    }

    /// `secrets pending` never carries a value, whether the queue is empty
    /// or has an ask in it. Not audited (no `handle_line` audit call on
    /// this op, matching `graph pending list`'s own precedent), so no
    /// redirection needed.
    #[test]
    fn pending_list_never_contains_a_value() {
        let home = tmp_home("pending-list");
        let parked = ParkRegistry::new();

        let empty = handle_line(&home, &home.join("events.jsonl"), r#"{"op":"pending"}"#, &parked, &mut Vec::new(), None);
        assert_eq!(empty["ok"], true);
        assert_eq!(empty["pending"].as_array().unwrap().len(), 0);

        let (id, _rx) = parked.park("db-prod", "m", 1_700_000_123);
        let listed = handle_line(&home, &home.join("events.jsonl"), r#"{"op":"pending"}"#, &parked, &mut Vec::new(), None);
        let arr = listed["pending"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["id"], id);
        assert_eq!(arr[0]["secret"], "db-prod");
        assert_eq!(arr[0]["consumer"], "m");
        assert_eq!(arr[0]["requestedAt"], 1_700_000_123);
        assert!(!listed.to_string().to_lowercase().contains("value"), "{listed}");
        std::fs::remove_dir_all(&home).ok();
    }

    /// #73: `pending`'s reply carries the kernel-truth `peerUid` — additive
    /// over the pre-#73 wire shape (`null` when unstamped, the exact
    /// stamped value otherwise).
    #[test]
    fn pending_list_carries_the_stamped_peer_uid() {
        let home = tmp_home("pending-peer-uid");
        let parked = ParkRegistry::new();

        // Unstamped (e.g. `park()`'s own unbounded/no-peer-info shape) ->
        // `null`, never a bare-omitted field (additive-but-present, same
        // discipline `argv0`/`reason` already hold elsewhere in this file).
        let (unstamped_id, _rx1) = parked.park("no-peer", "m", 1);
        let listed = handle_line(&home, &home.join("events.jsonl"), r#"{"op":"pending"}"#, &parked, &mut Vec::new(), None);
        let arr = listed["pending"].as_array().unwrap();
        let entry = arr.iter().find(|e| e["id"] == unstamped_id).unwrap();
        assert!(entry["peerUid"].is_null(), "{entry}");

        let (stamped_id, _rx2) = parked.park_if_room("with-peer", "m", 2, usize::MAX, Some(4242), None, AskOrigin::default()).unwrap();
        let listed = handle_line(&home, &home.join("events.jsonl"), r#"{"op":"pending"}"#, &parked, &mut Vec::new(), None);
        let arr = listed["pending"].as_array().unwrap();
        let entry = arr.iter().find(|e| e["id"] == stamped_id).unwrap();
        assert_eq!(entry["peerUid"], 4242);
        std::fs::remove_dir_all(&home).ok();
    }

    /// Task requirement: a resolve WITH a code is completely unchanged by
    /// this whole phase — the fast path never touches `ParkRegistry` at all.
    #[test]
    fn resolve_with_a_code_never_parks_the_fast_path_is_unchanged() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("fastpath-unchanged");
        let mut p = Policy::new("t", "scratch", "stored-value");
        p.consumers = vec!["m".to_string()];
        let secret = seed_enrolled(&home, p);
        let parked = ParkRegistry::new();
        let code = code_for_now(&secret, unix_now());

        with_redirected_audit_log(&home, || {
            let reply = handle_line(
                &home,
                &home.join("events.jsonl"),
                &format!(r#"{{"op":"resolve","secret":"t","consumer":"m","totp":"{code}"}}"#),
                &parked,
                &mut Vec::new(),
                None,
            );
            assert_eq!(reply["ok"], true, "{reply}");
            assert_eq!(reply["value"], "stored-value");
        });
        assert!(parked.list().is_empty(), "a resolve WITH a code must never touch the park registry");
        std::fs::remove_dir_all(&home).ok();
    }

    /// The timeout path, with a tiny configured timeout (never the real
    /// 300s default) — names the timeout/knob/both completion paths (task
    /// requirement) and removes the ask.
    #[test]
    fn park_times_out_and_names_the_knob_and_both_completion_paths() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_timeout = std::env::var(crate::park::PARK_TIMEOUT_ENV).ok();
        std::env::set_var(crate::park::PARK_TIMEOUT_ENV, "1");

        let home = tmp_home("park-timeout");
        let p = Policy::new("t", "scratch", "stored-value");
        seed_enrolled(&home, p);
        let parked = ParkRegistry::new();

        with_redirected_audit_log(&home, || {
            let reply = handle_line(&home, &home.join("events.jsonl"), r#"{"op":"resolve","secret":"t","consumer":"m"}"#, &parked, &mut Vec::new(), None);
            assert_eq!(reply["ok"], false);
            let err = reply["error"].as_str().unwrap();
            assert!(err.contains("timed out after 1s"), "{err}");
            assert!(err.contains(crate::park::PARK_TIMEOUT_ENV), "must name the knob: {err}");
            assert!(err.contains("--totp"), "must name the inline completion path: {err}");
            assert!(err.contains("secrets approve"), "must name the approve completion path: {err}");
        });
        assert!(parked.list().is_empty(), "a timed-out ask must be removed");

        match saved_timeout {
            Some(v) => std::env::set_var(crate::park::PARK_TIMEOUT_ENV, v),
            None => std::env::remove_var(crate::park::PARK_TIMEOUT_ENV),
        }
        std::fs::remove_dir_all(&home).ok();
    }

    /// Concurrency, at the connection-thread level (task's hard
    /// constraint): while one `resolve` sits parked (blocking ITS thread),
    /// an UNRELATED `resolve` on a totally separate call completes
    /// normally against the SAME `ParkRegistry` — proving nothing about
    /// parking serializes unrelated work. (The full accept-loop-level
    /// proof — a real second SOCKET connection completing while another is
    /// parked — lives in `tests/e2e.rs`, which exercises the real
    /// `broker::serve` thread-per-connection accept loop this unit test
    /// can't reach.)
    #[test]
    fn an_unrelated_resolve_completes_while_another_is_parked() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("park-concurrency");
        let mut gated = Policy::new("locked", "scratch", "locked-value");
        gated.consumers = vec!["m".to_string()];
        gated.require_totp = true;
        let mut free = Policy::new("open", "scratch", "open-value");
        free.consumers = vec!["m".to_string()];
        seed(&home, &[gated, free]);
        let totp_secret = b"a-twenty-byte-totp-s".to_vec();
        crate::store::save_totp_secret(&home, &totp_secret).unwrap();
        let parked = ParkRegistry::new();

        with_redirected_audit_log(&home, || {
            std::thread::scope(|scope| {
                let resolve_handle = scope
                    .spawn(|| handle_line(&home, &home.join("events.jsonl"), r#"{"op":"resolve","secret":"locked","consumer":"m"}"#, &parked, &mut Vec::new(), None));

                let mut parked_yet = false;
                for _ in 0..200 {
                    if !parked.list().is_empty() {
                        parked_yet = true;
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                assert!(parked_yet, "the gated resolve did not park in time");

                // An unrelated resolve, on the SAME registry, completes
                // immediately — proving the parked ask never blocked it.
                let free_reply = handle_line(&home, &home.join("events.jsonl"), r#"{"op":"resolve","secret":"open","consumer":"m"}"#, &parked, &mut Vec::new(), None);
                assert_eq!(free_reply["ok"], true, "{free_reply}");
                assert_eq!(free_reply["value"], "open-value");

                // Clean up: dismiss the still-parked ask so the spawned
                // thread returns and this test doesn't leak a blocked one.
                let (id, ..) = parked.list().into_iter().next().unwrap();
                let dismissed = handle_line(&home, &home.join("events.jsonl"), &format!(r#"{{"op":"dismiss","id":"{id}"}}"#), &parked, &mut Vec::new(), operator_peer());
                assert_eq!(dismissed["ok"], true, "{dismissed}");
                let resolved = resolve_handle.join().unwrap();
                assert_eq!(resolved["ok"], false);
            });
        });
        std::fs::remove_dir_all(&home).ok();
    }

    // ── P-N2 review fix: the replay-ledger and put critical sections ────
    //
    // Thread-per-connection removed the implicit serialization the old
    // serial accept loop gave these two read-modify-write sections for
    // free (module doc's "read-modify-write sections" paragraph). Both
    // tests below reproduce the exact race the reviewer found — two
    // threads racing the SAME resource with a `Barrier` to align their
    // start as tightly as possible — iterated so a single lucky
    // (unlucky) interleaving can't hide a regression.

    /// The CRITICAL fix: two threads calling `resolve_gate` concurrently
    /// with the SAME valid TOTP code against a SHARED secrets home must
    /// grant exactly once, never twice. Before `replay_ledger_lock`
    /// existed, this reproduced a double-grant on roughly 5/20 iterations
    /// (reviewer's own repro rate) — iterated 20x here so a regression
    /// can't slip through on a lucky run.
    #[test]
    fn concurrent_resolve_with_the_same_code_never_grants_twice() {
        for i in 0..20 {
            let home = tmp_home(&format!("race-resolve-{i}"));
            let mut p = Policy::new("t", "scratch", "stored-value");
            p.consumers = vec!["m".to_string()];
            let secret = seed_enrolled(&home, p);
            let code = code_for_now(&secret, NOW);

            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

            let home_a = home.clone();
            let code_a = code.clone();
            let barrier_a = barrier.clone();
            let a = std::thread::spawn(move || {
                barrier_a.wait();
                resolve_gate(&home_a, "t", "m", Some(&code_a), NOW, None)
            });

            let home_b = home.clone();
            let code_b = code.clone();
            let barrier_b = barrier.clone();
            let b = std::thread::spawn(move || {
                barrier_b.wait();
                resolve_gate(&home_b, "t", "m", Some(&code_b), NOW, None)
            });

            let ra = a.join().unwrap();
            let rb = b.join().unwrap();
            let grants = [&ra, &rb].into_iter().filter(|o| matches!(o, GateOutcome::Granted { .. })).count();
            assert_eq!(
                grants, 1,
                "iteration {i}: exactly one of two concurrent resolves sharing a valid code must grant, got {grants}"
            );

            std::fs::remove_dir_all(&home).ok();
        }
    }

    /// The SECONDARY fix, same TOCTOU shape: two threads calling
    /// `put_gate` concurrently with `overwrite:false` against a SECRET
    /// THAT DOES NOT YET HAVE A VALUE must store exactly once — the other
    /// must see the value the first one stored and refuse with
    /// `DeniedExists`, never silently clobber it.
    #[test]
    fn concurrent_overwrite_false_puts_store_exactly_once() {
        for i in 0..20 {
            let home = tmp_home(&format!("race-put-{i}"));
            seed(&home, &[Policy::new("t", "scratch-write", "irrelevant")]);
            // `put_gate` needs a `set` template too — `seed`'s own
            // `scratch` backend only has `get`, so this test writes its
            // own backend entry with both.
            let store_path = home.join("store-file");
            // No `|| true` on the `get` template — `has_value` (module
            // doc) is exactly `fetch_value(...).is_ok()`, so the probe
            // must genuinely FAIL (non-zero exit) while the file doesn't
            // exist yet, for the "no value yet, race the first store"
            // shape this test needs.
            std::fs::write(
                crate::backend::backends_path(&home),
                serde_json::to_vec(&serde_json::json!({
                    "scratch-write": {
                        "get": format!("cat {}", store_path.display()),
                        "set": format!("cat > {}", store_path.display())
                    }
                }))
                .unwrap(),
            )
            .unwrap();

            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

            let home_a = home.clone();
            let barrier_a = barrier.clone();
            let a = std::thread::spawn(move || {
                barrier_a.wait();
                put_gate(&home_a, "t", "value-a", false)
            });

            let home_b = home.clone();
            let barrier_b = barrier.clone();
            let b = std::thread::spawn(move || {
                barrier_b.wait();
                put_gate(&home_b, "t", "value-b", false)
            });

            let ra = a.join().unwrap();
            let rb = b.join().unwrap();
            let stores = [&ra, &rb].into_iter().filter(|o| matches!(o, PutOutcome::Granted { .. })).count();
            assert_eq!(
                stores, 1,
                "iteration {i}: exactly one of two concurrent overwrite:false puts must store, got {stores}: \
                 a={ra:?} b={rb:?}"
            );

            std::fs::remove_dir_all(&home).ok();
        }
    }

    // ── broker event notifications (P-N3, extended P-G4/task #77) ───────
    //
    // Every notable broker event fires a NAME-ONLY line into THREE
    // destinations: the broker's own structured `audit.log` (read back via
    // [`own_log_lines`]), the mirrored aoide log (`with_redirected_
    // audit_log`, the same fixture every P-N2 park test above already
    // uses), and — as of P-G4 — the broker-owned events feed (read back
    // via [`events_feed_lines`], the destination `secrets watch` itself
    // now tails; the mirrored log stays audit-trail-only). No dedup/
    // throttle, deliberately (User decision, this phase, `README.md`'s
    // "Broker notifications" section): every TOTP-free release notifies,
    // every single time.

    /// Read the broker's own `audit.log` back as parsed JSON lines — every
    /// `emit_notify` call lands here via the SAME `append_own_log` every
    /// `audit_*` function already writes through.
    fn own_log_lines(home: &Path) -> Vec<Value> {
        std::fs::read_to_string(own_audit_log_path(home))
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// The mirrored aoide-log's own lines, same shape.
    fn mirrored_log_lines(home: &Path) -> Vec<Value> {
        std::fs::read_to_string(home.join("mirrored-aoide-log"))
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// The events feed's own lines (P-G4, task #77) — every test in this
    /// suite that calls `handle_line`/`handle_conn` uses `home.join(
    /// "events.jsonl")` as its events path (this module's own convention),
    /// so this reads that same file back. Byte-identical shape to
    /// [`own_log_lines`] (both come from the SAME `payload` — `emit_notify`'s
    /// own doc), so a hit here can be matched with the SAME [`find_notify_
    /// event`] helper.
    fn events_feed_lines(home: &Path) -> Vec<Value> {
        std::fs::read_to_string(home.join("events.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// The one line in `lines` whose `"event"` field equals `event` — the
    /// own `audit.log`'s notify shape (`emit_notify`'s `payload`, written
    /// verbatim). Panics with the whole log on a miss, so a failure shows
    /// what WAS written rather than just "not found".
    fn find_notify_event<'a>(lines: &'a [Value], event: &str) -> &'a Value {
        lines
            .iter()
            .find(|l| l.get("event").and_then(Value::as_str) == Some(event))
            .unwrap_or_else(|| panic!("no `{event}` notify event in: {lines:?}"))
    }

    /// The mirrored aoide-log's OWN shape (`AuditRecord`): the event kind
    /// rides as `status`, alongside `command: "secrets.notify"` — there is
    /// no `event` field here at all (that shape is `emit_notify`'s
    /// `payload`, embedded whole as this record's `message` string).
    fn find_mirrored_notify<'a>(lines: &'a [Value], kind: &str) -> &'a Value {
        lines
            .iter()
            .find(|l| l.get("command").and_then(Value::as_str) == Some("secrets.notify") && l.get("status").and_then(Value::as_str) == Some(kind))
            .unwrap_or_else(|| panic!("no mirrored `secrets.notify`/`{kind}` line in: {lines:?}"))
    }

    /// `released` (task's exact shape: `{event, secret, consumer}`, no
    /// `id`) fires on an ordinary `requireTotp:false` resolve — the
    /// baseline TOTP-free case.
    #[test]
    fn released_fires_on_a_requiretotp_false_resolve() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("notify-released-free");
        let mut p = Policy::new("t", "scratch", "stored-value");
        p.consumers = vec!["m".to_string()];
        seed(&home, &[p]);
        let parked = ParkRegistry::new();

        with_redirected_audit_log(&home, || {
            let reply = handle_line(&home, &home.join("events.jsonl"), r#"{"op":"resolve","secret":"t","consumer":"m"}"#, &parked, &mut Vec::new(), None);
            assert_eq!(reply["ok"], true, "{reply}");
        });

        let own_lines = own_log_lines(&home);
        let ev = find_notify_event(&own_lines, "released");
        assert_eq!(ev["secret"], "t");
        assert_eq!(ev["consumer"], "m");
        assert!(ev.get("id").is_none(), "`released` carries no `id`: {ev}");
        assert!(!ev.to_string().contains("stored-value"), "the notify event leaked the value: {ev}");

        let mirrored_lines = mirrored_log_lines(&home);
        let mirrored = find_mirrored_notify(&mirrored_lines, "released");
        assert!(!mirrored.to_string().contains("stored-value"), "{mirrored}");

        // P-G4 (task #77): the THIRD destination, byte-identical to the
        // own `audit.log` line — `secrets watch` now tails this one.
        let feed_lines = events_feed_lines(&home);
        let feed_ev = find_notify_event(&feed_lines, "released");
        assert_eq!(feed_ev["secret"], "t");
        assert_eq!(feed_ev["consumer"], "m");
        assert!(!feed_ev.to_string().contains("stored-value"), "the events feed leaked the value: {feed_ev}");

        std::fs::remove_dir_all(&home).ok();
    }

    /// The OTHER TOTP-free path (P-N1's automation-skip, not a bare
    /// `requireTotp:false` policy) also fires `released` — the task's own
    /// wording ("automation-skip or requireTotp=false") names both.
    #[test]
    fn released_fires_on_an_automation_skip_resolve() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("notify-released-automation");
        let mut p = Policy::new("t", "scratch", "stored-value");
        p.consumers = vec!["m".to_string()];
        p.require_totp = true;
        p.automation.enabled = true;
        p.automation.consumers = vec!["m".to_string()];
        // No enrollment on this host at all — proves the grant came from
        // the automation skip, never a code check.
        seed(&home, &[p]);
        let parked = ParkRegistry::new();

        with_redirected_audit_log(&home, || {
            let reply = handle_line(&home, &home.join("events.jsonl"), r#"{"op":"resolve","secret":"t","consumer":"m"}"#, &parked, &mut Vec::new(), None);
            assert_eq!(reply["ok"], true, "{reply}");
        });

        let own_lines = own_log_lines(&home);
        let ev = find_notify_event(&own_lines, "released");
        assert_eq!(ev["secret"], "t");
        assert_eq!(ev["consumer"], "m");

        std::fs::remove_dir_all(&home).ok();
    }

    /// The negative space that proves the `totp_free` distinction is real:
    /// a resolve that validates its OWN inline `--totp` code is granted
    /// exactly as before, but must NEVER fire `released` — the caller just
    /// typed the code themselves, there is nothing for a desktop popup to
    /// tell them.
    #[test]
    fn released_does_not_fire_when_an_inline_totp_code_is_used() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("notify-no-release-on-code");
        let mut p = Policy::new("t", "scratch", "stored-value");
        p.consumers = vec!["m".to_string()];
        let secret = seed_enrolled(&home, p);
        let parked = ParkRegistry::new();
        let code = code_for_now(&secret, unix_now());

        with_redirected_audit_log(&home, || {
            let reply = handle_line(
                &home,
                &home.join("events.jsonl"),
                &format!(r#"{{"op":"resolve","secret":"t","consumer":"m","totp":"{code}"}}"#),
                &parked,
                &mut Vec::new(),
                None,
            );
            assert_eq!(reply["ok"], true, "{reply}");
        });

        let lines = own_log_lines(&home);
        assert!(
            lines.iter().all(|l| l.get("event").and_then(Value::as_str) != Some("released")),
            "a code-verified resolve must never fire `released`: {lines:?}"
        );

        std::fs::remove_dir_all(&home).ok();
    }

    /// `parked` (task's exact shape: `{event, id, secret, consumer,
    /// timeoutSecs}`) — the popup's future trigger, fired once per park.
    #[test]
    fn parked_fires_with_the_id_and_timeout_when_a_resolve_parks() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("notify-parked");
        let p = Policy::new("t", "scratch", "stored-value");
        seed_enrolled(&home, p);
        let parked = ParkRegistry::new();

        with_redirected_audit_log(&home, || {
            std::thread::scope(|scope| {
                let resolve_handle =
                    scope.spawn(|| handle_line(&home, &home.join("events.jsonl"), r#"{"op":"resolve","secret":"t","consumer":"m"}"#, &parked, &mut Vec::new(), None));

                let mut id = None;
                for _ in 0..200 {
                    if let Some((pid, ..)) = parked.list().into_iter().next() {
                        id = Some(pid);
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                let id = id.expect("the ask did not park in time");

                let own_lines = own_log_lines(&home);
                let ev = find_notify_event(&own_lines, "parked");
                assert_eq!(ev["id"], id);
                assert_eq!(ev["secret"], "t");
                assert_eq!(ev["consumer"], "m");
                assert!(ev["timeoutSecs"].as_u64().is_some(), "{ev}");

                // Clean up: dismiss so the spawned thread returns.
                let dismissed = handle_line(&home, &home.join("events.jsonl"), &format!(r#"{{"op":"dismiss","id":"{id}"}}"#), &parked, &mut Vec::new(), operator_peer());
                assert_eq!(dismissed["ok"], true, "{dismissed}");
                resolve_handle.join().unwrap();
            });
        });
        std::fs::remove_dir_all(&home).ok();
    }

    /// `completed` (task's exact shape: `{event, id, secret, consumer}`)
    /// fires once, on the APPROVER's own side, when a parked ask releases.
    #[test]
    fn completed_fires_on_a_successful_approve() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("notify-completed");
        let mut p = Policy::new("t", "scratch", "stored-value");
        p.consumers = vec!["m".to_string()];
        let secret = seed_enrolled(&home, p);
        let parked = ParkRegistry::new();

        with_redirected_audit_log(&home, || {
            std::thread::scope(|scope| {
                let resolve_handle =
                    scope.spawn(|| handle_line(&home, &home.join("events.jsonl"), r#"{"op":"resolve","secret":"t","consumer":"m"}"#, &parked, &mut Vec::new(), None));

                let mut id = None;
                for _ in 0..200 {
                    if let Some((pid, ..)) = parked.list().into_iter().next() {
                        id = Some(pid);
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                let id = id.expect("the ask did not park in time");
                let code = code_for_now(&secret, unix_now());

                let approved =
                    handle_line(&home, &home.join("events.jsonl"), &format!(r#"{{"op":"approve","id":"{id}","totp":"{code}"}}"#), &parked, &mut Vec::new(), None);
                assert_eq!(approved["ok"], true, "{approved}");

                let own_lines = own_log_lines(&home);
                let ev = find_notify_event(&own_lines, "completed");
                assert_eq!(ev["id"], id);
                assert_eq!(ev["secret"], "t");
                assert_eq!(ev["consumer"], "m");
                assert!(!ev.to_string().contains("stored-value"), "{ev}");

                let resolved = resolve_handle.join().unwrap();
                assert_eq!(resolved["ok"], true, "{resolved}");
            });
        });
        std::fs::remove_dir_all(&home).ok();
    }

    /// `dismissed` (task's exact shape: `{event, id, secret, consumer}`)
    /// fires when an operator dismisses a parked ask.
    #[test]
    fn dismissed_fires_on_a_dismiss() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("notify-dismissed");
        let p = Policy::new("t", "scratch", "stored-value");
        seed_enrolled(&home, p);
        let parked = ParkRegistry::new();

        with_redirected_audit_log(&home, || {
            std::thread::scope(|scope| {
                let resolve_handle =
                    scope.spawn(|| handle_line(&home, &home.join("events.jsonl"), r#"{"op":"resolve","secret":"t","consumer":"m"}"#, &parked, &mut Vec::new(), None));

                let mut id = None;
                for _ in 0..200 {
                    if let Some((pid, ..)) = parked.list().into_iter().next() {
                        id = Some(pid);
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                let id = id.expect("the ask did not park in time");

                let dismissed = handle_line(&home, &home.join("events.jsonl"), &format!(r#"{{"op":"dismiss","id":"{id}"}}"#), &parked, &mut Vec::new(), operator_peer());
                assert_eq!(dismissed["ok"], true, "{dismissed}");

                let own_lines = own_log_lines(&home);
                let ev = find_notify_event(&own_lines, "dismissed");
                assert_eq!(ev["id"], id);
                assert_eq!(ev["secret"], "t");
                assert_eq!(ev["consumer"], "m");

                let resolved = resolve_handle.join().unwrap();
                assert_eq!(resolved["ok"], false);
            });
        });
        std::fs::remove_dir_all(&home).ok();
    }

    /// `expired` (task's exact shape: `{event, id, secret, consumer}`)
    /// fires on the ORIGINAL caller's own side when a park times out with
    /// no answer — same tiny-timeout fixture `park_times_out_and_names_
    /// the_knob_and_both_completion_paths` above already uses.
    #[test]
    fn expired_fires_on_a_park_timeout() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_timeout = std::env::var(crate::park::PARK_TIMEOUT_ENV).ok();
        std::env::set_var(crate::park::PARK_TIMEOUT_ENV, "1");

        let home = tmp_home("notify-expired");
        let p = Policy::new("t", "scratch", "stored-value");
        seed_enrolled(&home, p);
        let parked = ParkRegistry::new();

        with_redirected_audit_log(&home, || {
            let reply = handle_line(&home, &home.join("events.jsonl"), r#"{"op":"resolve","secret":"t","consumer":"m"}"#, &parked, &mut Vec::new(), None);
            assert_eq!(reply["ok"], false, "{reply}");
        });

        let own_lines = own_log_lines(&home);
        let ev = find_notify_event(&own_lines, "expired");
        assert_eq!(ev["secret"], "t");
        assert_eq!(ev["consumer"], "m");
        assert!(ev.get("id").and_then(Value::as_str).is_some(), "{ev}");

        match saved_timeout {
            Some(v) => std::env::set_var(crate::park::PARK_TIMEOUT_ENV, v),
            None => std::env::remove_var(crate::park::PARK_TIMEOUT_ENV),
        }
        std::fs::remove_dir_all(&home).ok();
    }

    /// The sentinel test (mirrors `put_sentinel_value_never_leaks_on_
    /// missing_policy_or_missing_set_template` above): a full
    /// park→approve→release lifecycle with a sentinel value must never let
    /// that value reach either notify destination, on any of the three
    /// events it touches (`parked`, `completed`, and the wire reply
    /// itself).
    #[test]
    fn notify_never_carries_a_value_across_the_full_lifecycle() {
        const SENTINEL: &str = "SENTINEL-NOTIFY-VALUE-XYZ";
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("notify-no-value-leak");
        let mut p = Policy::new("t", "scratch", SENTINEL);
        p.consumers = vec!["m".to_string()];
        let secret = seed_enrolled(&home, p);
        let parked = ParkRegistry::new();

        with_redirected_audit_log(&home, || {
            std::thread::scope(|scope| {
                let resolve_handle =
                    scope.spawn(|| handle_line(&home, &home.join("events.jsonl"), r#"{"op":"resolve","secret":"t","consumer":"m"}"#, &parked, &mut Vec::new(), None));

                let mut id = None;
                for _ in 0..200 {
                    if let Some((pid, ..)) = parked.list().into_iter().next() {
                        id = Some(pid);
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                let id = id.expect("the ask did not park in time");
                let code = code_for_now(&secret, unix_now());
                let approved =
                    handle_line(&home, &home.join("events.jsonl"), &format!(r#"{{"op":"approve","id":"{id}","totp":"{code}"}}"#), &parked, &mut Vec::new(), None);
                assert_eq!(approved["ok"], true, "{approved}");
                assert!(!approved.to_string().contains(SENTINEL), "the approve reply leaked the value: {approved}");

                let resolved = resolve_handle.join().unwrap();
                assert_eq!(resolved["value"], SENTINEL, "the ORIGINAL caller still gets the real value");
            });
        });

        let own_log = std::fs::read_to_string(own_audit_log_path(&home)).unwrap();
        assert!(!own_log.contains(SENTINEL), "the broker's own audit.log leaked the sentinel via a notify line:\n{own_log}");
        let mirrored_log = std::fs::read_to_string(home.join("mirrored-aoide-log")).unwrap();
        assert!(!mirrored_log.contains(SENTINEL), "the mirrored aoide log leaked the sentinel via a notify line:\n{mirrored_log}");
        // P-G4 (task #77): the name-only discipline extends to the THIRD
        // notify destination, the broker-owned events feed.
        let events_feed = std::fs::read_to_string(home.join("events.jsonl")).unwrap();
        assert!(!events_feed.contains(SENTINEL), "the events feed leaked the sentinel via a notify line:\n{events_feed}");
        assert!(events_feed.contains("\"event\":\"parked\""), "{events_feed}");
        assert!(events_feed.contains("\"event\":\"completed\""), "{events_feed}");

        std::fs::remove_dir_all(&home).ok();
    }

    // ── the events feed itself (P-G4, task #77) ─────────────────────────

    /// `append_events_feed` creates the file `0640` — group-read, no
    /// world access, never left to the process umask.
    #[test]
    fn append_events_feed_creates_the_file_0640() {
        let home = tmp_home("events-perms");
        let events_path = home.join("events.jsonl");
        append_events_feed(&events_path, &json!({"event": "released", "secret": "t", "consumer": "m"}));
        let mode = std::fs::metadata(&events_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "the events feed must be 0640, got {mode:o}");
        std::fs::remove_dir_all(&home).ok();
    }

    /// A second (and later) append never re-chmods — proven indirectly by
    /// the file staying readable/writable by its own owner after a mode
    /// change in between (if a later append re-created it, the manual
    /// chmod below would have been silently undone).
    #[test]
    fn append_events_feed_does_not_rechmod_an_existing_file() {
        let home = tmp_home("events-no-rechmod");
        let events_path = home.join("events.jsonl");
        append_events_feed(&events_path, &json!({"event": "released", "secret": "t", "consumer": "m"}));
        std::fs::set_permissions(&events_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        append_events_feed(&events_path, &json!({"event": "released", "secret": "t2", "consumer": "m"}));
        let mode = std::fs::metadata(&events_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a later append must not re-chmod an already-existing file, got {mode:o}");
        std::fs::remove_dir_all(&home).ok();
    }

    /// The size guard (task requirement): past `EVENTS_MAX_BYTES`, the next
    /// append truncates the file to empty FIRST — `watch::Follower::poll`'s
    /// own `len() < pos` branch is what makes this transparent to a live
    /// tail (confirmed by reading `watch.rs` directly: `Follower::poll`
    /// reopens at 0 whenever the file has shrunk since the last poll,
    /// which a truncate-then-write always produces relative to a follower
    /// sitting at the old, larger EOF).
    #[test]
    fn append_events_feed_truncates_once_the_cap_is_exceeded() {
        let home = tmp_home("events-cap");
        let events_path = home.join("events.jsonl");
        // Pad the file past the cap directly — writing enough real events
        // one at a time to cross 1 MiB would make this test slow for no
        // extra coverage; `append_events_feed` only ever consults the
        // file's CURRENT size, not how it got there.
        std::fs::write(&events_path, vec![b'x'; (EVENTS_MAX_BYTES + 1) as usize]).unwrap();
        assert!(std::fs::metadata(&events_path).unwrap().len() > EVENTS_MAX_BYTES);

        append_events_feed(&events_path, &json!({"event": "released", "secret": "t", "consumer": "m"}));

        let contents = std::fs::read_to_string(&events_path).unwrap();
        assert!(!contents.contains('x'), "the oversized padding must be gone after truncation: {contents}");
        assert!(contents.contains("\"event\":\"released\""), "{contents}");
        assert!(
            (contents.len() as u64) < EVENTS_MAX_BYTES,
            "the file must be back under the cap right after truncating, got {} bytes",
            contents.len()
        );
        std::fs::remove_dir_all(&home).ok();
    }

    /// Below the cap, an append is an ordinary append — proven by two
    /// lines both surviving (a truncating append would lose the first).
    #[test]
    fn append_events_feed_appends_normally_under_the_cap() {
        let home = tmp_home("events-normal-append");
        let events_path = home.join("events.jsonl");
        append_events_feed(&events_path, &json!({"event": "released", "secret": "first", "consumer": "m"}));
        append_events_feed(&events_path, &json!({"event": "released", "secret": "second", "consumer": "m"}));
        let contents = std::fs::read_to_string(&events_path).unwrap();
        assert!(contents.contains("first"), "{contents}");
        assert!(contents.contains("second"), "{contents}");
        assert_eq!(contents.lines().count(), 2, "{contents}");
        std::fs::remove_dir_all(&home).ok();
    }

    /// Best-effort proof (task requirement): a resolve still succeeds when
    /// BOTH notify destinations are unavailable — the own `audit.log` file
    /// is read-only (root ignores file permissions, so this skips under a
    /// root test runner, same precedent `an_unreadable_policy_json_
    /// teaches_the_chown_reference_fix_on_both_gates` sets) and the
    /// mirrored aoide log points at a path no process could ever create
    /// (a parent component is a plain FILE, not a directory).
    #[test]
    fn resolve_still_succeeds_when_the_notify_sink_is_unavailable() {
        if crate::home::effective_uid() == 0 {
            return;
        }
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("notify-sink-unavailable");
        let mut p = Policy::new("t", "scratch", "stored-value");
        p.consumers = vec!["m".to_string()];
        seed(&home, &[p]);

        // Pre-create the broker's own audit.log, then strip write
        // permission — `append_own_log`'s `OpenOptions::append` must fail.
        let own_log = own_audit_log_path(&home);
        std::fs::write(&own_log, "").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&own_log, std::fs::Permissions::from_mode(0o400)).unwrap();

        // A mirrored-log path that can never be created: a regular FILE
        // stands in for what would need to be a directory component.
        let blocker_file = home.join("blocker-file");
        std::fs::write(&blocker_file, "not a directory").unwrap();
        let unreachable_mirror = blocker_file.join("log");

        let saved = std::env::var("AOIDE_AUDIT_LOG").ok();
        std::env::set_var("AOIDE_AUDIT_LOG", &unreachable_mirror);

        let parked = ParkRegistry::new();
        let reply = handle_line(&home, &home.join("events.jsonl"), r#"{"op":"resolve","secret":"t","consumer":"m"}"#, &parked, &mut Vec::new(), None);

        match saved {
            Some(v) => std::env::set_var("AOIDE_AUDIT_LOG", v),
            None => std::env::remove_var("AOIDE_AUDIT_LOG"),
        }
        // Restore write permission before cleanup can remove the tempdir.
        std::fs::set_permissions(&own_log, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(reply["ok"], true, "a resolve must succeed even when BOTH notify sinks are unreachable: {reply}");
        assert_eq!(reply["value"], "stored-value");

        std::fs::remove_dir_all(&home).ok();
    }

    /// P-G4 review gap (task #76 item 6b): the sibling test above proves a
    /// resolve survives the OTHER two notify destinations failing — this
    /// closes the matching gap for the events feed itself (P-G4's THIRD
    /// destination, `append_events_feed`): its PARENT directory is
    /// read-only, so `OpenOptions::new().create(true)` can never make the
    /// file at all, the same "best-effort, never blocks the resolve it
    /// rides alongside" contract `emit_notify`'s own doc holds for all
    /// three writes. Root ignores directory permissions too, so this skips
    /// under a root test runner — same precedent as the sibling test.
    #[test]
    fn resolve_still_succeeds_when_the_events_feed_path_is_unwritable() {
        if crate::home::effective_uid() == 0 {
            return;
        }
        let home = tmp_home("events-feed-unwritable");
        let mut p = Policy::new("t", "scratch", "stored-value");
        p.consumers = vec!["m".to_string()];
        seed(&home, &[p]);

        let ro_dir = home.join("events-ro-dir");
        std::fs::create_dir_all(&ro_dir).unwrap();
        use std::os::unix::fs::PermissionsExt;
        // Read + execute (so the dir can still be traversed/stat'd), no
        // write — a brand-new file can never be created under it.
        std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let events_path = ro_dir.join("events.jsonl");

        let parked = ParkRegistry::new();
        let reply = handle_line(&home, &events_path, r#"{"op":"resolve","secret":"t","consumer":"m"}"#, &parked, &mut Vec::new(), None);

        // Restore write permission before cleanup can remove the tempdir.
        std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert_eq!(reply["ok"], true, "a resolve must succeed even when the events feed's own path is unwritable: {reply}");
        assert_eq!(reply["value"], "stored-value");
        assert!(!events_path.exists(), "the events feed file must never have been created under a read-only parent");

        std::fs::remove_dir_all(&home).ok();
    }

    // ── task #79: `{op:"admin"}` over the broker socket ─────────────────

    /// Task #79 item 6a: an `{op:"admin","command":"add"}` request over a REAL
    /// socket connection (`UnixStream::pair` + [`handle_conn`], the same
    /// pattern [`park_over_a_real_connection_writes_the_interim_line_then_the_final_reply`]
    /// already establishes) round-trips a genuine mutation into
    /// `policy.json` — proving the wire framing end to end, not just
    /// [`handle_admin`]'s own logic called directly. A real socketpair
    /// reports THIS test process's own euid on both ends, which is exactly
    /// [`admin_gate`]'s happy path: the connecting peer IS the broker's own
    /// process here, so no uid needs to be faked for this test to exercise
    /// the real gate honestly.
    #[test]
    fn admin_add_over_a_real_socket_connection_round_trips_into_policy_json() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("admin-add-real-socket");
        let parked = Arc::new(ParkRegistry::new());

        with_redirected_audit_log(&home, || {
            let (client_end, server_end) = UnixStream::pair().expect("socketpair");
            let home_for_conn = home.clone();
            let events_for_conn = home.join("events.jsonl");
            let parked_for_conn = Arc::clone(&parked);
            let conn_handle =
                std::thread::spawn(move || handle_conn(&home_for_conn, &events_for_conn, server_end, &parked_for_conn));

            let mut writer = client_end.try_clone().expect("clone client end");
            let req = json!({
                "op": "admin", "command": "add", "name": "t", "backend": "scratch", "key": "k",
                "requireTotp": false, "consumers": [],
            });
            writer.write_all((req.to_string() + "\n").as_bytes()).unwrap();

            let mut reader = BufReader::new(client_end);
            let mut line = String::new();
            reader.read_line(&mut line).expect("reading the admin reply");
            let reply: Value = serde_json::from_str(line.trim()).expect("reply must be JSON");
            assert_eq!(reply["ok"], true, "{reply}");
            assert!(reply["message"].as_str().unwrap().contains("added secret `t`"), "{reply}");
            assert_eq!(reply["changed"], json!(["policy:t"]), "{reply}");

            drop(reader);
            drop(writer);
            conn_handle.join().unwrap();
        });

        let policies = crate::store::load_policies(&home).unwrap();
        assert_eq!(policies.len(), 1, "the admin op must have landed a real policy row");
        assert_eq!(policies[0].name, "t");
        std::fs::remove_dir_all(&home).ok();
    }

    /// Task #79 item 6b (wrong-uid refusal): a connection whose peer uid
    /// does NOT match the broker's own effective uid gets [`admin_gate`]'s
    /// refusal, and `policy.json` is never touched — the scratch broker's
    /// OWN euid is this test process's real euid, so the mismatch is
    /// manufactured the same `wrapping_add` sentinel way the dismiss-gate
    /// tests above already establish (a real socketpair can't produce a
    /// genuinely different uid in-test).
    #[test]
    fn admin_op_from_a_mismatched_peer_uid_is_refused_and_policy_json_is_untouched() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("admin-wrong-uid");
        let real_euid = unsafe { libc::geteuid() };
        let wrong_uid = real_euid.wrapping_add(40_000);

        with_redirected_audit_log(&home, || {
            let req = json!({"op": "admin", "command": "add", "name": "t", "backend": "scratch", "key": "k"});
            let wrong_peer = Some(crate::peercred::PeerCred { uid: wrong_uid, gid: 0, pid: 0 });
            let reply = handle_admin(&home, &req, wrong_peer);
            assert_eq!(reply["ok"], false, "{reply}");
            let err = reply["error"].as_str().unwrap();
            assert!(err.contains(&wrong_uid.to_string()), "{err}");
            assert!(err.contains("must run as the broker user"), "{err}");
        });

        assert!(crate::store::load_policies(&home).unwrap_or_default().is_empty(), "a refused admin op must never touch policy.json");
        std::fs::remove_dir_all(&home).ok();
    }

    /// Task #79 item 2: root (uid 0) is refused the identical taught error
    /// the direct-write path's `require_admin_identity` already gives —
    /// plain `sudo` is still wrong over the socket too, never a bypass.
    #[test]
    fn admin_op_from_root_is_refused_the_same_taught_error_the_direct_path_gives() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("admin-root");
        with_redirected_audit_log(&home, || {
            let req = json!({"op": "admin", "command": "add", "name": "t", "backend": "scratch", "key": "k"});
            let root_peer = Some(crate::peercred::PeerCred { uid: 0, gid: 0, pid: 0 });
            let reply = handle_admin(&home, &req, root_peer);
            assert_eq!(reply["ok"], false, "{reply}");
            let err = reply["error"].as_str().unwrap();
            assert!(err.contains("root (uid 0)"), "{err}");
            assert!(err.to_lowercase().contains("plain `sudo`"), "{err}");
        });
        std::fs::remove_dir_all(&home).ok();
    }

    /// Task #79's fail-closed default, extended from `dismiss_authorized`
    /// to `admin_gate`: an unidentified connection (SO_PEERCRED read
    /// failed) is refused outright — there's no uid to compare, so the
    /// safe answer is refusal, never a permissive fallback.
    #[test]
    fn admin_op_from_an_unidentified_connection_is_refused() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("admin-unidentified");
        with_redirected_audit_log(&home, || {
            let req = json!({"op": "admin", "command": "add", "name": "t", "backend": "scratch", "key": "k"});
            let reply = handle_admin(&home, &req, None);
            assert_eq!(reply["ok"], false, "{reply}");
            assert!(reply["error"].as_str().unwrap().contains("IDENTIFIED"), "{reply}");
        });
        std::fs::remove_dir_all(&home).ok();
    }

    /// Task #79 item 6d (migrate-over-socket durability order): the SAME
    /// fetch -> store -> flip -> remove-old-last ordering [`crate::admin::
    /// migrate`]'s own doc holds regardless of caller, proven here end to
    /// end over the real wire — the new backend already holds the value
    /// AND the old built-in's file is gone, both observed AFTER a single
    /// `{op:"admin","command":"migrate"}` round trip.
    #[test]
    fn admin_migrate_over_a_real_socket_connection_lands_the_new_value_and_removes_the_old_one() {
        if !age_tools_available() {
            eprintln!(
                "skipping admin_migrate_over_a_real_socket_connection_lands_the_new_value_and_removes_the_old_one: \
                 age/age-keygen not found on PATH"
            );
            return;
        }
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("admin-migrate-real-socket");
        crate::backend::seed_default_backends(&home).unwrap();
        crate::store::save_policies(&home, &[Policy::new("t", "file", "k")]).unwrap();
        crate::backend::store_value(&home, "file", "k", "the-value").unwrap();
        let parked = Arc::new(ParkRegistry::new());

        with_redirected_audit_log(&home, || {
            let (client_end, server_end) = UnixStream::pair().expect("socketpair");
            let home_for_conn = home.clone();
            let events_for_conn = home.join("events.jsonl");
            let parked_for_conn = Arc::clone(&parked);
            let conn_handle =
                std::thread::spawn(move || handle_conn(&home_for_conn, &events_for_conn, server_end, &parked_for_conn));

            let mut writer = client_end.try_clone().expect("clone client end");
            let req = json!({"op": "admin", "command": "migrate", "name": "t", "target": "age"});
            writer.write_all((req.to_string() + "\n").as_bytes()).unwrap();

            let mut reader = BufReader::new(client_end);
            let mut line = String::new();
            reader.read_line(&mut line).expect("reading the admin reply");
            let reply: Value = serde_json::from_str(line.trim()).expect("reply must be JSON");
            assert_eq!(reply["ok"], true, "{reply}");

            drop(reader);
            drop(writer);
            conn_handle.join().unwrap();
        });

        assert_eq!(crate::backend::fetch_value(&home, "age", "k").unwrap(), "the-value", "the new backend must durably hold the value");
        assert!(!home.join("store").join("k").exists(), "the old file-backend value must be removed");
        std::fs::remove_dir_all(&home).ok();
    }

    /// Task #79 composed with task #74/P-G3: `handle_admin`'s "migrate" arm
    /// runs `crate::admin::migrate` — which shells out to the SOURCE
    /// backend's `get` via `crate::backend::fetch_value` — INSIDE the same
    /// `put_lock` critical section `put_gate` itself uses (`handle_admin`'s
    /// own module doc: "run inside `put_lock`'s critical section... the
    /// SAME lock a `put` already serializes under"). The two tests above
    /// (`a_hung_set_template_no_longer_wedges_put_lock_forever`,
    /// `a_hung_age_keygen_mint_no_longer_wedges_put_lock_forever`) already
    /// prove `wait_bounded` frees `put_lock` for `put_gate`'s own shell-outs
    /// — this proves the SAME bound applies through the admin socket op,
    /// since that composition (admin command -> `crate::admin` -> a hung
    /// backend shell-out -> `put_lock`) was never exercised by those two.
    #[test]
    fn a_hung_admin_migrate_no_longer_wedges_put_lock_forever() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let home = tmp_home("admin-migrate-hung-bounded");
        let out = home.join("out.txt");
        let p_hangs = Policy::new("t", "hangs", "k");
        let p_scratch = Policy::new("other", "scratch", "k");
        crate::store::save_policies(&home, &[p_hangs, p_scratch]).unwrap();
        let backends = serde_json::json!({
            "hangs": { "get": "sleep 60", "set": "true" },
            "scratch": { "get": format!("cat {}", out.display()), "set": format!("cat > {}", out.display()) },
        });
        std::fs::write(crate::backend::backends_path(&home), serde_json::to_vec(&backends).unwrap()).unwrap();

        let saved_timeout = std::env::var(crate::backend::BACKEND_TIMEOUT_ENV).ok();
        std::env::set_var(crate::backend::BACKEND_TIMEOUT_ENV, "1");

        let (elapsed, reply, granted, result) = with_redirected_audit_log(&home, || {
            let req = json!({"op": "admin", "command": "migrate", "name": "t", "target": "scratch"});
            let start = std::time::Instant::now();
            let reply = handle_admin(&home, &req, operator_peer());
            let elapsed = start.elapsed();
            // A second, unrelated put right after — the SAME "lock genuinely
            // freed, not just this caller giving up" proof the two
            // precedent tests make.
            let (granted, result) = put_outcome_as_result(put_gate(&home, "other", "second-caller-value", false));
            (elapsed, reply, granted, result)
        });

        match saved_timeout {
            Some(v) => std::env::set_var(crate::backend::BACKEND_TIMEOUT_ENV, v),
            None => std::env::remove_var(crate::backend::BACKEND_TIMEOUT_ENV),
        }

        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "handle_admin migrate against a hung source-backend fetch took {elapsed:?} — put_lock was not freed in bounded time"
        );
        assert_eq!(reply["ok"], false, "{reply}");
        assert!(reply["error"].as_str().unwrap().contains("timed out"), "{reply}");
        assert!(granted, "the second, unrelated put must succeed once put_lock is freed: {result:?}");
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "second-caller-value");

        std::fs::remove_dir_all(&home).ok();
    }
}
