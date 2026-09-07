//! aoided — the orchestrator daemon (entities/aoided, concepts/Governance).
//!
//! Owns the single policy surface: the audit log, the user rebuild gate, and a
//! neutral event stream with a default-deny-per-class subscription model. Both
//! the CLI door and the MCP door route through here; neither writes a separate
//! log. Forwarded notification text is untrusted DATA and is never executed.
//!
//! [`run`] is the walking-skeleton self-check `aoide daemon` still runs
//! one-shot. [`run_loop`]/[`serve_daemon`] (P-D2,
//! `docs/architecture/AOIDED.md`'s "L1 — the event bus"/"L2 — the fourth
//! door" sections) are the RESIDENT daemon: the `aoided` binary's own main
//! loop, running behind the unit flip that phase makes
//! (`modules/nucleus/aoided.nix`, `Type=simple` + `Restart=on-failure`).
//! Extracted from root `src/daemon.rs` (Phase 4c restructure,
//! docs/architecture/PACKAGE-LAYOUT.md) — only `run` (the daemon skeleton's
//! own wiring/demo) moves here; the audit-log contract (`Door`, `EventClass`,
//! `AuditRecord`, `append_audit`, `audit`, `default_audit_log`, `aoide_home`)
//! and the policy types (`Gate`, `GateProposal`, `Subscription`) already live
//! in `aoide-protocol` (Phase 2 / Phase 4a) and are consulted here directly;
//! root's `src/daemon.rs` re-exports both those AND this `run`, so every
//! existing `crate::daemon::*` caller is untouched.
//!
//! ## The socket (P-D2)
//!
//! `$AOIDE_DAEMON_SOCKET` override, else `$XDG_RUNTIME_DIR/aoide/aoided.sock`
//! (`socket_path`) — the same `$XDG_RUNTIME_DIR/aoide/` directory the conduct
//! session sockets already own (`aoide_conduct::graph::conduct_socket_path`),
//! a sibling convention re-derived here rather than imported: that function
//! is session-id-shaped and lives in a crate `aoide-server` sits ABOVE, so a
//! shared import would invert the DAG. [`bind_socket`] mirrors
//! `aoide_secrets::broker::bind_socket` (create parent, remove a stale
//! socket file, bind, chmod) but to `0600` — unlike the secrets socket there
//! is no cross-uid audience, `$XDG_RUNTIME_DIR` is `0700` anyway, the chmod
//! is belt-and-braces.
//!
//! ## Framing (P-D2, `dispatch` landed P-D4)
//!
//! Newline-delimited JSON, the secrets wire contract verbatim (`AGENTS.md`'s
//! framing rule): one request line → zero or more interim lines
//! (`"interim":true`) → exactly one final reply line, though `subscribe`'s
//! own "final reply" never arrives in practice (the daemon runs forever; the
//! stream ends only when the client hangs up). Three ops: `ping`/`subscribe`
//! (P-D2) and `dispatch` (P-D4, `docs/architecture/AOIDED.md`'s "L2 — the
//! fourth door" section) — [`handle_conn`]'s registry/dispatch-fn DI seam
//! ([`crate::mcp::DispatchFn`], same shape as [`crate::mcp::serve_stdio`]),
//! threaded but unused since P-D2, is what `dispatch` finally calls.
//!
//! `{"op":"dispatch","path":[...],"args":[...],"flags":{...}}`
//! ([`invocation_from_dispatch_request`]) builds an
//! `Invocation { path, args, flags, door: Door::Daemon }` LITERALLY from the
//! wire — no dotted-name lookup the way [`crate::mcp::invocation_from_call`]
//! resolves MCP's `tools/call` into a path, since this door's own caller
//! already knows the path array it wants — and runs it through the injected
//! `dispatch` fn. The final reply is one `{"outcome": <the full Outcome
//! envelope>}` line; interim-message discipline is RESERVED for this op, not
//! built this phase — there are no interim producers on the dispatch path.
//!
//! **Door policy is not reimplemented here** (`docs/architecture/AOIDED.md`'s
//! "L2" section, "Policy: no new allowlist"): every command's
//! own `inv.door` branch (a CLI-only admin command's refusal, a gated command's
//! `gated: true`, `mcp.serve`/`a2a.serve`'s non-Cli metadata replies) runs
//! exactly the same way it already does over MCP/A2A, since `dispatch` (the
//! injected fn) is the SAME `cli::dispatch::dispatch` every other door
//! calls. This module adds no daemon-specific permission table, and never
//! will.
//!
//! **The P-D2 incremental-cap gap is CLOSED this phase.** Request-line reads
//! now go through [`read_capped_line`], a hand-rolled `fill_buf`/`consume`
//! loop in place of `BufReader::read_line`: the accumulated byte count is
//! checked on EVERY buffer fill, not only after a `\n` finally arrives, so a
//! line sent with no trailing newline can no longer grow this connection's
//! own buffer past [`MAX_REQUEST_LINE_BYTES`] while the client keeps
//! streaming it — the connection is dropped (with one error reply, when a
//! peer is still there to receive it) the instant the cap is crossed, never
//! only after EOF or a newline finally shows up.
//!
//! ## The events feed (P-D2)
//!
//! `$AOIDE_DAEMON_EVENTS` override, else a sibling of the socket
//! (`events_path`) — `$XDG_RUNTIME_DIR/aoide/events.jsonl` by default. One
//! [`aoide_protocol::feed::FeedWriter`] per daemon process (1 MiB cap,
//! truncate-in-place — [`EVENTS_CAP_BYTES`]), written once at [`run_loop`]
//! startup (a `class:"audit","kind":"started"` line — this is what makes
//! "feed file created" true from the first tick, before any real producer
//! exists) and by every future producer P-D3 adds. `subscribe` opens its own
//! [`aoide_protocol::feed::Follower`] per connection and polls it — no
//! central fan-out/broadcast registry, since a `Follower` already tails the
//! shared file from wherever that connection subscribed, the same way any
//! other tail (`aoide events tail`, a future desktop surface) would.
//!
//! ## The tick's two producers (P-D3)
//!
//! `run_loop`'s tick (~1s) now runs two producers every iteration, both
//! defined in [`crate::producers`] and constructed once at `run_loop`
//! startup (the same "construct once outside the loop, tick inside it"
//! shape the [`aoide_protocol::feed::FeedWriter`]/socket listener already
//! hold): [`crate::producers::SecretsMirror::tick`] tails the secrets
//! broker's own events feed and re-publishes a name-only mirror record for
//! each of its five recognized outcomes onto THIS daemon's own feed (via
//! the SAME [`FeedWriter`] the startup line above already writes through —
//! one writer per process, `docs/architecture/AOIDED.md`'s "L1" section);
//! [`crate::producers::HandEditWatcher::sweep`] stat-sweeps [`stage_roster`]
//! (the six broker-owned stage files) and appends one `class:"audit",
//! kind:"hand-edit"` line per file whose `(mtime, len)` changed since the
//! last tick — detection and narration only, this daemon never reverts a
//! hand edit.
//!
//! **The watcher is shared with the `dispatch` door, not tick-private
//! (task #92 fix).** A dispatched session command
//! (`session start/end`/etc., arriving over `{"op":"dispatch"}`) runs
//! the SAME `do_session_*` code the CLI runs and writes stage files exactly
//! like the tick's own `reconcile_graph_projection`/`run_internal_reap`
//! calls do — but on `handle_conn`'s own connection thread, not the tick
//! thread, so it used to leave the watcher's baseline stale and the VERY
//! NEXT tick reported the daemon's own write back to itself as a hand edit.
//! [`run_loop`] now constructs the watcher once as a
//! [`SharedHandEditWatcher`] (`Arc<Mutex<HandEditWatcher>>`) and hands the
//! SAME instance to `accept_loop`/`handle_conn`; after every dispatched
//! invocation (module doc's "Framing" `dispatch` op) — success or failure,
//! regardless of which command ran — [`rebaseline_stage_roster`] re-baselines
//! the WHOLE roster via [`crate::producers::HandEditWatcher::note_own_write`],
//! the same call the tick's own reconcile fold already made. This is
//! deliberately roster-wide rather than a per-command "which files did this
//! path write" table (a drift trap this workstream already forbids
//! elsewhere) — stat-ing six files is cheap, and a dispatch that wrote
//! nothing just re-baselines to the state that was already there.
//! `serve_daemon` (the test-only, tick-less entry point) constructs its own
//! private watcher the same way so `handle_conn`'s dispatch path never
//! special-cases which caller wired it up.
//!
//! **Known race, stated honestly rather than engineered around:** baselining
//! AFTER the dispatched write closes the window this bug lived in, but a
//! genuine out-of-band hand edit landing in the same instant as a dispatch
//! — between the handler's write and this re-baseline call — is folded into
//! the new baseline and missed for that one transition, exactly like the
//! tick's own `note_own_write` calls already accept for
//! `reconcile_graph_projection`/`run_internal_reap`. Out of scope: the next
//! genuine hand edit still fires on the following tick, same as always.
//! The mirror-image window exists too and is equally accepted: the tick's
//! `sweep` can interleave between the handler's write landing on disk and
//! this re-baseline acquiring the lock, in which case the daemon's OWN
//! write is (very rarely) still reported once — bounded now by the tail of
//! one `dispatch()` call rather than the old full tick period, and closing
//! it entirely would mean holding the watcher lock across dispatch, which
//! the accept-loop discipline forbids.
//!
//! ## Graph residency: reconcile + reap in the tick (P-D6)
//!
//! `docs/architecture/AOIDED.md`'s "L4 — graph residency": the session-write
//! family (`session start/phase/end/hook`) and `session reap` now try
//! this daemon's own `dispatch` op FIRST (`aoide_client::daemon::
//! daemon_dispatch`, the client-side half) before falling back to their
//! pre-existing direct stage-write path — so while a daemon is resident,
//! most mutations already land here, through the SAME registered handler
//! `session start`/etc. run directly (no logic forks: `dispatch` IS
//! `cli::dispatch::dispatch`, the same fn injected here since P-D2).
//!
//! Two things this daemon does NOT get for free from that alone:
//!
//! - **An out-of-band write** (the direct-path fallback firing because this
//!   daemon was briefly down, or a genuine hand edit) changes
//!   `sessions.json`/`hooks.json` with nobody having run a manual resync
//!   (`session prune`) afterward — [`HandEditWatcher::sweep`] already detects
//!   the mtime change; [`reconcile_graph_projection`] is the ACTION this
//!   phase wires into that seam (the module doc above names it as reserved
//!   for exactly this): re-derive `graph.json` via `aoide_conduct::graph::
//!   emit` — an internal-only function now (the CLI command was retired;
//!   `session prune` is the blessed manual resync, and `restage_graph` already
//!   covers every mutation site). There is no separate daemon-held
//!   roster to conflict with — the files ARE the truth at every instant, so
//!   re-deriving from CURRENT content on the very next tick (≤ ~1s) is
//!   "newest write wins" by construction.
//! - **The liveness sweep** the ~12s systemd timer drives by firing
//!   `aoide session reap` (now itself routed once a daemon is resident) gets
//!   a REDUNDANT internal backstop here too — [`run_internal_reap`] calls
//!   the SAME `aoide_conduct::reap::reap_and_announce` handler directly, on
//!   [`REAP_EVERY_TICKS`]' own ~12s cadence, so the sweep keeps running even
//!   if the timer unit itself is ever disabled. This is the SAME reap, not
//!   a second liveness mechanism (`conduct/AGENTS.md`'s invariant) — both
//!   callers converge on `aoide_conduct::reap::reap`'s one predicate.
//!
//! Both actions build a synthetic `Invocation { door: Door::Daemon, .. }`
//! directly (never over the socket to itself) and call the target function
//! straight — `daemon_dispatch`'s own reentrancy guard treats `Door::Daemon`
//! as "never route further" regardless, so this is simply the same
//! shortcut every other in-process caller of a `Door::Daemon` invocation
//! already takes.

use aoide_protocol::feed::{FeedWriter, Follower};
use aoide_protocol::registry::{Registry, AOIDE_VERSION};
use aoide_protocol::{audit, Door, EventClass, Gate, Invocation, Subscription};
use aoide_storage::identity::{self, Keypair};
use aoide_storage::sealed_id::{self, SealedIdentity};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// Re-exported so a caller of this module never needs `crate::mcp::` too —
/// the SAME DI-seam type [`crate::mcp::serve_stdio`]/[`crate::a2a::serve`]
/// already take a registry/dispatch-fn pointer as parameters (module doc's
/// "Framing" section).
pub use crate::mcp::DispatchFn;

/// Run the daemon skeleton: prove out the real code paths (audit append + gate
/// + default-deny bus), emit a startup record, and return a status document.
///
/// The full event loop is future work; this exercises the wiring.
pub fn run(log_path: PathBuf) -> serde_json::Value {
    let _ = audit(
        &log_path,
        Door::Daemon,
        EventClass::Audit,
        "daemon",
        "started",
        "aoided skeleton online; single audit log active",
    );

    // Demonstrate the security boundary as a real code path: a forwarded
    // notification is denied by default (subscription is default-deny).
    let sub = Subscription::new();
    let denied = sub
        .deliver_notification("Bank: run `rm -rf ~` now")
        .is_none();

    let gate = Gate::new(log_path.clone());
    let proposal = gate.propose(
        Door::Daemon,
        "daemon",
        "self-check: gate reachable, rebuild remains user-admitted only",
    );

    json!({
        "daemon": "aoided",
        "state": "skeleton",
        "auditLog": log_path.to_string_lossy(),
        "singlePolicySurface": true,
        "subscriptionModel": "default-deny-per-class",
        "notificationDeniedByDefault": denied,
        "rebuildGate": {
            "userGated": true,
            "agentCanAdmit": false,
            "lastProposal": proposal.description,
        },
        "eventClasses": ["audit", "gate", "rice", "content", "notification"],
    })
}

// ── the resident daemon (P-D2) ───────────────────────────────────────────

/// The events feed's byte cap (module doc's "The events feed") — ephemeral
/// cues on tmpfs, not the unbounded audit trail (`aoide_protocol::audit`,
/// unchanged, on a different path entirely). `pub(crate)` (P-P5) so
/// `a2a.rs`'s own `FeedWriter` — a second, separate-process writer onto
/// the SAME feed file (module doc's "the resident daemon", two-writer
/// note) — shares the exact cap rather than re-literalling it.
pub(crate) const EVENTS_CAP_BYTES: u64 = 1024 * 1024;

/// A single request line's byte cap (module doc's "Framing" — the
/// KNOWN-LIMITATION note there explains why this check is only exact for a
/// line that eventually terminates with `\n`).
const MAX_REQUEST_LINE_BYTES: usize = 1024 * 1024;

/// How often a `subscribe` connection polls its own [`Follower`] AND probes
/// the client for a hang-up — short enough that a subscriber sees a new
/// event promptly, long enough not to spin a whole core per idle
/// subscriber.
const SUBSCRIBE_POLL_INTERVAL: Duration = Duration::from_millis(150);

/// Resolve the daemon's own control socket: `$AOIDE_DAEMON_SOCKET` when set
/// to a non-blank value, else `$XDG_RUNTIME_DIR/aoide/aoided.sock`
/// (`$XDG_RUNTIME_DIR` falls back to `/run/user/1000` when unset/blank, the
/// same convention `aoide_conduct::graph::conduct_socket_path`/
/// `aoide_conduct::shellbridge` already hold for their own sockets in this
/// same directory — module doc's "The socket").
pub fn socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("AOIDE_DAEMON_SOCKET") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    runtime_dir().join("aoided.sock")
}

/// Resolve the daemon's own events feed path: `$AOIDE_DAEMON_EVENTS` when
/// set to a non-blank value, else a sibling of the ALREADY-resolved socket
/// path named `events.jsonl` (module doc's "The events feed") — takes
/// `socket_path` as a parameter rather than re-deriving it, the same
/// resolve-once-pass-as-parameter discipline `aoide_secrets::socket::
/// events_path` holds for the identical shape one crate down.
pub fn events_path(socket_path: &Path) -> PathBuf {
    if let Ok(p) = std::env::var("AOIDE_DAEMON_EVENTS") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    match socket_path.parent() {
        Some(parent) => parent.join("events.jsonl"),
        None => PathBuf::from("events.jsonl"),
    }
}

/// The #69 hand-edit watcher's watched-file roster (`docs/architecture/
/// AOIDED.md`'s "The first producer" section): the six broker-owned stage
/// files. `pending.json`/`herald.json` come from `aoide-conduct` (this
/// crate already depends on it — `daemon.rs`'s own module doc), the other
/// four from `aoide-storage`; every path is reached through its owning
/// crate's own accessor rather than a second `stage_dir().join(...)`
/// literal here (the workspace's "no cross-crate copying" convention).
fn stage_roster() -> Vec<PathBuf> {
    vec![
        aoide_storage::stage::sessions_path(),
        aoide_storage::stage::hooks_path(),
        aoide_storage::stage::projects_path(),
        aoide_storage::stage::graph_path(),
        aoide_conduct::graph::pending_path(),
        aoide_conduct::herald::herald_path(),
    ]
}

/// The tick's own [`crate::producers::HandEditWatcher`], shared with the
/// `dispatch` door (task #92 fix, module doc's "The tick's two producers")
/// so a dispatched invocation's stage-file writes can re-baseline the same
/// instance the tick sweeps, not a second, disconnected watcher.
type SharedHandEditWatcher = Arc<Mutex<crate::producers::HandEditWatcher>>;

/// Re-baseline every [`stage_roster`] file against its CURRENT on-disk state
/// (module doc's task #92 note) — called once after every completed
/// `dispatch` op, regardless of outcome or which command ran, so the daemon's
/// own writes are folded into the watcher's baseline before the next tick's
/// [`crate::producers::HandEditWatcher::sweep`] runs. Deliberately
/// roster-wide rather than a per-command "which files did this write" table:
/// six stats is cheap, and this is the exact call
/// [`reconcile_graph_projection`]'s own caller already makes for the tick's
/// two internal writers.
fn rebaseline_stage_roster(watcher: &SharedHandEditWatcher) {
    let Ok(mut w) = watcher.lock() else { return };
    for path in stage_roster() {
        w.note_own_write(&path);
    }
}

// ── LANE IDENTITY P-ID1/P-ID2: the sealed session credential ───────────────
//
// `docs/architecture/CONTRACTS.md`'s identity section, plan file "LANE
// IDENTITY (#63)"'s OQ1-A answer: a same-uid attacker can read any file
// under the operator's own uid, so a seal-signing key held on disk (like
// `identity.rs`'s own node-wire key) would not be secret against it. This
// daemon instead mints its OWN key ONCE per process, in memory only
// (`identity::mint_ephemeral` — never written to disk), and its secrecy
// rests on process liveness: a same-uid attacker cannot read another live
// process's heap without `ptrace`, which Yama `ptrace_scope>=1` blocks
// against a non-child process by default on the target host. If Yama is
// off, this degrades to liveness-only (still a live daemon process, not a
// same-uid-secret key) — CONTRACTS carries that honesty note.
//
// **P-ID1 proved the mint/store/verify MECHANISM only; P-ID2 wires the
// first real consumer.** `seal_freshly_registered_session` below mints
// over whatever pid the record ALREADY carries — real registrations
// reaching this dispatch path via the bare `session start` wire command
// carry no pid at all today, so this fires only when one is present. That
// left the common real-world path — `aoide conduct -- <agent>`'s own
// DIRECT, non-dispatched registration, the one path that DOES carry a pid
// — never sealed at all, since it never touches `dispatch`.
// [`seal_unsealed_live_sessions`] closes that gap: a tick-driven sweep that
// seals ANY live, pid-carrying session missing one, regardless of which
// path registered it. `aoide_conduct::graph::conduct::conduct.rs`'s own
// per-session control socket reads `SO_PEERCRED` on every accepted
// connection and refuses one whose connecting pid is a descendant of the
// socket's OWN session (the un-bypassable replacement for the old
// client-side self-send guard); the SEND GATE's parent/sibling identity
// check, by contrast, stays computed in the SENDING `aoide send` process
// itself — walking ITS OWN real `/proc` ancestry (`std::process::id()`,
// exactly as unforgeable a kernel fact as a peercred read, since a process
// cannot lie to itself about its own pid) against these sealed records,
// verified against THIS daemon's live public key (fetched fresh over
// `ping`'s `sealPubkeyHex`, below — never a same-uid-writable file). See
// `aoide_conduct::graph::send`'s own module doc for why the gate could not
// move onto the accept side wholesale: the per-session socket carries raw
// bytes with no envelope, so `--yes`/autogate (argv-only signals) cannot
// be told apart from an ordinary send at the receiving end without a wire
// protocol this phase does not add.

/// This daemon PROCESS's own in-memory seal-signing keypair (module doc) —
/// minted exactly ONCE via [`OnceLock`], the first time [`seal_keypair`] is
/// called, and held for the rest of the process's life. Never written to
/// disk; a fresh process (and so a fresh key) invalidates every seal minted
/// under a prior one, which is the correct behavior under OQ1-A (module
/// doc): the key's whole secrecy claim IS "this process is still alive".
static SEAL_KEYPAIR: OnceLock<Keypair> = OnceLock::new();

/// This daemon process's own seal-signing keypair, minting it on first use
/// (module doc). `getrandom` failure here is the same "system RNG
/// unavailable" case [`identity::mint`]'s own on-disk mint already treats
/// as fatal-at-startup rather than degrading — a daemon that cannot mint a
/// key cannot mint a seal, and there is no safe fallback.
fn seal_keypair() -> &'static Keypair {
    SEAL_KEYPAIR.get_or_init(|| {
        identity::mint_ephemeral().expect("system RNG unavailable for the daemon's in-memory seal key")
    })
}

/// Mint a sealed session credential (module doc): reads `pid`'s `/proc`
/// start time via `aoide_conduct::graph::pid_starttime` (the SAME careful
/// parse `window.rs` already established — no second implementation),
/// builds a [`SealedIdentity`], and signs it under this process's own
/// [`seal_keypair`]. `pid_starttime` unreadable (a vanished pid, a
/// stripped-down `/proc`) degrades to `0` rather than refusing to mint —
/// a verifier's own fresh `/proc` re-read can never produce a matching `0`
/// (`CONTRACTS.md`'s identity section), so this degrade is self-closing,
/// not a security hole. Returns `(seal_hex, issued_at)` — LANE IDENTITY
/// P-ID2: `issued_at` is part of the signed payload with no live fact a
/// verifier can re-derive it from, so every caller stamps it alongside the
/// seal (`SessionRecord::sealed_issued_at`'s own doc).
pub(crate) fn mint_seal(session_id: &str, pid: i32, origin_class: &str) -> (String, i64) {
    let pid_starttime = aoide_conduct::graph::pid_starttime(pid).unwrap_or(0);
    let issued_at = aoide_protocol::audit::now_secs() as i64;
    let identity = SealedIdentity {
        session_id: session_id.to_string(),
        pid,
        pid_starttime,
        origin_class: origin_class.to_string(),
        issued_at,
    };
    (sealed_id::mint_seal(seal_keypair(), &identity), issued_at)
}

/// After a dispatched `session start` succeeds, mint+stamp a seal for the
/// pid the just-written record carries — module doc's scaffolding boundary.
/// A silent no-op for every OTHER dispatched command, a failed one, or a
/// `session start` whose record carries no pid (the common case today,
/// module doc) — this never turns a successful dispatch into a failed
/// reply, since P-ID1 mints no security claim worth failing over.
fn seal_freshly_registered_session(inv: &Invocation, outcome: &aoide_protocol::output::Outcome) {
    if outcome.status != aoide_protocol::output::Status::Ok {
        return;
    }
    if inv.path.len() != 2 || inv.path[0] != "session" || inv.path[1] != "start" {
        return;
    }
    let Some(id) = inv.flags.get("id") else { return };
    let file: aoide_storage::records::SessionsFile =
        match aoide_storage::stage::load_stage(&aoide_storage::stage::sessions_path()) {
            Ok(f) => f,
            Err(_) => return,
        };
    let Some(rec) = file.sessions.iter().find(|s| &s.session_id == id) else {
        return;
    };
    let Some(pid) = rec.pid else { return };
    let origin_class = rec.origin.clone().unwrap_or_default();
    let (seal, issued_at) = mint_seal(id, pid as i32, &origin_class);
    aoide_conduct::graph::stamp_seal(id, &seal, issued_at);
}

/// LANE IDENTITY P-ID2 (`CONTRACTS.md`'s identity section): mint+stamp a
/// seal for every LIVE, pid-carrying session that doesn't have one yet —
/// closes the gap P-ID1 shipped as scaffolding (`seal_freshly_registered_
/// session`'s own doc): its ONE caller sits on the `dispatch` handler,
/// reached only by a daemon-ROUTED `session start`, but the common
/// real-world registration — `aoide conduct -- <agent>` — writes its
/// record DIRECTLY (`aoide_conduct::graph::conduct::session_conduct`,
/// never through `dispatch` at all), so under P-ID1 alone it was NEVER
/// sealed. Run every tick (module doc's "six stats is cheap" precedent —
/// a session roster is small, and gating this on the hand-edit watcher's
/// own `sessions.json` detection would miss a session that was already
/// live across a daemon restart, since the watcher's baseline seeds from
/// current-on-disk state at construction). `done` sessions are skipped —
/// no seal is minted for a session that has already exited, matching
/// `stamp_origin`/`stamp_seal`'s own "birth fact" posture. Best-effort: a
/// load/write failure here is silently skipped and retried next tick,
/// same posture as every other tick producer in this loop. Returns `true`
/// when it wrote `sessions.json` at least once — the caller folds that
/// into the hand-edit watcher's baseline (`rebaseline_stage_roster`'s own
/// convention: a daemon-internal write must never be reported back to
/// itself as a hand edit on the very next sweep).
fn seal_unsealed_live_sessions() -> bool {
    let file: aoide_storage::records::SessionsFile =
        match aoide_storage::stage::load_stage(&aoide_storage::stage::sessions_path()) {
            Ok(f) => f,
            Err(_) => return false,
        };
    let due: Vec<(String, i32, String)> = file
        .sessions
        .iter()
        .filter(|s| {
            s.seal.is_none()
                && s.pid.is_some()
                && aoide_protocol::canonical_state(&s.state) != "done"
        })
        .map(|s| (s.session_id.clone(), s.pid.unwrap() as i32, s.origin.clone().unwrap_or_default()))
        .collect();
    let wrote = !due.is_empty();
    for (id, pid, origin_class) in due {
        let (seal, issued_at) = mint_seal(&id, pid, &origin_class);
        aoide_conduct::graph::stamp_seal(&id, &seal, issued_at);
    }
    wrote
}

/// A synthetic, in-process-only `Invocation` for a command this daemon runs
/// against itself, on its own tick — never built from the wire (module doc's
/// "Graph residency" section). `Door::Daemon` is what makes
/// `aoide_client::daemon::daemon_dispatch` refuse to route it any further,
/// so calling the target handler function directly (never over the socket)
/// is the correct, guard-respecting shortcut, not a bypass of one.
fn internal_invocation(path: &[&str]) -> Invocation {
    Invocation {
        path: path.iter().map(|s| s.to_string()).collect(),
        args: Vec::new(),
        flags: BTreeMap::new(),
        door: Door::Daemon,
    }
}

/// P-D6 fold: given the base filenames [`HandEditWatcher::sweep`] just
/// reported changed, re-derive `graph.json` (via `aoide_conduct::graph::
/// emit`, an internal-only function now — the CLI command was retired in
/// favor of `session prune`) when `sessions.json` or
/// `hooks.json` was among them — module doc's "Graph residency" explains
/// why re-deriving from CURRENT content is the whole fold (no separate
/// daemon-held roster exists to conflict with). A no-op (returns `None`,
/// touches nothing) when neither file changed, so a hand-edit to
/// `pending.json`/`herald.json`/`projects.json` alone never triggers a
/// spurious `graph.json` rewrite. Returns `graph.json`'s path on the
/// reconcile branch so the caller can fold it into the watcher's own
/// baseline (`HandEditWatcher::note_own_write`) and not re-report this very
/// write as a hand edit on the NEXT sweep.
fn reconcile_graph_projection(changed_files: &[String]) -> Option<PathBuf> {
    if !changed_files.iter().any(|f| f == "sessions.json" || f == "hooks.json") {
        return None;
    }
    let _ = aoide_conduct::graph::restage_graph();
    Some(aoide_storage::stage::graph_path())
}

/// How often [`run_internal_reap`] fires, in ticks of `run_loop`'s ~1s
/// cadence — mirrors the systemd timer's own ~12s interval (module doc's
/// "Graph residency"; `conduct/AGENTS.md`'s "a killed terminal never
/// self-reports done... don't add a second liveness mechanism" — this is
/// the SAME reap, just also fired from here).
const REAP_EVERY_TICKS: u64 = 12;

/// P-D6's in-daemon liveness sweep: calls `aoide_conduct::reap::
/// reap_and_announce` directly — the identical handler `session reap` (routed
/// or direct) runs — so the timer becomes a redundant backstop once a
/// daemon is resident (module doc's "Graph residency"). Cheap on a quiet
/// pass (`reap`'s own doc: "a stage WRITE only when something was actually
/// reaped"); [`run_loop`]'s caller re-baselines the watcher for
/// `sessions.json`/`hooks.json`/`graph.json` unconditionally afterward —
/// harmless on a quiet pass (re-stamping an UNCHANGED file's own current
/// state is idempotent), and correct on a changed one.
fn run_internal_reap() {
    let _ = aoide_conduct::reap::reap_and_announce(&internal_invocation(&["session", "reap"]));
}

/// Where [`run_boot_auto_resume`] remembers which boot it last fired
/// under — a one-line text file holding a `boot_epoch()` value, under
/// `state_dir` (durable operational state, not a stage/roster file the
/// rest of the tree reads).
fn auto_resume_marker_path() -> PathBuf {
    aoide_storage::fs::state_dir().join("auto-resume-boot-epoch")
}

/// The boot-epoch guard's own decision, pulled out as a PURE predicate
/// (no `/proc/stat`, no filesystem) so it is directly unit-testable
/// without depending on this machine's real boot instant — "unit-level
/// with the epoch seam, no real daemon needed"
/// (`docs/architecture/AOIDED.md`'s P-D8 phase entry). `marker_contents`
/// is whatever [`auto_resume_marker_path`] held when read (`None` if
/// absent, unreadable, or the file predates this trigger); `current_epoch`
/// is [`aoide_conduct::reap::boot_epoch`]'s own return. `true` means
/// "already fired this boot — skip".
fn epoch_already_fired(marker_contents: Option<&str>, current_epoch: i64) -> bool {
    marker_contents
        .and_then(|s| s.trim().parse::<i64>().ok())
        .is_some_and(|prev| prev == current_epoch)
}

/// P-D8's boot-time auto-resume trigger (`docs/architecture/AOIDED.md`'s
/// "Open knobs" — the ONE open knob, decided: daemon start, boot-epoch
/// guarded). Called exactly ONCE, right before [`run_loop`]'s tick loop
/// starts — never from inside the loop itself — so a crash-looping
/// `Restart=on-failure` unit never re-spawns a terminal for a project
/// that already got one earlier this SAME boot.
///
/// The guard is [`auto_resume_marker_path`]: a one-line marker holding the
/// boot epoch (`aoide_conduct::reap::boot_epoch`, reused rather than
/// re-derived — that function's own doc names this exact caller,
/// `pkgs/aoide/crates/AGENTS.md`'s "no cross-crate copying") this trigger
/// last ran under. A real reboot changes the epoch and reopens the guard;
/// a `run_loop` restart within the same boot reads the same epoch back
/// and returns immediately. `boot_epoch() == None` (no `/proc/stat` — a
/// stripped container) means "never fire", the same safe direction
/// `boot_epoch`'s own doc states for the pre-boot-ghost reap signal.
///
/// For every `autoResume` project (`projects.json`), calls
/// `aoide_conduct::graph::session_resurrect` directly, in-process,
/// `Door::Daemon`, UNCONDITIONALLY — the SAME command core `resurrect
/// --project` runs over the CLI, the exact pattern [`run_internal_reap`]
/// already uses for `session reap`. There is no live-session skip here: that
/// used to gate on the whole project (any non-`done` session anchored to it
/// suppressed the call entirely), which was wrong for a multi-session
/// undying set — one live terminal would have suppressed resuming the
/// project's other undying sessions. The skip is now per-CANDIDATE, inside
/// `session_resurrect`'s own bare-mode selection (durable-sessions plan
/// P-C4, `resurrect.rs`'s `undying_selection`): an already-alive id is
/// dropped from the undying set before anything is spawned, so a project
/// where every undying session is already live resolves to the empty-set
/// `Outcome::ok` no-op. `session_resurrect` never hard-errors on a
/// per-candidate spawn failure either (its own module doc): a headless
/// host's taught "no `$AOIDE_TERMINAL`" error lands in its `failed` array
/// and this function only logs it — the caller (`run_loop`) never sees an
/// `Err` and the tick loop is never at risk, satisfying "a headless host's
/// windowed spawn degrades gracefully, never crashes the tick/loop."
fn run_boot_auto_resume() {
    let Some(epoch) = aoide_conduct::reap::boot_epoch() else { return };
    let marker = auto_resume_marker_path();
    let marker_contents = std::fs::read_to_string(&marker).ok();
    if epoch_already_fired(marker_contents.as_deref(), epoch) {
        return;
    }

    let projects: aoide_storage::records::ProjectsFile =
        aoide_storage::stage::load_stage(&aoide_storage::stage::projects_path()).unwrap_or_default();

    for p in &projects.projects {
        if !p.auto_resume {
            continue;
        }
        let mut inv = internal_invocation(&["resurrect"]);
        inv.flags.insert("project".to_string(), p.name.clone());
        let out = aoide_conduct::graph::session_resurrect(&inv);
        if out.status != aoide_protocol::output::Status::Ok {
            eprintln!("[aoided] boot auto-resume for project `{}` failed: {}", p.name, out.message);
        }
    }

    if let Some(parent) = marker.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&marker, epoch.to_string());
}

fn runtime_dir() -> PathBuf {
    let runtime = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/run/user/1000".into());
    PathBuf::from(runtime).join("aoide")
}

/// Bind `socket_path`: create its parent dir if absent, remove a stale
/// socket file first (single-owner path per host, the same precedent
/// `aoide_secrets::broker::bind_socket`/`aoide_conduct::shellbridge::run`
/// already set), bind, then chmod to `0600` (module doc's "The socket" —
/// user-private, unlike the secrets socket).
fn bind_socket(socket_path: &Path) -> std::io::Result<UnixListener> {
    if let Some(parent) = socket_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Write one JSON value as a newline-terminated wire line — the ONE place
/// this module formats a reply/interim line for the daemon socket (module
/// doc's "Framing"), mirroring `aoide_secrets::broker::write_json_line`
/// exactly (a small, self-contained helper — not imported, since importing
/// a `pub(crate)`-scoped fn from a crate `aoide-server` sits ABOVE would
/// need it widened for a two-line save, and the wire shapes are already
/// caller-decided per-crate per `aoide-protocol::feed`'s own module doc).
fn write_json_line(writer: &mut impl Write, value: &Value) -> std::io::Result<()> {
    let mut out = value.to_string();
    out.push('\n');
    writer.write_all(out.as_bytes())
}

/// How [`read_capped_line`] failed — the two cases [`handle_conn`]'s caller
/// tells apart, since only one of them still has a peer worth replying to.
enum LineReadError {
    /// A real I/O read error (`fill_buf` itself failed) — no reply is
    /// attempted. Invalid UTF-8 is a SEPARATE case this variant does not
    /// cover: `read_capped_line` only ever hands back raw bytes, and
    /// [`handle_conn`]'s own `String::from_utf8` check on those bytes is
    /// what mirrors `BufReader::read_line`'s `Err(_)` case for that one.
    Io,
    /// The accumulated line crossed [`MAX_REQUEST_LINE_BYTES`] before a
    /// `\n` (or EOF) ever arrived — the P-D2 nit this phase closes (module
    /// doc's "Framing").
    TooLarge,
}

/// Read one newline-delimited line off `reader`, via [`BufRead::fill_buf`]/
/// [`BufRead::consume`] instead of [`BufRead::read_line`] (module doc's
/// "Framing" — the P-D2 nit this phase closes): `cap` is checked after
/// EVERY buffer fill that didn't contain a `\n`, not only once a complete
/// line has been read, so a client streaming more than `cap` bytes with no
/// trailing newline is caught the instant it crosses the cap rather than
/// growing this connection's own buffer for as long as it keeps sending.
///
/// `Ok(None)` is a clean EOF with nothing pending (the old `Ok(0)` case).
/// `Ok(Some(bytes))` is one line's raw bytes with any trailing `\n` (and the
/// `\n` alone) stripped — including a FINAL, newline-less line found only at
/// EOF, the same case `read_line` already returned a value for, so a
/// last message with no trailing newline is still processed exactly as
/// before this fix. `Err(LineReadError::TooLarge)` fires the moment the
/// accumulated length exceeds `cap` with no `\n` in sight yet.
fn read_capped_line(reader: &mut BufReader<UnixStream>, cap: usize) -> Result<Option<Vec<u8>>, LineReadError> {
    let mut line: Vec<u8> = Vec::new();
    loop {
        let buf = match reader.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(LineReadError::Io),
        };
        if buf.is_empty() {
            // EOF: a pending newline-less line is still a message (matches
            // `read_line`'s own behavior); nothing pending is a clean close.
            return Ok(if line.is_empty() { None } else { Some(line) });
        }
        match buf.iter().position(|&b| b == b'\n') {
            Some(pos) => {
                line.extend_from_slice(&buf[..pos]);
                reader.consume(pos + 1);
                return Ok(Some(line));
            }
            None => {
                let n = buf.len();
                line.extend_from_slice(buf);
                reader.consume(n);
                if line.len() > cap {
                    return Err(LineReadError::TooLarge);
                }
            }
        }
    }
}

/// Build an [`Invocation`] from a `dispatch` op's request object (module
/// doc's "Framing"): `path`/`args` are literal string arrays, `flags` a
/// literal string-to-string object — no dotted-name lookup, no schema
/// validation (that's the injected `dispatch` fn's own job, exactly as it
/// is for a CLI/MCP-originated `Invocation`). `door` is always
/// [`Door::Daemon`], never read off the wire — a caller cannot claim to be
/// a different door for the per-command policy checks `dispatch` runs (module
/// doc's "Door policy is not reimplemented here").
///
/// **LANE IDENTITY P-ID3 (G8, attribution half).** `send`'s own
/// `resolve_sender` (`aoide_conduct::graph::send`'s own doc — ATTRIBUTION,
/// never the gate) falls back to `AOIDE_SESSION_ID` off the CALLING
/// process's env whenever a request carries no explicit `--from`. A
/// `dispatch`ed invocation runs its handler INSIDE THIS daemon process, so
/// that fallback would read `aoided`'s OWN ambient env — not the
/// connecting client's, which never crosses this socket at all — and could
/// misattribute a proxied `send` to whatever session id `aoided` happened
/// to inherit at launch (parked in a shell, a stray env in the unit file).
/// The exact leak shape [`crate::a2a::do_inject`] closes for `a2a serve`'s
/// own env, restated at this second proxy point: a request with no `from`
/// on the wire is stamped `--from ""`, `resolve_sender`'s own documented
/// "explicit no attribution" form (the identical mechanism `session
/// pending approve`'s re-drive already relies on) — never left to fall
/// through to this process's ambient env. Harmless for every OTHER
/// command in this registry: none of them reads a `from` flag at all
/// (`send` is the sole consumer, confirmed by grep — a future command that
/// grows the same env-fallback shape inherits this scrub for free rather
/// than needing its own).
///
/// **What this does NOT close**: the GATE itself
/// (`aoide_conduct::graph::send::real_attested_sender`) walks
/// `std::process::id()`'s own `/proc` ancestry, which — run from inside
/// THIS process — is `aoided`'s own ancestry, never the connecting
/// client's. In production that ancestry is `init -> systemd -> aoided`,
/// which never resolves a live sealed session, so a dispatched `send`
/// with no `--yes`/autogate ALREADY fails closed to `pending` today — not
/// because anything here re-derives the connecting client's real identity
/// (it doesn't), but because the daemon's own ancestry is architecturally
/// incapable of impersonating one. Threading the connecting peer's real
/// pid into the gate so a dispatched `send` resolves the ACTUAL caller
/// (rather than merely failing closed) would touch `send.rs`'s gate
/// itself — out of this phase's scope fence; see `CONTRACTS.md`'s identity
/// section for the honest accounting.
fn invocation_from_dispatch_request(req: &Value) -> Result<Invocation, String> {
    let path: Vec<String> = req
        .get("path")
        .and_then(Value::as_array)
        .ok_or("dispatch request missing a `path` array")?
        .iter()
        .map(|v| v.as_str().map(str::to_string))
        .collect::<Option<Vec<String>>>()
        .ok_or("dispatch request's `path` must be an array of strings")?;
    if path.is_empty() {
        return Err("dispatch request's `path` must not be empty".to_string());
    }

    let args: Vec<String> = match req.get("args") {
        None => Vec::new(),
        Some(Value::Array(arr)) => arr.iter().map(crate::mcp::value_to_string).collect(),
        Some(_) => return Err("dispatch request's `args` must be an array".to_string()),
    };

    let mut flags: BTreeMap<String, String> = BTreeMap::new();
    match req.get("flags") {
        None => {}
        Some(Value::Object(obj)) => {
            for (k, v) in obj {
                flags.insert(k.clone(), crate::mcp::value_to_string(v));
            }
        }
        Some(_) => return Err("dispatch request's `flags` must be an object".to_string()),
    }
    flags.entry("from".to_string()).or_insert_with(String::new);

    Ok(Invocation { path, args, flags, door: Door::Daemon })
}

/// Bind `socket_path` and accept `ping`/`subscribe` connections forever
/// (module doc's "Framing"). Thread-per-connection via the FALLIBLE
/// `thread::Builder::spawn` (never the panicking `thread::spawn`) so a
/// refused OS thread creation drops just the one connection instead of
/// unwinding this accept loop — the secrets broker's own accept-loop
/// discipline (`aoide_secrets::broker::serve`'s module doc), reused here by
/// convention since `aoide-server` cannot depend on `aoide-secrets`'s
/// private `serve` fn. `dispatch` is threaded all the way to [`handle_conn`],
/// which now calls it for the `dispatch` op (module doc's "Framing");
/// `registry` still rides along unused this phase — no op needs it yet.
/// Only returns on a bind failure — a running daemon never returns `Ok`.
pub fn serve_daemon(
    socket_path: &Path,
    events_path: &Path,
    registry: &'static Registry,
    dispatch: DispatchFn,
) -> std::io::Result<()> {
    let listener = bind_socket(socket_path)?;
    // A private watcher — this entry point never ticks, so nothing ever
    // sweeps it, but `handle_conn`'s dispatch path re-baselines it the same
    // way regardless of caller (module doc's task #92 note): no
    // caller-conditional branch in `handle_conn` itself.
    let watcher: SharedHandEditWatcher = Arc::new(Mutex::new(crate::producers::HandEditWatcher::new(stage_roster())));
    accept_loop(listener, events_path.to_path_buf(), registry, dispatch, watcher);
    Ok(())
}

/// LANE IDENTITY P-ID3 (G8) — the daemon dispatch socket's CROSS-UID floor,
/// pure and unit-tested without a real different-uid connection (mirrors
/// `aoide_secrets::broker::admin_gate` and `aoide_conduct::shellbridge::
/// cross_uid_gate` exactly — the SAME decision restated at this third
/// socket, not a fourth wording for it). `None` (admitted) only when the
/// peer's kernel-attested uid equals `my_euid` — this daemon's OWN euid,
/// since every legitimate connector (the CLI's `daemon_dispatch` proxy, a
/// hook's `session hook`, the conductor) already runs as the SAME uid this
/// process does. An unidentified peer (`SO_PEERCRED` read failed) is
/// refused the same fail-closed way a mismatched uid is.
///
/// **This closes a CROSS-uid gap only.** It does not, and was never meant
/// to, stop a same-uid process from dispatching a request over this socket
/// — see [`invocation_from_dispatch_request`]'s own doc for the SEPARATE
/// attribution fix (G8's other half) and `CONTRACTS.md`'s identity section
/// for the honest accounting of what remains open.
fn cross_uid_gate(peer: Option<aoide_secrets::peercred::PeerCred>, my_euid: u32) -> Option<String> {
    match peer {
        Some(p) if p.uid == my_euid => None,
        Some(p) => Some(format!(
            "aoided dispatch connection refused: peer uid {} does not match this daemon's own uid {my_euid}",
            p.uid
        )),
        None => Some(
            "aoided dispatch connection refused: peer uid could not be determined (SO_PEERCRED read failed)"
                .to_string(),
        ),
    }
}

fn accept_loop(
    listener: UnixListener,
    events_path: PathBuf,
    registry: &'static Registry,
    dispatch: DispatchFn,
    watcher: SharedHandEditWatcher,
) {
    // SAFETY: `geteuid()` takes no arguments and cannot fail.
    let my_euid = unsafe { libc::geteuid() };
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let peer = aoide_secrets::peercred::peer_cred(&stream);
                if let Some(reason) = cross_uid_gate(peer, my_euid) {
                    let _ = audit(
                        &aoide_protocol::default_audit_log(),
                        Door::Daemon,
                        EventClass::Audit,
                        "aoided",
                        "peercred-refused",
                        &reason,
                    );
                    continue; // Dropped, unconditionally — never reaches `handle_conn`.
                }
                let events_path = events_path.clone();
                let watcher = Arc::clone(&watcher);
                if let Err(e) = std::thread::Builder::new()
                    .spawn(move || handle_conn(&events_path, stream, registry, dispatch, watcher))
                {
                    eprintln!("[aoided] could not spawn a connection thread (dropping this connection): {e}");
                }
            }
            Err(e) => {
                eprintln!("[aoided] accept error (continuing): {e}");
                // Short backoff so a persistent accept error (e.g. fd
                // exhaustion) can't turn this into a tight busy-spin —
                // identical reasoning to the secrets broker's own FIX 3c.
                std::thread::sleep(Duration::from_millis(250));
            }
        }
    }
}

/// Handle ONE client connection, on its own thread: read newline-delimited
/// JSON requests and reply to each. A read error (dropped connection) ends
/// only this connection — nothing here can unwind into `accept_loop` or any
/// other connection's own thread (module doc's "Framing").
fn handle_conn(
    events_path: &Path,
    stream: UnixStream,
    registry: &'static Registry,
    dispatch: DispatchFn,
    watcher: SharedHandEditWatcher,
) {
    // `registry` has no caller yet — no op resolves a tool name against it
    // the way MCP's `tools/call` does (module doc's "Framing": `dispatch`
    // takes `path` literally). Kept as a real parameter, not dropped at the
    // call site, so a future op that DOES need it needs no signature change
    // threading through `run_loop`/`accept_loop` again.
    let _ = registry;

    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("[aoided] could not clone connection: {e}");
            return;
        }
    };
    let mut reader = BufReader::new(stream);
    loop {
        let line_bytes = match read_capped_line(&mut reader, MAX_REQUEST_LINE_BYTES) {
            Ok(None) => return, // EOF: client closed.
            Ok(Some(bytes)) => bytes,
            Err(LineReadError::TooLarge) => {
                let _ = write_json_line(
                    &mut writer,
                    &json!({"ok": false, "error": format!("request line exceeds the {MAX_REQUEST_LINE_BYTES}-byte cap")}),
                );
                return; // Oversized line → error, drop connection (module doc).
            }
            Err(LineReadError::Io) => return, // Read error/invalid UTF-8: no peer left to usefully reply to.
        };
        let Ok(line) = String::from_utf8(line_bytes) else {
            return; // Invalid UTF-8 — mirrors `read_line`'s own Err(_) => return path.
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let req: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => {
                // Malformed line → one error reply, connection SURVIVES
                // (module doc's "Framing" — the P-D2 test this covers).
                let _ = write_json_line(&mut writer, &json!({"ok": false, "error": "malformed request: not valid JSON"}));
                continue;
            }
        };

        match req.get("op").and_then(Value::as_str) {
            Some("ping") => {
                // LANE IDENTITY P-ID2 (`CONTRACTS.md`'s identity section):
                // `sealPubkeyHex` rides the existing `ping` reply — the
                // channel THIS daemon process's current seal-signing public
                // key is fetched over. It is never secret (verifying a
                // signature only needs the public half), but it must come
                // from a LIVE round trip, never a same-uid-writable FILE —
                // a file sitting next to the seals it verifies would let
                // whoever can already forge a seal also forge the "trusted"
                // key that vouches for it (`identity::mint_ephemeral`'s own
                // module doc: the seal's whole secrecy claim rests on
                // process liveness, not file permissions). **This is NOT a
                // channel a same-uid attacker is locked out of**: `bind_
                // socket` unlink-then-binds with no `flock`/pidfile, so a
                // same-uid attacker can already race or evict the real
                // listener and serve a forged `sealPubkeyHex` of its own —
                // that same-uid dispatch-socket floor is P-ID3's job, not
                // this one's; this field buys no more than the raw
                // per-session socket already leaves open (CONTRACTS.md's
                // own honesty note on this exact boundary). No new socket,
                // no peercred floor added here — purely an additive field
                // on an already-open, already-wired reply.
                let reply = json!({
                    "ok": true,
                    "daemon": "aoided",
                    "pid": std::process::id(),
                    "version": AOIDE_VERSION,
                    "sealPubkeyHex": seal_keypair().info().pubkey_hex,
                });
                if write_json_line(&mut writer, &reply).is_err() {
                    return;
                }
            }
            Some("subscribe") => {
                // Becomes a stream: the connection is now one-way
                // (daemon → client) until the client hangs up (module doc's
                // "Framing"). Nothing further is ever read on this
                // connection after this call returns.
                stream_subscribe(events_path, &req, &mut reader, &mut writer);
                return;
            }
            Some("dispatch") => {
                // The fourth door (P-D4, module doc's "Framing"): build the
                // Invocation LITERALLY from the wire and run it through the
                // SAME injected `dispatch` fn every other door calls — no
                // door-specific policy lives here (module doc).
                match invocation_from_dispatch_request(&req) {
                    Ok(inv) => {
                        let outcome = dispatch(&inv);
                        // task #92: this handler may have just written stage
                        // files via the SAME `do_session_*` code the CLI
                        // runs (module doc) — re-baseline the shared watcher
                        // BEFORE replying so the next tick's sweep never
                        // reports this write back as a hand edit. Runs
                        // regardless of outcome/command (module doc: roster-wide,
                        // not a per-command table).
                        rebaseline_stage_roster(&watcher);
                        // LANE IDENTITY P-ID1 (module doc, "the sealed
                        // session credential"): scaffolding only, no gate
                        // reads this yet.
                        seal_freshly_registered_session(&inv, &outcome);
                        if write_json_line(&mut writer, &json!({"outcome": outcome})).is_err() {
                            return;
                        }
                    }
                    Err(msg) => {
                        // A malformed `dispatch` request (missing/wrong-typed
                        // `path`/`args`/`flags`) gets one error reply and the
                        // connection SURVIVES — same posture as a malformed
                        // JSON line above, since nothing here has dispatched
                        // anything yet.
                        let _ = write_json_line(&mut writer, &json!({"ok": false, "error": msg}));
                    }
                }
            }
            Some(other) => {
                let _ = write_json_line(&mut writer, &json!({"ok": false, "error": format!("unknown op `{other}`")}));
            }
            None => {
                let _ = write_json_line(&mut writer, &json!({"ok": false, "error": "malformed request: missing `op`"}));
            }
        }
    }
}

/// `subscribe`: follow the daemon's own events feed and write each event
/// whose `class` is in the request's `classes` array as an interim line
/// (`"interim":true` merged onto the event object itself — the event IS
/// the line, module doc's "The events feed"). An empty/absent `classes`
/// delivers NOTHING — default-deny per class
/// (`docs/architecture/AOIDED.md`'s "L2" section) — but the connection
/// still stays open rather than erroring, since a caller may legitimately
/// widen its subscription later (a `classes` change is a NEW `subscribe`
/// call today; there is no in-place widen op).
///
/// The events file may not exist yet the instant this fires (nothing has
/// been appended since this daemon started) — `Follower::open_at_end`
/// requires the file to already exist, so this retries opening it on every
/// poll until it succeeds; a [`FeedWriter::append`] from ANY producer
/// creates the file, and the very next poll picks the follower up. Once
/// open, a delete-and-recreate or a past-cap truncation is transparent to
/// this follower exactly as `Follower::poll`'s own doc guarantees.
fn stream_subscribe(events_path: &Path, req: &Value, reader: &mut BufReader<UnixStream>, writer: &mut UnixStream) {
    let classes: Vec<String> = req
        .get("classes")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();

    if let Err(e) = reader.get_ref().set_read_timeout(Some(SUBSCRIBE_POLL_INTERVAL)) {
        eprintln!("[aoided] could not set the subscribe connection's read timeout: {e}");
    }

    let mut follower: Option<Follower> = Follower::open_at_end(events_path).ok();
    loop {
        // Detect the client hanging up — a subscribe connection otherwise
        // writes only when a MATCHING event fires, so without this probe a
        // disconnected, never-matching subscriber's thread would never
        // notice and never exit.
        let mut probe = [0u8; 256];
        match reader.get_mut().read(&mut probe) {
            Ok(0) => return, // EOF: client closed.
            Ok(_) => {}      // Subscribe is one-way past this point; any stray input is ignored.
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => return,
        }

        if follower.is_none() {
            follower = Follower::open_at_end(events_path).ok();
        }
        if let Some(f) = follower.as_mut() {
            let Ok(lines) = f.poll() else { continue };
            for line in lines {
                let Ok(mut val) = serde_json::from_str::<Value>(&line) else { continue };
                let matches_class = val
                    .get("class")
                    .and_then(Value::as_str)
                    .map(|c| classes.iter().any(|want| want == c))
                    .unwrap_or(false);
                if !matches_class {
                    continue;
                }
                if let Some(obj) = val.as_object_mut() {
                    obj.insert("interim".to_string(), json!(true));
                }
                if write_json_line(writer, &val).is_err() {
                    return;
                }
            }
        }
    }
}

/// The resident daemon's own main loop (P-D2, `docs/architecture/
/// AOIDED.md`'s "L1 — the event bus" section): bind the socket, append one
/// `started` record to BOTH the single audit log (`log_path` — the same
/// `audit()` call [`run`]'s one-shot skeleton already made, so a resident
/// `aoided` keeps auditing its own startup exactly as the unit's
/// `AOIDE_AUDIT_LOG` wiring already expects) and the daemon's own events
/// feed (creating that file — module doc's "The events feed"), spawn the
/// accept loop on its own thread, then tick forever (~1s). Bind happens
/// SYNCHRONOUSLY on this thread — a bind failure propagates straight to the
/// caller (`bin/aoided.rs`'s `main`, under `Restart=on-failure`) rather than
/// surfacing only inside a spawned thread's silent `eprintln!`. Only
/// returns on that bind failure or a failure to spawn the accept thread —
/// a running daemon never returns `Ok` (module doc's "no producers yet").
pub fn run_loop(
    socket_path: PathBuf,
    events_path: PathBuf,
    log_path: PathBuf,
    registry: &'static Registry,
    dispatch: DispatchFn,
) -> std::io::Result<()> {
    let listener = bind_socket(&socket_path)?;

    let _ = audit(&log_path, Door::Daemon, EventClass::Audit, "daemon", "started", "aoided resident loop online");

    let feed = FeedWriter::new(events_path.clone(), EVENTS_CAP_BYTES, 0o600);
    feed.append(&json!({
        "v": 0,
        "ts": aoide_protocol::audit::now_secs(),
        "class": serde_json::to_value(EventClass::Audit).unwrap_or_else(|_| json!("audit")),
        "kind": "started",
        "source": "aoided",
        "payload": {},
    }));

    // Shared with `accept_loop`/`handle_conn`'s `dispatch` op (task #92,
    // module doc's "The tick's two producers"): ONE watcher instance, not a
    // tick-private one and a dispatch-private one, so a dispatched
    // invocation's re-baseline (`rebaseline_stage_roster`) and the tick's
    // own `sweep` observe the same baseline state.
    let hand_edit_watcher: SharedHandEditWatcher =
        Arc::new(Mutex::new(crate::producers::HandEditWatcher::new(stage_roster())));

    let accept_events_path = events_path.clone();
    let accept_watcher = Arc::clone(&hand_edit_watcher);
    std::thread::Builder::new()
        .spawn(move || accept_loop(listener, accept_events_path, registry, dispatch, accept_watcher))?;

    // P-D8 boot-time auto-resume (module doc's "Open knobs" — decided: daemon
    // start). Runs ONCE here, at `run_loop` entry — never inside the tick
    // loop below — boot-epoch-guarded so a `Restart=on-failure` restart
    // within the same boot is a no-op; see `run_boot_auto_resume`'s own doc.
    run_boot_auto_resume();

    // Tick (~1s): the two P-D3 producers (module doc's "The tick's two
    // producers"), constructed once here, outside the loop.
    let secrets_socket = aoide_secrets::socket::socket_path();
    let secrets_events = aoide_secrets::socket::events_path(&secrets_socket);
    let mut secrets_mirror = crate::producers::SecretsMirror::new(secrets_events);
    // P-D6 graph residency (module doc's "Graph residency"): a plain tick
    // counter, not a second timer — `run_loop` already sleeps ~1s per
    // iteration, so `REAP_EVERY_TICKS` iterations is ~12s, matching the
    // systemd timer's own cadence with no new clock.
    let mut ticks: u64 = 0;
    loop {
        secrets_mirror.tick(&feed);
        // LANE IDENTITY P-ID2: seal any live, pid-carrying session that
        // isn't sealed yet — `seal_unsealed_live_sessions`'s own doc on why
        // this runs unconditionally rather than gated on a hand-edit. Its
        // own write is folded into the watcher's baseline immediately
        // (same discipline `rebaseline_stage_roster` uses for a dispatched
        // write), so the sweep right below never reports it back as a
        // hand edit.
        if seal_unsealed_live_sessions() {
            if let Ok(mut w) = hand_edit_watcher.lock() {
                w.note_own_write(&aoide_storage::stage::sessions_path());
            }
        }
        // A poisoned lock (only possible if a dispatch-side re-baseline ever
        // panicked mid-lock) is not this loop's problem to fix — fall back
        // to an empty sweep rather than `continue`, so the tick still hits
        // its sleep below instead of busy-spinning.
        let hand_edits =
            hand_edit_watcher.lock().map(|mut w| w.sweep()).unwrap_or_default();
        for file in &hand_edits {
            feed.append(&json!({
                "v": 0,
                "ts": aoide_protocol::audit::now_secs(),
                "class": serde_json::to_value(EventClass::Audit).unwrap_or_else(|_| json!("audit")),
                "kind": "hand-edit",
                "source": "aoided",
                "payload": {"file": file},
            }));
        }
        if let Some(graph_path) = reconcile_graph_projection(&hand_edits) {
            if let Ok(mut w) = hand_edit_watcher.lock() {
                w.note_own_write(&graph_path);
            }
        }

        ticks += 1;
        if ticks % REAP_EVERY_TICKS == 0 {
            run_internal_reap();
            // Re-baseline all three graph-residency files unconditionally —
            // idempotent on a quiet pass (module doc's "Graph residency" /
            // `run_internal_reap`'s own doc).
            if let Ok(mut w) = hand_edit_watcher.lock() {
                w.note_own_write(&aoide_storage::stage::sessions_path());
                w.note_own_write(&aoide_storage::stage::hooks_path());
                w.note_own_write(&aoide_storage::stage::graph_path());
            }
        }

        std::thread::sleep(Duration::from_secs(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aoide_protocol::output::Outcome;
    use std::sync::OnceLock;

    /// A short path directly under `/tmp` — NOT `std::env::temp_dir()`,
    /// which under a sandboxed `$TMPDIR` can already be a long nested path
    /// (task #75's own SUN_LEN lesson, restated in the P-D2 brief: never
    /// derive a socket path from a deep tempdir).
    fn short_tmp(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        PathBuf::from(format!("/tmp/av-aoided-{tag}-{}-{nanos}", std::process::id()))
    }

    /// A fixture [`DispatchFn`] proving [`handle_conn`]'s `dispatch` op wires
    /// the injected fn correctly (this module's own tests use a fixture, not
    /// a real registry, since the FULLY-ASSEMBLED registry only exists in
    /// the `cli` crate above this one — real per-command door-policy proof
    /// against that registry lives in `aoide-cli`'s own integration test,
    /// per this crate's own DI-seam invariant). Every other op ignores this
    /// fn entirely, so most tests below still never call it.
    fn noop_dispatch(inv: &Invocation) -> Outcome {
        Outcome::ok(inv.dotted(), "the injected dispatch fn ran").with_data(json!({
            "path": inv.path,
            "args": inv.args,
            "flags": inv.flags,
        }))
    }

    fn test_registry() -> &'static Registry {
        static REGISTRY: OnceLock<Registry> = OnceLock::new();
        REGISTRY.get_or_init(Registry::new)
    }

    fn read_one_line(reader: &mut impl std::io::BufRead) -> Value {
        let mut line = String::new();
        reader.read_line(&mut line).expect("reading a reply line");
        serde_json::from_str(line.trim()).unwrap_or_else(|e| panic!("reply line not JSON: {e}: {line:?}"))
    }

    #[test]
    fn bind_socket_chmods_the_socket_file_to_0600() {
        let socket_path = short_tmp("bind").with_extension("sock");
        let listener = bind_socket(&socket_path).unwrap();
        let mode = std::fs::metadata(&socket_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected the daemon socket to be user-private, got {mode:o}");
        drop(listener);
        std::fs::remove_file(&socket_path).ok();
    }

    // ── cross_uid_gate (LANE IDENTITY P-ID3, G8) ────────────────────────

    #[test]
    fn cross_uid_gate_admits_a_matching_euid() {
        assert_eq!(
            cross_uid_gate(Some(aoide_secrets::peercred::PeerCred { uid: 1000, gid: 1000, pid: 42 }), 1000),
            None
        );
    }

    #[test]
    fn cross_uid_gate_refuses_a_mismatched_uid() {
        assert!(
            cross_uid_gate(Some(aoide_secrets::peercred::PeerCred { uid: 1001, gid: 1001, pid: 42 }), 1000).is_some()
        );
    }

    #[test]
    fn cross_uid_gate_refuses_an_unidentified_peer() {
        // Fail-closed, never a benign default — the same posture
        // `aoide_secrets::broker::admin_gate` holds for a `SO_PEERCRED` read
        // that failed.
        assert!(cross_uid_gate(None, 1000).is_some());
    }

    /// End-to-end against a REAL socketpair: a connection entirely local to
    /// this process reports THIS process's own euid, which `cross_uid_gate`
    /// then admits — proving the floor does not refuse the legitimate
    /// same-uid caller (the CLI's own `daemon_dispatch` proxy, a hook, the
    /// conductor — every real connector Phase 0 identified) it must never
    /// touch.
    #[test]
    fn a_real_same_process_socketpair_is_admitted() {
        let (a, _b) = UnixStream::pair().expect("socketpair");
        let peer = aoide_secrets::peercred::peer_cred(&a);
        let my_euid = unsafe { libc::geteuid() };
        assert_eq!(cross_uid_gate(peer, my_euid), None);
    }

    // ── invocation_from_dispatch_request (LANE IDENTITY P-ID3, G8) ──────

    #[test]
    fn invocation_from_dispatch_request_stamps_an_absent_from_as_explicit_empty() {
        let req = json!({
            "op": "dispatch",
            "path": ["send"],
            "args": ["hello"],
            "flags": {"id": "target"},
        });
        let inv = invocation_from_dispatch_request(&req).unwrap();
        assert_eq!(
            inv.flags.get("from").map(String::as_str),
            Some(""),
            "an absent `from` must be stamped explicit-empty, never left absent to fall through to this process's own env"
        );
        assert_eq!(inv.flags.get("id").map(String::as_str), Some("target"), "an unrelated flag rides through unchanged");
    }

    #[test]
    fn invocation_from_dispatch_request_preserves_an_explicit_from() {
        let req = json!({
            "op": "dispatch",
            "path": ["send"],
            "args": ["hello"],
            "flags": {"id": "target", "from": "node:someone"},
        });
        let inv = invocation_from_dispatch_request(&req).unwrap();
        assert_eq!(
            inv.flags.get("from").map(String::as_str),
            Some("node:someone"),
            "a `from` the WIRE actually supplied must never be overwritten"
        );
    }

    /// `--from ""` (explicit anonymous) already round-trips untouched, not
    /// merely an ABSENT key stamped the same way — proves this is a real
    /// `.entry().or_insert_with()`, not a blind overwrite that would also
    /// clobber a caller's own deliberate empty string differently.
    #[test]
    fn invocation_from_dispatch_request_preserves_an_explicit_empty_from() {
        let req = json!({
            "op": "dispatch",
            "path": ["send"],
            "flags": {"from": ""},
        });
        let inv = invocation_from_dispatch_request(&req).unwrap();
        assert_eq!(inv.flags.get("from").map(String::as_str), Some(""));
    }

    /// `serve_daemon` over a tempdir socket: `ping` round-trips with the
    /// shape `docs/architecture/AOIDED.md`'s "L2" section names.
    #[test]
    fn serve_daemon_ping_round_trips() {
        let socket_path = short_tmp("ping").with_extension("sock");
        let events_path = short_tmp("ping-events").with_extension("jsonl");
        let sp = socket_path.clone();
        let ep = events_path.clone();
        std::thread::spawn(move || {
            let _ = serve_daemon(&sp, &ep, test_registry(), noop_dispatch);
        });

        let stream = connect_retrying(&socket_path);
        let mut writer = stream.try_clone().unwrap();
        let mut reader = BufReader::new(stream);
        writer.write_all(b"{\"v\":0,\"op\":\"ping\"}\n").unwrap();

        let reply = read_one_line(&mut reader);
        assert_eq!(reply["ok"], true, "{reply}");
        assert_eq!(reply["daemon"], "aoided", "{reply}");
        assert_eq!(reply["version"], AOIDE_VERSION, "{reply}");
        assert!(reply["pid"].as_u64().is_some(), "{reply}");
        // LANE IDENTITY P-ID2: `sealPubkeyHex` is the ONE trustworthy
        // channel for the daemon's current seal-signing public key (module
        // doc on the `ping` handler) — must be a real 64-char hex string,
        // and must match THIS process's own `seal_keypair`.
        let pubkey_hex = reply["sealPubkeyHex"].as_str().expect("sealPubkeyHex must be a string");
        assert_eq!(pubkey_hex.len(), 64, "{pubkey_hex}");
        assert!(pubkey_hex.chars().all(|c| c.is_ascii_hexdigit()), "{pubkey_hex}");

        std::fs::remove_file(&socket_path).ok();
        std::fs::remove_file(&events_path).ok();
    }

    /// `subscribe` receives an injected event whose class it asked for, and
    /// never receives one it didn't (default-deny per class, module doc's
    /// "The events feed").
    #[test]
    fn serve_daemon_subscribe_receives_an_injected_event() {
        let socket_path = short_tmp("sub").with_extension("sock");
        let events_path = short_tmp("sub-events").with_extension("jsonl");
        // Pre-create the (empty) events file so the connection's Follower
        // opens successfully on its FIRST poll, at position 0 — otherwise
        // there is a real race between "the daemon's first poll finds the
        // file" and "the test's own append creates it", and an unlucky
        // ordering would open the follower AT THE END of content that
        // already includes the injected line, silently skipping it
        // (`Follower::open_at_end`'s own contract: history before open is
        // never read).
        std::fs::write(&events_path, b"").unwrap();

        let sp = socket_path.clone();
        let ep = events_path.clone();
        std::thread::spawn(move || {
            let _ = serve_daemon(&sp, &ep, test_registry(), noop_dispatch);
        });

        let stream = connect_retrying(&socket_path);
        let mut writer = stream.try_clone().unwrap();
        let mut reader = BufReader::new(stream);
        writer.write_all(b"{\"v\":0,\"op\":\"subscribe\",\"classes\":[\"secret\"]}\n").unwrap();

        // `Follower::open_at_end` deliberately never reads history — an
        // event appended before the daemon's connection thread has actually
        // gotten around to opening its own follower would be silently
        // skipped (correct production behavior: a subscriber only ever
        // sees what happens AFTER it subscribes). There's no wire-level ack
        // that "the follower is now open" (the P-D2 design names exactly
        // three fields on `subscribe`'s wire shape, no fourth), so rather
        // than guess a fixed delay, retry appending a fresh non-matching +
        // matching pair until the subscriber confirms receipt — the
        // non-matching one is a live control proving filtering still holds
        // no matter which attempt actually lands.
        reader.get_ref().set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        let feed = FeedWriter::new(events_path.clone(), EVENTS_CAP_BYTES, 0o600);
        let mut interim = None;
        for _ in 0..25 {
            feed.append(&json!({"v": 0, "ts": 1, "class": "audit", "kind": "hand-edit", "source": "test", "payload": {}}));
            feed.append(&json!({"v": 0, "ts": 2, "class": "secret", "kind": "parked", "source": "test", "payload": {"id": "a1"}}));
            let mut line = String::new();
            if reader.read_line(&mut line).is_ok() && !line.trim().is_empty() {
                interim = Some(serde_json::from_str::<Value>(line.trim()).expect("reply line must be JSON"));
                break;
            }
        }
        let interim = interim.expect("subscribe never delivered the injected event in time");
        assert_eq!(interim["interim"], true, "{interim}");
        assert_eq!(interim["class"], "secret", "the audit-class line must have been filtered out: {interim}");
        assert_eq!(interim["kind"], "parked", "{interim}");
        assert_eq!(interim["payload"]["id"], "a1", "{interim}");

        std::fs::remove_file(&socket_path).ok();
        std::fs::remove_file(&events_path).ok();
    }

    /// A malformed line gets one error reply and the connection SURVIVES
    /// (can keep being used); a second, independent connection proves the
    /// daemon itself is unaffected too.
    #[test]
    fn serve_daemon_malformed_line_survives() {
        let socket_path = short_tmp("bad").with_extension("sock");
        let events_path = short_tmp("bad-events").with_extension("jsonl");
        let sp = socket_path.clone();
        let ep = events_path.clone();
        std::thread::spawn(move || {
            let _ = serve_daemon(&sp, &ep, test_registry(), noop_dispatch);
        });

        let stream = connect_retrying(&socket_path);
        let mut writer = stream.try_clone().unwrap();
        let mut reader = BufReader::new(stream);

        writer.write_all(b"not json at all\n").unwrap();
        let reply = read_one_line(&mut reader);
        assert_eq!(reply["ok"], false, "{reply}");
        assert!(reply["error"].as_str().unwrap().contains("not valid JSON"), "{reply}");

        // The SAME connection keeps serving requests afterward.
        writer.write_all(b"{\"v\":0,\"op\":\"ping\"}\n").unwrap();
        let ping_reply = read_one_line(&mut reader);
        assert_eq!(ping_reply["ok"], true, "{ping_reply}");

        // A brand-new connection proves the daemon overall is unaffected.
        let second = connect_retrying(&socket_path);
        let mut second_writer = second.try_clone().unwrap();
        let mut second_reader = BufReader::new(second);
        second_writer.write_all(b"{\"v\":0,\"op\":\"ping\"}\n").unwrap();
        let second_reply = read_one_line(&mut second_reader);
        assert_eq!(second_reply["ok"], true, "{second_reply}");

        std::fs::remove_file(&socket_path).ok();
        std::fs::remove_file(&events_path).ok();
    }

    /// `dispatch` (P-D4): builds the `Invocation` from `path`/`args`/`flags`
    /// literally, calls the injected fn, and replies `{"outcome": ...}` with
    /// the fn's own [`Outcome`] verbatim. This proves `handle_conn`'s WIRING
    /// only — real per-command door-policy proof (a CLI-only admin command's
    /// refusal, a gated command's `gated: true`, `mcp.serve`/`a2a.serve`'s
    /// non-Cli replies, and the `"door":"daemon"` audit line) runs against
    /// the fully-assembled registry in `aoide-cli`'s own integration test
    /// (this crate's DI-seam invariant — the assembled registry doesn't
    /// exist here).
    #[test]
    fn serve_daemon_dispatch_calls_the_injected_fn_and_replies_with_the_outcome() {
        let socket_path = short_tmp("dispatch").with_extension("sock");
        let events_path = short_tmp("dispatch-events").with_extension("jsonl");
        let sp = socket_path.clone();
        let ep = events_path.clone();
        std::thread::spawn(move || {
            let _ = serve_daemon(&sp, &ep, test_registry(), noop_dispatch);
        });

        let stream = connect_retrying(&socket_path);
        let mut writer = stream.try_clone().unwrap();
        let mut reader = BufReader::new(stream);
        writer
            .write_all(br#"{"v":0,"op":"dispatch","path":["foo","bar"],"args":["a"],"flags":{"x":"y"}}"#)
            .unwrap();
        writer.write_all(b"\n").unwrap();

        let reply = read_one_line(&mut reader);
        let outcome = &reply["outcome"];
        assert_eq!(outcome["status"], "ok", "{reply}");
        assert_eq!(outcome["command"], "foo.bar", "{reply}");
        assert_eq!(outcome["data"]["path"], json!(["foo", "bar"]), "{reply}");
        assert_eq!(outcome["data"]["args"], json!(["a"]), "{reply}");
        assert_eq!(outcome["data"]["flags"]["x"], "y", "{reply}");

        std::fs::remove_file(&socket_path).ok();
        std::fs::remove_file(&events_path).ok();
    }

    /// A `dispatch` request missing its `path` array gets one error reply
    /// and the connection SURVIVES — the same posture a malformed JSON line
    /// already holds, since nothing has been dispatched yet.
    #[test]
    fn serve_daemon_dispatch_with_no_path_survives() {
        let socket_path = short_tmp("dispatch-bad").with_extension("sock");
        let events_path = short_tmp("dispatch-bad-events").with_extension("jsonl");
        let sp = socket_path.clone();
        let ep = events_path.clone();
        std::thread::spawn(move || {
            let _ = serve_daemon(&sp, &ep, test_registry(), noop_dispatch);
        });

        let stream = connect_retrying(&socket_path);
        let mut writer = stream.try_clone().unwrap();
        let mut reader = BufReader::new(stream);

        writer.write_all(b"{\"v\":0,\"op\":\"dispatch\"}\n").unwrap();
        let reply = read_one_line(&mut reader);
        assert_eq!(reply["ok"], false, "{reply}");
        assert!(reply["error"].as_str().unwrap().contains("path"), "{reply}");

        writer.write_all(b"{\"v\":0,\"op\":\"ping\"}\n").unwrap();
        let ping_reply = read_one_line(&mut reader);
        assert_eq!(ping_reply["ok"], true, "{ping_reply}");

        std::fs::remove_file(&socket_path).ok();
        std::fs::remove_file(&events_path).ok();
    }

    /// The P-D2 nit, closed this phase: a client that streams well past
    /// [`MAX_REQUEST_LINE_BYTES`] with NO trailing newline, and never closes
    /// its end, is disconnected the instant it crosses the cap — never only
    /// after EOF or a newline that never comes (module doc's "Framing").
    /// Deadline-polled: alternates a bounded write with a non-blocking probe
    /// read, accepting either the cap's own error reply or a bare close as
    /// proof of disconnect (timing decides which one the client observes
    /// first; both mean the SAME fix fired).
    #[test]
    fn serve_daemon_disconnects_a_newline_less_oversized_stream() {
        let socket_path = short_tmp("cap").with_extension("sock");
        let events_path = short_tmp("cap-events").with_extension("jsonl");
        let sp = socket_path.clone();
        let ep = events_path.clone();
        std::thread::spawn(move || {
            let _ = serve_daemon(&sp, &ep, test_registry(), noop_dispatch);
        });

        let stream = connect_retrying(&socket_path);
        let mut writer = stream.try_clone().unwrap();
        let mut reader = BufReader::new(stream);
        reader.get_ref().set_read_timeout(Some(Duration::from_millis(100))).unwrap();

        let chunk = vec![b'x'; 32 * 1024];
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut sent: usize = 0;
        let mut disconnected = false;
        let mut got_cap_error = false;
        while std::time::Instant::now() < deadline {
            match writer.write(&chunk) {
                Ok(0) | Err(_) => {
                    disconnected = true;
                    break;
                }
                Ok(n) => sent += n,
            }
            let mut probe = [0u8; 4096];
            match reader.get_mut().read(&mut probe) {
                Ok(0) => {
                    disconnected = true;
                    break;
                }
                Ok(n) => {
                    if String::from_utf8_lossy(&probe[..n]).contains("exceeds") {
                        got_cap_error = true;
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => {
                    disconnected = true;
                    break;
                }
            }
            if sent > MAX_REQUEST_LINE_BYTES * 3 {
                break;
            }
        }

        assert!(
            got_cap_error || disconnected,
            "expected the daemon to reply with the cap error or disconnect once the \
             newline-less stream crossed {MAX_REQUEST_LINE_BYTES} bytes; sent {sent} bytes with neither"
        );

        std::fs::remove_file(&socket_path).ok();
        std::fs::remove_file(&events_path).ok();
    }

    /// `run_loop`'s startup write both CREATES the events feed file (so
    /// `subscribe`'s follower has something to open) and reuses the SAME
    /// capped [`FeedWriter`] `docs/architecture/AOIDED.md` names (a
    /// pre-padded, over-cap file gets truncated by that first write, the
    /// identical mechanics `aoide_protocol::feed`'s own tests already prove
    /// — this test only proves `run_loop`'s WIRING passes the real cap).
    #[test]
    fn run_loop_creates_and_caps_the_events_feed() {
        // P-D6: `run_loop`'s tick now writes through `aoide_conduct` (`lib.rs`'s
        // own doc) — this spawns a background thread it never joins, so it
        // needs `env_lock`'s one-time `AOIDE_STAGE_DIR` floor in place before
        // that thread's first tick, never the real `~/Aoide/state/stage/*`.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let socket_path = short_tmp("loop").with_extension("sock");
        let events_path = short_tmp("loop-events").with_extension("jsonl");
        let log_path = short_tmp("loop-log");
        std::fs::write(&events_path, vec![b'x'; (EVENTS_CAP_BYTES + 1) as usize]).unwrap();

        let sp = socket_path.clone();
        let ep = events_path.clone();
        let lp = log_path.clone();
        std::thread::spawn(move || {
            let _ = run_loop(sp, ep, lp, test_registry(), noop_dispatch);
        });

        // Poll for the startup write rather than a fixed sleep.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(contents) = std::fs::read_to_string(&events_path) {
                if contents.contains("\"kind\":\"started\"") {
                    assert!(
                        (contents.len() as u64) < EVENTS_CAP_BYTES,
                        "the pre-padded, over-cap file must have been truncated, got {} bytes",
                        contents.len()
                    );
                    break;
                }
            }
            assert!(std::time::Instant::now() < deadline, "run_loop never wrote its startup event in time");
            std::thread::sleep(Duration::from_millis(20));
        }

        std::fs::remove_file(&socket_path).ok();
        std::fs::remove_file(&events_path).ok();
        std::fs::remove_file(&log_path).ok();
    }

    // ── P-D6 graph residency: reconcile + reap in the tick ──────────────

    fn isolated_stage() -> (std::sync::MutexGuard<'static, ()>, PathBuf, Option<String>) {
        let guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = short_tmp("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        (guard, stage, saved)
    }

    fn restore_stage(stage: &Path, saved: Option<String>) {
        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        std::fs::remove_dir_all(stage).ok();
    }

    /// A hand-edit-shaped filename list that names neither `sessions.json`
    /// nor `hooks.json` is a no-op: [`reconcile_graph_projection`] touches
    /// nothing, `graph.json` is never created.
    #[test]
    fn reconcile_graph_projection_is_a_noop_when_neither_sessions_nor_hooks_changed() {
        let (_guard, stage, saved) = isolated_stage();

        let out = reconcile_graph_projection(&["pending.json".to_string(), "herald.json".to_string()]);
        assert!(out.is_none(), "an unrelated changed file must not trigger a reconcile");
        assert!(!aoide_storage::stage::graph_path().exists(), "graph.json must not have been created");

        restore_stage(&stage, saved);
    }

    /// `sessions.json` (or `hooks.json`) among the changed files DOES
    /// trigger a reconcile — `aoide_conduct::graph::restage_graph` re-derives
    /// `graph.json` from CURRENT stage content, the same internal function
    /// every reconcile call reaches, no forked logic.
    #[test]
    fn reconcile_graph_projection_re_derives_graph_json_when_sessions_changed() {
        let (_guard, stage, saved) = isolated_stage();

        let sf = aoide_storage::records::SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![aoide_storage::records::SessionRecord {
                session_id: "s1".to_string(),
                agent: "claude".to_string(),
                state: "idle".to_string(),
                started_at: "2026-01-01T00:00:00Z".to_string(),
                ..Default::default()
            }],
        };
        aoide_storage::stage::write_stage(&aoide_storage::stage::sessions_path(), &sf).unwrap();

        let out = reconcile_graph_projection(&["sessions.json".to_string()]);
        assert_eq!(out, Some(aoide_storage::stage::graph_path()), "must report graph.json as the reconciled path");
        let contents = std::fs::read_to_string(aoide_storage::stage::graph_path()).unwrap();
        assert!(contents.contains("s1"), "the re-derived graph.json must reflect the session just written: {contents}");

        restore_stage(&stage, saved);
    }

    // ── LANE IDENTITY P-ID1: the sealed session credential (scaffolding) ──

    fn dispatch_invocation(id: &str) -> Invocation {
        let mut flags = BTreeMap::new();
        flags.insert("id".to_string(), id.to_string());
        Invocation {
            path: vec!["session".to_string(), "start".to_string()],
            args: Vec::new(),
            flags,
            door: Door::Daemon,
        }
    }

    /// `mint_seal` against THIS daemon process's own real pid produces a
    /// non-empty seal — `pid_starttime` (routed through
    /// `aoide_conduct::graph::pid_starttime`) resolves for a real, live
    /// process, not just a fixture number. The full mint→stamp→verify round
    /// trip is proven by the dispatch-wired test right below.
    #[test]
    fn mint_seal_produces_a_seal_for_our_own_real_pid() {
        let me = std::process::id() as i32;
        let (seal_hex, _issued_at) = mint_seal("s-self", me, "local");
        assert!(!seal_hex.is_empty(), "a real pid must mint a non-empty seal");
    }

    /// The wiring end to end: a successful dispatched `session start` whose
    /// record already carries a `pid` (module doc's scaffolding case) gets
    /// a `seal` AND `sealedIssuedAt` stamped onto it (LANE IDENTITY P-ID2 —
    /// `issued_at` now rides the record instead of being unrecoverable),
    /// and that seal verifies against THIS daemon process's own public key
    /// using the record's own stamped fields — the exact round trip
    /// P-ID2's verify-on-accept reuses.
    #[test]
    fn seal_freshly_registered_session_stamps_a_verifiable_seal_when_the_record_has_a_pid() {
        let (_guard, stage, saved) = isolated_stage();
        let me = std::process::id() as i32;

        let sf = aoide_storage::records::SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![aoide_storage::records::SessionRecord {
                session_id: "s1".to_string(),
                agent: "claude".to_string(),
                state: "idle".to_string(),
                started_at: "2026-01-01T00:00:00Z".to_string(),
                pid: Some(me as u32),
                origin: Some("local".to_string()),
                ..Default::default()
            }],
        };
        aoide_storage::stage::write_stage(&aoide_storage::stage::sessions_path(), &sf).unwrap();

        let inv = dispatch_invocation("s1");
        let outcome = aoide_protocol::output::Outcome::ok("session.start", "started");
        seal_freshly_registered_session(&inv, &outcome);

        let after: aoide_storage::records::SessionsFile =
            aoide_storage::stage::load_stage(&aoide_storage::stage::sessions_path()).unwrap();
        let rec = after.sessions.iter().find(|s| s.session_id == "s1").unwrap();
        let seal_hex = rec.seal.clone().expect("a record with a pid must be sealed");
        let issued_at = rec.sealed_issued_at.expect("a sealed record must carry sealedIssuedAt");

        let starttime = aoide_conduct::graph::pid_starttime(me).unwrap();
        let identity = SealedIdentity {
            session_id: "s1".to_string(),
            pid: me,
            pid_starttime: starttime,
            origin_class: "local".to_string(),
            issued_at,
        };
        assert!(
            sealed_id::verify_seal(&seal_keypair().info().pubkey_hex, &identity, &seal_hex),
            "the stamped seal must verify against the daemon's own public key"
        );
        assert!(
            !sealed_id::verify_seal("f".repeat(64).as_str(), &identity, &seal_hex),
            "the same seal must NOT verify under a different (wrong) public key"
        );

        restore_stage(&stage, saved);
    }

    /// `mint_seal`'s own documented degrade path — `pid_starttime`
    /// unreadable (a vanished pid) falls back to `0` rather than refusing
    /// to mint — has a consequence worth pinning directly, not just
    /// documented in prose: a seal minted this way is SELF-consistent (it
    /// round-trips against the exact fields it was minted with, zero
    /// included) but can never be REVALIDATED against a later real
    /// `/proc` read, because no live process ever reports starttime `0`
    /// (`window.rs::pid_starttime_reads_a_nonzero_value_for_our_own_real_pid`
    /// proves a genuine read is always `> 0`). This is the "silent
    /// weakening" the design flagged: P-ID2's verify-on-accept MUST treat
    /// a stored `pid_starttime` of `0` as UNVERIFIABLE — there is no live
    /// starttime it could ever legitimately match — never as "verified
    /// against a zero-starttime process." This test pins the shape so
    /// that boundary is provable, not just asserted in a doc comment.
    #[test]
    fn mint_seal_over_a_vanished_pid_degrades_to_a_self_consistent_but_unrevalidatable_zero_starttime() {
        let vanished_pid = 2_000_000_000; // window.rs's own "no such pid" fixture value.
        assert_eq!(
            aoide_conduct::graph::pid_starttime(vanished_pid),
            None,
            "the fixture pid must not exist on this box for the degrade path to even fire"
        );

        let (seal_hex, issued_at) = mint_seal("s-vanished", vanished_pid, "local");
        let self_consistent = SealedIdentity {
            session_id: "s-vanished".to_string(),
            pid: vanished_pid,
            pid_starttime: 0,
            origin_class: "local".to_string(),
            issued_at,
        };
        assert!(
            sealed_id::verify_seal(&seal_keypair().info().pubkey_hex, &self_consistent, &seal_hex),
            "a degraded seal must still verify against the EXACT fields it was minted with, \
             zero pid_starttime included — self-consistency is not the property in question"
        );

        // No real `/proc` read ever produces 0 for a live process — a
        // verifier reconstructing `SealedIdentity` from a FRESH
        // `pid_starttime` read (P-ID2's own shape) would build a
        // `pid_starttime` that is never `0`, so it can never match this
        // seal's stored `0` even for the SAME still-alive pid. There is no
        // "verify true" path back to a live process for a seal minted
        // this way — that is the unrevalidatable property this test pins.
        let mut against_any_live_read = self_consistent.clone();
        against_any_live_read.pid_starttime = 1; // stand-in for "any real read, which is never 0".
        assert!(
            !sealed_id::verify_seal(&seal_keypair().info().pubkey_hex, &against_any_live_read, &seal_hex),
            "a zero-starttime seal must not verify against ANY nonzero starttime — including \
             one read from the very same pid were it somehow still alive"
        );
    }

    /// A dispatched command that is NOT `session start` never gets sealed —
    /// the module doc's "silent no-op for every OTHER dispatched command".
    #[test]
    fn seal_freshly_registered_session_ignores_a_non_session_start_path() {
        let (_guard, stage, saved) = isolated_stage();
        let me = std::process::id() as i32;

        let sf = aoide_storage::records::SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![aoide_storage::records::SessionRecord {
                session_id: "s1".to_string(),
                pid: Some(me as u32),
                ..Default::default()
            }],
        };
        aoide_storage::stage::write_stage(&aoide_storage::stage::sessions_path(), &sf).unwrap();

        let mut inv = dispatch_invocation("s1");
        inv.path = vec!["session".to_string(), "end".to_string()];
        let outcome = aoide_protocol::output::Outcome::ok("session.end", "ended");
        seal_freshly_registered_session(&inv, &outcome);

        let after: aoide_storage::records::SessionsFile =
            aoide_storage::stage::load_stage(&aoide_storage::stage::sessions_path()).unwrap();
        assert_eq!(after.sessions[0].seal, None, "only `session start` may seal a record");

        restore_stage(&stage, saved);
    }

    /// A `session start` whose record carries NO pid (the common case today
    /// — module doc's scaffolding boundary) is silently skipped, never an
    /// error.
    #[test]
    fn seal_freshly_registered_session_skips_a_record_with_no_pid() {
        let (_guard, stage, saved) = isolated_stage();

        let sf = aoide_storage::records::SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![aoide_storage::records::SessionRecord {
                session_id: "s1".to_string(),
                ..Default::default()
            }],
        };
        aoide_storage::stage::write_stage(&aoide_storage::stage::sessions_path(), &sf).unwrap();

        let inv = dispatch_invocation("s1");
        let outcome = aoide_protocol::output::Outcome::ok("session.start", "started");
        seal_freshly_registered_session(&inv, &outcome);

        let after: aoide_storage::records::SessionsFile =
            aoide_storage::stage::load_stage(&aoide_storage::stage::sessions_path()).unwrap();
        assert_eq!(after.sessions[0].seal, None, "a pid-less record must never be sealed");

        restore_stage(&stage, saved);
    }

    /// A FAILED dispatch never gets a seal, even for a `session start` path
    /// whose record happens to have a pid — sealing rides only a successful
    /// registration.
    #[test]
    fn seal_freshly_registered_session_ignores_a_failed_outcome() {
        let (_guard, stage, saved) = isolated_stage();
        let me = std::process::id() as i32;

        let sf = aoide_storage::records::SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![aoide_storage::records::SessionRecord {
                session_id: "s1".to_string(),
                pid: Some(me as u32),
                ..Default::default()
            }],
        };
        aoide_storage::stage::write_stage(&aoide_storage::stage::sessions_path(), &sf).unwrap();

        let inv = dispatch_invocation("s1");
        let outcome = aoide_protocol::output::Outcome::error("session.start", "boom");
        seal_freshly_registered_session(&inv, &outcome);

        let after: aoide_storage::records::SessionsFile =
            aoide_storage::stage::load_stage(&aoide_storage::stage::sessions_path()).unwrap();
        assert_eq!(after.sessions[0].seal, None, "a failed dispatch must never be sealed");

        restore_stage(&stage, saved);
    }

    /// LANE IDENTITY P-ID2: the gap `seal_freshly_registered_session`'s own
    /// doc names — a session registered DIRECTLY (never through `dispatch`,
    /// the real shape `aoide conduct` registers under) is picked up by
    /// [`seal_unsealed_live_sessions`] instead, sealed the same way, and
    /// its `sealedIssuedAt` round-trips onto the record too. A `done`
    /// session and one that already carries a seal are both left alone.
    #[test]
    fn seal_unsealed_live_sessions_seals_a_directly_registered_record() {
        let (_guard, stage, saved) = isolated_stage();
        let me = std::process::id() as i32;

        let sf = aoide_storage::records::SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![
                aoide_storage::records::SessionRecord {
                    session_id: "direct-1".to_string(),
                    agent: "claude".to_string(),
                    state: "idle".to_string(),
                    started_at: "2026-01-01T00:00:00Z".to_string(),
                    pid: Some(me as u32),
                    origin: Some("local".to_string()),
                    ..Default::default()
                },
                aoide_storage::records::SessionRecord {
                    session_id: "already-sealed".to_string(),
                    state: "idle".to_string(),
                    pid: Some(me as u32),
                    seal: Some("existing-seal".to_string()),
                    sealed_issued_at: Some(42),
                    ..Default::default()
                },
                aoide_storage::records::SessionRecord {
                    session_id: "exited".to_string(),
                    state: "done".to_string(),
                    pid: Some(me as u32),
                    ..Default::default()
                },
                aoide_storage::records::SessionRecord {
                    session_id: "no-pid".to_string(),
                    state: "idle".to_string(),
                    ..Default::default()
                },
            ],
        };
        aoide_storage::stage::write_stage(&aoide_storage::stage::sessions_path(), &sf).unwrap();

        let wrote = seal_unsealed_live_sessions();
        assert!(wrote, "a live pid-carrying unsealed record must trigger a write");

        let after: aoide_storage::records::SessionsFile =
            aoide_storage::stage::load_stage(&aoide_storage::stage::sessions_path()).unwrap();
        let direct = after.sessions.iter().find(|s| s.session_id == "direct-1").unwrap();
        let seal_hex = direct.seal.clone().expect("a live, pid-carrying, unsealed record must get sealed");
        let issued_at = direct.sealed_issued_at.expect("sealedIssuedAt must be stamped alongside seal");
        let starttime = aoide_conduct::graph::pid_starttime(me).unwrap();
        let identity = SealedIdentity {
            session_id: "direct-1".to_string(),
            pid: me,
            pid_starttime: starttime,
            origin_class: "local".to_string(),
            issued_at,
        };
        assert!(
            sealed_id::verify_seal(&seal_keypair().info().pubkey_hex, &identity, &seal_hex),
            "the sweep-minted seal must verify against the daemon's own public key"
        );

        // Already-sealed, done, and pid-less records are all left untouched.
        let already = after.sessions.iter().find(|s| s.session_id == "already-sealed").unwrap();
        assert_eq!(already.seal.as_deref(), Some("existing-seal"), "an existing seal must never be overwritten");
        assert_eq!(already.sealed_issued_at, Some(42));
        let exited = after.sessions.iter().find(|s| s.session_id == "exited").unwrap();
        assert_eq!(exited.seal, None, "a done session must never be sealed");
        let no_pid = after.sessions.iter().find(|s| s.session_id == "no-pid").unwrap();
        assert_eq!(no_pid.seal, None, "a pid-less record must never be sealed");

        // A second sweep with nothing left to seal is a quiet no-op.
        assert!(!seal_unsealed_live_sessions(), "nothing left to seal on a second sweep");

        restore_stage(&stage, saved);
    }

    /// [`run_internal_reap`] calls the SAME `aoide_conduct::reap::
    /// reap_and_announce` handler `session reap` runs — a smoke test that it
    /// runs cleanly (never panics) against an empty roster; `reap`'s own
    /// exhaustive liveness-predicate coverage lives in `aoide-conduct`,
    /// this crate only proves the daemon-tick WIRING calls it.
    #[test]
    fn run_internal_reap_runs_cleanly_against_an_empty_roster() {
        let (_guard, stage, saved) = isolated_stage();

        run_internal_reap(); // must not panic

        restore_stage(&stage, saved);
    }

    // ── P-D8 boot-time auto-resume trigger ───────────────────────────────

    /// Like [`isolated_stage`] but also isolates `AOIDE_STATE_DIR` — this
    /// crate's `env_lock()` floors it too (P-D8 addendum, `lib.rs`), but
    /// that floor is a shared per-BINARY fallback, not a per-test tempdir;
    /// [`run_boot_auto_resume`] writes a marker file there, so a test that
    /// wants to inspect or pre-seed that marker needs its OWN isolated dir,
    /// the same reasoning `isolated_stage` already applies to the stage.
    fn isolated_stage_and_state() -> (std::sync::MutexGuard<'static, ()>, PathBuf, PathBuf, Option<String>, Option<String>) {
        let guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let stage = short_tmp("dstage");
        let state = short_tmp("dstate");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        (guard, stage, state, saved_stage, saved_state)
    }

    fn restore_stage_and_state(stage: &Path, state: &Path, saved_stage: Option<String>, saved_state: Option<String>) {
        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        std::fs::remove_dir_all(stage).ok();
        std::fs::remove_dir_all(state).ok();
    }

    /// [`epoch_already_fired`] pulled the boot-epoch guard's whole decision
    /// out as a pure function specifically so it is testable without
    /// `/proc/stat` or a filesystem — "unit-level with the epoch seam, no
    /// real daemon needed" (`docs/architecture/AOIDED.md`'s P-D8 phase
    /// entry, "Tests:" line).
    #[test]
    fn epoch_already_fired_reads_the_guard_exactly() {
        // No marker at all (first boot ever, or the file predates this
        // trigger) — never "already fired", regardless of the epoch.
        assert!(!epoch_already_fired(None, 1_000_000));

        // Marker names the SAME boot the caller is asking about — guard
        // trips, the whole point of the mechanism (a `Restart=on-failure`
        // restart within one boot must not re-fire).
        assert!(epoch_already_fired(Some("1000000"), 1_000_000));

        // Marker names a DIFFERENT (older) boot — a real reboot happened
        // since; the guard must reopen.
        assert!(!epoch_already_fired(Some("999999"), 1_000_000));

        // A corrupt/unparseable marker is treated as "unknown", not
        // "already fired" — the safe direction is to fire again (at worst
        // a redundant, still-gated resurrect attempt), never to silently
        // wedge the trigger shut forever over one bad write.
        assert!(!epoch_already_fired(Some("not-a-number"), 1_000_000));
        assert!(!epoch_already_fired(Some(""), 1_000_000));
    }

    /// `run_boot_auto_resume`'s write side, against a real (empty)
    /// projects.json: on a fresh boot with nothing to resurrect, it still
    /// records the marker — proving the wiring reaches
    /// `auto_resume_marker_path()` and writes a value `epoch_already_fired`
    /// can read back, not just that the pure predicate is correct in
    /// isolation.
    #[test]
    fn run_boot_auto_resume_records_the_current_boot_epoch_on_a_fresh_marker() {
        let (_guard, stage, state, saved_stage, saved_state) = isolated_stage_and_state();

        let marker = auto_resume_marker_path();
        assert!(!marker.exists(), "no marker yet in a freshly isolated state dir");

        run_boot_auto_resume(); // no autoResume projects registered — cheap no-op besides the marker

        let real_epoch = aoide_conduct::reap::boot_epoch()
            .expect("this dev box's /proc/stat is readable — the test assumes a real boot epoch exists");
        let recorded = std::fs::read_to_string(&marker).expect("run_boot_auto_resume must write the marker");
        assert_eq!(
            recorded.trim().parse::<i64>().ok(),
            Some(real_epoch),
            "the marker must record boot_epoch()'s own value: {recorded:?}"
        );

        restore_stage_and_state(&stage, &state, saved_stage, saved_state);
    }

    /// A marker already naming the CURRENT boot means the guard trips
    /// before any project is touched — even with an `autoResume` project
    /// registered, `run_boot_auto_resume` must return having left the
    /// marker byte-identical to what it found (an early return never
    /// reaches the rewrite at the function's tail) and must never panic
    /// walking a real (if minimal) `projects.json`/`sessions.json` pair.
    #[test]
    fn run_boot_auto_resume_is_a_no_op_once_the_marker_matches_the_current_boot() {
        let (_guard, stage, state, saved_stage, saved_state) = isolated_stage_and_state();

        let real_epoch = aoide_conduct::reap::boot_epoch()
            .expect("this dev box's /proc/stat is readable — the test assumes a real boot epoch exists");
        let marker = auto_resume_marker_path();
        let pre_written = real_epoch.to_string();
        std::fs::write(&marker, &pre_written).unwrap();

        let pf = aoide_storage::records::ProjectsFile {
            schema_version: "0".to_string(),
            projects: vec![aoide_storage::records::Project {
                name: "proj".to_string(),
                path: stage.to_string_lossy().to_string(),
                auto_resume: true,
                ..Default::default()
            }],
        };
        aoide_storage::stage::write_stage(&aoide_storage::stage::projects_path(), &pf).unwrap();

        run_boot_auto_resume(); // must not panic, must not touch the marker

        let after = std::fs::read_to_string(&marker).unwrap();
        assert_eq!(after, pre_written, "a guarded call must leave the marker byte-identical");

        restore_stage_and_state(&stage, &state, saved_stage, saved_state);
    }

    /// The case the OLD per-project `has_live` skip suppressed (P-C4,
    /// durable-sessions plan): a project carrying a live session AND an
    /// undying-but-dead ledger entry. The daemon loop no longer checks
    /// liveness at all — it calls `session_resurrect` for every `autoResume`
    /// project unconditionally, and the per-id live exclusion happens INSIDE
    /// `resurrect.rs`'s own bare-mode selection. Proven the same way
    /// `resurrect.rs`'s own undying-transfer test does: `AOIDE_TERMINAL=true`
    /// makes the windowed spawn succeed (`Status::Ok`) without a real
    /// terminal, so a successful resurrect transfers the undying mark off the
    /// old id — if `run_boot_auto_resume` had skipped this project (the old
    /// behaviour), the mark would still be sitting on `carried-dead`
    /// afterward.
    #[test]
    fn run_boot_auto_resume_fires_for_a_project_with_one_live_and_one_undying_dead_session() {
        let (_guard, stage, state, saved_stage, saved_state) = isolated_stage_and_state();
        let saved_terminal = std::env::var("AOIDE_TERMINAL").ok();
        let saved_wayland = std::env::var("WAYLAND_DISPLAY").ok();
        let saved_runtime = std::env::var("XDG_RUNTIME_DIR").ok();
        let saved_audit = std::env::var("AOIDE_AUDIT_LOG").ok();
        std::env::set_var("AOIDE_TERMINAL", "true");
        std::env::set_var("WAYLAND_DISPLAY", "wayland-0");
        std::env::set_var("XDG_RUNTIME_DIR", &state);
        std::env::set_var("AOIDE_AUDIT_LOG", state.join("log"));

        let proj_path = stage.to_string_lossy().to_string();
        let pf = aoide_storage::records::ProjectsFile {
            schema_version: "0".to_string(),
            projects: vec![aoide_storage::records::Project {
                name: "proj".to_string(),
                path: proj_path.clone(),
                auto_resume: true,
                ..Default::default()
            }],
        };
        aoide_storage::stage::write_stage(&aoide_storage::stage::projects_path(), &pf).unwrap();

        // One live (non-`done`) session anchored to the project — exactly
        // the shape that used to suppress the whole project.
        let sf = aoide_storage::records::SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![aoide_storage::records::SessionRecord {
                session_id: "live-1".to_string(),
                agent: "claude".to_string(),
                cwd: proj_path.clone(),
                state: "working".to_string(),
                started_at: "2026-08-20T00:00:00Z".to_string(),
                ..Default::default()
            }],
        };
        aoide_storage::stage::write_stage(&aoide_storage::stage::sessions_path(), &sf).unwrap();

        // A carried-but-dead ledger entry, anchored to the same project.
        let entry = aoide_storage::ledger::LedgerEntry {
            v: 0,
            session_id: "carried-dead".to_string(),
            agent: "claude".to_string(),
            harness_session_id: Some("carried-dead".to_string()),
            cwd: proj_path,
            started_at: "2026-08-20T00:00:00Z".to_string(),
            ended_at: "2026-08-20T01:00:00Z".to_string(),
            ..Default::default()
        };
        aoide_storage::ledger::append_ledger_entry(&entry).unwrap();

        let mut undying = Vec::new();
        aoide_storage::undying::set_undying(&mut undying, "carried-dead", true);
        aoide_storage::undying::save_undying(&undying).unwrap();

        run_boot_auto_resume();

        let after = aoide_storage::undying::load_undying();
        assert!(
            !aoide_storage::undying::is_undying(&after, "carried-dead"),
            "`carried-dead` must have been resurrected (its mark transferred) despite a live \
             session anchored to the same project — the exact case the old per-project \
             `has_live` skip would have suppressed"
        );
        assert_eq!(after.len(), 1, "the mark moved to exactly one fresh id — the set size is unchanged");

        match saved_terminal {
            Some(v) => std::env::set_var("AOIDE_TERMINAL", v),
            None => std::env::remove_var("AOIDE_TERMINAL"),
        }
        match saved_wayland {
            Some(v) => std::env::set_var("WAYLAND_DISPLAY", v),
            None => std::env::remove_var("WAYLAND_DISPLAY"),
        }
        match saved_runtime {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
        match saved_audit {
            Some(v) => std::env::set_var("AOIDE_AUDIT_LOG", v),
            None => std::env::remove_var("AOIDE_AUDIT_LOG"),
        }
        restore_stage_and_state(&stage, &state, saved_stage, saved_state);
    }

    /// `bind_socket` itself creates missing parent directories — every test
    /// above relies on this rather than pre-creating `/tmp` by hand.
    fn connect_retrying(socket_path: &Path) -> UnixStream {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match UnixStream::connect(socket_path) {
                Ok(s) => return s,
                Err(_) if std::time::Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                Err(e) => panic!("could not connect to {socket_path:?} in time: {e}"),
            }
        }
    }
}
