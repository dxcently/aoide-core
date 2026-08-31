//! `aoide pair watch` (P-P5): a foreground, line-mode follow of
//! `aoided`'s own events feed for the pairing-ceremony milestones
//! `aoide_server::a2a::emit_pairing_event` writes (`pair-parked`/
//! `pair-revealed`, `class: "gate"`, `source: "a2a-door"`, CONTRACTS.md
//! §6's "Pairing events feed" subsection) — the SAME tail/reconcile/
//! narrate shape. The third kind, `pair-awaiting-confirm`, is DORMANT
//! since task #119 retired the approver→requester callback that was its
//! only emitter: approval is learned by `pair <id>`'s own
//! synchronous poll, so the watcher can no longer self-trigger on an
//! outbound approval (CONTRACTS.md's feed subsection carries the same
//! note; active polling in this watch loop is the named follow-on, not
//! built). [`PairEvent::AwaitingConfirm`] still parses for old lines.
//! The shape is the one
//! `aoide_secrets::watch` already proved for the secrets broker's own
//! feed, and the same simpler (no socket, no interactive prompt) core
//! `aoide_server::events::tail` already proved for a passive follow.
//!
//! **The feed line is a TRIGGER; `aoide_storage::pairing::list_inbound`/
//! `list_outbound` is the AUTHORITY** (the same "tail is a trigger"
//! precedent `aoide_secrets::watch`'s own module doc states for its own
//! feed): [`parse_pair_line`] never carries a SAS, pubkey, nonce, or
//! commitment — [`reconcile`] re-derives the SAS locally from THIS
//! instance's own identity plus the parked/pending entry, exactly the
//! arg order `approve_inbound`/`approve_outbound`
//! (`aoide_client::commands`) already use for each direction — `peer
//! pending` itself carries no SAS at all (P-PV2, the User's locked spec).
//! A missed
//! or malformed line never strands a request: [`run`]'s 30s reconcile
//! safety tick re-derives the actionable set from scratch on the same
//! cadence `aoide_secrets::watch::Queue::reconcile` already holds.
//!
//! `--popup` is REFUSED up front when NEITHER `lyra` nor `zenity` resolves,
//! the same "refuse before ever entering popup mode" gate `aoide_secrets::
//! watch::run` already holds for its own two dialog binaries. `--popup`+
//! `--json` together is refused one layer up, by `handle_peer_pair_watch`
//! (`aoide_client::commands`) — the same split `aoide_secrets::commands::
//! handle_secrets_watch`/`aoide_server::commands::handle_events_tail`
//! already hold between "gate the door and the flag combo" (the
//! dispatched handler) and "run the blocking loop" (this module,
//! special-cased in `cli`'s own `run_cli`).
//!
//! **The popup arm (F6, upgraded P-PV3/task #132): TWO dialog shapes, one
//! per pairing direction — never a single bare yes/no.**
//! [`resolve_lyra_bin`] feature-detects `lyra` the SAME three-tier way
//! `aoide_secrets::watch::resolve_lyra_bin` does (env override,
//! `current_exe()` sibling, bare-name-on-`PATH` — duplicated here rather
//! than imported, since neither crate may depend on the other or on
//! `aoide-cli`); when it resolves, the dialog spawns a `lyra pair`
//! subcommand instead of a `zenity` invocation, falling back to zenity on
//! a `lyra` `SpawnError`/`DialogFailure` for that one attempt
//! (`aoide_secrets::watch::run_ask_dialog`'s own fallback shape, reused
//! unchanged: the plugin philosophy's whole point, root `AGENTS.md` house
//! rule 7, is that the fancy surface degrades to the plain one, never that
//! a fancy-surface failure strands the request).
//!
//! **INBOUND (approver): a TYPED-CODE entry dialog** — [`run_ask_dialog`]
//! spawns `lyra pair ask` (the SAME six-boxes-plus-dash surface `lyra
//! secrets ask` renders) or `zenity --entry`. The operator TYPES the
//! confirmation code they read off the REQUESTER's own screen,
//! out-of-band — matching the CLI tty path's own `InboundGate::Prompt`
//! gate byte for byte: [`commit_approval`] runs `InboundGate::Code(<typed>)`
//! through `approve_inbound`, so the SAME SAS comparison and
//! [`crate::commands::MAX_CODE_TRIES`] auto-deny machinery the CLI already
//! holds applies identically here — `InboundGate::DialogConfirmed` (a bare
//! "the dialog itself IS the confirmation," no code check at all) is
//! RETIRED by this upgrade; nothing constructs it any more (`crate::
//! commands`' own doc has the removal). The dialog NEVER shows the code
//! (the approver's whole gate is typing a code read from elsewhere;
//! showing it would collapse the out-of-band comparison into a copy
//! exercise, the same reasoning `crate::commands::approve_inbound`'s own
//! doc gives for why its tty prompt never echoes the SAS either).
//!
//! **OUTBOUND (requester): a CONFIRM dialog, never a retype** —
//! [`run_confirm_dialog`] spawns `lyra pair confirm` or `zenity
//! --question`. This instance GENERATED the SAS itself
//! (`reconcile`'s own outbound arm) before the dialog ever opens, so the
//! dialog SHOWS it large and plain (not a leak — the CLI's own
//! `confirm_sas` prints the identical value) and the operator's whole job
//! is a single Approve/Reject action — `commit_approval`'s outbound arm
//! commits UNCONDITIONALLY on Approve (`approve_outbound(true, ...)`,
//! `skip_confirm` — the dialog itself IS the confirmation, exactly as it
//! was before this whole phase). **This is a deliberate REVERT within
//! P-PV3 itself** (a design-review round on this same task): an earlier
//! pass on this phase collected a typed retype on the outbound arm too —
//! reusing the SAME six-box entry surface with the code pre-shown as
//! context — which a review correctly called out as copy-the-pixels
//! theater: the code is already on screen in the SAME window the boxes
//! sit in, so retyping it proves nothing an Approve click doesn't already
//! prove, while visually borrowing the INBOUND arm's security-critical
//! typed-entry language for a step that was never a security gate
//! (`crate::commands::code_matches`'s own outbound-comparison call, and
//! the whole notion of a typed value crossing this arm, is GONE — don't
//! reintroduce it here without re-deriving why the copy-the-pixels
//! critique doesn't apply to whatever prompted the reintroduction).
//!
//! Four structural rules hold throughout this arm, all provable at the
//! text-builder/argv level rather than by trusting a comment: (1) a feed
//! line is a TRIGGER, never a display source — [`dialog_context`]/
//! [`dialog_code`] are built ONLY from a [`Pending`] `reconcile` itself
//! produced, never from a [`PairEvent`]'s fields; (2) the INBOUND SAS is
//! NEVER shown in the dialog — [`dialog_code`] returns `None` for an
//! inbound `Pending` unconditionally; the OUTBOUND SAS is shown
//! deliberately, on a CONFIRM surface, never an entry one (see above);
//! (3) argv carries identifiers and display text only, never a value used
//! to VALIDATE anything on the dialog's own side — neither
//! [`spawn_zenity_entry`]/[`spawn_lyra_entry`] (inbound) nor
//! [`spawn_zenity_confirm`]/[`spawn_lyra_confirm`] (outbound) ever receive
//! an expected code to compare against; the inbound dialogs render
//! whatever the operator typed back to the caller for THIS process to
//! compare, the outbound ones render only a boolean Approve/Reject; (4)
//! nothing is ever executed on this instance's behalf by a dialog's own
//! output — no `sh -c`, no shell interpolation; a hostile `name`/`url`
//! reaches dialog text as inert display text, protected from Pango
//! corruption by `--no-markup` on the zenity path (`aoide_secrets::
//! watch::spawn_zenity_entry`'s own doc has the live-verified reasoning)
//! and from breaking a QML string literal by `dialog_qml::qml_escape` on
//! the lyra path (`crates/lyra/src/commands/dialog_qml.rs`'s own doc).

use aoide_protocol::dialog::{
    is_locked, locker_process_name, next_spawn_backoff, run_entry_dialog, sleep_backoff_interruptible, zenity_available, DialogResult,
    SPAWN_BACKOFF_INITIAL, SPAWN_BACKOFF_MAX,
};
use aoide_protocol::feed::Follower;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sigint(_signum: libc::c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

fn install_sigint_handler() {
    unsafe {
        libc::signal(libc::SIGINT, on_sigint as *const () as libc::sighandler_t);
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn hms(ts: u64) -> String {
    let s = ts % 86_400;
    format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
}

/// How often [`run`]'s tail polls the feed file — matches
/// `aoide_server::events::TAIL_POLL_INTERVAL` (a local file read, not a
/// socket call, so a tight interval costs only an idle `stat(2)`).
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// How often [`run`] re-derives the actionable set from
/// `aoide_storage::pairing::list_inbound`/`list_outbound` directly,
/// regardless of what the tail saw — the safety backstop a missed or
/// malformed feed line can never defeat (module doc).
const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);

/// How long either popup dialog shape stays open before this watcher gives
/// up on THIS attempt and lets it close — 60s, the User's own number (task
/// #135 popup-phase spec, part 1). Neither the inbound typed-code entry nor
/// the outbound confirm may sit open forever: a stale dialog blocks the
/// operator's own desktop (a modal window that outlives the moment they'd
/// have actually noticed it) for a request that stays perfectly answerable
/// later. Closing a dialog this way is a TIMEOUT — see [`decide`]'s own
/// `CancelledExternally` arm — never Cancel/Dismiss, and it must never land
/// the id in `ignored` (module doc part 2: "didn't answer within a minute"
/// is not "no").
const DIALOG_TIMEOUT: Duration = Duration::from_secs(60);

/// How long a timed-out id sits out before [`popup_tick`] offers its
/// dialog again — reuses [`RECONCILE_INTERVAL`]'s own already-justified 30s
/// safety cadence rather than inventing a second arbitrary number (part 2's
/// own ask: a dialog must not re-raise on the very next [`POLL_INTERVAL`]
/// tick, or the operator can never use their own desktop in between).
const DIALOG_TIMEOUT_COOLDOWN: Duration = RECONCILE_INTERVAL;

/// How often [`run`]'s popup loop actively polls every outbound entry still
/// `awaiting-approval`, through [`poll_pending_outbound`] —
/// `commands::poll_outbound_once` is the ONLY production site that ever
/// advances an outbound entry to `awaiting-confirm` (module doc), and
/// nothing else in this watcher calls it: with no timer of its own, a
/// detached `--wait 0` (or timed-out) outbound request would sit unpolled
/// forever and its confirm dialog could never fire from `--popup` at all.
/// Its OWN timer, deliberately never folded into [`POLL_INTERVAL`]'s 200ms
/// cadence — a network call at that cadence is the one thing [`popup_tick`]
/// must never make (part 3's own ask). ~60s, the User's own number.
const OUTBOUND_POLL_INTERVAL: Duration = Duration::from_secs(60);

/// The default `zenity` binary name `run` checks for before ever entering
/// `--popup` mode, and [`spawn_zenity_entry`]'s own default target —
/// `aoide_secrets::watch::ZENITY_CMD`'s exact shape, re-declared here
/// rather than imported (a `&str` constant carries no "no cross-crate
/// copying" weight the way a moved TYPE or FUNCTION does, and
/// `aoide-client` has no reason to depend on `aoide-secrets` for one
/// literal). Passed as a PARAMETER everywhere it matters (never a bare
/// `Command::new("zenity")` inline) so a test can point at a shim path
/// with no `PATH` mutation, the same discipline `aoide_secrets::watch`
/// already holds for its own `zenity_cmd` parameters.
pub(crate) const ZENITY_CMD: &str = "zenity";

/// The `--extra-button`/dismiss-control label EVERY dialog this module
/// spawns carries — [`spawn_zenity_entry`]/[`spawn_zenity_confirm`] and
/// `lyra pair ask`/`lyra pair confirm` alike — and [`run_entry_dialog`]
/// compares stdout against (F6) — deliberately its OWN string, never
/// `aoide_protocol::dialog::DISMISS_LABEL`: two different ceremonies, two
/// different labels, sharing only the reader (`run_entry_dialog`'s own
/// doc on `dismiss_label`).
pub(crate) const REJECT_LABEL: &str = "Reject request";

// ── the three pairing-ceremony milestones ────────────────────────────────

/// One pairing-events-feed line, parsed. Never carries a SAS, pubkey,
/// nonce, or commitment — module doc's "the feed line is a TRIGGER."
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairEvent {
    /// `pair-parked`: an inbound request just landed (unrevealed — no SAS
    /// derivable yet, module doc on `aoide_server::a2a::pair_request`).
    Parked { id: String, name: String, origin_addr: String, url: String, ts: u64 },
    /// `pair-revealed`: an inbound request's commitment just verified — a
    /// SAS is now derivable (`aoide_storage::pairing::reveal_inbound`'s
    /// own Ok arm).
    Revealed { id: String, name: String, ts: u64 },
    /// `pair-awaiting-confirm`: DORMANT (module doc — task #119 deleted
    /// its only emitter with the callback; kept so old feed lines still
    /// parse, never fired by current code).
    AwaitingConfirm { id: String, name: String, ts: u64 },
}

/// Parse ONE pairing-events-feed line into a [`PairEvent`] — pure, total,
/// never panics. Checks `class == "gate"` AND `source == "a2a-door"`
/// FIRST (mirrors `aoide_secrets::watch::parse_notify_line`'s own
/// single-purpose parse discipline): a `class: "secret"` line (the
/// broker's own mirror), any other `source`, or anything that isn't even
/// valid JSON all read as `None` rather than erroring — the caller skips
/// it and moves on, the tail's own posture for a line it doesn't
/// recognize. `ts` arrives as a PARAMETER (this crate's own
/// clock-as-parameter discipline, matching `parse_notify_line`) since the
/// emitted payload carries no per-line timestamp of its own
/// (`aoide_server::a2a::emit_pairing_event`'s own record shape).
pub fn parse_pair_line(line: &str, ts: u64) -> Option<PairEvent> {
    let record: Value = serde_json::from_str(line).ok()?;
    if record.get("class").and_then(Value::as_str) != Some("gate") {
        return None;
    }
    if record.get("source").and_then(Value::as_str) != Some("a2a-door") {
        return None;
    }
    let kind = record.get("kind").and_then(Value::as_str)?;
    let payload = record.get("payload")?;
    let id = payload.get("id").and_then(Value::as_str)?.to_string();
    let name = payload.get("name").and_then(Value::as_str)?.to_string();
    match kind {
        "pair-parked" => {
            let origin_addr = payload.get("originAddr").and_then(Value::as_str)?.to_string();
            let url = payload.get("url").and_then(Value::as_str)?.to_string();
            Some(PairEvent::Parked { id, name, origin_addr, url, ts })
        }
        "pair-revealed" => Some(PairEvent::Revealed { id, name, ts }),
        "pair-awaiting-confirm" => Some(PairEvent::AwaitingConfirm { id, name, ts }),
        _ => None,
    }
}

/// Render one [`PairEvent`] as a narration line (tty/piped text mode) —
/// never a value, ever (nothing in [`PairEvent`] ever holds one).
pub fn narrate(event: &PairEvent) -> String {
    match event {
        PairEvent::Parked { id, name, origin_addr, ts, .. } => {
            format!("  {}  parked      pairing request {id} from `{name}` ({origin_addr})", hms(*ts))
        }
        PairEvent::Revealed { id, name, ts } => {
            format!(
                "  {}  revealed    pairing request {id} from `{name}` \u{2014} run `aoide pair {id}` \
                 and type the code read from the requester's own screen",
                hms(*ts)
            )
        }
        PairEvent::AwaitingConfirm { id, name, ts } => {
            format!("  {}  approved    `{name}` approved pairing {id} \u{2014} confirm with `aoide pair {id}`", hms(*ts))
        }
    }
}

/// Render one [`PairEvent`] as the `--json` line shape — one object per
/// line, flushed per line by the caller, same contract
/// `aoide_secrets::watch::event_to_json` already holds.
pub fn event_to_json(event: &PairEvent) -> Value {
    match event {
        PairEvent::Parked { id, name, origin_addr, url, ts } => json!({
            "event": "parked", "id": id, "name": name, "originAddr": origin_addr, "url": url, "ts": ts,
        }),
        PairEvent::Revealed { id, name, ts } => json!({ "event": "revealed", "id": id, "name": name, "ts": ts }),
        PairEvent::AwaitingConfirm { id, name, ts } => json!({ "event": "awaiting-confirm", "id": id, "name": name, "ts": ts }),
    }
}

// ── reconcile: the AUTHORITY, re-derived from scratch ────────────────────

/// One pending pairing request, re-derived directly from
/// `aoide_storage::pairing::list_inbound`/`list_outbound` — never from the
/// feed (module doc). `direction` is `"inbound"`/`"outbound"`;
/// `origin_addr` is `Some` only for an inbound entry (an outbound request
/// has no connecting-peer address of its own to report — module doc on
/// `aoide_storage::pairing::OutboundPairingRequest`); `state` carries
/// `OutboundState::as_str()` (`"awaiting-approval"`/`"awaiting-confirm"`)
/// for an outbound entry and this end's own verdict
/// (`"awaiting-approval"`/`"approved"`, off
/// `InboundPairingRequest::approved`) for an inbound one — [`actionable`]
/// is the one place that reads it. `sas` is `None` for an inbound entry that hasn't been
/// revealed yet (no requester nonce to derive against); always `Some` for
/// an outbound entry (its own nonce was chosen locally before the
/// commitment was ever sent — `OutboundPairingRequest::requester_nonce_hex`
/// is never optional).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub id: String,
    pub direction: String,
    pub name: String,
    pub origin_addr: Option<String>,
    pub url: String,
    pub sas: Option<String>,
    pub state: Option<String>,
}

/// Re-derive every pending pairing request directly from
/// `aoide_storage::pairing::list_inbound`/`list_outbound` — the AUTHORITY
/// (module doc), never the feed. SAS derivation uses the EXACT arg orders
/// `approve_inbound`/`approve_outbound` (`aoide_client::commands`) already
/// use per direction (inbound: `(entry.pubkeyHex, own_pubkey, requester_nonce,
/// entry.approverNonceHex)`; outbound: `(own_pubkey, entry.pubkeyHex,
/// requester_nonce, approver_nonce)`) — a swap here would silently derive
/// a DIFFERENT code than `pair <id>` shows, which is
/// exactly what this module's own byte-equality test catches. An
/// identity-load failure degrades to an empty list (best-effort,
/// consistent with a watcher's own "can't answer this tick, try again
/// next tick" posture) rather than erroring — there is no `Outcome`
/// channel here to carry an error through.
pub fn reconcile(now_epoch: i64) -> Vec<Pending> {
    let inbound = aoide_storage::pairing::list_inbound(now_epoch);
    let outbound = aoide_storage::pairing::list_outbound(now_epoch);
    if inbound.is_empty() && outbound.is_empty() {
        return Vec::new();
    }
    let Ok((kp, _)) = aoide_storage::identity::load_or_mint() else {
        return Vec::new();
    };
    let own_pubkey = kp.info().pubkey_hex;

    let mut out = Vec::with_capacity(inbound.len() + outbound.len());
    for e in &inbound {
        let sas = e
            .requester_nonce_hex
            .as_deref()
            .map(|n| aoide_storage::pairing::derive_sas(&e.pubkey_hex, &own_pubkey, n, &e.approver_nonce_hex));
        out.push(Pending {
            id: e.id.clone(),
            direction: "inbound".to_string(),
            name: e.name.clone(),
            origin_addr: Some(e.origin_addr.clone()),
            url: e.url.clone(),
            sas,
            state: Some(if e.approved { "approved" } else { "awaiting-approval" }.to_string()),
        });
    }
    for e in &outbound {
        let sas = aoide_storage::pairing::derive_sas(&own_pubkey, &e.pubkey_hex, &e.requester_nonce_hex, &e.approver_nonce_hex);
        out.push(Pending {
            id: e.id.clone(),
            direction: "outbound".to_string(),
            name: e.name.clone(),
            origin_addr: None,
            url: e.url.clone(),
            sas: Some(sas),
            state: Some(e.state.as_str().to_string()),
        });
    }
    out
}

/// Is `p` actionable RIGHT NOW — worth a `pair <id>`, or (with
/// `--popup`) a confirm dialog? An inbound entry only once it carries a
/// SAS (unrevealed means nothing to confirm yet, `approve_inbound`'s own
/// `awaiting-reveal` refusal) AND is still `awaiting-approval` — an
/// approved entry stays PARKED so the requester's own `aoide/pairPoll`
/// can find it (`aoide_storage::pairing::mark_inbound_approved`), so a
/// SAS alone would re-raise the code dialog on every tick for a request
/// this operator already answered. An outbound entry only once it reached
/// `awaiting-confirm` (`awaiting-approval` means the PEER hasn't approved
/// yet — nothing on THIS end to confirm, `approve_outbound`'s own
/// refusal).
pub fn actionable(p: &Pending) -> bool {
    match p.direction.as_str() {
        "inbound" => p.sas.is_some() && p.state.as_deref() == Some("awaiting-approval"),
        "outbound" => p.state.as_deref() == Some("awaiting-confirm"),
        _ => false,
    }
}

// ── the popup arm (F6, upgraded P-PV3) ───────────────────────────────────

/// Feature-detect a real `lyra` executable the SAME three-tier way
/// `aoide_secrets::watch::resolve_lyra_bin` does — `aoide_protocol::
/// bin::rice_bin`'s env/sibling tiers are already trusted (both return a
/// path containing `/`, or the env override verbatim); only its bare-name
/// fallback (`"lyra"`, left for `Command::spawn` to resolve at exec time)
/// needs a `PATH` probe of our own before this crate treats it as
/// "resolved." Repeated here rather than imported: this crate cannot
/// depend on `aoide-secrets`, and the three-line wrapper carries no
/// "no cross-crate copying" weight the way a moved TYPE or FUNCTION would
/// (`ZENITY_CMD`'s own doc states the identical rationale for its literal).
fn resolve_lyra_bin() -> Option<String> {
    let bin = aoide_protocol::bin::rice_bin();
    let resolved = bin.contains('/') || aoide_protocol::bin::on_path(&bin);
    resolved.then_some(bin)
}

/// The zenity ENTRY dialog's own argv (INBOUND only) — `--entry` (this
/// direction COLLECTS a typed code, read off the requester's own screen),
/// `--no-markup` load-bearing for the identical reason `aoide_secrets::
/// watch::spawn_zenity_entry`'s own doc gives, `--extra-button`
/// [`REJECT_LABEL`] is the third choice `run_entry_dialog` reads back off
/// stdout. `zenity_cmd` is a parameter (never `Command::new("zenity")`
/// inline) so a test can stand in a shim with no `PATH` mutation.
fn spawn_zenity_entry(zenity_cmd: &str, title: &str, text: &str) -> std::io::Result<Child> {
    Command::new(zenity_cmd)
        .args(["--entry", "--no-markup", "--title", title, "--text", text, "--extra-button", REJECT_LABEL])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
}

/// `lyra pair ask`'s own argv (INBOUND only) — `--id`/`--name`/`--context`,
/// never a code (that command carries no `--code` flag at all — the
/// approver's whole gate is typing a value that arrives from elsewhere).
/// `lyra_cmd` is a path/name parameter, matching [`spawn_zenity_entry`]'s
/// own shape.
fn spawn_lyra_entry(lyra_cmd: &str, id: &str, name: &str, context: &str) -> std::io::Result<Child> {
    let mut cmd = Command::new(lyra_cmd);
    cmd.args(["pair", "ask", "--id", id, "--name", name, "--context", context]);
    // `stderr(Stdio::inherit())` — same live-incident fix
    // `aoide_secrets::watch::spawn_lyra_entry`'s own doc gives: `lyra pair
    // ask`'s own failure `eprintln!`s land directly in this process's
    // stderr, which the deployed unit routes to the journal.
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn()
}

fn run_zenity_entry(zenity_cmd: &str, title: &str, text: &str, should_cancel: impl FnMut() -> bool) -> DialogResult {
    run_entry_dialog(|| spawn_zenity_entry(zenity_cmd, title, text), REJECT_LABEL, should_cancel)
}

fn run_lyra_entry(lyra_cmd: &str, id: &str, name: &str, context: &str, should_cancel: impl FnMut() -> bool) -> DialogResult {
    run_entry_dialog(|| spawn_lyra_entry(lyra_cmd, id, name, context), REJECT_LABEL, should_cancel)
}

/// The INBOUND dialog CHOICE — `lyra pair ask` when [`resolve_lyra_bin`]
/// found one, falling back to `zenity --entry` for the SAME attempt on a
/// `lyra` `SpawnError`/`DialogFailure` (`aoide_secrets::watch::
/// run_ask_dialog`'s own fallback shape, reused unchanged — module doc's
/// popup-arm section). `context` doubles as zenity's own `--text` — the
/// inbound dialog never has a second, code-carrying line to append
/// ([`dialog_code`] is unconditionally `None` for this direction).
fn run_ask_dialog(lyra_cmd: Option<&str>, zenity_cmd: &str, id: &str, name: &str, title: &str, context: &str, mut should_cancel: impl FnMut() -> bool) -> DialogResult {
    let Some(lyra) = lyra_cmd else {
        return run_zenity_entry(zenity_cmd, title, context, should_cancel);
    };
    let result = run_lyra_entry(lyra, id, name, context, &mut should_cancel);
    match &result {
        DialogResult::SpawnError(e) | DialogResult::DialogFailure(e) => {
            eprintln!("aoide pair watch --popup: lyra pair ask failed for request {id}: {e} \u{2014} falling back to zenity for this request");
            if zenity_available(zenity_cmd) {
                run_zenity_entry(zenity_cmd, title, context, should_cancel)
            } else {
                eprintln!("aoide pair watch --popup: zenity is not available either \u{2014} request {id} stays parked, will retry");
                result
            }
        }
        _ => result,
    }
}

/// The zenity CONFIRM dialog's own argv (OUTBOUND only, P-PV3 revert) —
/// `--question` (never `--entry`: this direction shows a code already
/// GENERATED and known, it never collects one typed back),
/// `--ok-label`/`--cancel-label` name the two ordinary buttons,
/// `--extra-button` [`REJECT_LABEL`] the third — restored to the EXACT
/// pre-P-PV3 argv shape this ceremony's confirm dialog always held
/// (`spawn_pair_confirm`, this module's own git history), since nothing
/// about outbound's own confirmation ever needed to change.
fn spawn_zenity_confirm(zenity_cmd: &str, title: &str, text: &str) -> std::io::Result<Child> {
    Command::new(zenity_cmd)
        .args(["--question", "--no-markup", "--title", title, "--text", text, "--ok-label", "Approve", "--cancel-label", "Ignore", "--extra-button", REJECT_LABEL])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
}

/// `lyra pair confirm`'s own argv (OUTBOUND only) — `--id`/`--name`/
/// `--context`/`--code`, the last ALWAYS present (a confirm dialog with
/// nothing to show would be a blank window — `lyra pair confirm`'s own
/// `handle_pair_confirm` refuses without it).
fn spawn_lyra_confirm(lyra_cmd: &str, id: &str, name: &str, context: &str, code: &str) -> std::io::Result<Child> {
    let mut cmd = Command::new(lyra_cmd);
    cmd.args(["pair", "confirm", "--id", id, "--name", name, "--context", context, "--code", code]);
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn()
}

fn run_zenity_confirm(zenity_cmd: &str, title: &str, text: &str, should_cancel: impl FnMut() -> bool) -> DialogResult {
    run_entry_dialog(|| spawn_zenity_confirm(zenity_cmd, title, text), REJECT_LABEL, should_cancel)
}

fn run_lyra_confirm(lyra_cmd: &str, id: &str, name: &str, context: &str, code: &str, should_cancel: impl FnMut() -> bool) -> DialogResult {
    run_entry_dialog(|| spawn_lyra_confirm(lyra_cmd, id, name, context, code), REJECT_LABEL, should_cancel)
}

/// The OUTBOUND dialog CHOICE — `lyra pair confirm` when [`resolve_lyra_bin`]
/// found one, falling back to `zenity --question` for the SAME attempt on
/// a `lyra` `SpawnError`/`DialogFailure`, mirroring [`run_ask_dialog`]'s
/// own fallback shape exactly, just against the confirm pair instead of
/// the entry pair.
#[allow(clippy::too_many_arguments)]
fn run_confirm_dialog(
    lyra_cmd: Option<&str>,
    zenity_cmd: &str,
    id: &str,
    name: &str,
    title: &str,
    text: &str,
    context: &str,
    code: &str,
    mut should_cancel: impl FnMut() -> bool,
) -> DialogResult {
    let Some(lyra) = lyra_cmd else {
        return run_zenity_confirm(zenity_cmd, title, text, should_cancel);
    };
    let result = run_lyra_confirm(lyra, id, name, context, code, &mut should_cancel);
    match &result {
        DialogResult::SpawnError(e) | DialogResult::DialogFailure(e) => {
            eprintln!("aoide pair watch --popup: lyra pair confirm failed for request {id}: {e} \u{2014} falling back to zenity for this request");
            if zenity_available(zenity_cmd) {
                run_zenity_confirm(zenity_cmd, title, text, should_cancel)
            } else {
                eprintln!("aoide pair watch --popup: zenity is not available either \u{2014} request {id} stays parked, will retry");
                result
            }
        }
        _ => result,
    }
}

/// The dialog's title — pure (module doc's structural rule 1): built ONLY
/// from a [`Pending`] `reconcile` produced, never from a [`PairEvent`]'s
/// own fields.
fn confirm_title(p: &Pending) -> String {
    format!("aoide \u{b7} pairing with {}", p.name)
}

/// The dialog's CONTEXT line — pure, same sourcing rule as
/// [`confirm_title`]. Never carries a SAS on EITHER direction (structural
/// rule 2, module doc): the code — when it is ever shown at all — is
/// [`dialog_code`]'s own, separate line.
fn dialog_context(p: &Pending) -> String {
    match p.direction.as_str() {
        "inbound" => format!("pairing request from `{}` ({}) \u{b7} id {}", p.name, p.origin_addr.as_deref().unwrap_or(""), p.id),
        _ => format!("confirm pairing with `{}` \u{b7} id {}", p.name, p.id),
    }
}

/// The dialog's own code line — `None` for an INBOUND [`Pending`],
/// UNCONDITIONALLY (structural rule 2, module doc: the approver's whole
/// gate is typing a code read from elsewhere — showing it here would
/// collapse the comparison into a copy exercise, the same reasoning
/// `crate::commands::approve_inbound`'s own doc gives for why its tty
/// prompt never echoes the SAS either). `Some(sas)` for an OUTBOUND
/// [`Pending`] — this instance generated that SAS itself
/// (`reconcile`'s own outbound arm), so showing it is not a leak; the CLI's
/// own `confirm_sas` prints the identical value for the identical reason.
/// The outbound direction always carries `Some` in practice
/// (`Pending::sas`'s own doc: "always `Some` for an outbound entry").
fn dialog_code(p: &Pending) -> Option<&str> {
    match p.direction.as_str() {
        "inbound" => None,
        _ => p.sas.as_deref(),
    }
}

/// What a finished [`DialogResult`] means for the request it was shown
/// for — pure, the ONE place this arm's mapping (F6) is decided, so it is
/// testable with a synthetic [`DialogResult`] and no real dialog spawn.
/// Takes `result` BY VALUE so [`PopupDecision::Approve`]'s payload moves
/// out with no clone.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PopupDecision {
    /// Exit 0. On the INBOUND arm the `String` is the operator's TYPED
    /// code, gated through `commit_approval`'s `InboundGate::Code`; on the
    /// OUTBOUND arm it is an irrelevant empty string (a confirm dialog has
    /// no value to carry) and `commit_approval` ignores it outright —
    /// module doc's popup-arm section has the full split.
    Approve(String),
    /// Exit 1, stdout was [`REJECT_LABEL`] — `reject_by_id`.
    Reject,
    /// Exit 1, empty stdout — a bare Cancel/Escape/window-close. Session-
    /// only: added to the caller's own `ignored` set, never touches
    /// storage.
    Ignore,
    /// The dialog could not run at all (both `lyra` and its zenity
    /// fallback failed), or a genuine infra-failure exit landed. Back off
    /// the retry cadence; NEVER `Ignore` — a broken dialog binary must not
    /// silently stop offering a request just because it failed to show
    /// once.
    Backoff,
    /// [`DIALOG_TIMEOUT`] elapsed with no answer — `should_cancel` closed
    /// the dialog itself, and the request is STILL actionable (task #135
    /// popup-phase spec, part 1/2). Distinct from `Noop` on purpose: this
    /// id must be offered again later (after [`DIALOG_TIMEOUT_COOLDOWN`]),
    /// and it must NEVER land in `ignored` — "didn't answer within a
    /// minute" is not "no."
    TimedOut,
    /// The request resolved elsewhere while the dialog sat open
    /// (`should_cancel` fired, and the request is no longer actionable) —
    /// already handled, nothing left to do.
    Noop,
}

/// What a finished dialog round means for the request it was shown for —
/// pure (module doc, and this variant's own doc). `still_actionable` is the
/// ONE extra input `CancelledExternally` needs to tell its two causes apart
/// (`should_cancel` returns `true` for EITHER "no longer actionable —
/// resolved elsewhere" OR "[`DIALOG_TIMEOUT`] elapsed," and a bare
/// `DialogResult` cannot distinguish them): a request that timed out is
/// still sitting there, unchanged, so `still_actionable` reads `true`; one
/// that resolved elsewhere does not, so it reads `false`. Every other
/// `DialogResult` was never subject to `should_cancel` at all (`
/// run_entry_dialog`'s own doc — it is the ONLY producer of
/// `CancelledExternally`), so `still_actionable` is simply ignored for them.
fn decide(result: DialogResult, still_actionable: bool) -> PopupDecision {
    match result {
        DialogResult::Approved(code) => PopupDecision::Approve(code),
        DialogResult::Dismissed => PopupDecision::Reject,
        DialogResult::Cancelled => PopupDecision::Ignore,
        DialogResult::CancelledExternally if still_actionable => PopupDecision::TimedOut,
        DialogResult::CancelledExternally => PopupDecision::Noop,
        DialogResult::SpawnError(_) | DialogResult::DialogFailure(_) => PopupDecision::Backoff,
    }
}

/// Pure: F8's gate — no dialog opens while the screen is locked, ever
/// (`aoide_protocol::dialog::locked_state`'s own OR of the two real
/// probes is what `popup_tick` feeds in; this is the one place that
/// probe's answer turns into a "show or don't" decision, kept separate
/// from the real I/O so it stays independently testable).
fn popup_allowed(locked: bool) -> bool {
    !locked
}

/// Pure: has a timed-out id's cooldown elapsed enough to offer its dialog
/// again? Takes the elapsed [`Duration`] since the id's last timeout
/// directly (this file's clock-as-parameter discipline — `reconcile`,
/// `popup_allowed`, and [`decide`] all take their inputs pre-resolved
/// rather than reading a clock themselves), so the boundary is provable
/// with no real sleep. `None` (never timed out, or no longer tracked at
/// all) always reads as elapsed — there is nothing to cool down from.
fn cooldown_elapsed(elapsed_since_timeout: Option<Duration>) -> bool {
    elapsed_since_timeout.is_none_or(|elapsed| elapsed >= DIALOG_TIMEOUT_COOLDOWN)
}

/// Pure: is `p` eligible for a NEW dialog RIGHT NOW? [`actionable`] plus
/// every gate this phase adds beside `ignored` — its own cooldown
/// ([`cooldown_elapsed`]) and a LIVE blocking `aoide pair`'s own marker
/// (`marker_live`, task #135 popup-phase spec part 4) — each pre-resolved
/// and passed in rather than read here, so this is the ONE place
/// [`popup_tick`]'s own candidate selection is decided (module doc's
/// discipline for `decide`/`popup_allowed`) and a synthetic case never
/// needs a real dialog, a real clock, or a real marker file.
fn eligible_for_dialog(p: &Pending, ignored: bool, cooldown_ok: bool, marker_live: bool) -> bool {
    actionable(p) && !ignored && cooldown_ok && !marker_live
}

/// Commit `p`'s pairing on a dialog Approve — looks up ITS FRESH entry by
/// id and direction (never trusts anything cached from an earlier
/// `reconcile` call, the same "re-check before acting" discipline
/// [`actionable`]'s own callers hold). **Inbound: runs
/// `InboundGate::Code(code)` through `approve_inbound`** — the SAME SAS
/// comparison and [`crate::commands::MAX_CODE_TRIES`] auto-deny machinery
/// the CLI tty path already holds, byte-identical (`InboundGate::
/// DialogConfirmed` is RETIRED — nothing constructs it any more,
/// `crate::commands`' own doc on the removal). **Outbound: `code` is
/// IGNORED and the commit is UNCONDITIONAL** (`approve_outbound(true,
/// ...)`, `skip_confirm` — the dialog itself IS the confirmation, module
/// doc's popup-arm section: a confirm dialog has no typed value to gate
/// on in the first place, this is the ceremony's original shape, restored).
fn commit_approval(p: &Pending, code: &str, now_epoch: i64) -> aoide_protocol::output::Outcome {
    let now = aoide_storage::time::now_iso_utc();
    match p.direction.as_str() {
        "inbound" => match aoide_storage::pairing::list_inbound(now_epoch).into_iter().find(|e| e.id == p.id) {
            Some(entry) => crate::commands::approve_inbound(crate::commands::InboundGate::Code(code.to_string()), "pair", &p.id, entry, &now, now_epoch, None),
            None => aoide_protocol::output::Outcome::error(
                "pair",
                format!("pairing request `{}` is no longer pending — nothing to confirm", p.id),
            ),
        },
        _ => match aoide_storage::pairing::list_outbound(now_epoch).into_iter().find(|e| e.id == p.id) {
            Some(entry) => crate::commands::approve_outbound(true, "pair", &p.id, entry, &now, now_epoch, None),
            None => aoide_protocol::output::Outcome::error(
                "pair",
                format!("pairing request `{}` is no longer pending — nothing to confirm", p.id),
            ),
        },
    }
}

// ── the outbound poll timer (F6, task #135 popup phase, part 3) ─────────

/// Pure: does `state` ever need [`poll_pending_outbound`]'s wire round
/// trip at all? Only `awaiting-approval` does — an entry already
/// `awaiting-confirm` has everything it needs (this end's own operator is
/// the actor now; `commands::poll_outbound_once`'s own early return for
/// exactly this state confirms a second call would be a no-op anyway).
fn needs_outbound_poll(state: aoide_storage::pairing::OutboundState) -> bool {
    state == aoide_storage::pairing::OutboundState::AwaitingApproval
}

/// [`OUTBOUND_POLL_INTERVAL`]'s own tick: poll every outbound entry still
/// `awaiting-approval` once, through [`crate::commands::poll_outbound_once`]
/// — the single seam (module doc, part 3): this never re-implements the
/// wire call or the `awaiting-confirm` state transition, only decides WHEN
/// to trigger it. Best-effort per entry, and the outcome is discarded on
/// purpose — a `Refused`/`Pending` answer is simply left for the next
/// tick, the SAME "can't answer this tick, try again next tick" posture
/// [`reconcile`]'s own doc already holds for an identity-load failure; a
/// `Released` answer needs no reaction here at all, since [`popup_tick`]'s
/// own very next 200ms tick re-derives [`reconcile`] from scratch and
/// notices the entry is `actionable` now.
fn poll_pending_outbound(now_epoch: i64) {
    for entry in aoide_storage::pairing::list_outbound(now_epoch) {
        if !needs_outbound_poll(entry.state) {
            continue;
        }
        let id = entry.id.clone();
        let _ = crate::commands::poll_outbound_once("pair.watch", &id, &entry, now_epoch);
    }
}

// ── the pid-marker arbiter (F6, task #135 popup phase, part 4) ──────────

/// `$XDG_RUNTIME_DIR/aoide/` — RE-DERIVED here rather than imported
/// (`aoide_storage::tunnel`'s own module doc states the identical rule for
/// this SAME directory, and re-derives it rather than depending upward for
/// the identical reason [`ZENITY_CMD`]'s own doc gives for its literal: a
/// three-line resolution carries none of the "no cross-crate copying"
/// weight a moved TYPE or FUNCTION would).
fn marker_runtime_dir() -> std::path::PathBuf {
    let runtime = std::env::var("XDG_RUNTIME_DIR").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "/run/user/1000".into());
    std::path::PathBuf::from(runtime).join("aoide")
}

/// Where a LIVE blocking `aoide pair <id>`'s own pid marker lives —
/// `$XDG_RUNTIME_DIR/aoide/pair-active/<id>.pid`. `None` for an id that is
/// not safe to join onto a path with no further checking (empty, a path
/// separator, a NUL byte, a leading `.`) — the same traversal guard
/// `aoide_storage::tunnel::is_safe_id` holds for its own session-id path
/// segment, re-derived here for the identical reason [`marker_runtime_dir`]
/// gives; a pairing id is minted, never operator-typed, but nothing here
/// trusts that instead of checking.
fn marker_path(id: &str) -> Option<std::path::PathBuf> {
    let safe = !id.is_empty() && !id.contains('/') && !id.contains('\\') && !id.contains('\0') && !id.starts_with('.');
    safe.then(|| marker_runtime_dir().join("pair-active").join(format!("{id}.pid")))
}

/// Is `pid` a live process? `aoide_client::tunnel::proc_exists`'s exact
/// `/proc/<pid>` check, RE-DERIVED here — that function is private to its
/// own module (not even `pub(crate)`), and a two-line check carries none of
/// the "no cross-crate copying" weight a moved TYPE or FUNCTION would
/// ([`marker_runtime_dir`]'s own doc gives the identical reasoning).
fn pid_is_alive(pid: u32) -> bool {
    std::path::Path::new("/proc").join(pid.to_string()).exists()
}

/// Pure: does a marker naming `marker_pid` mean "a blocking `aoide pair`
/// is live for this id right now"? Takes the liveness ANSWER as a
/// parameter rather than probing `/proc` itself — the same injected-probe
/// discipline [`popup_allowed`] already holds for `locked_state`'s own OR.
/// `None` (no marker file, or one that failed to parse) never suppresses —
/// an unanswerable probe reads as "not live," never as "live"
/// (`aoide_protocol::dialog::probe_loginctl_locked`'s own doc gives the
/// identical posture for its own OR term).
fn marker_suppresses(marker_pid: Option<u32>, is_alive: impl FnOnce(u32) -> bool) -> bool {
    marker_pid.is_some_and(is_alive)
}

/// Read `id`'s marker pid off disk, tolerating a missing file, an
/// unreadable one, or unparseable content as `None` — the same
/// tolerate-missing-as-absent discipline `aoide_storage::tunnel::load`
/// already holds for its own record.
fn read_marker_pid(id: &str) -> Option<u32> {
    let path = marker_path(id)?;
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Is a LIVE blocking `aoide pair <id>` currently holding `id`'s marker?
/// [`popup_tick`]'s own read side (part 4): a marker naming a pid that is
/// no longer alive is STALE, never suppresses, and is cleaned up here
/// (best-effort) so a later read never has to re-discover the same
/// staleness — "a stale marker must not suppress forever" (module doc),
/// not "a stale marker suppresses once more before it's noticed."
fn is_marker_live(id: &str) -> bool {
    let pid = read_marker_pid(id);
    if marker_suppresses(pid, pid_is_alive) {
        return true;
    }
    if pid.is_some() {
        if let Some(path) = marker_path(id) {
            let _ = std::fs::remove_file(path);
        }
    }
    false
}

/// The blocking `pair` path's own marker (`commands::wait_and_commit`'s
/// one caller) — [`Self::acquire`] writes it, [`Drop`] removes it
/// unconditionally, so every return path out of a blocking poll loop (a
/// terminal answer, a timeout, a future early return) clears it the same
/// way, with no per-branch bookkeeping to keep in sync. Since P2
/// (`commands::wait_and_commit`'s own doc), a blocking `aoide pair` polls
/// and can commit an outbound request entirely on its own — without this
/// marker, `--popup`'s own outbound poll timer (part 3) racing the SAME id
/// would let two processes both try to commit it (module doc, part 4).
pub(crate) struct PairActiveMarker {
    id: String,
}

impl PairActiveMarker {
    /// Claim `id`'s marker for as long as this guard lives, naming THIS
    /// process's own pid. Best-effort: a write failure (an unwritable
    /// runtime dir) degrades to "no suppression," never a hard error
    /// surfaced through the blocking loop this guards — the storage commit
    /// underneath (`commit_approval`/`commit_outbound`) is still the single
    /// source of truth either the popup or the tty path gates through, so a
    /// missed suppression risks a double DIALOG, never a double commit.
    pub(crate) fn acquire(id: &str) -> Self {
        if let Some(path) = marker_path(id) {
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let _ = std::fs::write(&path, std::process::id().to_string());
        }
        Self { id: id.to_string() }
    }
}

impl Drop for PairActiveMarker {
    fn drop(&mut self) {
        if let Some(path) = marker_path(&self.id) {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// One popup iteration: pick the next [`eligible_for_dialog`] [`Pending`]
/// (actionable, un-ignored, its timeout cooldown elapsed, no LIVE blocking
/// `aoide pair` marker — task #135 popup-phase spec, parts 2/4), skip while
/// the screen is locked (F8 — re-offered next tick, never shown behind a
/// lock screen), show its dialog — [`run_ask_dialog`] (typed-code entry) on
/// the INBOUND arm, [`run_confirm_dialog`] (a single Approve/Reject over
/// the already-known code) on the OUTBOUND one, EITHER capped at
/// [`DIALOG_TIMEOUT`] (part 1) — and act on [`decide`]'s mapping.
/// `should_cancel` re-derives [`reconcile`] fresh on every ~200ms poll
/// (`run_entry_dialog`'s own interval) rather than reading a cached queue —
/// this arm's request volume is low enough that the extra
/// `list_inbound`/`list_outbound`/identity-load cost per poll is cheaper
/// than the machinery a shared, mutex-guarded queue would add. The
/// OUTBOUND leg's own network poll (part 3, [`poll_pending_outbound`]) is
/// deliberately NOT here — this function must never make a network call on
/// [`POLL_INTERVAL`]'s own 200ms cadence; [`run`]'s own loop calls it
/// separately, on [`OUTBOUND_POLL_INTERVAL`].
fn popup_tick(ignored: &mut HashSet<String>, timed_out: &mut HashMap<String, Instant>, spawn_backoff: &mut Duration, spawn_failing: &mut bool, json_mode: bool, lyra_cmd: Option<&str>) {
    let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap_or(0);
    let pending = reconcile(now_epoch);
    ignored.retain(|id| pending.iter().any(|p| &p.id == id));
    timed_out.retain(|id, _| pending.iter().any(|p| &p.id == id));
    let Some(p) = pending.into_iter().find(|p| {
        eligible_for_dialog(
            p,
            ignored.contains(&p.id),
            cooldown_elapsed(timed_out.get(&p.id).map(Instant::elapsed)),
            is_marker_live(&p.id),
        )
    }) else {
        return;
    };

    if !popup_allowed(is_locked(&locker_process_name())) {
        return;
    }

    let title = confirm_title(&p);
    let context = dialog_context(&p);
    let id = p.id.clone();
    let deadline = Instant::now() + DIALOG_TIMEOUT;

    let result = if p.direction == "inbound" {
        let cancel_id = id.clone();
        run_ask_dialog(lyra_cmd, ZENITY_CMD, &id, &p.name, &title, &context, move || {
            Instant::now() >= deadline || {
                let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap_or(0);
                !reconcile(now_epoch).iter().any(|q| q.id == cancel_id && actionable(q))
            }
        })
    } else {
        // The zenity `--text` mirrors the SAME context/code lines
        // `dialog_qml::render_code_confirm_qml` renders for the lyra path,
        // so both dialogs show byte-identical wording (module doc's "one
        // place this wording lives" precedent, `aoide_secrets::watch::
        // format_origin_line`'s own doc has the same discipline).
        let code = dialog_code(&p).unwrap_or("").to_string();
        let text = format!("{context}\ncode: {code}");
        let cancel_id = id.clone();
        run_confirm_dialog(lyra_cmd, ZENITY_CMD, &id, &p.name, &title, &text, &context, &code, move || {
            Instant::now() >= deadline || {
                let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap_or(0);
                !reconcile(now_epoch).iter().any(|q| q.id == cancel_id && actionable(q))
            }
        })
    };

    if !matches!(result, DialogResult::SpawnError(_) | DialogResult::DialogFailure(_)) && *spawn_failing {
        *spawn_failing = false;
        *spawn_backoff = SPAWN_BACKOFF_INITIAL;
        if !json_mode {
            println!("  aoide pair watch --popup: the dialog is spawning again \u{2014} backoff cleared");
        }
    }

    // `still_actionable` is only ever consulted by `decide` on a
    // `CancelledExternally` result (its own doc) — the fresh reconcile it
    // costs is skipped for every other, far more common, outcome.
    let still_actionable = matches!(result, DialogResult::CancelledExternally) && {
        let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap_or(0);
        reconcile(now_epoch).iter().any(|q| q.id == id && actionable(q))
    };

    match decide(result, still_actionable) {
        PopupDecision::Approve(code) => {
            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap_or(0);
            let outcome = commit_approval(&p, &code, now_epoch);
            if !json_mode {
                println!("  {}", outcome.message);
            }
        }
        PopupDecision::Reject => {
            let outcome = crate::commands::reject_by_id("pair.reject", &p.id);
            if !json_mode {
                println!("  {}", outcome.message);
            }
        }
        PopupDecision::Ignore => {
            ignored.insert(p.id.clone());
        }
        PopupDecision::TimedOut => {
            timed_out.insert(p.id.clone(), Instant::now());
            if !json_mode {
                println!(
                    "  pairing request {} timed out waiting for an answer \u{2014} still pending, offered again in {}s",
                    p.id,
                    DIALOG_TIMEOUT_COOLDOWN.as_secs()
                );
            }
        }
        PopupDecision::Noop => {
            if !json_mode {
                println!("  pairing request {} resolved elsewhere while its popup was open \u{2014} closing the dialog", p.id);
            }
        }
        PopupDecision::Backoff => {
            if !*spawn_failing {
                *spawn_failing = true;
                if !json_mode {
                    eprintln!(
                        "  aoide pair watch --popup: request {} has no working dialog right now \u{2014} backing off, retrying up to every {}s",
                        p.id,
                        SPAWN_BACKOFF_MAX.as_secs()
                    );
                }
            }
            // #108: interruptible — a plain `thread::sleep` here would make
            // Ctrl-C wait out the full backoff (up to `SPAWN_BACKOFF_MAX`,
            // 60s) before `run`'s own `INTERRUPTED` check (top of its loop)
            // is reached again.
            sleep_backoff_interruptible(*spawn_backoff, &INTERRUPTED);
            *spawn_backoff = next_spawn_backoff(*spawn_backoff);
        }
    }
}

// ── the blocking loop ─────────────────────────────────────────────────────

/// "The events feed hasn't appeared yet — wait a moment," mirroring
/// `aoide_secrets::watch::wait_for_follower` exactly: only
/// [`std::io::ErrorKind::NotFound`] waits (a permission error or anything
/// else fails immediately, `Err(1)`); `Err(0)` means Ctrl-C landed while
/// waiting, a clean exit. `poll_interval` is a parameter so a test never
/// has to spend real seconds on it.
fn wait_for_follower(events_path: &Path, poll_interval: Duration) -> Result<Follower, i32> {
    let mut narrated = false;
    loop {
        match Follower::open_at_end(events_path) {
            Ok(f) => return Ok(f),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if !narrated {
                    eprintln!("aoide pair watch: waiting for the events feed to appear at {}", events_path.display());
                    narrated = true;
                }
            }
            Err(e) => {
                eprintln!("aoide pair watch: opening {}: {e}", events_path.display());
                return Err(1);
            }
        }
        if INTERRUPTED.load(Ordering::SeqCst) {
            return Err(0);
        }
        std::thread::sleep(poll_interval);
        if INTERRUPTED.load(Ordering::SeqCst) {
            return Err(0);
        }
    }
}

/// The full `aoide pair watch` command — foreground, blocks until
/// Ctrl-C. `events_path` is resolved ONCE by the caller (`cli`'s own
/// `special` hook, the SAME "resolve once, pass as a parameter"
/// discipline `events tail`/`secrets watch` already hold) — this function
/// never re-derives it. `json_mode` (module doc's `--json`) prints one
/// [`event_to_json`] object per recognized line and nothing else — no
/// startup banner, no actionable-request narration — the same
/// machine-parseable-only contract `aoide_secrets::watch`'s own `--json`
/// mode holds.
///
/// **`popup_mode` (`--popup`) is refused up front when NEITHER `lyra` nor
/// `zenity` resolves** (module doc's popup-arm section, the SAME gate
/// `aoide_secrets::watch::run` holds). Past that guard, EVERY poll tick
/// runs [`popup_tick`] instead of the plain narrate-only reconcile below —
/// the confirm dialog it shows subsumes the "actionable request"
/// narration, so the two are mutually exclusive within one invocation,
/// never layered.
pub fn run(events_path: &Path, json_mode: bool, popup_mode: bool) -> i32 {
    let lyra_cmd = resolve_lyra_bin();
    if popup_mode && lyra_cmd.is_none() && !zenity_available(ZENITY_CMD) {
        eprintln!(
            "aoide pair watch --popup: neither `lyra` nor `zenity` was found \u{2014} install \
             one of them, or run `aoide pair watch` (without --popup) instead"
        );
        return 1;
    }

    install_sigint_handler();

    let mut follower = match wait_for_follower(events_path, Duration::from_secs(1)) {
        Ok(f) => f,
        Err(code) => return code,
    };

    if !json_mode {
        println!("watching pairing events \u{2014} ^C to leave (parked requests stay parked)");
        let _ = std::io::stdout().flush();
    }

    let mut last_reconcile = Instant::now();
    let mut last_outbound_poll = Instant::now();
    let mut ignored: HashSet<String> = HashSet::new();
    let mut timed_out: HashMap<String, Instant> = HashMap::new();
    let mut spawn_backoff = SPAWN_BACKOFF_INITIAL;
    let mut spawn_failing = false;
    loop {
        if INTERRUPTED.load(Ordering::SeqCst) {
            return 0;
        }

        match follower.poll() {
            Ok(lines) => {
                for line in &lines {
                    if let Some(event) = parse_pair_line(line, unix_now()) {
                        if json_mode {
                            println!("{}", event_to_json(&event));
                        } else {
                            println!("{}", narrate(&event));
                        }
                    }
                }
                if !lines.is_empty() {
                    let _ = std::io::stdout().flush();
                }
            }
            Err(_) => {
                follower = match wait_for_follower(events_path, Duration::from_secs(1)) {
                    Ok(f) => f,
                    Err(code) => return code,
                };
            }
        }

        if popup_mode {
            // Part 3's own timer — NEVER folded into the 200ms cadence
            // `popup_tick` itself runs on ([`OUTBOUND_POLL_INTERVAL`]'s own
            // doc): this is the only place a network call happens in the
            // popup arm's own loop.
            if last_outbound_poll.elapsed() >= OUTBOUND_POLL_INTERVAL {
                last_outbound_poll = Instant::now();
                let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap_or(0);
                poll_pending_outbound(now_epoch);
            }
            popup_tick(&mut ignored, &mut timed_out, &mut spawn_backoff, &mut spawn_failing, json_mode, lyra_cmd.as_deref());
        } else if last_reconcile.elapsed() >= RECONCILE_INTERVAL {
            last_reconcile = Instant::now();
            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap_or(0);
            if !json_mode {
                for p in reconcile(now_epoch).iter().filter(|p| actionable(p)) {
                    println!("  {} is actionable \u{2014} run `aoide pair {}` (or `aoide pair reject`)", p.id, p.id);
                }
                let _ = std::io::stdout().flush();
            }
        }

        std::thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_pair_line: pure, total ─────────────────────────────────────

    #[test]
    fn parse_reads_all_three_kinds() {
        let parked = r#"{"v":0,"ts":1,"class":"gate","kind":"pair-parked","source":"a2a-door","payload":{"id":"abc12345","name":"box-a","originAddr":"10.0.0.5","url":"http://box-a/","direction":"inbound"}}"#;
        assert_eq!(
            parse_pair_line(parked, 99),
            Some(PairEvent::Parked {
                id: "abc12345".to_string(),
                name: "box-a".to_string(),
                origin_addr: "10.0.0.5".to_string(),
                url: "http://box-a/".to_string(),
                ts: 99,
            })
        );

        let revealed = r#"{"class":"gate","kind":"pair-revealed","source":"a2a-door","payload":{"id":"abc12345","name":"box-a"}}"#;
        assert_eq!(
            parse_pair_line(revealed, 100),
            Some(PairEvent::Revealed { id: "abc12345".to_string(), name: "box-a".to_string(), ts: 100 })
        );

        let awaiting = r#"{"class":"gate","kind":"pair-awaiting-confirm","source":"a2a-door","payload":{"id":"deadbeef","name":"box-b"}}"#;
        assert_eq!(
            parse_pair_line(awaiting, 101),
            Some(PairEvent::AwaitingConfirm { id: "deadbeef".to_string(), name: "box-b".to_string(), ts: 101 })
        );
    }

    #[test]
    fn parse_rejects_a_secrets_mirror_line_and_any_non_gate_class() {
        let secret_class = r#"{"class":"secret","kind":"pair-parked","source":"a2a-door","payload":{"id":"x","name":"y"}}"#;
        assert_eq!(parse_pair_line(secret_class, 1), None);

        let wrong_source = r#"{"class":"gate","kind":"pair-parked","source":"secrets-mirror","payload":{"id":"x","name":"y","originAddr":"a","url":"b"}}"#;
        assert_eq!(parse_pair_line(wrong_source, 1), None);

        let hand_edit = r#"{"class":"gate","kind":"hand-edit","source":"aoided","payload":{}}"#;
        assert_eq!(parse_pair_line(hand_edit, 1), None, "a real gate-classed line of an unrecognized kind still reads as None");
    }

    #[test]
    fn parse_never_panics_on_hostile_input() {
        assert_eq!(parse_pair_line("not json at all", 1), None);
        assert_eq!(parse_pair_line("[1,2,3]", 1), None);
        assert_eq!(parse_pair_line("\"just a string\"", 1), None);
        assert_eq!(parse_pair_line("null", 1), None);
        assert_eq!(parse_pair_line("", 1), None);

        // A pathologically deep nest — serde_json's own recursion limit
        // returns `Err` well before any risk of a stack overflow; this
        // proves that stays a graceful `None`, never a crash.
        let deep = "[".repeat(200_000);
        assert_eq!(parse_pair_line(&deep, 1), None);

        // A megabyte of unterminated objects — never valid JSON, must
        // still return promptly with `None`, not hang or panic.
        let huge = "{".repeat(1024 * 1024);
        assert_eq!(parse_pair_line(&huge, 1), None);

        // Embedded NULs.
        assert_eq!(parse_pair_line("{\"class\":\"gate\",\"kind\":\"pair-parked\",\0\0\0}", 1), None);

        // A hostile `kind` value (path-traversal-shaped) is just an
        // unrecognized kind — None, never treated as a file path anywhere
        // in this module.
        let hostile_kind = r#"{"class":"gate","kind":"../../etc/passwd","source":"a2a-door","payload":{"id":"x","name":"y"}}"#;
        assert_eq!(parse_pair_line(hostile_kind, 1), None);
    }

    // ── reconcile: the swap-catcher ──────────────────────────────────────

    fn with_peer_state<T>(tag: &str, f: impl FnOnce() -> T) -> T {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let dir = std::env::temp_dir().join(format!(
            "aoide-client-pair-watch-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::env::set_var("AOIDE_STATE_DIR", &dir);
        let out = f();
        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        out
    }

    /// The swap-catcher: `reconcile`'s own SAS-derivation arg order must
    /// stay byte-identical to `approve_inbound`'s (the AUTHORITATIVE
    /// derivation an approver's own `pair <id>` commits against) —
    /// bare `pair` itself carries no SAS to compare against any more
    /// (P-PV2, the User's locked spec), so this pins against the approve
    /// path directly instead.
    #[test]
    fn reconcile_derives_the_same_sas_approve_inbound_would() {
        with_peer_state("swap-catcher", || {
            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap();
            aoide_storage::pairing::park_inbound(
                &"a".repeat(64),
                "box-a",
                "10.0.0.5",
                "http://box-a/",
                &aoide_storage::pairing::derive_commit(&"a".repeat(64), &"c".repeat(32)),
                &aoide_storage::time::now_iso_utc(),
                &aoide_storage::pairing::expires_at_from(now_epoch),
                None,
            )
            .unwrap();
            let id = aoide_storage::pairing::list_inbound(now_epoch)[0].id.clone();
            aoide_storage::pairing::reveal_inbound(&id, &"c".repeat(32), now_epoch).unwrap();

            let entry = aoide_storage::pairing::list_inbound(now_epoch).into_iter().find(|e| e.id == id).unwrap();
            let (kp, _) = aoide_storage::identity::load_or_mint().unwrap();
            let own_pubkey = kp.info().pubkey_hex;
            // The exact arg order `approve_inbound` (`aoide_client::commands`)
            // derives its own SAS with.
            let expected_sas = aoide_storage::pairing::derive_sas(
                &entry.pubkey_hex,
                &own_pubkey,
                entry.requester_nonce_hex.as_deref().unwrap(),
                &entry.approver_nonce_hex,
            );

            let pending = reconcile(now_epoch);
            assert_eq!(pending.len(), 1);
            assert_eq!(pending[0].sas.as_deref(), Some(expected_sas.as_str()), "reconcile must derive the BYTE-IDENTICAL code approve_inbound would");
        });
    }

    #[test]
    fn an_unrevealed_inbound_entry_is_never_actionable() {
        with_peer_state("unrevealed", || {
            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap();
            aoide_storage::pairing::park_inbound(
                &"a".repeat(64),
                "box-a",
                "10.0.0.5",
                "http://box-a/",
                &aoide_storage::pairing::derive_commit(&"a".repeat(64), &"c".repeat(32)),
                &aoide_storage::time::now_iso_utc(),
                &aoide_storage::pairing::expires_at_from(now_epoch),
                None,
            )
            .unwrap();

            let pending = reconcile(now_epoch);
            assert_eq!(pending.len(), 1);
            assert!(pending[0].sas.is_none(), "unrevealed — no SAS derivable yet");
            assert!(!actionable(&pending[0]), "an unrevealed inbound entry must never be actionable");
        });
    }

    #[test]
    fn an_outbound_entry_awaiting_approval_is_never_actionable() {
        with_peer_state("awaiting-approval", || {
            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap();
            aoide_storage::pairing::park_outbound(aoide_storage::pairing::OutboundPairingRequest {
                id: "deadbeef".to_string(),
                url: "http://box-b/".to_string(),
                name: "box-b".to_string(),
                pubkey_hex: "b".repeat(64),
                requester_nonce_hex: "c".repeat(32),
                approver_nonce_hex: "d".repeat(32),
                requested_at: aoide_storage::time::now_iso_utc(),
                expires_at: aoide_storage::pairing::expires_at_from(now_epoch),
                state: aoide_storage::pairing::OutboundState::AwaitingApproval,
                via: None,
            })
            .unwrap();

            let pending = reconcile(now_epoch);
            assert_eq!(pending.len(), 1);
            assert!(pending[0].sas.is_some(), "outbound always carries its own nonce, so a SAS is always derivable");
            assert!(!actionable(&pending[0]), "awaiting-approval means the PEER hasn't approved yet — nothing on this end to confirm");
        });
    }

    #[test]
    fn an_approved_inbound_entry_stops_being_actionable() {
        with_peer_state("approved-inbound", || {
            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap();
            let nonce = "c".repeat(32);
            let id = aoide_storage::pairing::park_inbound(
                &"a".repeat(64),
                "box-a",
                "10.0.0.5",
                "http://box-a/",
                &aoide_storage::pairing::derive_commit(&"a".repeat(64), &nonce),
                &aoide_storage::time::now_iso_utc(),
                &aoide_storage::pairing::expires_at_from(now_epoch),
                None,
            )
            .unwrap()
            .id;
            aoide_storage::pairing::reveal_inbound(&id, &nonce, now_epoch).unwrap();

            let pending = reconcile(now_epoch);
            assert_eq!(pending.len(), 1);
            assert!(actionable(&pending[0]), "a revealed, unapproved inbound entry is the one thing the code dialog is for");

            // Approval leaves the entry PARKED so the requester's own
            // pairPoll can still find it — the very reason a SAS alone
            // used to re-raise the dialog on every 30s tick.
            aoide_storage::pairing::mark_inbound_approved(&id, now_epoch).unwrap();
            let pending = reconcile(now_epoch);
            assert_eq!(pending.len(), 1, "still parked for the requester's poll");
            assert!(pending[0].sas.is_some(), "still revealed — the SAS never goes away");
            assert!(!actionable(&pending[0]), "this operator already typed the code; never ask again");
        });
    }
    // ── the tail: deadline-loop, never a fixed sleep ─────────────────────

    #[test]
    fn follower_sees_appended_pairing_lines_via_a_deadline_loop() {
        let path = std::env::temp_dir().join(format!(
            "aoide-client-pair-watch-follower-{}-{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::write(&path, b"").unwrap();
        let mut follower = Follower::open_at_end(&path).unwrap();
        let feed = aoide_protocol::feed::FeedWriter::new(path.clone(), 1024 * 1024, 0o600);

        feed.append(&json!({
            "v": 0, "ts": 1, "class": "gate", "kind": "pair-parked", "source": "a2a-door",
            "payload": { "id": "abc12345", "name": "box-a", "originAddr": "10.0.0.5", "url": "http://box-a/", "direction": "inbound" },
        }));

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut got = Vec::new();
        while got.is_empty() {
            got = follower.poll().unwrap();
            assert!(std::time::Instant::now() < deadline, "the follower never saw the appended line in time");
            if got.is_empty() {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        assert_eq!(got.len(), 1);
        assert_eq!(
            parse_pair_line(&got[0], 42),
            Some(PairEvent::Parked {
                id: "abc12345".to_string(),
                name: "box-a".to_string(),
                origin_addr: "10.0.0.5".to_string(),
                url: "http://box-a/".to_string(),
                ts: 42,
            })
        );

        std::fs::remove_file(&path).ok();
    }

    // ── the popup arm (F6) ────────────────────────────────────────────────

    fn fixture_pending(direction: &str, sas: Option<&str>) -> Pending {
        Pending {
            id: "abc12345".to_string(),
            direction: direction.to_string(),
            name: "box-a".to_string(),
            origin_addr: Some("10.0.0.5".to_string()),
            url: "http://box-a:8710/".to_string(),
            sas: sas.map(str::to_string),
            state: if direction == "outbound" { Some("awaiting-confirm".to_string()) } else { None },
        }
    }

    #[test]
    fn decide_maps_every_dialog_result_and_a_spawn_failure_is_never_ignore() {
        assert_eq!(decide(DialogResult::Approved("740-729".to_string()), false), PopupDecision::Approve("740-729".to_string()));
        assert_eq!(decide(DialogResult::Dismissed, false), PopupDecision::Reject);
        assert_eq!(decide(DialogResult::Cancelled, false), PopupDecision::Ignore);
        // The swap-catcher: a spawn failure must back off, and must NEVER
        // read as `Ignore` — `Ignore` would permanently stop offering a
        // request just because the dialog binary glitched once.
        assert_eq!(decide(DialogResult::SpawnError("no such file".to_string()), false), PopupDecision::Backoff);
        assert_ne!(decide(DialogResult::SpawnError("no such file".to_string()), false), PopupDecision::Ignore);
        assert_eq!(decide(DialogResult::DialogFailure("exit 3".to_string()), false), PopupDecision::Backoff);
    }

    /// Task #135 popup-phase spec, part 1/2: `CancelledExternally` is the
    /// ONE `DialogResult` `should_cancel` ever produces, for EITHER of two
    /// reasons (`decide`'s own doc) — `still_actionable` is what tells
    /// them apart. Still actionable (nothing changed underneath the
    /// dialog) means IT gave up — a timeout, offered again later, never
    /// `ignored`. No longer actionable (resolved elsewhere) means the
    /// SAME `Noop` this arm always gave.
    #[test]
    fn decide_tells_a_timeout_from_a_resolved_elsewhere_cancel() {
        assert_eq!(decide(DialogResult::CancelledExternally, true), PopupDecision::TimedOut);
        assert_eq!(decide(DialogResult::CancelledExternally, false), PopupDecision::Noop);
        assert_ne!(
            decide(DialogResult::CancelledExternally, true),
            PopupDecision::Ignore,
            "a timeout must never be indistinguishable from an explicit Cancel/Dismiss"
        );
    }

    #[test]
    fn popup_allowed_is_the_negation_of_locked_state() {
        assert!(popup_allowed(false));
        assert!(!popup_allowed(true));
        // Driven through the real `locked_state` OR, the same combinator
        // `aoide_protocol::dialog`'s own tests already exercise directly —
        // this proves THIS module's gate reads its answer correctly, not
        // that `locked_state` itself is correct (already covered there).
        assert!(!popup_allowed(aoide_protocol::dialog::locked_state(Some(true), false)));
        assert!(!popup_allowed(aoide_protocol::dialog::locked_state(None, true)));
        assert!(popup_allowed(aoide_protocol::dialog::locked_state(Some(false), false)));
    }

    // ── cooldown_elapsed / eligible_for_dialog (part 2/4's own gates) ────

    #[test]
    fn cooldown_elapsed_gates_on_the_boundary_inclusive() {
        assert!(cooldown_elapsed(None), "never timed out — nothing to cool down from");
        assert!(!cooldown_elapsed(Some(DIALOG_TIMEOUT_COOLDOWN - Duration::from_millis(1))), "just under the cooldown must still suppress");
        assert!(cooldown_elapsed(Some(DIALOG_TIMEOUT_COOLDOWN)), "the boundary itself has cooled down");
        assert!(cooldown_elapsed(Some(DIALOG_TIMEOUT_COOLDOWN + Duration::from_secs(1))));
    }

    #[test]
    fn eligible_for_dialog_requires_actionable_and_every_new_gate_clear() {
        let p = fixture_pending("outbound", Some("111-222"));
        assert!(eligible_for_dialog(&p, false, true, false), "actionable, unignored, cooled down, unmarked — eligible");
        assert!(!eligible_for_dialog(&p, true, true, false), "explicitly ignored");
        assert!(!eligible_for_dialog(&p, false, false, false), "still cooling down from a timeout");
        assert!(!eligible_for_dialog(&p, false, true, true), "a live marker suppresses regardless of every other gate");

        // The inbound fixture's own `state` is never `awaiting-approval`
        // (`fixture_pending`'s own shape) — never actionable, so every
        // other gate being wide open must not matter.
        let never_actionable = fixture_pending("inbound", Some("111-222"));
        assert!(!eligible_for_dialog(&never_actionable, false, true, false));
    }

    // ── needs_outbound_poll (part 3) ──────────────────────────────────────

    #[test]
    fn needs_outbound_poll_is_true_only_for_awaiting_approval() {
        assert!(needs_outbound_poll(aoide_storage::pairing::OutboundState::AwaitingApproval));
        assert!(!needs_outbound_poll(aoide_storage::pairing::OutboundState::AwaitingConfirm));
    }

    /// End to end (real local listener, this crate's own established
    /// pattern — `commands.rs`'s own `spawn_fake_pair_poll_server`,
    /// duplicated here because it is `#[cfg(test)]`-private to that
    /// module: a few lines crossing a MODULE boundary carries none of the
    /// "no cross-crate copying" weight a moved TYPE or FUNCTION would
    /// (`marker_runtime_dir`'s own doc gives the identical reasoning for a
    /// crate boundary)): proves [`poll_pending_outbound`] is the thing that
    /// actually unlocks the outbound confirm dialog for a detached
    /// (`--wait 0`) request sitting at `awaiting-approval` — without this
    /// wiring, `commands::poll_outbound_once` (the only production site
    /// that ever advances the state) is never called by the watcher at
    /// all.
    fn spawn_fake_pair_poll_server(body: &'static str) -> (std::net::TcpListener, u16) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepter = listener.try_clone().unwrap();
        std::thread::spawn(move || {
            use std::io::Read as _;
            loop {
                let Ok((mut stream, _)) = accepter.accept() else { break };
                let mut buf = [0u8; 4096];
                if stream.read(&mut buf).unwrap_or(0) == 0 {
                    continue;
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (listener, port)
    }

    #[test]
    fn poll_pending_outbound_advances_an_awaiting_approval_entry_to_awaiting_confirm() {
        with_peer_state("poll-pending-outbound", || {
            let pubkey_b = "b".repeat(64);
            let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{{"status":"approved","pubkeyHex":"{pubkey_b}"}}}}"#);
            let body: &'static str = Box::leak(body.into_boxed_str());
            let (_listener, port) = spawn_fake_pair_poll_server(body);
            let url = format!("http://127.0.0.1:{port}/");
            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap();
            aoide_storage::pairing::park_outbound(aoide_storage::pairing::OutboundPairingRequest {
                id: "deadbeef".to_string(),
                url,
                name: "box-b".to_string(),
                pubkey_hex: pubkey_b,
                requester_nonce_hex: "c".repeat(32),
                approver_nonce_hex: "d".repeat(32),
                requested_at: aoide_storage::time::now_iso_utc(),
                expires_at: aoide_storage::pairing::expires_at_from(now_epoch),
                state: aoide_storage::pairing::OutboundState::AwaitingApproval,
                via: None,
            })
            .unwrap();

            poll_pending_outbound(now_epoch);

            let listed = aoide_storage::pairing::list_outbound(now_epoch);
            assert_eq!(listed.len(), 1);
            assert_eq!(listed[0].state, aoide_storage::pairing::OutboundState::AwaitingConfirm, "the ONLY way this ever advances without a live wait_and_commit loop");
            let pending = reconcile(now_epoch);
            assert!(actionable(&pending.into_iter().find(|p| p.id == "deadbeef").unwrap()), "now the outbound confirm dialog has something to fire on");
        });
    }

    // ── the pid-marker arbiter (part 4) ───────────────────────────────────

    fn with_temp_marker_runtime_dir<T>(tag: &str, f: impl FnOnce() -> T) -> T {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("XDG_RUNTIME_DIR").ok();
        let dir = std::env::temp_dir().join(format!(
            "aoide-client-pair-watch-marker-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", &dir);
        let out = f();
        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
        out
    }

    #[test]
    fn marker_suppresses_only_when_a_pid_is_present_and_reads_alive() {
        assert!(marker_suppresses(Some(123), |_| true));
        assert!(!marker_suppresses(Some(123), |_| false));
        assert!(!marker_suppresses(None, |_| true), "no marker at all is never live, regardless of what the probe would say");
    }

    #[test]
    fn pair_active_marker_is_live_while_held_and_gone_after_drop() {
        with_temp_marker_runtime_dir("live-drop", || {
            assert!(!is_marker_live("abc12345"), "no marker written yet");
            {
                let _marker = PairActiveMarker::acquire("abc12345");
                assert!(is_marker_live("abc12345"), "this process's own pid is alive by definition");
            }
            assert!(!is_marker_live("abc12345"), "Drop must remove the marker unconditionally");
        });
    }

    /// Part 4's own ask: "a stale marker (dead pid) must not suppress
    /// forever." A pid this large will never exist on a real Linux box
    /// (default `pid_max` sits far below `u32::MAX`) — the same
    /// "definitely-dead, never a recycled pid we might collide with"
    /// caution `client::tunnel`'s own module doc holds for its liveness
    /// probe.
    #[test]
    fn a_marker_naming_a_dead_pid_is_stale_never_suppresses_and_is_cleaned_up() {
        with_temp_marker_runtime_dir("stale", || {
            let path = marker_path("deadbeef").unwrap();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "999999999").unwrap();
            assert!(!is_marker_live("deadbeef"), "a dead pid's marker must never suppress");
            assert!(!path.exists(), "a stale marker is cleaned up once read, never left to suppress on a later read too");
        });
    }

    #[test]
    fn a_missing_or_corrupt_marker_reads_as_not_live() {
        with_temp_marker_runtime_dir("missing-corrupt", || {
            assert!(!is_marker_live("nosuchid-at-all"), "no file at all");
            let path = marker_path("corrupt-id").unwrap();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "not-a-pid").unwrap();
            assert!(!is_marker_live("corrupt-id"), "unparseable content is never live");
        });
    }

    #[test]
    fn marker_path_refuses_traversal_shaped_ids() {
        assert!(marker_path("../etc").is_none());
        assert!(marker_path("a/b").is_none());
        assert!(marker_path("").is_none());
        assert!(marker_path(".hidden").is_none());
    }

    #[test]
    fn dialog_code_is_none_for_inbound_regardless_of_a_derived_sas() {
        // Structural rule 2 (module doc): the approver's dialog must NEVER
        // show the code, or the whole out-of-band comparison collapses into
        // a copy exercise.
        let p = fixture_pending("inbound", Some("111-222"));
        assert_eq!(dialog_code(&p), None);
    }

    #[test]
    fn dialog_code_is_some_for_outbound_carrying_its_own_sas() {
        let p = fixture_pending("outbound", Some("777-888"));
        assert_eq!(dialog_code(&p), Some("777-888"));
    }

    #[test]
    fn dialog_context_never_contains_another_requests_id_or_origin() {
        let a = fixture_pending("inbound", Some("111-222"));
        let mut b = fixture_pending("inbound", Some("333-444"));
        b.id = "deadbeef".to_string();
        b.name = "box-b".to_string();
        b.origin_addr = Some("10.0.0.9".to_string());

        let text_a = dialog_context(&a);
        let text_b = dialog_context(&b);
        assert!(text_a.contains("abc12345"));
        assert!(!text_a.contains("deadbeef"), "box-a's context must never carry box-b's id: {text_a}");
        assert!(text_b.contains("deadbeef"));
        assert!(text_b.contains("10.0.0.9"));
        assert!(!text_b.contains("10.0.0.5"), "box-b's context must never carry box-a's origin: {text_b}");
    }

    #[test]
    fn dialog_context_and_title_survive_hostile_name_intact_and_never_carry_the_sas() {
        // `--no-markup` (spawn_zenity_entry's own doc)/`qml_escape`
        // (`dialog_qml`'s own doc) are what protect the RENDER — the
        // builder itself must never truncate, escape, or drop hostile
        // bytes; it just formats what it was given.
        let mut p = fixture_pending("inbound", Some("555-666"));
        p.name = "box-<b>evil</b>-&-more".to_string();
        p.origin_addr = Some("10.0.0.5&x=1".to_string());

        let title = confirm_title(&p);
        let text = dialog_context(&p);
        assert!(title.contains(&p.name), "{title}");
        assert!(text.contains(&p.name), "{text}");
        assert!(text.contains(p.origin_addr.as_deref().unwrap()), "{text}");
        assert!(!text.contains("555-666"), "the inbound context must never carry the SAS: {text}");
    }

    #[test]
    fn dialog_context_outbound_carries_no_origin_addr_field() {
        let p = fixture_pending("outbound", Some("777-888"));
        let text = dialog_context(&p);
        // An outbound entry has no connecting-peer address of its own
        // (`Pending::origin_addr`'s own doc) — an "origin:"-shaped
        // substring must never appear for one, and the SAS lives in
        // `dialog_code`, never inline here.
        assert!(!text.contains("origin"), "{text}");
        assert!(!text.contains("777-888"), "the SAS lives in dialog_code, never inline in the context: {text}");
    }

    /// Serializes this module's own write-a-shim-then-exec-it tests
    /// against each other — the same genuine `execve()`/`close()` TOCTOU
    /// `aoide_secrets::watch`'s own `shim_lock` documents at length
    /// (`crates/secrets/src/watch.rs`, the "Text file busy" flake found
    /// under heavy parallel contention): every shim here gets its own
    /// unique tempdir, yet the race still reproduced under heavy
    /// `--test-threads` contention on a just-written, just-chmod'd file —
    /// a kernel-timing race, not a path collision, so the fix is simply
    /// not contending: this lock serializes this module's own write+exec
    /// pairs against each other.
    fn shim_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `#!/bin/sh` shebang (the one interpreter the nix build sandbox
    /// provides — `/usr/bin/env` does not exist there; secrets' shims set
    /// the precedent), shell builtins only (`echo`/`exit` — never an
    /// external `sleep`).
    fn write_shim(tag: &str, script: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aoide-client-pair-confirm-shim-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let shim = dir.join("confirm-shim");
        std::fs::write(&shim, script).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        shim
    }

    fn remove_shim(shim: &std::path::Path) {
        if let Some(dir) = shim.parent() {
            std::fs::remove_dir_all(dir).ok();
        }
    }

    #[test]
    fn run_zenity_entry_exit_zero_is_approved_with_the_typed_code() {
        let _guard = shim_lock();
        let shim = write_shim("approve", "#!/bin/sh\necho 740-729\nexit 0\n");
        let result = run_zenity_entry(shim.to_str().unwrap(), "t", "x", || false);
        assert_eq!(result_code(&result), Some("740-729".to_string()));
        remove_shim(&shim);
    }

    #[test]
    fn run_zenity_entry_reject_label_on_stdout_is_dismissed() {
        let _guard = shim_lock();
        let shim = write_shim("reject", "#!/bin/sh\necho 'Reject request'\nexit 1\n");
        let result = run_zenity_entry(shim.to_str().unwrap(), "t", "x", || false);
        assert!(matches!(result, DialogResult::Dismissed), "expected Dismissed, got {result:?}");
        remove_shim(&shim);
    }

    #[test]
    fn run_zenity_entry_bare_cancel_is_cancelled_not_dismissed() {
        let _guard = shim_lock();
        let shim = write_shim("cancel", "#!/bin/sh\nexit 1\n");
        let result = run_zenity_entry(shim.to_str().unwrap(), "t", "x", || false);
        assert!(matches!(result, DialogResult::Cancelled), "expected Cancelled, got {result:?}");
        remove_shim(&shim);
    }

    #[test]
    fn run_zenity_entry_reports_a_spawn_error_for_a_nonexistent_shim() {
        let result = run_zenity_entry("/no/such/aoide-pair-entry-shim-never-exists", "t", "x", || false);
        assert!(matches!(result, DialogResult::SpawnError(_)), "expected SpawnError, got {result:?}");
    }

    fn result_code(result: &DialogResult) -> Option<String> {
        match result {
            DialogResult::Approved(c) => Some(c.clone()),
            _ => None,
        }
    }

    // ── run_ask_dialog: the lyra/zenity choice + fallback ─────────────────

    #[test]
    fn run_ask_dialog_prefers_lyra_when_a_bin_resolves() {
        let _guard = shim_lock();
        let lyra_shim = write_shim("lyra-ok", "#!/bin/sh\necho 111-222\nexit 0\n");
        let zenity_shim = write_shim("zenity-unused", "#!/bin/sh\necho 999-999\nexit 0\n");
        let result = run_ask_dialog(Some(lyra_shim.to_str().unwrap()), zenity_shim.to_str().unwrap(), "id1", "box-a", "t", "ctx", || false);
        assert_eq!(result_code(&result), Some("111-222".to_string()), "lyra's own answer must win when it resolves");
        remove_shim(&lyra_shim);
        remove_shim(&zenity_shim);
    }

    #[test]
    fn run_ask_dialog_falls_back_to_zenity_on_a_lyra_spawn_error() {
        let _guard = shim_lock();
        let zenity_shim = write_shim("zenity-fallback", "#!/bin/sh\necho 333-444\nexit 0\n");
        let result = run_ask_dialog(Some("/no/such/aoide-pair-lyra-shim-never-exists"), zenity_shim.to_str().unwrap(), "id1", "box-a", "t", "ctx", || false);
        assert_eq!(result_code(&result), Some("333-444".to_string()), "a lyra spawn failure must fall back to zenity for the SAME attempt");
        remove_shim(&zenity_shim);
    }

    #[test]
    fn run_ask_dialog_with_no_lyra_bin_goes_straight_to_zenity() {
        let _guard = shim_lock();
        let zenity_shim = write_shim("zenity-only", "#!/bin/sh\necho 555-666\nexit 0\n");
        let result = run_ask_dialog(None, zenity_shim.to_str().unwrap(), "id1", "box-a", "t", "ctx", || false);
        assert_eq!(result_code(&result), Some("555-666".to_string()));
        remove_shim(&zenity_shim);
    }

    // ── run_zenity_confirm / run_confirm_dialog (P-PV3 revert, outbound) ──

    #[test]
    fn run_zenity_confirm_exit_zero_is_approved_with_no_typed_value() {
        let _guard = shim_lock();
        let shim = write_shim("confirm-approve", "#!/bin/sh\nexit 0\n");
        let result = run_zenity_confirm(shim.to_str().unwrap(), "t", "x", || false);
        assert_eq!(result_code(&result), Some(String::new()), "a plain OK carries no payload -- the confirm never collects a typed value");
        remove_shim(&shim);
    }

    #[test]
    fn run_zenity_confirm_reject_label_on_stdout_is_dismissed() {
        let _guard = shim_lock();
        let shim = write_shim("confirm-reject", "#!/bin/sh\necho 'Reject request'\nexit 1\n");
        let result = run_zenity_confirm(shim.to_str().unwrap(), "t", "x", || false);
        assert!(matches!(result, DialogResult::Dismissed), "expected Dismissed, got {result:?}");
        remove_shim(&shim);
    }

    #[test]
    fn run_zenity_confirm_bare_cancel_is_cancelled_not_dismissed() {
        let _guard = shim_lock();
        let shim = write_shim("confirm-cancel", "#!/bin/sh\nexit 1\n");
        let result = run_zenity_confirm(shim.to_str().unwrap(), "t", "x", || false);
        assert!(matches!(result, DialogResult::Cancelled), "expected Cancelled, got {result:?}");
        remove_shim(&shim);
    }

    #[test]
    fn run_confirm_dialog_prefers_lyra_when_a_bin_resolves() {
        let _guard = shim_lock();
        let lyra_shim = write_shim("confirm-lyra-ok", "#!/bin/sh\nexit 0\n");
        let zenity_shim = write_shim("confirm-zenity-unused", "#!/bin/sh\necho should-not-run\nexit 1\n");
        let result = run_confirm_dialog(Some(lyra_shim.to_str().unwrap()), zenity_shim.to_str().unwrap(), "id1", "box-b", "t", "x", "ctx", "111-222", || false);
        assert_eq!(result_code(&result), Some(String::new()), "lyra's own answer must win when it resolves");
        remove_shim(&lyra_shim);
        remove_shim(&zenity_shim);
    }

    #[test]
    fn run_confirm_dialog_falls_back_to_zenity_on_a_lyra_spawn_error() {
        let _guard = shim_lock();
        let zenity_shim = write_shim("confirm-zenity-fallback", "#!/bin/sh\nexit 0\n");
        let result = run_confirm_dialog(
            Some("/no/such/aoide-pair-confirm-lyra-shim-never-exists"),
            zenity_shim.to_str().unwrap(),
            "id1",
            "box-b",
            "t",
            "x",
            "ctx",
            "111-222",
            || false,
        );
        assert_eq!(result_code(&result), Some(String::new()), "a lyra spawn failure must fall back to zenity for the SAME attempt");
        remove_shim(&zenity_shim);
    }

    #[test]
    fn run_confirm_dialog_with_no_lyra_bin_goes_straight_to_zenity() {
        let _guard = shim_lock();
        let zenity_shim = write_shim("confirm-zenity-only", "#!/bin/sh\nexit 0\n");
        let result = run_confirm_dialog(None, zenity_shim.to_str().unwrap(), "id1", "box-b", "t", "x", "ctx", "111-222", || false);
        assert_eq!(result_code(&result), Some(String::new()));
        remove_shim(&zenity_shim);
    }

    // ── commit_approval: same peers.json the CLI's `--yes` path writes ────

    /// `approve_inbound`'s own commit is now PURELY LOCAL (Design A, task
    /// #119 — module doc on `commands::approve_inbound`): no network call at
    /// all, so this test needs no fake server the way the old callback-era
    /// version of it did — proving that IS part of the point.
    #[test]
    fn commit_approval_on_an_inbound_entry_writes_the_same_peers_json_the_cli_would() {
        with_peer_state("commit-approval-inbound", || {
            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap();
            aoide_storage::pairing::park_inbound(
                &"a".repeat(64),
                "box-a",
                "10.0.0.5",
                "http://box-a-is-loopback-only.invalid/",
                &aoide_storage::pairing::derive_commit(&"a".repeat(64), &"c".repeat(32)),
                &aoide_storage::time::now_iso_utc(),
                &aoide_storage::pairing::expires_at_from(now_epoch),
                None,
            )
            .unwrap();
            let id = aoide_storage::pairing::list_inbound(now_epoch)[0].id.clone();
            aoide_storage::pairing::reveal_inbound(&id, &"c".repeat(32), now_epoch).unwrap();

            let pending = reconcile(now_epoch);
            assert_eq!(pending.len(), 1);
            assert!(actionable(&pending[0]));
            let sas = pending[0].sas.clone().unwrap();

            let outcome = commit_approval(&pending[0], &sas, now_epoch);
            assert_eq!(outcome.status, aoide_protocol::output::Status::Ok, "{outcome:?}");

            let peers = aoide_storage::peer_store::load_peers();
            assert_eq!(peers.len(), 1);
            assert_eq!(peers[0].name, "box-a");
            assert_eq!(peers[0].pubkey.as_deref(), Some("a".repeat(64).as_str()));
            assert!(peers[0].verified);

            // Design A: the parked entry stays PARKED, marked approved, for
            // the requester's own poll to find later — never taken here.
            let listed = aoide_storage::pairing::list_inbound(now_epoch);
            assert_eq!(listed.len(), 1, "the entry stays parked so the requester's poll can find it");
            assert!(listed[0].approved);
        });
    }

    /// P-PV3 (task #132): `commit_approval`'s inbound arm now runs
    /// `InboundGate::Code` — a wrong typed code must count a persisted try
    /// exactly the way the CLI tty/`--code` path already does, and the
    /// [`crate::commands::MAX_CODE_TRIES`]rd wrong code must auto-deny —
    /// through THIS function, the popup's own entry point, not just
    /// `approve_inbound` directly (`commands.rs`'s own test already pins
    /// that half; this pins the popup wiring reaches the identical gate).
    #[test]
    fn commit_approval_inbound_wrong_code_counts_a_try_then_auto_denies_at_max_tries() {
        with_peer_state("commit-approval-inbound-wrong-code", || {
            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap();
            aoide_storage::pairing::park_inbound(
                &"a".repeat(64),
                "box-a",
                "10.0.0.5",
                "http://box-a-is-loopback-only.invalid/",
                &aoide_storage::pairing::derive_commit(&"a".repeat(64), &"c".repeat(32)),
                &aoide_storage::time::now_iso_utc(),
                &aoide_storage::pairing::expires_at_from(now_epoch),
                None,
            )
            .unwrap();
            let id = aoide_storage::pairing::list_inbound(now_epoch)[0].id.clone();
            aoide_storage::pairing::reveal_inbound(&id, &"c".repeat(32), now_epoch).unwrap();

            for expected_tries in 1..=2u32 {
                let pending = reconcile(now_epoch);
                assert_eq!(pending.len(), 1);
                let outcome = commit_approval(&pending[0], "xxx-xxx", now_epoch);
                assert_eq!(outcome.status, aoide_protocol::output::Status::Error, "{outcome:?}");
                assert_eq!(aoide_storage::pairing::list_inbound(now_epoch)[0].tries, expected_tries);
            }

            // The MAX_CODE_TRIESrd wrong code auto-denies: entry removed,
            // nothing committed — the same clean removal `pair reject`
            // performs.
            let pending = reconcile(now_epoch);
            assert_eq!(pending.len(), 1);
            let outcome = commit_approval(&pending[0], "xxx-xxx", now_epoch);
            assert_eq!(outcome.status, aoide_protocol::output::Status::Error, "{outcome:?}");
            assert_eq!(outcome.data.as_ref().and_then(|d| d.get("reason")).and_then(Value::as_str), Some("auto-deny-on-code-mismatch"));
            assert!(aoide_storage::pairing::list_inbound(now_epoch).is_empty(), "auto-denied — the parked entry is removed");
            assert!(aoide_storage::peer_store::load_peers().is_empty(), "nothing was ever committed");
        });
    }

    #[test]
    fn commit_approval_on_an_outbound_entry_writes_the_same_peers_json_the_cli_would() {
        with_peer_state("commit-approval-outbound", || {
            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap();
            aoide_storage::pairing::park_outbound(aoide_storage::pairing::OutboundPairingRequest {
                id: "deadbeef".to_string(),
                url: "http://box-b/".to_string(),
                name: "box-b".to_string(),
                pubkey_hex: "b".repeat(64),
                requester_nonce_hex: "c".repeat(32),
                approver_nonce_hex: "d".repeat(32),
                requested_at: aoide_storage::time::now_iso_utc(),
                expires_at: aoide_storage::pairing::expires_at_from(now_epoch),
                state: aoide_storage::pairing::OutboundState::AwaitingConfirm,
                via: None,
            })
            .unwrap();

            let pending = reconcile(now_epoch);
            assert_eq!(pending.len(), 1);
            assert!(actionable(&pending[0]));

            // The confirm dialog carries no typed value (P-PV3 revert) —
            // `commit_approval` is called with an EMPTY string here on
            // purpose, proving the outbound arm never looks at it.
            let outcome = commit_approval(&pending[0], "", now_epoch);
            assert_eq!(outcome.status, aoide_protocol::output::Status::Ok, "{outcome:?}");

            let peers = aoide_storage::peer_store::load_peers();
            assert_eq!(peers.len(), 1);
            assert_eq!(peers[0].name, "box-b");
            assert_eq!(peers[0].pubkey.as_deref(), Some("b".repeat(64).as_str()));
            assert!(peers[0].verified);
            assert!(aoide_storage::pairing::list_outbound(now_epoch).is_empty(), "the parked entry is taken on commit");
        });
    }

    /// P-PV3 revert (task #132, review round): the outbound arm's `code`
    /// parameter is IGNORED entirely — a confirm dialog has no typed value
    /// to gate on, so approval commits unconditionally regardless of what
    /// string `commit_approval` happens to be called with. This is the
    /// ceremony's ORIGINAL shape, restored: an earlier pass on this same
    /// phase added a `code_matches` comparison here (retyping the
    /// already-shown code), which review correctly called copy-the-pixels
    /// theater — this test pins that the comparison is genuinely gone, not
    /// merely undocumented.
    #[test]
    fn commit_approval_on_an_outbound_entry_commits_regardless_of_the_code_argument() {
        with_peer_state("commit-approval-outbound-unconditional", || {
            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap();
            aoide_storage::pairing::park_outbound(aoide_storage::pairing::OutboundPairingRequest {
                id: "deadbeef".to_string(),
                url: "http://box-b/".to_string(),
                name: "box-b".to_string(),
                pubkey_hex: "b".repeat(64),
                requester_nonce_hex: "c".repeat(32),
                approver_nonce_hex: "d".repeat(32),
                requested_at: aoide_storage::time::now_iso_utc(),
                expires_at: aoide_storage::pairing::expires_at_from(now_epoch),
                state: aoide_storage::pairing::OutboundState::AwaitingConfirm,
                via: None,
            })
            .unwrap();

            let pending = reconcile(now_epoch);
            assert_eq!(pending.len(), 1);
            assert!(actionable(&pending[0]));

            // "xxx-xxx" would have failed the old code_matches comparison —
            // it must commit anyway, proving no comparison runs at all.
            let outcome = commit_approval(&pending[0], "xxx-xxx", now_epoch);
            assert_eq!(outcome.status, aoide_protocol::output::Status::Ok, "{outcome:?}");

            let peers = aoide_storage::peer_store::load_peers();
            assert_eq!(peers.len(), 1);
            assert!(peers[0].verified);
            assert!(aoide_storage::pairing::list_outbound(now_epoch).is_empty(), "the parked entry is taken on commit");
        });
    }

    /// P-PV3 (task #132): a dismissed or cancelled outbound dialog must
    /// never reach `commit_approval` at all — `decide`'s own mapping
    /// (already pinned above) sends `Dismissed`/`Cancelled` to
    /// `PopupDecision::Reject`/`Ignore`, and `popup_tick`'s match only
    /// ever calls `commit_approval` from the `Approve` arm. This test pins
    /// the OUTBOUND storage side of that: neither a reject nor an ignore
    /// touches `peers.json` or takes the parked entry.
    #[test]
    fn an_outbound_entry_is_untouched_by_reject_and_by_a_bare_ignore() {
        with_peer_state("outbound-reject-and-ignore-untouched", || {
            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap();
            aoide_storage::pairing::park_outbound(aoide_storage::pairing::OutboundPairingRequest {
                id: "deadbeef".to_string(),
                url: "http://box-b/".to_string(),
                name: "box-b".to_string(),
                pubkey_hex: "b".repeat(64),
                requester_nonce_hex: "c".repeat(32),
                approver_nonce_hex: "d".repeat(32),
                requested_at: aoide_storage::time::now_iso_utc(),
                expires_at: aoide_storage::pairing::expires_at_from(now_epoch),
                state: aoide_storage::pairing::OutboundState::AwaitingConfirm,
                via: None,
            })
            .unwrap();

            // `Cancelled` (a bare Esc/close) — `decide` sends it to
            // `Ignore`, which never calls `commit_approval` at all.
            assert_eq!(decide(DialogResult::Cancelled, false), PopupDecision::Ignore);
            // `Dismissed` — `decide` sends it to `Reject`, `popup_tick`'s
            // own arm calls `reject_by_id`, never `commit_approval`.
            let out = crate::commands::reject_by_id("pair.reject", "deadbeef");
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");

            assert!(aoide_storage::peer_store::load_peers().is_empty(), "nothing was ever committed");
            assert!(aoide_storage::pairing::list_outbound(now_epoch).is_empty(), "reject aborts the outbound entry outright");
        });
    }
}
