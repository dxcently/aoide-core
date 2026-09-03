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
//! **The popup arm (F6, upgraded first by P-PV3/task #132, then made
//! genuinely mutual by R1): ONE dialog SHAPE, both directions — never a
//! bare yes/no, and never a surface that shows the value it is about to
//! validate.** [`resolve_lyra_bin`] feature-detects `lyra` the SAME
//! three-tier way `aoide_secrets::watch::resolve_lyra_bin` does (env
//! override, `current_exe()` sibling, bare-name-on-`PATH` — duplicated
//! here rather than imported, since neither crate may depend on the other
//! or on `aoide-cli`); when it resolves, the dialog spawns a `lyra pair`
//! subcommand instead of a `zenity` invocation, falling back to zenity on
//! a `lyra` `SpawnError`/`DialogFailure` for that one attempt
//! (`aoide_secrets::watch::run_ask_dialog`'s own fallback shape, reused
//! unchanged: the plugin philosophy's whole point, root `AGENTS.md` house
//! rule 7, is that the fancy surface degrades to the plain one, never that
//! a fancy-surface failure strands the request).
//!
//! **Both directions run [`run_ask_dialog`] — a TYPED-CODE entry surface,
//! never a display.** [`run_ask_dialog`] spawns `lyra pair ask` (the SAME
//! six-boxes-plus-dash surface `lyra secrets ask` renders) or
//! `zenity --entry`, differing only in [`dialog_context`]'s own wording:
//! INBOUND (approver) reads "pairing request from `<name>` ... id <id>"
//! and types the code shown on the REQUESTER's screen; OUTBOUND
//! (requester) reads "type the reply code shown on `<name>`'s screen ...
//! id <id>" and types the reply code shown on the APPROVER's screen — a
//! genuinely different, far surface either way, out-of-band — matching
//! the CLI tty path's own `CodeGate::Prompt` gate byte for byte on BOTH
//! legs: [`commit_approval`] runs `CodeGate::Code(<typed>)` through
//! `approve_inbound`/`approve_outbound` respectively, so the SAME code
//! comparison and [`crate::commands::MAX_CODE_TRIES`] auto-deny/
//! auto-abort machinery the CLI already holds applies identically on
//! either arm. NEITHER dialog ever shows the code it is about to validate
//! — the whole gate is typing a value read from elsewhere; showing it
//! would collapse the out-of-band comparison into a copy exercise, the
//! reasoning `crate::commands::approve_inbound`'s own doc always gave for
//! its tty prompt, now holding unconditionally on both legs rather than
//! only one.
//!
//! **This reverses P-PV3's own outbound CONFIRM dialog — the theater
//! argument that justified it no longer applies (the mutual-code
//! redesign, R1).** This module's own prior doc argued at length that an
//! outbound retype was copy-the-pixels theater, because the code shown
//! then was the PLAIN code — this instance generated it itself
//! (`reconcile`'s own outbound arm) and had already displayed it at
//! request time, so retyping it proved nothing an Approve click didn't
//! already prove. That argument was never about typed entry in general —
//! it named its own boundary: retyping is theater only when the value
//! sits on screen in the SAME window. The REPLY code the outbound
//! operator now types fails that test on purpose — it comes from a
//! genuinely DIFFERENT surface (the approver's own screen, relayed
//! out-of-band), precisely the condition the argument itself named as the
//! one where typed entry has real meaning. `run_confirm_dialog`,
//! `spawn_zenity_confirm`, `spawn_lyra_confirm`, and `dialog_code` (whose
//! only job was showing the plain code on the outbound confirm) are GONE
//! — don't reintroduce a bare-confirm outbound surface without
//! re-deriving why this reversal doesn't apply to whatever prompted it.
//!
//! Three structural rules hold throughout this arm, all provable at the
//! text-builder/argv level rather than by trusting a comment: (1) a feed
//! line is a TRIGGER, never a display source — [`dialog_context`] is built
//! ONLY from a [`Pending`] `reconcile` itself produced, never from a
//! [`PairEvent`]'s fields; (2) NEITHER direction's dialog is ever handed
//! the code it is about to validate — the never-echo-the-expected-value
//! rule holds unconditionally now, not only on the inbound leg; (3) argv
//! carries identifiers and display text only, never a value used to
//! VALIDATE anything on the dialog's own side — [`spawn_zenity_entry`]/
//! [`spawn_lyra_entry`] never receive an expected code to compare against
//! on EITHER leg; both render whatever the operator typed back to the
//! caller for THIS process to compare; (4) nothing is ever executed on
//! this instance's behalf by a dialog's own output — no `sh -c`, no shell
//! interpolation; a hostile `name`/`url` reaches dialog text as inert
//! display text, protected from Pango corruption by `--no-markup` on the
//! zenity path (`aoide_secrets::watch::spawn_zenity_entry`'s own doc has
//! the live-verified reasoning) and from breaking a QML string literal by
//! `dialog_qml::qml_escape` on the lyra path
//! (`crates/lyra/src/commands/dialog_qml.rs`'s own doc).
//!
//! **After a popup-driven INBOUND commit succeeds, the approver's own reply
//! code gets a stay-open display dialog of its own (R2, the mutual-code
//! redesign's popup phase).** [`popup_tick`]'s `Approve` arm reads
//! `replySas` straight off [`commit_approval`]'s outcome data
//! (`approve_inbound`'s own Ok text already carries it, `crate::commands`'
//! own doc) and hands it to [`run_show_dialog`] — `lyra pair show` when
//! [`resolve_lyra_bin`] finds one, `zenity --info --no-markup` otherwise —
//! shown large with a Copy control and a Done control, no reject control at
//! all: the approver's own commit already happened, so there is nothing
//! left here to approve or reject, only to relay out-of-band and dismiss.
//! The SAME commit also fires [`notify_reply_code`] — a `notify-send`
//! toast carrying the same reply code, spawned FIRST and independently of
//! the dialog, so a popup-infra failure (`lyra`/`zenity` both missing)
//! still leaves the code somewhere durable beside the terminal's own
//! `println!`. Never spawned for an outbound commit — that leg's own
//! ceremony is already complete the moment its reply code validates, with
//! nothing further to relay.
//!
//! **No pairing dialog closes on a timer any more (R2).** The old 60s
//! per-dialog timeout and its 30s cooldown existed only to keep a stale
//! dialog from pinning the operator's desktop for a request that stayed
//! perfectly answerable later; both are gone outright, along with the
//! `TimedOut` decision and the cooldown bookkeeping that offered a
//! timed-out id again after a wait. An open dialog — either the typed-code
//! entry [`run_ask_dialog`] or the reply-code display [`run_show_dialog`]
//! — now sits open until the operator answers it, the request it belongs
//! to is resolved elsewhere, a live blocking `aoide pair` claims the same
//! id (the pid-marker arbiter, part 4, unchanged), or Ctrl-C interrupts
//! this process outright ([`should_cancel_dialog`]'s first parameter reads
//! `interrupted`, not a deadline, since nothing else can close a dialog
//! that never times out). **Accepted consequence, stated plainly rather
//! than rediscovered later:** while a dialog sits open, [`popup_tick`]
//! itself is blocked inside it — feed narration queues up and
//! [`poll_pending_outbound`]'s own timer pauses — previously bounded at
//! 60s, now unbounded. On a single-operator desktop, with R3's
//! one-live-request-per-machine rule holding on both the inbound and
//! outbound side, this is one modal question at a time either way, which
//! is the point; the alternative (threading the dialog wait so [`run`]'s
//! loop never blocks on it) buys machinery for a contention this system
//! now structurally avoids. If it ever bites, that's the named escape —
//! not a reason to bring the timer back.

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
/// spawns carries — [`spawn_zenity_entry`] and `lyra pair ask` alike, on
/// BOTH directions now (the mutual-code redesign, R1) — and
/// [`run_entry_dialog`] compares stdout against (F6) — deliberately its
/// OWN string, never
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

/// The dialog CHOICE for EITHER direction now — `lyra pair ask` when
/// [`resolve_lyra_bin`] found one, falling back to `zenity --entry` for the
/// SAME attempt on a `lyra` `SpawnError`/`DialogFailure`
/// (`aoide_secrets::watch::run_ask_dialog`'s own fallback shape, reused
/// unchanged — module doc's popup-arm section). `context` doubles as
/// zenity's own `--text` — neither direction has a second, code-carrying
/// line to append: this is an ENTRY dialog, never a display (structural
/// rule 2, module doc) — the OUTBOUND leg's own reply code, once it
/// exists, gets its own separate display dialog, [`run_show_dialog`].
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

/// The dialog's title — pure (module doc's structural rule 1): built ONLY
/// from a [`Pending`] `reconcile` produced, never from a [`PairEvent`]'s
/// own fields.
fn dialog_title(p: &Pending) -> String {
    format!("aoide \u{b7} pairing with {}", p.name)
}

/// The dialog's CONTEXT line — pure, same sourcing rule as
/// [`dialog_title`]. Never carries a code on EITHER direction (structural
/// rule 2, module doc) — this line is the ONLY thing either entry dialog
/// ever shows, since R1 retired the outbound arm's separate code-display
/// line along with the confirm surface it belonged to. INBOUND names the
/// requester and where the request came from; OUTBOUND (the mutual-code
/// redesign) names what to type and whose screen it's read off, mirroring
/// the inbound wording's own shape rather than a bare "confirm pairing
/// with" that no longer describes what this dialog collects.
fn dialog_context(p: &Pending) -> String {
    match p.direction.as_str() {
        "inbound" => format!("pairing request from `{}` ({}) \u{b7} id {}", p.name, p.origin_addr.as_deref().unwrap_or(""), p.id),
        _ => format!("type the reply code shown on `{}`'s screen \u{b7} id {}", p.name, p.id),
    }
}

// ── the reply-code display dialog (R2) ───────────────────────────────────

/// The show dialog's own CONTEXT line — pure, same sourcing rule as
/// [`dialog_context`], but this one DOES describe a code (never the code
/// itself — that is a separate `--code`/`--text` argument on either spawn
/// path, never interpolated into this line): this dialog fires only after
/// an inbound commit already succeeded, so `p.name` here is the PEER whose
/// operator needs the code relayed back to them, out-of-band.
fn show_context(p: &Pending) -> String {
    format!("read this code back to `{}`'s operator \u{b7} id {}", p.name, p.id)
}

/// The zenity DISPLAY dialog's own argv — `--info --no-markup` (a single
/// acknowledgement control, no typed entry, no extra reject button: zenity
/// has none to give it — module doc's popup-arm section states this
/// fallback gap plainly rather than papering over it with a fake control),
/// the code appended to `--text` since zenity has no separate "large code"
/// element the way the lyra dialog's own QML does.
fn spawn_zenity_show(zenity_cmd: &str, title: &str, context: &str, code: &str) -> std::io::Result<Child> {
    Command::new(zenity_cmd)
        .args(["--info", "--no-markup", "--title", title, "--text", &format!("{context}\n\n{code}")])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
}

/// `lyra pair show`'s own argv — `--id`/`--name`/`--context`/`--code`, the
/// last carrying THIS instance's own locally-derived reply SAS
/// (`commit_approval`'s Ok outcome data, `replySas`) for the dialog to
/// render large and plain with a Copy control (`crates/lyra/src/commands/
/// pair.rs`'s own module doc has the full rundown).
fn spawn_lyra_show(lyra_cmd: &str, id: &str, name: &str, context: &str, code: &str) -> std::io::Result<Child> {
    let mut cmd = Command::new(lyra_cmd);
    cmd.args(["pair", "show", "--id", id, "--name", name, "--context", context, "--code", code]);
    // Same live-incident fix `spawn_lyra_entry`'s own doc gives: `lyra pair
    // show`'s own failure `eprintln!`s land directly in this process's
    // stderr, which the deployed unit routes to the journal.
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn()
}

fn run_zenity_show(zenity_cmd: &str, title: &str, context: &str, code: &str, should_cancel: impl FnMut() -> bool) -> DialogResult {
    // `REJECT_LABEL` is passed only because `run_entry_dialog`'s own
    // signature requires SOME dismiss label to compare a non-zero exit's
    // stdout against — neither this dialog nor its zenity fallback ever
    // offers a control that could print it (no reject control exists at
    // all, module doc), so the comparison never matches in practice; any
    // non-zero exit here reads as a bare `Cancelled`, never `Dismissed`.
    run_entry_dialog(|| spawn_zenity_show(zenity_cmd, title, context, code), REJECT_LABEL, should_cancel)
}

fn run_lyra_show(lyra_cmd: &str, id: &str, name: &str, context: &str, code: &str, should_cancel: impl FnMut() -> bool) -> DialogResult {
    run_entry_dialog(|| spawn_lyra_show(lyra_cmd, id, name, context, code), REJECT_LABEL, should_cancel)
}

/// The display-dialog CHOICE — `lyra pair show` when [`resolve_lyra_bin`]
/// found one, falling back to `zenity --info --no-markup` for the SAME
/// attempt on a `lyra` `SpawnError`/`DialogFailure`, the identical
/// fallback shape [`run_ask_dialog`] already holds for the entry dialog.
/// `should_cancel` is Ctrl-C ONLY (`popup_tick`'s own call site) — this
/// dialog fires strictly after the commit it belongs to already succeeded,
/// so there is no "resolved elsewhere" or marker race left to guard
/// against, unlike the entry dialog's own three-reason `should_cancel`.
fn run_show_dialog(
    lyra_cmd: Option<&str>,
    zenity_cmd: &str,
    id: &str,
    name: &str,
    title: &str,
    context: &str,
    code: &str,
    mut should_cancel: impl FnMut() -> bool,
) -> DialogResult {
    let Some(lyra) = lyra_cmd else {
        return run_zenity_show(zenity_cmd, title, context, code, should_cancel);
    };
    let result = run_lyra_show(lyra, id, name, context, code, &mut should_cancel);
    match &result {
        DialogResult::SpawnError(e) | DialogResult::DialogFailure(e) => {
            eprintln!("aoide pair watch --popup: lyra pair show failed for request {id}: {e} \u{2014} falling back to zenity for this request");
            if zenity_available(zenity_cmd) {
                run_zenity_show(zenity_cmd, title, context, code, should_cancel)
            } else {
                eprintln!(
                    "aoide pair watch --popup: zenity is not available either \u{2014} the reply code for {id} already printed above this line"
                );
                result
            }
        }
        _ => result,
    }
}

/// Spawn the reply-code display dialog for `p` (an INBOUND request whose
/// popup-driven commit just succeeded) and block until it closes — Done,
/// Esc, the native window close, or Ctrl-C are all this dialog's own
/// terminal states (module doc's "no pairing dialog closes on a timer any
/// more" section); a spawn/infra failure is logged, never panics, since
/// the code already reached the operator via [`popup_tick`]'s own
/// `println!` of [`commit_approval`]'s outcome message and
/// [`notify_reply_code`]'s own toast moments earlier.
fn show_reply_code(lyra_cmd: Option<&str>, p: &Pending, code: &str, json_mode: bool) {
    let title = dialog_title(p);
    let context = show_context(p);
    let result = run_show_dialog(lyra_cmd, ZENITY_CMD, &p.id, &p.name, &title, &context, code, || INTERRUPTED.load(Ordering::SeqCst));
    if let DialogResult::SpawnError(e) | DialogResult::DialogFailure(e) = &result {
        if !json_mode {
            eprintln!("  aoide pair watch --popup: could not show the reply code dialog for {} \u{2014} it already printed above: {e}", p.id);
        }
    }
}

/// The reply-code toast's SUMMARY and BODY — pure (module doc's structural
/// rule 1 applies here too: built only from what [`commit_approval`]'s own
/// outcome already handed back, never a feed line), so it is unit-testable
/// with no `notify-send` spawn involved. `name` is the PEER's own display
/// name (peer-supplied, root `AGENTS.md` house rule 4's untrusted-display-
/// data rule) — it lands in the returned strings as plain text and reaches
/// `notify-send` as a single argv element in [`notify_reply_code`], never
/// through a shell, so nothing in it is ever interpreted.
fn reply_notification_text(name: &str, code: &str) -> (String, String) {
    let summary = format!("pairing reply code for {name}");
    let body = format!("{code}\n\nrelay this to {name} \u{2014} they type it into their own pairing prompt to finish");
    (summary, body)
}

/// Toast the reply code through the stock freedesktop client, detached —
/// fired BEFORE and independently of [`show_reply_code`]'s own popup (the
/// User's ask): a popup-infra failure (`lyra`/`zenity` both missing, or a
/// headless session) must still land the code somewhere durable beside the
/// terminal's own `println!`, and the toast is orthogonal machinery the
/// popup path never depends on either way. Same idiom
/// `aoide_conduct::reap::announce_reap` already holds: `notify-send` by
/// BARE NAME (bare-name lookup needs `pkgs.libnotify` on the deployed
/// unit's own `path`, `modules/nucleus/aoided.nix`, the same reason
/// `pkgs.zenity` rides there already), spawned and collected on a detached
/// thread so a slow/hung notifier can never delay the ceremony, and a
/// spawn failure is an `eprintln`, never a panic or a return that blocks
/// anything — the code already reached the operator by the time this
/// could fail. The reply code is this instance's own derived value,
/// already shown openly on stdout and in the popup (CONTRACTS.md §6), so
/// it needs no masking here either.
fn notify_reply_code(name: &str, code: &str, json_mode: bool) {
    let (summary, body) = reply_notification_text(name, code);
    match std::process::Command::new("notify-send").args(["--app-name=aoide", &summary]).arg(&body).spawn() {
        Ok(mut child) => {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
        Err(e) => {
            if !json_mode {
                eprintln!("  aoide pair watch --popup: could not toast the reply code \u{2014} it already printed above: {e}");
            }
        }
    }
}

/// What a finished [`DialogResult`] means for the request it was shown
/// for — pure, the ONE place this arm's mapping (F6) is decided, so it is
/// testable with a synthetic [`DialogResult`] and no real dialog spawn.
/// Takes `result` BY VALUE so [`PopupDecision::Approve`]'s payload moves
/// out with no clone.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PopupDecision {
    /// Exit 0. The `String` is the operator's TYPED code on EITHER arm now
    /// (the mutual-code redesign, R1) — inbound gates it through
    /// `commit_approval`'s `CodeGate::Code` against `derive_sas`, outbound
    /// against `derive_reply_sas` — module doc's popup-arm section has the
    /// full split.
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
    /// `should_cancel` closed an already-open dialog because the request it
    /// belonged to was withdrawn — resolved elsewhere, or claimed by a live
    /// blocking `aoide pair` — while it sat open (R2: no timer exists any
    /// more to close one for any OTHER reason, so `CancelledExternally` now
    /// has exactly this one meaning). Already handled; nothing left to do.
    Noop,
}

/// What a finished dialog round means for the request it was shown for —
/// pure (module doc, and this variant's own doc). `CancelledExternally` is
/// the ONLY way `should_cancel` ever closes a dialog now (R2 deleted the
/// timeout branch that used to race it), so it maps to exactly one
/// [`PopupDecision`] with no second parameter needed to tell causes apart.
fn decide(result: DialogResult) -> PopupDecision {
    match result {
        DialogResult::Approved(code) => PopupDecision::Approve(code),
        DialogResult::Dismissed => PopupDecision::Reject,
        DialogResult::Cancelled => PopupDecision::Ignore,
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

/// Pure: is `p` eligible for a NEW dialog RIGHT NOW? [`actionable`] plus
/// every gate this phase adds beside `ignored` — a LIVE blocking
/// `aoide pair`'s own marker (`marker_live`, task #135 popup-phase spec
/// part 4), pre-resolved and passed in rather than read here, so this is
/// the ONE place [`popup_tick`]'s own candidate selection is decided
/// (module doc's discipline for `decide`/`popup_allowed`) and a synthetic
/// case never needs a real dialog, a real clock, or a real marker file.
fn eligible_for_dialog(p: &Pending, ignored: bool, marker_live: bool) -> bool {
    actionable(p) && !ignored && !marker_live
}

/// Pure: should an ALREADY-OPEN dialog be cancelled RIGHT NOW? The three
/// reasons `should_cancel` ORs together inside [`popup_tick`]'s own
/// closures — this process was INTERRUPTED (Ctrl-C; R2 — with no deadline
/// left to fall back on, an open dialog would otherwise pin [`run`]'s own
/// loop past a shutdown signal forever, since the `INTERRUPTED` check at
/// the top of that loop is unreachable while blocked inside
/// `run_entry_dialog`), the request stopped being actionable (resolved
/// elsewhere), or a LIVE blocking `aoide pair` now holds this id's marker.
/// The third is a review finding (defect 1) on this arm's own first
/// landing: [`eligible_for_dialog`]'s marker gate only ever ran at
/// candidate-SELECTION time, so a dialog already open when the marker
/// appeared sat there, oblivious — racing the SAME commit
/// ([`PairActiveMarker`]'s own doc) the marker exists to prevent, and
/// `peer_store::save_peers` has no cross-process lock of its own
/// (plain load → modify → atomic write), so two concurrent commits are a
/// genuine lost update, not a cosmetic double-dialog. Extracted as its
/// own pure function (rather than left inline in the closures) so this
/// exact condition is provable with three synthetic bools, no real
/// dialog, clock, or marker file required.
fn should_cancel_dialog(interrupted: bool, still_actionable: bool, marker_live: bool) -> bool {
    interrupted || !still_actionable || marker_live
}

/// Pure: should an `Approve` verdict actually commit, or has a live
/// blocking `aoide pair` already claimed this id (defect 1's
/// belt-and-suspenders check, right before [`popup_tick`] would call
/// [`commit_approval`])? Only the OUTBOUND direction can ever race a
/// marker — nothing ever marks an INBOUND id (`PairActiveMarker`'s own
/// doc) — so an inbound `Approve` always commits regardless of
/// `marker_live`.
fn should_commit_approve(direction: &str, marker_live: bool) -> bool {
    direction != "outbound" || !marker_live
}

/// Commit `p`'s pairing on a dialog Approve — looks up ITS FRESH entry by
/// id and direction (never trusts anything cached from an earlier
/// `reconcile` call, the same "re-check before acting" discipline
/// [`actionable`]'s own callers hold). **Both directions run
/// `CodeGate::Code(code)` (the mutual-code redesign, R1) — inbound through
/// `approve_inbound`, outbound through `approve_outbound`** — the SAME code
/// comparison and [`crate::commands::MAX_CODE_TRIES`] auto-deny/auto-abort
/// machinery the CLI tty path already holds, byte-identical on either leg
/// (the old outbound shape, `approve_outbound(true, ...)` ignoring `code`
/// outright, is GONE along with the confirm dialog it belonged to —
/// module doc's popup-arm section has the reversal's own reasoning).
fn commit_approval(p: &Pending, code: &str, now_epoch: i64) -> aoide_protocol::output::Outcome {
    let now = aoide_storage::time::now_iso_utc();
    match p.direction.as_str() {
        "inbound" => match aoide_storage::pairing::list_inbound(now_epoch).into_iter().find(|e| e.id == p.id) {
            Some(entry) => crate::commands::approve_inbound(crate::commands::CodeGate::Code(code.to_string()), "pair", &p.id, entry, &now, now_epoch, None),
            None => aoide_protocol::output::Outcome::error(
                "pair",
                format!("pairing request `{}` is no longer pending — nothing to confirm", p.id),
            ),
        },
        _ => match aoide_storage::pairing::list_outbound(now_epoch).into_iter().find(|e| e.id == p.id) {
            Some(entry) => crate::commands::approve_outbound(crate::commands::CodeGate::Code(code.to_string()), "pair", &p.id, entry, &now, now_epoch, None),
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

/// Outbound-poll backoff floor (review defect 2): after a `Refused`
/// answer, this id is not polled again until at least this long has
/// passed — one whole [`OUTBOUND_POLL_INTERVAL`] BEYOND the normal
/// cadence, so a single failure already skips the very next tick rather
/// than retrying immediately at the next 60s boundary.
const OUTBOUND_POLL_BACKOFF_INITIAL: Duration = OUTBOUND_POLL_INTERVAL;

/// Ceiling [`next_outbound_poll_backoff`] never exceeds — 30 minutes,
/// well inside a pairing request's own 4-hour default expiry
/// (`aoide_storage::pairing::DEFAULT_PAIRING_TIMEOUT_SECS`), so a
/// persistently unreachable peer still gets checked roughly every half
/// hour rather than the ~240 blind round trips a flat 60s cadence would
/// cost over the same window (review defect 2's own arithmetic: 4h / 60s).
const OUTBOUND_POLL_BACKOFF_MAX: Duration = Duration::from_secs(30 * 60);

/// The doubling step for a per-id outbound-poll backoff — [`next_spawn_backoff`]'s
/// own SHAPE (double, then cap), NOT that function itself:
/// `next_spawn_backoff` hardcodes [`SPAWN_BACKOFF_MAX`] (60s), calibrated
/// for the dialog-spawn retry's own ~200ms-poll problem. At THIS poll's
/// own 60s-tick granularity, a 60s ceiling is a no-op — it can never
/// exceed even ONE tick of [`OUTBOUND_POLL_INTERVAL`] — so this reuses the
/// ALGORITHM with its own constants scaled to its own, much coarser,
/// cadence instead of literally calling `next_spawn_backoff`.
fn next_outbound_poll_backoff(current: Duration) -> Duration {
    current.saturating_mul(2).min(OUTBOUND_POLL_BACKOFF_MAX)
}

/// Pure: has this id's own outbound-poll backoff elapsed? Same
/// clock-as-parameter split this file's own pure gates all hold (
/// `reconcile`, `popup_allowed`, [`decide`]) — `elapsed` is `None` when no
/// prior failure is on record for this id (always reads as elapsed,
/// nothing to back off from); `Some` compares directly against `backoff`,
/// this id's own current threshold ([`next_outbound_poll_backoff`]'s own
/// doubling, not a fixed constant).
fn outbound_backoff_elapsed(elapsed: Option<Duration>, backoff: Duration) -> bool {
    elapsed.is_none_or(|e| e >= backoff)
}

/// [`OUTBOUND_POLL_INTERVAL`]'s own tick: poll every outbound entry still
/// `awaiting-approval` (and past its own backoff, if any) once, through
/// [`crate::commands::poll_outbound_once`] — the single seam (module doc,
/// part 3): this never re-implements the wire call or the
/// `awaiting-confirm` state transition, only decides WHEN to trigger it.
///
/// **Review defect 2: a `Refused` answer now backs off, it is never
/// silently retried forever at the flat 60s cadence.** A `Pending` answer
/// is the ORDINARY steady state while waiting (not a failure) and clears
/// any backoff on record — only `Refused` (unreachable, an HTTP error, a
/// malformed reply — `poll_outbound_once`'s own `Refused` arms) engages
/// [`next_outbound_poll_backoff`], the SAME log-once-when-it-starts-
/// failing/reset-on-recovery shape [`popup_tick`]'s own `spawn_backoff`/
/// `spawn_failing` state already holds for repeated dialog-spawn
/// failures, applied per id here since more than one outbound entry can
/// be `awaiting-approval` at once, each with its own independent history.
/// `backoff` is pruned of any id no longer `awaiting-approval` at all —
/// the SAME retain-on-no-longer-pending discipline [`popup_tick`]'s own
/// `ignored` set already holds.
fn poll_pending_outbound(now_epoch: i64, backoff: &mut HashMap<String, (Duration, Instant)>, json_mode: bool) {
    let outbound = aoide_storage::pairing::list_outbound(now_epoch);
    backoff.retain(|id, _| outbound.iter().any(|e| &e.id == id && needs_outbound_poll(e.state)));

    for entry in outbound {
        if !needs_outbound_poll(entry.state) {
            continue;
        }
        let current_backoff = backoff.get(&entry.id).map_or(OUTBOUND_POLL_BACKOFF_INITIAL, |(b, _)| *b);
        let elapsed = backoff.get(&entry.id).map(|(_, failed_at)| failed_at.elapsed());
        if !outbound_backoff_elapsed(elapsed, current_backoff) {
            continue;
        }

        let id = entry.id.clone();
        let name = entry.name.clone();
        match crate::commands::poll_outbound_once("pair.watch", &id, &entry, now_epoch) {
            crate::commands::PollOutcome::Refused(out) => {
                let was_failing = backoff.contains_key(&id);
                let next = if was_failing { next_outbound_poll_backoff(current_backoff) } else { OUTBOUND_POLL_BACKOFF_INITIAL };
                backoff.insert(id.clone(), (next, Instant::now()));
                if !was_failing && !json_mode {
                    eprintln!(
                        "  aoide pair watch --popup: polling `{name}` for pairing request {id} failed ({}) \u{2014} backing off, retrying up to every {}s",
                        out.message,
                        OUTBOUND_POLL_BACKOFF_MAX.as_secs()
                    );
                }
            }
            _ => {
                if backoff.remove(&id).is_some() && !json_mode {
                    println!("  aoide pair watch --popup: polling `{name}` for pairing request {id} is working again \u{2014} backoff cleared");
                }
            }
        }
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
/// (actionable, un-ignored, no LIVE blocking `aoide pair` marker — task
/// #135 popup-phase spec parts 2/4), skip while the screen is locked (F8 —
/// re-offered next tick, never shown behind a lock screen), show its dialog
/// — [`run_ask_dialog`] (typed-code entry), the SAME shape on BOTH
/// directions now (the mutual-code redesign, R1) — and act on [`decide`]'s
/// mapping. No timer bounds the dialog any more (R2, module doc): it sits
/// open until answered, withdrawn, or this process is interrupted.
/// `should_cancel` re-derives [`reconcile`] fresh on every ~200ms poll
/// (`run_entry_dialog`'s own interval) rather than reading a cached queue —
/// this arm's request volume is low enough that the extra
/// `list_inbound`/`list_outbound`/identity-load cost per poll is cheaper
/// than the machinery a shared, mutex-guarded queue would add. The
/// OUTBOUND leg's own network poll (part 3, [`poll_pending_outbound`]) is
/// deliberately NOT here — this function must never make a network call on
/// [`POLL_INTERVAL`]'s own 200ms cadence; [`run`]'s own loop calls it
/// separately, on [`OUTBOUND_POLL_INTERVAL`].
fn popup_tick(ignored: &mut HashSet<String>, spawn_backoff: &mut Duration, spawn_failing: &mut bool, json_mode: bool, lyra_cmd: Option<&str>) {
    let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap_or(0);
    let pending = reconcile(now_epoch);
    ignored.retain(|id| pending.iter().any(|p| &p.id == id));
    let Some(p) = pending.into_iter().find(|p| eligible_for_dialog(p, ignored.contains(&p.id), is_marker_live(&p.id))) else {
        return;
    };

    if !popup_allowed(is_locked(&locker_process_name())) {
        return;
    }

    let title = dialog_title(&p);
    let context = dialog_context(&p);
    let id = p.id.clone();

    // Both directions run the SAME entry dialog now (the mutual-code
    // redesign, R1 — `dialog_context` is the only per-direction thing left
    // to build; module doc's popup-arm section has the reversal). The
    // `should_cancel` closure below is shared for the identical reason: a
    // LIVE blocking `aoide pair` marker can appear at any point while
    // EITHER direction's dialog sits open (defect 1's own fix, preserved)
    // — `PairActiveMarker`'s own doc notes only the outbound blocking leg
    // ever acquires one today, so this reads `false` for an inbound id in
    // practice, but the check runs regardless so this never silently
    // drifts if that ever changes.
    let cancel_id = id.clone();
    let result = run_ask_dialog(lyra_cmd, ZENITY_CMD, &id, &p.name, &title, &context, move || {
        let still_actionable = {
            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap_or(0);
            reconcile(now_epoch).iter().any(|q| q.id == cancel_id && actionable(q))
        };
        should_cancel_dialog(INTERRUPTED.load(Ordering::SeqCst), still_actionable, is_marker_live(&cancel_id))
    });

    if !matches!(result, DialogResult::SpawnError(_) | DialogResult::DialogFailure(_)) && *spawn_failing {
        *spawn_failing = false;
        *spawn_backoff = SPAWN_BACKOFF_INITIAL;
        if !json_mode {
            println!("  aoide pair watch --popup: the dialog is spawning again \u{2014} backoff cleared");
        }
    }

    match decide(result) {
        PopupDecision::Approve(code) => {
            // Belt and suspenders beyond `should_cancel_dialog` (defect 1):
            // an `Approved` exit and a marker becoming live can still land
            // in the SAME ~200ms poll window (`run_entry_dialog` checks
            // `try_wait` BEFORE `should_cancel` — module doc). One more,
            // near-free marker read right before the commit closes that
            // window down from "up to 200ms" to "up to this one check."
            if should_commit_approve(&p.direction, is_marker_live(&p.id)) {
                let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap_or(0);
                let outcome = commit_approval(&p, &code, now_epoch);
                if !json_mode {
                    println!("  {}", outcome.message);
                }
                // After a popup-driven INBOUND commit succeeds, the reply
                // code `approve_inbound`'s own outcome data already carries
                // (`replySas`) gets its own stay-open display dialog (R2) —
                // never for an outbound commit, whose own ceremony is
                // already complete the moment its reply code validates
                // (module doc's "reply-code display dialog" section). The
                // toast fires FIRST and independently of the dialog — a
                // popup-infra failure (`lyra`/`zenity` both missing) must
                // still land the code somewhere durable beside stdout.
                if p.direction == "inbound" && outcome.status == aoide_protocol::output::Status::Ok {
                    if let Some(reply_sas) = outcome.data.as_ref().and_then(|d| d.get("replySas")).and_then(Value::as_str) {
                        notify_reply_code(&p.name, reply_sas, json_mode);
                        show_reply_code(lyra_cmd, &p, reply_sas, json_mode);
                    }
                }
            } else if !json_mode {
                println!(
                    "  pairing request {} is now held by a live blocking `aoide pair` \u{2014} the popup is standing down without committing",
                    p.id
                );
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
        PopupDecision::Noop => {
            // An interrupt closes the dialog too (should_cancel_dialog's first
            // reason) — the loop exits on its own check next tick, and calling
            // that "resolved elsewhere" would misreport a Ctrl-C as far-side
            // activity.
            if !json_mode && !INTERRUPTED.load(Ordering::SeqCst) {
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
    let mut outbound_poll_backoff: HashMap<String, (Duration, Instant)> = HashMap::new();
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
                poll_pending_outbound(now_epoch, &mut outbound_poll_backoff, json_mode);
            }
            popup_tick(&mut ignored, &mut spawn_backoff, &mut spawn_failing, json_mode, lyra_cmd.as_deref());
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
                tries: 0,
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
            .0
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
        assert_eq!(decide(DialogResult::Approved("740-729".to_string())), PopupDecision::Approve("740-729".to_string()));
        assert_eq!(decide(DialogResult::Dismissed), PopupDecision::Reject);
        assert_eq!(decide(DialogResult::Cancelled), PopupDecision::Ignore);
        // The swap-catcher: a spawn failure must back off, and must NEVER
        // read as `Ignore` — `Ignore` would permanently stop offering a
        // request just because the dialog binary glitched once.
        assert_eq!(decide(DialogResult::SpawnError("no such file".to_string())), PopupDecision::Backoff);
        assert_ne!(decide(DialogResult::SpawnError("no such file".to_string())), PopupDecision::Ignore);
        assert_eq!(decide(DialogResult::DialogFailure("exit 3".to_string())), PopupDecision::Backoff);
    }

    /// R2: with the timeout branch gone, `CancelledExternally` has exactly
    /// ONE meaning left — the request was withdrawn (resolved elsewhere, or
    /// claimed by a live blocking `aoide pair`) while the dialog sat open —
    /// so `decide` needs no second parameter to tell causes apart any more.
    #[test]
    fn decide_maps_cancelled_externally_to_noop_unconditionally() {
        assert_eq!(decide(DialogResult::CancelledExternally), PopupDecision::Noop);
        assert_ne!(
            decide(DialogResult::CancelledExternally),
            PopupDecision::Ignore,
            "a withdrawn request must never be indistinguishable from an explicit Cancel/Dismiss"
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

    // ── eligible_for_dialog (part 4's own gate; R2 dropped the cooldown one) ─

    #[test]
    fn eligible_for_dialog_requires_actionable_and_every_new_gate_clear() {
        let p = fixture_pending("outbound", Some("111-222"));
        assert!(eligible_for_dialog(&p, false, false), "actionable, unignored, unmarked — eligible");
        assert!(!eligible_for_dialog(&p, true, false), "explicitly ignored");
        assert!(!eligible_for_dialog(&p, false, true), "a live marker suppresses regardless of every other gate");

        // The inbound fixture's own `state` is never `awaiting-approval`
        // (`fixture_pending`'s own shape) — never actionable, so every
        // other gate being wide open must not matter.
        let never_actionable = fixture_pending("inbound", Some("111-222"));
        assert!(!eligible_for_dialog(&never_actionable, false, false));
    }

    // ── should_cancel_dialog / should_commit_approve (review defect 1:
    // ── the marker must retract an ALREADY-OPEN dialog, not just gate
    // ── candidate selection) ────────────────────────────────────────────

    #[test]
    fn should_cancel_dialog_fires_on_interrupt_resolution_or_a_live_marker() {
        assert!(!should_cancel_dialog(false, true, false), "nothing has changed yet — keep the dialog open");
        assert!(should_cancel_dialog(true, true, false), "Ctrl-C interrupted this process (R2 — no deadline left to fall back on)");
        assert!(should_cancel_dialog(false, false, false), "resolved elsewhere");
        // The defect-1 fix itself: a marker going live while the dialog is
        // open must retract it even though NEITHER interruption NOR
        // actionability changed — before this fix, an already-open dialog
        // had no way to learn a blocking `aoide pair` had claimed the SAME
        // id and would sit open, racing it, for as long as the operator
        // left it unanswered.
        assert!(should_cancel_dialog(false, true, true), "a live marker must retract an already-open dialog");
    }

    #[test]
    fn should_commit_approve_only_a_live_marker_on_the_outbound_leg_ever_blocks_it() {
        assert!(should_commit_approve("outbound", false), "no marker — commit as usual");
        assert!(!should_commit_approve("outbound", true), "a live marker on the OUTBOUND leg must stand down, never double-commit");
        // No production writer ever marks an inbound id — the inbound leg
        // always commits regardless of what `marker_live` happens to read.
        assert!(should_commit_approve("inbound", true));
        assert!(should_commit_approve("inbound", false));
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
                tries: 0,
            })
            .unwrap();

            let mut backoff = HashMap::new();
            poll_pending_outbound(now_epoch, &mut backoff, false);

            let listed = aoide_storage::pairing::list_outbound(now_epoch);
            assert_eq!(listed.len(), 1);
            assert_eq!(listed[0].state, aoide_storage::pairing::OutboundState::AwaitingConfirm, "the ONLY way this ever advances without a live wait_and_commit loop");
            let pending = reconcile(now_epoch);
            assert!(actionable(&pending.into_iter().find(|p| p.id == "deadbeef").unwrap()), "now the outbound confirm dialog has something to fire on");
            assert!(backoff.is_empty(), "a successful poll must never leave backoff state behind");
        });
    }

    // ── outbound-poll backoff (review defect 2) ───────────────────────────

    #[test]
    fn next_outbound_poll_backoff_doubles_from_the_floor_and_caps() {
        assert_eq!(next_outbound_poll_backoff(OUTBOUND_POLL_BACKOFF_INITIAL), OUTBOUND_POLL_BACKOFF_INITIAL * 2);
        assert_eq!(next_outbound_poll_backoff(OUTBOUND_POLL_BACKOFF_MAX), OUTBOUND_POLL_BACKOFF_MAX, "never exceeds the ceiling");
        assert_eq!(next_outbound_poll_backoff(OUTBOUND_POLL_BACKOFF_MAX / 2 + Duration::from_secs(1)), OUTBOUND_POLL_BACKOFF_MAX, "a doubling that would overshoot clamps to the ceiling, never wraps");
    }

    #[test]
    fn outbound_backoff_elapsed_gates_on_the_boundary_inclusive() {
        assert!(outbound_backoff_elapsed(None, OUTBOUND_POLL_BACKOFF_INITIAL), "no prior failure — nothing to back off from");
        assert!(!outbound_backoff_elapsed(Some(OUTBOUND_POLL_BACKOFF_INITIAL - Duration::from_secs(1)), OUTBOUND_POLL_BACKOFF_INITIAL));
        assert!(outbound_backoff_elapsed(Some(OUTBOUND_POLL_BACKOFF_INITIAL), OUTBOUND_POLL_BACKOFF_INITIAL), "the boundary itself has elapsed");
    }

    /// The defect-2 fix, end to end: a `Refused` answer (nothing listening
    /// on this port) must NOT be retried on the very next call —
    /// [`poll_pending_outbound`] discarding the outcome and gating only on
    /// `AwaitingApproval` (the ORIGINAL shape) would hit this same
    /// unreachable port again immediately; the fix must record a backoff
    /// that suppresses that immediate re-poll.
    #[test]
    fn poll_pending_outbound_backs_off_after_a_refused_answer_instead_of_retrying_immediately() {
        with_peer_state("poll-pending-outbound-backoff", || {
            let pubkey_b = "b".repeat(64);
            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap();
            // Port 1 on loopback: nothing listens, so the poll fails fast
            // with a `Refused` (`poll-unreachable`) every single call —
            // this test is not exercising a lucky race, EVERY attempt fails.
            aoide_storage::pairing::park_outbound(aoide_storage::pairing::OutboundPairingRequest {
                id: "deadbeef".to_string(),
                url: "http://127.0.0.1:1/".to_string(),
                name: "box-b".to_string(),
                pubkey_hex: pubkey_b,
                requester_nonce_hex: "c".repeat(32),
                approver_nonce_hex: "d".repeat(32),
                requested_at: aoide_storage::time::now_iso_utc(),
                expires_at: aoide_storage::pairing::expires_at_from(now_epoch),
                state: aoide_storage::pairing::OutboundState::AwaitingApproval,
                via: None,
                tries: 0,
            })
            .unwrap();

            let mut backoff = HashMap::new();
            poll_pending_outbound(now_epoch, &mut backoff, true);
            assert_eq!(backoff.get("deadbeef").map(|(b, _)| *b), Some(OUTBOUND_POLL_BACKOFF_INITIAL), "the FIRST refusal records the floor backoff");

            // Called again immediately (same tick, `Instant::now()` barely
            // moved) — WITHOUT the fix, this would poll port 1 again; WITH
            // it, `outbound_backoff_elapsed` refuses because no real time
            // has passed. Provable without a real sleep: doubling never
            // happens on an id that was correctly skipped this round.
            poll_pending_outbound(now_epoch, &mut backoff, true);
            assert_eq!(
                backoff.get("deadbeef").map(|(b, _)| *b),
                Some(OUTBOUND_POLL_BACKOFF_INITIAL),
                "an immediate re-call must be suppressed by the still-fresh backoff, never re-attempted (which would have doubled it)"
            );
        });
    }

    #[test]
    fn poll_pending_outbound_clears_backoff_once_a_poll_stops_being_refused() {
        with_peer_state("poll-pending-outbound-backoff-clears", || {
            let pubkey_b = "b".repeat(64);
            let body = r#"{"jsonrpc":"2.0","id":1,"result":{"status":"pending"}}"#;
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
                tries: 0,
            })
            .unwrap();

            // Seed a pre-existing backoff as if an earlier tick had already
            // failed, but far enough in the past that it has elapsed.
            let mut backoff = HashMap::new();
            backoff.insert("deadbeef".to_string(), (OUTBOUND_POLL_BACKOFF_INITIAL, Instant::now() - OUTBOUND_POLL_BACKOFF_INITIAL));

            poll_pending_outbound(now_epoch, &mut backoff, true);

            assert!(backoff.is_empty(), "a `Pending` (ordinary, non-failure) answer must clear the backoff entirely, not just leave it un-doubled");
        });
    }

    // ── the pid-marker arbiter (part 4) ───────────────────────────────────

    fn with_temp_marker_runtime_dir<T>(tag: &str, f: impl FnOnce() -> T) -> T {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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

        let title = dialog_title(&p);
        let text = dialog_context(&p);
        assert!(title.contains(&p.name), "{title}");
        assert!(text.contains(&p.name), "{text}");
        assert!(text.contains(p.origin_addr.as_deref().unwrap()), "{text}");
        assert!(!text.contains("555-666"), "the inbound context must never carry the SAS: {text}");
    }

    #[test]
    fn dialog_context_outbound_carries_no_origin_addr_field_or_the_code() {
        let p = fixture_pending("outbound", Some("777-888"));
        let text = dialog_context(&p);
        // An outbound entry has no connecting-peer address of its own
        // (`Pending::origin_addr`'s own doc) — an "origin:"-shaped
        // substring must never appear for one, and (R1) the outbound
        // dialog is now an entry surface too — it must never carry the
        // code it's about to validate, the same rule the inbound context
        // always held.
        assert!(!text.contains("origin"), "{text}");
        assert!(!text.contains("777-888"), "the outbound dialog must never show the code it is about to validate: {text}");
        assert!(text.contains("reply code"), "the outbound context names what it collects: {text}");
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

    // ── show_context / run_show_dialog (R2) ────────────────────────────────

    #[test]
    fn show_context_names_the_recipient_and_never_carries_the_code() {
        let p = fixture_pending("inbound", Some("222-333"));
        let text = show_context(&p);
        assert!(text.contains(&p.name), "{text}");
        assert!(text.contains(&p.id), "{text}");
        assert!(!text.contains("222-333"), "the context line must never carry the code itself: {text}");
    }

    // ── reply_notification_text (the reply-code toast) ─────────────────────

    #[test]
    fn reply_notification_text_names_the_peer_and_the_code_prominently() {
        let (summary, body) = reply_notification_text("box-a", "222-333");
        assert!(summary.contains("box-a"), "{summary}");
        assert!(summary.to_lowercase().contains("pairing"), "{summary}");
        assert!(body.starts_with("222-333"), "the code should lead the body: {body}");
        assert!(body.contains("box-a"), "{body}");
    }

    #[test]
    fn reply_notification_text_survives_a_hostile_peer_name_as_plain_data() {
        // Same discipline as `dialog_context_and_title_survive_hostile_name_
        // intact_and_never_carry_the_sas`: the builder never escapes or
        // truncates a hostile name — it just formats what it was given.
        // Safety here comes from argv (each `.args`/`.arg` element reaches
        // `execve` as one opaque string, never a shell), not from this
        // function stripping anything.
        let hostile = "box-<b>evil</b>-&-$(rm -rf ~)-`whoami`";
        let (summary, body) = reply_notification_text(hostile, "999-000");
        assert!(summary.contains(hostile), "{summary}");
        assert!(body.contains(hostile), "{body}");
        assert!(body.starts_with("999-000"), "{body}");

        // A `--`-leading name must never make an argv element that
        // `notify-send` could read as a FLAG: both elements are
        // literal-prefixed, so the fixed text always leads. Guards against a
        // future edit that drops the prefix down to a bare `{name}`.
        let dashed = "--icon=/etc/shadow";
        let (dsum, dbody) = reply_notification_text(dashed, "111-222");
        assert!(!dsum.starts_with("--"), "summary must not start with a flag: {dsum}");
        assert!(!dbody.starts_with("--"), "body must not start with a flag: {dbody}");
    }

    #[test]
    fn run_show_dialog_prefers_lyra_when_a_bin_resolves() {
        let _guard = shim_lock();
        let lyra_shim = write_shim("show-lyra-ok", "#!/bin/sh\nexit 0\n");
        let zenity_shim = write_shim("show-zenity-unused", "#!/bin/sh\nexit 1\n");
        let result = run_show_dialog(Some(lyra_shim.to_str().unwrap()), zenity_shim.to_str().unwrap(), "id1", "box-b", "t", "ctx", "111-222", || false);
        assert!(matches!(result, DialogResult::Approved(_)), "lyra's own exit must win when it resolves: {result:?}");
        remove_shim(&lyra_shim);
        remove_shim(&zenity_shim);
    }

    #[test]
    fn run_show_dialog_falls_back_to_zenity_on_a_lyra_spawn_error() {
        let _guard = shim_lock();
        let zenity_shim = write_shim("show-zenity-fallback", "#!/bin/sh\nexit 0\n");
        let result = run_show_dialog(
            Some("/no/such/aoide-pair-show-lyra-shim-never-exists"),
            zenity_shim.to_str().unwrap(),
            "id1",
            "box-b",
            "t",
            "ctx",
            "111-222",
            || false,
        );
        assert!(matches!(result, DialogResult::Approved(_)), "a lyra spawn failure must fall back to zenity for the SAME attempt: {result:?}");
        remove_shim(&zenity_shim);
    }

    #[test]
    fn run_show_dialog_with_no_lyra_bin_goes_straight_to_zenity() {
        let _guard = shim_lock();
        let zenity_shim = write_shim("show-zenity-only", "#!/bin/sh\nexit 0\n");
        let result = run_show_dialog(None, zenity_shim.to_str().unwrap(), "id1", "box-b", "t", "ctx", "111-222", || false);
        assert!(matches!(result, DialogResult::Approved(_)), "{result:?}");
        remove_shim(&zenity_shim);
    }

    #[test]
    fn run_show_dialog_cancels_on_interrupt_with_no_deadline_involved() {
        // R2's own point: there is no timer left to race — `should_cancel`
        // returning `true` here can only mean Ctrl-C, and a dialog that
        // never exits on its own must still be killed and reported as
        // `CancelledExternally`, never left hanging.
        let _guard = shim_lock();
        // Busy-loop via the `:` builtin, never an external `sleep` (this
        // file's own `write_shim` doc: the nix build sandbox provides no
        // interpreter but `/bin/sh` and none of its own external commands).
        let lyra_shim = write_shim("show-hangs", "#!/bin/sh\nwhile :; do :; done\n");
        let result = run_show_dialog(Some(lyra_shim.to_str().unwrap()), ZENITY_CMD, "id1", "box-b", "t", "ctx", "111-222", || true);
        assert!(matches!(result, DialogResult::CancelledExternally), "expected CancelledExternally, got {result:?}");
        remove_shim(&lyra_shim);
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
    /// `CodeGate::Code` — a wrong typed code must count a persisted try
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

    /// The expected reply code an outbound entry built inline by these
    /// tests gates its final commit on — `derive_reply_sas` from THIS
    /// process's own freshly-minted identity (`with_peer_state`'s
    /// sandboxed `AOIDE_STATE_DIR`) plus the fixture's own transcript
    /// fields, the exact computation `commit_outbound` itself performs
    /// (`commands.rs`'s own `expected_reply_sas` test helper, mirrored
    /// here since `pair_watch`'s test module has no access to a private
    /// helper defined in a sibling module).
    fn expected_reply_sas(pubkey_b: &str) -> String {
        let (kp, _) = aoide_storage::identity::load_or_mint().unwrap();
        aoide_storage::pairing::derive_reply_sas(&kp.info().pubkey_hex, pubkey_b, &"c".repeat(32), &"d".repeat(32))
    }

    #[test]
    fn commit_approval_on_an_outbound_entry_writes_the_same_peers_json_the_cli_would() {
        with_peer_state("commit-approval-outbound", || {
            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap();
            let pubkey_b = "b".repeat(64);
            aoide_storage::pairing::park_outbound(aoide_storage::pairing::OutboundPairingRequest {
                id: "deadbeef".to_string(),
                url: "http://box-b/".to_string(),
                name: "box-b".to_string(),
                pubkey_hex: pubkey_b.clone(),
                requester_nonce_hex: "c".repeat(32),
                approver_nonce_hex: "d".repeat(32),
                requested_at: aoide_storage::time::now_iso_utc(),
                expires_at: aoide_storage::pairing::expires_at_from(now_epoch),
                state: aoide_storage::pairing::OutboundState::AwaitingConfirm,
                via: None,
                tries: 0,
            })
            .unwrap();

            let pending = reconcile(now_epoch);
            assert_eq!(pending.len(), 1);
            assert!(actionable(&pending[0]));

            // The mutual-code redesign (R1): the outbound arm's dialog
            // collects a TYPED reply code now, gated the same way the
            // inbound arm's always been — the correct code, not an empty
            // string, is what commits.
            let outcome = commit_approval(&pending[0], &expected_reply_sas(&pubkey_b), now_epoch);
            assert_eq!(outcome.status, aoide_protocol::output::Status::Ok, "{outcome:?}");

            let peers = aoide_storage::peer_store::load_peers();
            assert_eq!(peers.len(), 1);
            assert_eq!(peers[0].name, "box-b");
            assert_eq!(peers[0].pubkey.as_deref(), Some("b".repeat(64).as_str()));
            assert!(peers[0].verified);
            assert!(aoide_storage::pairing::list_outbound(now_epoch).is_empty(), "the parked entry is taken on commit");
        });
    }

    /// The mutual-code redesign (R1): the outbound arm's `code` parameter
    /// is now gated exactly the way the inbound arm's always been — a
    /// WRONG reply code must count a persisted try and must NOT commit,
    /// mirroring `commit_approval_inbound_wrong_code_counts_a_try_then_
    /// auto_denies_at_max_tries` on the other leg. (The P-PV3 confirm
    /// dialog this test once pinned as unconditional is gone along with
    /// the shape it belonged to — module doc's popup-arm section has the
    /// reversal's own reasoning.)
    #[test]
    fn commit_approval_on_an_outbound_entry_with_a_wrong_code_counts_a_try_and_does_not_commit() {
        with_peer_state("commit-approval-outbound-wrong-code", || {
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
                tries: 0,
            })
            .unwrap();

            let pending = reconcile(now_epoch);
            assert_eq!(pending.len(), 1);
            assert!(actionable(&pending[0]));

            let outcome = commit_approval(&pending[0], "xxx-xxx", now_epoch);
            assert_eq!(outcome.status, aoide_protocol::output::Status::Error, "{outcome:?}");
            assert_eq!(aoide_storage::pairing::list_outbound(now_epoch)[0].tries, 1);
            assert!(aoide_storage::peer_store::load_peers().is_empty(), "nothing was ever committed on a wrong code");
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
                tries: 0,
            })
            .unwrap();

            // `Cancelled` (a bare Esc/close) — `decide` sends it to
            // `Ignore`, which never calls `commit_approval` at all.
            assert_eq!(decide(DialogResult::Cancelled), PopupDecision::Ignore);
            // `Dismissed` — `decide` sends it to `Reject`, `popup_tick`'s
            // own arm calls `reject_by_id`, never `commit_approval`.
            let out = crate::commands::reject_by_id("pair.reject", "deadbeef");
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");

            assert!(aoide_storage::peer_store::load_peers().is_empty(), "nothing was ever committed");
            assert!(aoide_storage::pairing::list_outbound(now_epoch).is_empty(), "reject aborts the outbound entry outright");
        });
    }
}
