//! `aoide peer pair watch` (P-P5): a foreground, line-mode follow of
//! `aoided`'s own events feed for the THREE pairing-ceremony milestones
//! `aoide_server::a2a::emit_pairing_event` writes (`pair-parked`/
//! `pair-revealed`/`pair-awaiting-confirm`, `class: "gate"`,
//! `source: "a2a-door"`, CONTRACTS.md §6's "Pairing events feed"
//! subsection) — the SAME tail/reconcile/narrate shape
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
//! arg order `handle_peer_pair_pending`
//! (`aoide_client::commands`) already uses for each direction. A missed
//! or malformed line never strands a request: [`run`]'s 30s reconcile
//! safety tick re-derives the actionable set from scratch on the same
//! cadence `aoide_secrets::watch::Queue::reconcile` already holds.
//!
//! `--popup` is REFUSED up front when `zenity` isn't installed, the same
//! "refuse before ever entering popup mode" gate `aoide_secrets::watch::run`
//! already holds for its own two dialog binaries. `--popup`+`--json`
//! together is refused one layer up, by `handle_peer_pair_watch`
//! (`aoide_client::commands`) — the same split `aoide_secrets::commands::
//! handle_secrets_watch`/`aoide_server::commands::handle_events_tail`
//! already hold between "gate the door and the flag combo" (the
//! dispatched handler) and "run the blocking loop" (this module,
//! special-cased in `cli`'s own `run_cli`).
//!
//! **The popup arm (F6): zenity `--question` ONLY** — `spawn_pair_confirm`'s
//! argv, never a `lyra` fallback the way `aoide_secrets::watch`'s own entry
//! dialog holds one; a QML confirm dialog is a named deferral, not built
//! here. Four structural rules hold throughout this arm, all provable at
//! the text-builder/argv level rather than by trusting a comment:
//! (1) a feed line is a TRIGGER, never a display source — [`confirm_text`]
//! is built ONLY from a [`Pending`] `reconcile` itself produced, never from
//! a [`PairEvent`]'s fields; (2) the SAS never crosses a socket, feed, or
//! argv — [`reconcile`] derives it in-process and [`confirm_text`] embeds
//! the resulting `String` directly into `--text`, the same way it already
//! reaches a terminal via `peer pair pending`; (3) argv carries identifiers
//! and display text only — [`spawn_pair_confirm`] never receives a code to
//! type back; (4) nothing is ever executed on this instance's behalf by a
//! dialog's own output — no `sh -c`, no shell interpolation; a hostile
//! `name`/`url` reaches `--text` as inert display text, protected from
//! Pango corruption by `--no-markup` alone (`aoide_secrets::watch::
//! spawn_zenity_entry`'s own doc has the live-verified reasoning).

use aoide_protocol::dialog::{is_locked, locker_process_name, next_spawn_backoff, run_entry_dialog, zenity_available, DialogResult, SPAWN_BACKOFF_INITIAL, SPAWN_BACKOFF_MAX};
use aoide_protocol::feed::Follower;
use serde_json::{json, Value};
use std::collections::HashSet;
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

/// The default `zenity` binary name `run` checks for before ever entering
/// `--popup` mode, and [`spawn_pair_confirm`]'s own default target —
/// `aoide_secrets::watch::ZENITY_CMD`'s exact shape, re-declared here
/// rather than imported (a `&str` constant carries no "no cross-crate
/// copying" weight the way a moved TYPE or FUNCTION does, and
/// `aoide-client` has no reason to depend on `aoide-secrets` for one
/// literal). Passed as a PARAMETER everywhere it matters (never a bare
/// `Command::new("zenity")` inline) so a test can point at a shim path
/// with no `PATH` mutation, the same discipline `aoide_secrets::watch`
/// already holds for its own `zenity_cmd` parameters.
pub(crate) const ZENITY_CMD: &str = "zenity";

/// The `--extra-button` label [`spawn_pair_confirm`]'s dialog carries and
/// [`run_entry_dialog`] compares stdout against (F6) — deliberately its
/// OWN string, never `aoide_protocol::dialog::DISMISS_LABEL`: two
/// different ceremonies, two different labels, sharing only the reader
/// (`run_entry_dialog`'s own doc on `dismiss_label`).
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
    /// `pair-awaiting-confirm`: an outbound request's peer just approved
    /// it — this instance's own operator can now confirm
    /// (`aoide_storage::pairing::mark_outbound_awaiting_confirm`'s own Ok
    /// arm).
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
            format!("  {}  revealed    pairing request {id} from `{name}` \u{2014} run `aoide peer pair pending` for its code", hms(*ts))
        }
        PairEvent::AwaitingConfirm { id, name, ts } => {
            format!("  {}  approved    `{name}` approved pairing {id} \u{2014} confirm with `aoide peer pair approve {id}`", hms(*ts))
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
/// `aoide_storage::pairing::OutboundPairingRequest`); `state` is `Some`
/// only for an outbound entry (`OutboundState::as_str()`, `"awaiting-
/// approval"`/`"awaiting-confirm"`) — [`actionable`] is the one place
/// that reads it. `sas` is `None` for an inbound entry that hasn't been
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
/// `handle_peer_pair_pending` (`aoide_client::commands`) already uses per
/// direction (inbound: `(entry.pubkeyHex, own_pubkey, requester_nonce,
/// entry.approverNonceHex)`; outbound: `(own_pubkey, entry.pubkeyHex,
/// requester_nonce, approver_nonce)`) — a swap here would silently derive
/// a DIFFERENT code than `peer pair pending`/`approve` show, which is
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
            state: None,
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

/// Is `p` actionable RIGHT NOW — worth a `peer pair approve`, or (with
/// `--popup`) a confirm dialog? An inbound entry only once it carries a
/// SAS (unrevealed means nothing to confirm yet, `approve_inbound`'s own
/// `awaiting-reveal` refusal); an outbound entry only once it reached
/// `awaiting-confirm` (`awaiting-approval` means the PEER hasn't approved
/// yet — nothing on THIS end to confirm, `approve_outbound`'s own
/// refusal).
pub fn actionable(p: &Pending) -> bool {
    match p.direction.as_str() {
        "inbound" => p.sas.is_some(),
        "outbound" => p.state.as_deref() == Some("awaiting-confirm"),
        _ => false,
    }
}

// ── the popup arm (F6) ────────────────────────────────────────────────────

/// The confirm dialog's own argv (F6): `--question` (not `--entry` — this
/// ceremony confirms a code already DERIVED and shown, it never collects
/// one typed back), `--no-markup` LOAD-BEARING for the identical reason
/// `aoide_secrets::watch::spawn_zenity_entry`'s own doc gives (a bare `&`
/// in a peer's `url` is a Pango entity-reference prefix and can corrupt
/// the render, or worse, without it), `--ok-label`/`--cancel-label` name
/// the two ordinary buttons, `--extra-button` [`REJECT_LABEL`] is the
/// third choice `run_entry_dialog` reads back off stdout. `zenity_cmd` is
/// a parameter (never `Command::new("zenity")` inline) so a test can
/// stand in a shim with no `PATH` mutation.
fn spawn_pair_confirm(zenity_cmd: &str, title: &str, text: &str) -> std::io::Result<Child> {
    Command::new(zenity_cmd)
        .args([
            "--question",
            "--no-markup",
            "--title",
            title,
            "--text",
            text,
            "--ok-label",
            "Approve",
            "--cancel-label",
            "Ignore",
            "--extra-button",
            REJECT_LABEL,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
}

/// Run one confirm dialog to completion via the shared
/// [`run_entry_dialog`] loop, comparing stdout against [`REJECT_LABEL`]
/// (never `aoide_protocol::dialog::DISMISS_LABEL` — `REJECT_LABEL`'s own
/// doc).
fn confirm_dialog(zenity_cmd: &str, title: &str, text: &str, should_cancel: impl FnMut() -> bool) -> DialogResult {
    run_entry_dialog(|| spawn_pair_confirm(zenity_cmd, title, text), REJECT_LABEL, should_cancel)
}

/// The dialog's title — pure, no more than `peer pair pending` already
/// shows (module doc's structural rule 1): built ONLY from a [`Pending`]
/// `reconcile` produced, never from a [`PairEvent`]'s own fields.
fn confirm_title(p: &Pending) -> String {
    format!("aoide \u{b7} pairing with {}", p.name)
}

/// The dialog's body — pure, same sourcing rule as [`confirm_title`]. The
/// SAS embeds directly (structural rule 2: it never crossed a socket,
/// feed, or argv to get here — [`reconcile`] derived it in-process, this
/// function only formats the `String` it already produced) — no more
/// context than `peer pair pending`'s own row already shows for the same
/// direction, and no fingerprint (`identity::fingerprint` is private; a
/// CLI-first change would need to land before any dialog can show one).
fn confirm_text(p: &Pending) -> String {
    let sas = p.sas.as_deref().unwrap_or("");
    match p.direction.as_str() {
        "inbound" => format!(
            "approve pairing with `{}`?\norigin: {}\nurl: {}\ncode: {sas}",
            p.name,
            p.origin_addr.as_deref().unwrap_or(""),
            p.url,
        ),
        _ => format!("confirm pairing with `{}`?\nurl: {}\ncode: {sas}", p.name, p.url),
    }
}

/// What a finished [`DialogResult`] means for the request it was shown
/// for — pure, the ONE place this arm's mapping (F6) is decided, so it is
/// testable with a synthetic [`DialogResult`] and no real dialog spawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PopupDecision {
    /// Exit 0 — commit the pairing (`approve_inbound`/`approve_outbound`,
    /// `skip_confirm: true` — the dialog itself already IS the
    /// confirmation).
    Approve,
    /// Exit 1, stdout was [`REJECT_LABEL`] — `reject_by_id`.
    Reject,
    /// Exit 1, empty stdout — a bare Cancel/Escape/window-close. Session-
    /// only: added to the caller's own `ignored` set, never touches
    /// storage.
    Ignore,
    /// The dialog could not run at all, or the (unreachable in practice
    /// for a zenity-only dialog — `LYRA_INFRA_FAILURE_EXIT`'s own doc)
    /// infra-failure exit landed. Back off the retry cadence; NEVER
    /// `Ignore` — a broken dialog binary must not silently stop offering
    /// a request just because it failed to show once.
    Backoff,
    /// The request resolved elsewhere while the dialog sat open
    /// (`should_cancel` fired) — already handled, nothing left to do.
    Noop,
}

fn decide(result: &DialogResult) -> PopupDecision {
    match result {
        DialogResult::Approved(_) => PopupDecision::Approve,
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

/// Commit `p`'s pairing with `skip_confirm: true` — looks up ITS FRESH
/// entry by id and direction (never trusts anything cached from an
/// earlier `reconcile` call, the same "re-check before acting" discipline
/// [`actionable`]'s own callers hold) and calls the SAME
/// `approve_inbound`/`approve_outbound` the CLI's `peer pair approve
/// --yes` path calls — an approved dialog commits the byte-identical
/// `peers.json` write a scripted CLI approval would, because it is
/// LITERALLY the same function, not a reimplementation.
fn commit_approval(p: &Pending, now_epoch: i64) -> aoide_protocol::output::Outcome {
    let now = aoide_storage::time::now_iso_utc();
    match p.direction.as_str() {
        "inbound" => match aoide_storage::pairing::list_inbound(now_epoch).into_iter().find(|e| e.id == p.id) {
            Some(entry) => crate::commands::approve_inbound(true, "peer.pair.approve", &p.id, entry, &now, now_epoch),
            None => aoide_protocol::output::Outcome::error(
                "peer.pair.approve",
                format!("pairing request `{}` is no longer pending — nothing to confirm", p.id),
            ),
        },
        _ => match aoide_storage::pairing::list_outbound(now_epoch).into_iter().find(|e| e.id == p.id) {
            Some(entry) => crate::commands::approve_outbound(true, "peer.pair.approve", &p.id, entry, &now, now_epoch),
            None => aoide_protocol::output::Outcome::error(
                "peer.pair.approve",
                format!("pairing request `{}` is no longer pending — nothing to confirm", p.id),
            ),
        },
    }
}

/// One popup iteration: pick the next un-ignored actionable [`Pending`],
/// skip while the screen is locked (F8 — re-offered next tick, never
/// shown behind a lock screen), show its confirm dialog, and act on
/// [`decide`]'s mapping. `should_cancel` re-derives [`reconcile`] fresh on
/// every ~200ms poll (`run_entry_dialog`'s own interval) rather than
/// reading a cached queue — this arm's request volume is low enough that
/// the extra `list_inbound`/`list_outbound`/identity-load cost per poll
/// is cheaper than the machinery a shared, mutex-guarded queue would add.
fn popup_tick(ignored: &mut HashSet<String>, spawn_backoff: &mut Duration, spawn_failing: &mut bool, json_mode: bool) {
    let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap_or(0);
    let pending = reconcile(now_epoch);
    ignored.retain(|id| pending.iter().any(|p| &p.id == id));
    let Some(p) = pending.into_iter().find(|p| actionable(p) && !ignored.contains(&p.id)) else {
        return;
    };

    if !popup_allowed(is_locked(&locker_process_name())) {
        return;
    }

    let title = confirm_title(&p);
    let text = confirm_text(&p);
    let id = p.id.clone();
    let result = confirm_dialog(ZENITY_CMD, &title, &text, || {
        let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap_or(0);
        !reconcile(now_epoch).iter().any(|q| q.id == id && actionable(q))
    });

    if !matches!(result, DialogResult::SpawnError(_) | DialogResult::DialogFailure(_)) && *spawn_failing {
        *spawn_failing = false;
        *spawn_backoff = SPAWN_BACKOFF_INITIAL;
        if !json_mode {
            println!("  aoide peer pair watch --popup: the dialog is spawning again \u{2014} backoff cleared");
        }
    }

    match decide(&result) {
        PopupDecision::Approve => {
            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap_or(0);
            let outcome = commit_approval(&p, now_epoch);
            if !json_mode {
                println!("  {}", outcome.message);
            }
        }
        PopupDecision::Reject => {
            let outcome = crate::commands::reject_by_id("peer.pair.reject", &p.id);
            if !json_mode {
                println!("  {}", outcome.message);
            }
        }
        PopupDecision::Ignore => {
            ignored.insert(p.id.clone());
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
                        "  aoide peer pair watch --popup: request {} has no working dialog right now \u{2014} backing off, retrying up to every {}s",
                        p.id,
                        SPAWN_BACKOFF_MAX.as_secs()
                    );
                }
            }
            std::thread::sleep(*spawn_backoff);
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
                    eprintln!("aoide peer pair watch: waiting for the events feed to appear at {}", events_path.display());
                    narrated = true;
                }
            }
            Err(e) => {
                eprintln!("aoide peer pair watch: opening {}: {e}", events_path.display());
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

/// The full `aoide peer pair watch` command — foreground, blocks until
/// Ctrl-C. `events_path` is resolved ONCE by the caller (`cli`'s own
/// `special` hook, the SAME "resolve once, pass as a parameter"
/// discipline `events tail`/`secrets watch` already hold) — this function
/// never re-derives it. `json_mode` (module doc's `--json`) prints one
/// [`event_to_json`] object per recognized line and nothing else — no
/// startup banner, no actionable-request narration — the same
/// machine-parseable-only contract `aoide_secrets::watch`'s own `--json`
/// mode holds.
///
/// **`popup_mode` (`--popup`) is refused up front when `zenity` isn't
/// installed** (module doc's popup-arm section). Past that guard, EVERY
/// poll tick runs [`popup_tick`] instead of the plain narrate-only
/// reconcile below — the confirm dialog it shows subsumes the "actionable
/// request" narration, so the two are mutually exclusive within one
/// invocation, never layered.
pub fn run(events_path: &Path, json_mode: bool, popup_mode: bool) -> i32 {
    if popup_mode && !zenity_available(ZENITY_CMD) {
        eprintln!(
            "aoide peer pair watch --popup: `zenity` was not found \u{2014} install it, or run \
             `aoide peer pair watch` (without --popup) instead"
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
    let mut ignored: HashSet<String> = HashSet::new();
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
            popup_tick(&mut ignored, &mut spawn_backoff, &mut spawn_failing, json_mode);
        } else if last_reconcile.elapsed() >= RECONCILE_INTERVAL {
            last_reconcile = Instant::now();
            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap_or(0);
            if !json_mode {
                for p in reconcile(now_epoch).iter().filter(|p| actionable(p)) {
                    println!("  {} is actionable \u{2014} run `aoide peer pair approve {}` (or `reject`)", p.id, p.id);
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

    #[test]
    fn reconcile_derives_the_same_sas_handle_peer_pair_pending_prints() {
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
            )
            .unwrap();
            let id = aoide_storage::pairing::list_inbound(now_epoch)[0].id.clone();
            aoide_storage::pairing::reveal_inbound(&id, &"c".repeat(32), now_epoch).unwrap();

            let inv = aoide_protocol::Invocation {
                path: vec!["peer".to_string(), "pair".to_string(), "pending".to_string()],
                args: Vec::new(),
                flags: Default::default(),
                door: aoide_protocol::Door::Cli,
            };
            let outcome = crate::commands::handle_peer_pair_pending(&inv);
            let expected_sas = outcome.data.as_ref().unwrap()["requests"][0]["sas"].as_str().unwrap().to_string();

            let pending = reconcile(now_epoch);
            assert_eq!(pending.len(), 1);
            assert_eq!(pending[0].sas.as_deref(), Some(expected_sas.as_str()), "reconcile must derive the BYTE-IDENTICAL code `peer pair pending` shows");
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
        assert_eq!(decide(&DialogResult::Approved("".to_string())), PopupDecision::Approve);
        assert_eq!(decide(&DialogResult::Dismissed), PopupDecision::Reject);
        assert_eq!(decide(&DialogResult::Cancelled), PopupDecision::Ignore);
        assert_eq!(decide(&DialogResult::CancelledExternally), PopupDecision::Noop);
        // The swap-catcher: a spawn failure must back off, and must NEVER
        // read as `Ignore` — `Ignore` would permanently stop offering a
        // request just because the dialog binary glitched once.
        assert_eq!(decide(&DialogResult::SpawnError("no such file".to_string())), PopupDecision::Backoff);
        assert_ne!(decide(&DialogResult::SpawnError("no such file".to_string())), PopupDecision::Ignore);
        assert_eq!(decide(&DialogResult::DialogFailure("exit 3".to_string())), PopupDecision::Backoff);
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

    #[test]
    fn confirm_text_never_contains_another_requests_sas() {
        let a = fixture_pending("inbound", Some("111-222"));
        let mut b = fixture_pending("inbound", Some("333-444"));
        b.id = "deadbeef".to_string();
        b.name = "box-b".to_string();

        let text_a = confirm_text(&a);
        let text_b = confirm_text(&b);
        assert!(text_a.contains("111-222"));
        assert!(!text_a.contains("333-444"), "box-a's dialog text must never carry box-b's code: {text_a}");
        assert!(text_b.contains("333-444"));
        assert!(!text_b.contains("111-222"), "box-b's dialog text must never carry box-a's code: {text_b}");
    }

    #[test]
    fn confirm_text_and_title_survive_hostile_name_and_url_intact() {
        // `--no-markup` (spawn_pair_confirm's own doc) is what protects the
        // RENDER — the builder itself must never truncate, escape, or drop
        // hostile bytes; it just formats what it was given.
        let mut p = fixture_pending("inbound", Some("555-666"));
        p.name = "box-<b>evil</b>-&-more".to_string();
        p.url = "http://evil/?a=1&b=<script>".to_string();
        p.origin_addr = Some("10.0.0.5&x=1".to_string());

        let title = confirm_title(&p);
        let text = confirm_text(&p);
        assert!(title.contains(&p.name), "{title}");
        assert!(text.contains(&p.name), "{text}");
        assert!(text.contains(&p.url), "{text}");
        assert!(text.contains(p.origin_addr.as_deref().unwrap()), "{text}");
        assert!(text.contains("555-666"));
    }

    #[test]
    fn confirm_text_outbound_carries_no_origin_addr_field() {
        let p = fixture_pending("outbound", Some("777-888"));
        let text = confirm_text(&p);
        // An outbound entry has no connecting-peer address of its own
        // (`Pending::origin_addr`'s own doc) — the inbound-only "origin:"
        // line must never appear for one.
        assert!(!text.contains("origin:"), "{text}");
        assert!(text.contains("777-888"));
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
    fn confirm_dialog_exit_zero_is_approved() {
        let _guard = shim_lock();
        let shim = write_shim("approve", "#!/bin/sh\nexit 0\n");
        let result = confirm_dialog(shim.to_str().unwrap(), "t", "x", || false);
        assert!(matches!(result, DialogResult::Approved(_)), "expected Approved, got {result:?}");
        remove_shim(&shim);
    }

    #[test]
    fn confirm_dialog_reject_label_on_stdout_is_dismissed() {
        let _guard = shim_lock();
        let shim = write_shim("reject", "#!/bin/sh\necho 'Reject request'\nexit 1\n");
        let result = confirm_dialog(shim.to_str().unwrap(), "t", "x", || false);
        assert!(matches!(result, DialogResult::Dismissed), "expected Dismissed, got {result:?}");
        remove_shim(&shim);
    }

    #[test]
    fn confirm_dialog_bare_cancel_is_cancelled_not_dismissed() {
        let _guard = shim_lock();
        let shim = write_shim("cancel", "#!/bin/sh\nexit 1\n");
        let result = confirm_dialog(shim.to_str().unwrap(), "t", "x", || false);
        assert!(matches!(result, DialogResult::Cancelled), "expected Cancelled, got {result:?}");
        remove_shim(&shim);
    }

    #[test]
    fn confirm_dialog_reports_a_spawn_error_for_a_nonexistent_shim() {
        let result = confirm_dialog("/no/such/aoide-pair-confirm-shim-never-exists", "t", "x", || false);
        assert!(matches!(result, DialogResult::SpawnError(_)), "expected SpawnError, got {result:?}");
    }

    // ── commit_approval: same peers.json the CLI's `--yes` path writes ────

    /// `approve_inbound`'s own commit is gated on delivering the
    /// `aoide/pairApprove` callback FIRST (module doc on
    /// `commands::approve_inbound` — "nothing local writes until that
    /// callback is acknowledged") — a real, minimal HTTP responder,
    /// mirroring `commands::tests::spawn_fake_card_server`'s exact shape
    /// one module over, so this test proves the REAL callback path, not a
    /// mocked-away one.
    fn spawn_fake_pair_approve_server() -> (std::net::TcpListener, u16) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepter = listener.try_clone().unwrap();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            loop {
                let Ok((mut stream, _)) = accepter.accept() else { break };
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    continue;
                }
                let body = r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true,"name":"box-a"}}"#;
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
    fn commit_approval_on_an_inbound_entry_writes_the_same_peers_json_the_cli_would() {
        with_peer_state("commit-approval-inbound", || {
            let (_listener, port) = spawn_fake_pair_approve_server();
            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap();
            aoide_storage::pairing::park_inbound(
                &"a".repeat(64),
                "box-a",
                "10.0.0.5",
                &format!("http://127.0.0.1:{port}/"),
                &aoide_storage::pairing::derive_commit(&"a".repeat(64), &"c".repeat(32)),
                &aoide_storage::time::now_iso_utc(),
                &aoide_storage::pairing::expires_at_from(now_epoch),
            )
            .unwrap();
            let id = aoide_storage::pairing::list_inbound(now_epoch)[0].id.clone();
            aoide_storage::pairing::reveal_inbound(&id, &"c".repeat(32), now_epoch).unwrap();

            let pending = reconcile(now_epoch);
            assert_eq!(pending.len(), 1);
            assert!(actionable(&pending[0]));

            let outcome = commit_approval(&pending[0], now_epoch);
            assert_eq!(outcome.status, aoide_protocol::output::Status::Ok, "{outcome:?}");

            let peers = aoide_storage::peer_store::load_peers();
            assert_eq!(peers.len(), 1);
            assert_eq!(peers[0].name, "box-a");
            assert_eq!(peers[0].pubkey.as_deref(), Some("a".repeat(64).as_str()));
            assert!(peers[0].verified);
            assert!(aoide_storage::pairing::list_inbound(now_epoch).is_empty(), "the parked entry is taken on commit");
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

            let outcome = commit_approval(&pending[0], now_epoch);
            assert_eq!(outcome.status, aoide_protocol::output::Status::Ok, "{outcome:?}");

            let peers = aoide_storage::peer_store::load_peers();
            assert_eq!(peers.len(), 1);
            assert_eq!(peers[0].name, "box-b");
            assert_eq!(peers[0].pubkey.as_deref(), Some("b".repeat(64).as_str()));
            assert!(peers[0].verified);
            assert!(aoide_storage::pairing::list_outbound(now_epoch).is_empty(), "the parked entry is taken on commit");
        });
    }
}
