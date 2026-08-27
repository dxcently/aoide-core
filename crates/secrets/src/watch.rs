//! `aoide secrets watch` — a foreground, line-mode terminal surface (design
//! doc: tracker #71 Part 1) that tail-follows the broker-owned events feed
//! (`socket::events_path` — P-G4, task #77, corrected from the mirrored
//! `~/Aoide/log` this module read through P-N3: the deployed broker unit
//! runs with `ProtectHome=true`, so its best-effort mirror into the
//! operator's home silently failed there, and this watcher saw ZERO event
//! lines, falling back to its 30s pending-reconcile tick for every popup —
//! found live on yomi-strix, 2026-08-23), narrates every broker event, and
//! — when stdin is a terminal and `--json` is absent — prompts inline for
//! each parked ask: approve with a hidden TOTP code, dismiss it outright,
//! or ignore it (leaving it parked for any other terminal). This is one of
//! the seven I/O-carrying modules in the crate (`AGENTS.md`'s "I/O is
//! confined to seven named modules" invariant) — `broker`/`client`/`store`/
//! `backend`/`enroll` are the other five.
//!
//! **`--popup` (tracker #71 Part 2)** swaps the tty prompt for a code-entry
//! dialog on each parked ask — the CHILD's own stdout pipe carries the typed
//! code straight into [`client::approve`], never argv (`Command::new`'s args
//! carry only prompt TEXT/identifiers, never the code). The entry is VISIBLE
//! (a TOTP code is a 30-second secret, not a password — nothing is gained by
//! hiding digits the operator is about to read off an authenticator anyway).
//! **P3 (this commit) adds a second dialog binary ahead of zenity's own:**
//! [`resolve_lyra_bin`] checks whether `lyra` resolves to a real executable
//! (`aoide_protocol::bin::rice_bin` + `on_path`, the SAME two-tier check
//! `cli::commands::onboard::lyra_bin_if_resolved` already runs — this crate
//! cannot depend on `aoide-cli`, so the three-line "is it actually there"
//! wrapper is repeated here rather than imported, the shared part
//! (`aoide-protocol::bin`'s resolver itself) is not duplicated) and, when it
//! does, spawns `lyra secrets ask --secret <name> --consumer <who> --seconds
//! <n>` instead of `zenity --entry` — [`spawn_lyra_entry`]/
//! [`spawn_zenity_entry`] share the identical output contract (code on
//! stdout + exit 0 = approved; the literal [`DISMISS_LABEL`] on stdout +
//! exit 1 = dismissed; anything else non-zero = cancelled) through the same
//! [`run_entry_dialog`] wait/parse loop, so [`popup_loop`]'s result handling
//! and its kill-by-pid expiry path never need to know which binary answered.
//! **Presence of `lyra` IS the choice — no new env flag exists to pick
//! between them** (the plugin philosophy, root `AGENTS.md` house rule 7):
//! absent, `--popup` falls back to zenity exactly as before this phase.
//! `zenity` remains a runtime shell-out declared BY NAME (zero new Cargo
//! dependencies, same feature-detection shape `enroll::render_qr` already
//! uses for `qrencode`); [`run`]'s own startup gate now refuses to enter
//! `--popup` only when NEITHER binary is available. Popups are
//! UNLOCK-GATED ([`locked_state`]: `loginctl
//! LockedHint` OR'd with a `/proc` scan for a named locker process, default
//! `hyprlock` — `AOIDE_SECRETS_LOCKER` overrides it; the design doc verified
//! hyprlock cannot set `LockedHint`, so the `/proc` half is load-bearing,
//! not a redundant fallback) and PARKED-ONLY: `released`/`completed`/
//! `dismissed`/`expired` never spawn a dialog, only narrate (same as every
//! other mode) — a tight automation loop never becomes a toast storm. The
//! near-expiry lockout ([`LOCKOUT_SECS`]) is enforced exactly as it is for
//! the tty prompt: no dialog OPENS below it, and the remaining time is
//! re-checked again after the dialog returns, before the code is sent. If
//! an ask resolves elsewhere (another terminal, or its own timeout) while
//! its dialog is open, [`run_zenity_entry`] kills that EXACT child by the
//! `std::process::Child` handle it already holds (never a re-derived pid)
//! and narrates. `--popup`+`--json` is a usage error (`commands::
//! handle_secrets_watch`) — the two modes both own "how a parked ask is
//! completed," and can't both drive it.
//!
//! **Why this crate, not a conductor pane.** Reaching the broker from
//! `aoide-conductor` would add a NEW `aoide-conductor` → `aoide-secrets`
//! dependency edge; `client::pending`/`approve`/`dismiss` are already right
//! here, and the code must never cross a process boundary as an argv token
//! (`client`'s own module doc). A conductor pane, or any future graphical
//! popup, stays a reasonable LATER addition as a consumer of this command's
//! `--json` stream — never a reason to duplicate this logic elsewhere.
//!
//! **Shape**: [`parse_notify_line`]/[`Queue`]/[`pick_next`]/
//! [`code_prompt_allowed`]/[`narrate_event`]/[`event_to_json`] are PURE —
//! clock-as-parameter throughout (this crate's own standing rule for
//! `totp`/`replay`; extended here to the fold, for the same testability
//! reason — `parse_notify_line` takes its own `ts` as a parameter for
//! exactly this reason, P-G4). [`Follower`] is the one piece of real file
//! I/O (tail-follow `AGENTS.md`'s events-feed discipline: open once, seek
//! to EOF, delta reads only, reopen-at-0 on a shrink — the events feed is
//! capped at 1 MiB and truncated back to empty in place rather than
//! rotated, `broker::append_events_feed`'s own doc, so this same
//! reopen-on-shrink branch is what makes that truncation transparent to a
//! live watcher). [`run`] wires both together behind two threads sharing
//! one `Queue` and one output lock, and is the only piece that touches a
//! socket, a terminal, or a signal.
//!
//! **The tail is a TRIGGER; `client::pending` is the AUTHORITY** (this
//! crate's own `AGENTS.md`, "P-N2's park lifecycle" precedent, extended
//! here): [`Queue::reconcile`] runs once at startup and again on every
//! event plus a 30s safety tick, so a watcher that started late, missed a
//! line, or is racing a broker restart still converges on the truth. An ask
//! `reconcile` discovers with no matching `parked` line has no
//! `timeoutSecs` to go on (the wire's own `pending` reply never carries
//! one) — it is given [`crate::park::park_timeout`] as an ESTIMATE
//! (`Ask::estimated`), rendered with a `~` prefix so the operator knows it
//! is a guess, not a fact from the broker.
//!
//! **Never displayed, ever: a secret value.** This module holds `id`,
//! secret *name*, consumer, timing — never a value. The typed TOTP code
//! lives in one local `String` from [`crate::client::read_hidden_line`] to
//! the [`crate::client::approve`] call and is never logged, echoed,
//! narrated, or placed on argv (`client::approve` sends it over the socket
//! directly, the same path `secrets approve --totp` already uses).

use crate::client::{self, PendingAsk};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// ── P1: the pure fold ───────────────────────────────────────────────────

/// One broker notification, parsed from an events-feed line — the exact
/// five shapes `broker::emit_notify` writes (crate `README.md`'s "Broker
/// notifications"). `ts` is the instant this line was READ (P-G4: the
/// events feed carries no per-line timestamp of its own — see
/// `parse_notify_line`'s own doc), reused as `requestedAt` for a
/// freshly-seen `Parked` ask — the notify fires right at park time and is
/// seen within one poll tick, so the two remain the same instant in
/// practice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Released { secret: String, consumer: String, ts: u64 },
    /// `reason`/`origin` are additive (P3): the wire's optional,
    /// self-asserted/best-effort context block a popup/prompt surface shows
    /// alongside the ask (`park::ParkedAsk::reason`/`park::AskOrigin`'s own
    /// docs) — `None`/default when the broker sent none.
    Parked {
        id: String,
        secret: String,
        consumer: String,
        timeout_secs: u64,
        ts: u64,
        reason: Option<String>,
        origin: client::PendingOrigin,
    },
    Completed { id: String, secret: String, consumer: String, ts: u64 },
    Dismissed { id: String, secret: String, consumer: String, ts: u64 },
    Expired { id: String, secret: String, consumer: String, ts: u64 },
}

impl Event {
    /// The parked-ask id this event names, if any (`Released` has none —
    /// it never carries an id, `broker.rs`'s own notify shape table).
    pub fn ask_id(&self) -> Option<&str> {
        match self {
            Event::Released { .. } => None,
            Event::Parked { id, .. }
            | Event::Completed { id, .. }
            | Event::Dismissed { id, .. }
            | Event::Expired { id, .. } => Some(id),
        }
    }
}

/// Parse ONE events-feed line into an [`Event`] — pure, total, and never
/// panics. As of P-G4 (task #77) this reads the RAW payload
/// `broker::emit_notify` already writes verbatim to its own `audit.log`
/// (`append_own_log`) and now, identically, to the broker-owned events
/// feed (`append_events_feed`) — a bare `{"event": "<kind>", ...}` object,
/// no `AuditRecord` wrapper and no `message`-as-JSON-string indirection
/// (that wrapper shape only ever existed on the mirrored `~/Aoide/log`
/// side, which this module no longer reads — module doc). `ts` arrives as
/// a PARAMETER (this module's own clock-as-parameter discipline) rather
/// than being read from the line itself: none of `emit_notify`'s five
/// payload shapes carry a timestamp field (they never have, even before
/// this phase — this parser previously borrowed the OUTER `AuditRecord`'s
/// own `ts` for that purpose, which no longer exists on this path), so the
/// caller (the tail loop, `unix_now()` at the moment the line was read)
/// supplies it instead. A malformed line — bad JSON, an unrecognized
/// `event` kind, a missing required field — returns `None` rather than
/// erroring; the caller skips it and moves on, same posture as before.
pub fn parse_notify_line(line: &str, ts: u64) -> Option<Event> {
    let payload: Value = serde_json::from_str(line).ok()?;
    let kind = payload.get("event").and_then(Value::as_str)?;
    let secret = payload.get("secret").and_then(Value::as_str)?.to_string();
    let consumer = payload.get("consumer").and_then(Value::as_str)?.to_string();

    match kind {
        "released" => Some(Event::Released { secret, consumer, ts }),
        "parked" => {
            let id = payload.get("id").and_then(Value::as_str)?.to_string();
            let timeout_secs = payload.get("timeoutSecs").and_then(Value::as_u64)?;
            let reason = payload.get("reason").and_then(Value::as_str).map(str::to_string);
            let origin = parse_origin(payload.get("origin"));
            Some(Event::Parked { id, secret, consumer, timeout_secs, ts, reason, origin })
        }
        "completed" => {
            let id = payload.get("id").and_then(Value::as_str)?.to_string();
            Some(Event::Completed { id, secret, consumer, ts })
        }
        "dismissed" => {
            let id = payload.get("id").and_then(Value::as_str)?.to_string();
            Some(Event::Dismissed { id, secret, consumer, ts })
        }
        "expired" => {
            let id = payload.get("id").and_then(Value::as_str)?.to_string();
            Some(Event::Expired { id, secret, consumer, ts })
        }
        _ => None,
    }
}

/// Parse a `parked` event's/`pending` reply entry's `"origin"` object
/// (`broker::origin_to_json`'s exact shape) into a [`client::PendingOrigin`]
/// — `None`/missing at any level (an absent `origin` key, an old broker, a
/// field individually `null`) reads as that field's own default, never a
/// parse error (this module's own "malformed line -> skip, never error"
/// posture, extended to a field rather than the whole line).
fn parse_origin(origin: Option<&Value>) -> client::PendingOrigin {
    let Some(o) = origin else { return client::PendingOrigin::default() };
    client::PendingOrigin {
        username: o.get("username").and_then(Value::as_str).map(str::to_string),
        pid: o.get("pid").and_then(Value::as_i64),
        comm: o.get("comm").and_then(Value::as_str).map(str::to_string),
        hostname: o.get("hostname").and_then(Value::as_str).map(str::to_string),
    }
}

/// The `--json` mirror of `broker::origin_to_json` — same shape, this
/// module's own copy since it renders `client::PendingOrigin`, not
/// `park::AskOrigin` (two different crate-internal types over the identical
/// wire shape, `client::PendingOrigin`'s own doc on why).
fn origin_to_json(origin: &client::PendingOrigin) -> Value {
    json!({
        "username": origin.username,
        "pid": origin.pid,
        "comm": origin.comm,
        "hostname": origin.hostname,
    })
}

/// One parked ask as this surface tracks it — id/secret/consumer/timing
/// ONLY, never a value (same "never store a value" rule `park::ParkedAsk`
/// itself holds). `estimated` is true only when [`Queue::reconcile`]
/// invented `timeout_secs` from [`crate::park::park_timeout`] because no
/// `parked` line was ever seen for this ask (this module's own doc).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ask {
    pub id: String,
    pub secret: String,
    pub consumer: String,
    pub requested_at: u64,
    pub timeout_secs: u64,
    pub estimated: bool,
    /// Additive (P3) — see [`Event::Parked`]'s own doc.
    pub reason: Option<String>,
    pub origin: client::PendingOrigin,
}

impl Ask {
    pub fn expires_at(&self) -> u64 {
        self.requested_at.saturating_add(self.timeout_secs)
    }

    /// Seconds left until expiry, at `now` — negative once past due.
    pub fn remaining(&self, now: u64) -> i64 {
        self.expires_at() as i64 - now as i64
    }
}

/// The in-memory set of currently-parked asks this watcher knows about.
/// [`Queue::apply`] folds one [`Event`] in (a trigger); [`Queue::reconcile`]
/// replaces it with the truth from `client::pending` (the authority) — see
/// this module's own doc for why both exist.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Queue {
    asks: Vec<Ask>,
}

impl Queue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.asks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.asks.is_empty()
    }

    pub fn get(&self, id: &str) -> Option<&Ask> {
        self.asks.iter().find(|a| a.id == id)
    }

    pub fn remove(&mut self, id: &str) {
        self.asks.retain(|a| a.id != id);
    }

    pub fn snapshot(&self) -> &[Ask] {
        &self.asks
    }

    /// Fold one event into the queue. `Parked` inserts (a `parked` line
    /// seen twice for the same id, e.g. a replayed log tail, is a no-op —
    /// `apply` never duplicates an id); `Completed`/`Dismissed`/`Expired`
    /// remove by id (an id this queue never had — e.g. an `expired` for an
    /// ask this watcher started too late to see `parked` for and hasn't
    /// reconciled yet — is also a no-op, never a panic); `Released` never
    /// touches the queue at all (it carries no id — `Event::ask_id`).
    pub fn apply(&mut self, event: &Event) {
        match event {
            Event::Parked { id, secret, consumer, timeout_secs, ts, reason, origin } => {
                if !self.asks.iter().any(|a| &a.id == id) {
                    self.asks.push(Ask {
                        id: id.clone(),
                        secret: secret.clone(),
                        consumer: consumer.clone(),
                        requested_at: *ts,
                        timeout_secs: *timeout_secs,
                        estimated: false,
                        reason: reason.clone(),
                        origin: origin.clone(),
                    });
                }
            }
            Event::Completed { id, .. } | Event::Dismissed { id, .. } | Event::Expired { id, .. } => {
                self.remove(id);
            }
            Event::Released { .. } => {}
        }
    }

    /// Reconcile against `client::pending`'s own list — THE authority
    /// (module doc). Drops any tracked ask no longer in `pending` (approved/
    /// dismissed/expired via a path this watcher's tail missed — e.g.
    /// completed from another terminal); adds any `pending` ask this queue
    /// doesn't know yet, with `default_timeout_secs` as an ESTIMATE
    /// (`Ask::estimated = true`) since the wire's `pending` reply carries
    /// no `timeoutSecs` field at all. An ask already tracked (a `parked`
    /// line was seen for it) is left exactly as it was — reconcile never
    /// downgrades a KNOWN timeout back into an estimate.
    pub fn reconcile(&mut self, pending: &[PendingAsk], default_timeout_secs: u64) {
        self.asks.retain(|a| pending.iter().any(|p| p.id == a.id));
        for p in pending {
            if !self.asks.iter().any(|a| a.id == p.id) {
                self.asks.push(Ask {
                    id: p.id.clone(),
                    secret: p.secret.clone(),
                    consumer: p.consumer.clone(),
                    requested_at: p.requested_at,
                    timeout_secs: default_timeout_secs,
                    estimated: true,
                    reason: p.reason.clone(),
                    origin: p.origin.clone(),
                });
            }
        }
    }
}

/// Queue ordering — FIFO by `requested_at` (the ask closest to expiry
/// prompts first, design doc's "1.5 Prompt flow"), excluding any id in
/// `ignored` (the `[i]` gesture, this session only — the caller filters,
/// this queue never forgets the ask). Pure and testable with a plain
/// `Vec<Ask>`, no queue/session state needed.
pub fn pick_next<'a>(asks: &'a [Ask], ignored: &HashSet<String>) -> Option<&'a Ask> {
    asks.iter().filter(|a| !ignored.contains(&a.id)).min_by_key(|a| a.requested_at)
}

/// Near-expiry lockout threshold, seconds (design doc's "1.5 Prompt flow" —
/// a TOTP step is 30s with a ±1 window, typing six digits takes ~3-5s, and
/// the approve round trip includes an unbounded backend shell-out; under
/// 10s the likely outcome is a code spent against an ask that expires
/// mid-flight). This is the BEFORE-OPEN half of the policy: no code prompt
/// (tty `[a]`) and no popup dialog ever OPENS once an ask has fewer than
/// this many seconds left ([`code_prompt_allowed`]/[`popup_action`]).
///
/// **The near-expiry policy, stated once, here, for both surfaces (P-N4,
/// task #76 item 1):** the tty prompt only ever needs this ONE threshold —
/// nothing keeps it open once opened (it blocks on a line read, not a
/// timer), so a stale-but-still-typeable prompt is re-checked at submit
/// time only (`handle_approve`'s own post-read check, same value). A
/// `--popup` dialog is different: `zenity --entry`'s own `--text` bakes
/// "Ns left" at spawn time and cannot be updated in place, so an ALREADY-
/// OPEN dialog can silently go stale while the operator is still looking at
/// it. [`POPUP_KILL_LOCKOUT_SECS`] is the SECOND half of the same policy,
/// set [`POPUP_KILL_MARGIN_SECS`] seconds AHEAD of this one: once an ask's
/// remaining time crosses below it, `popup_loop` kills the dialog that's
/// already open for it (the SAME [`ZenityResult::CancelledExternally`]/
/// `should_cancel` idiom that already kills a dialog whose ask resolved
/// elsewhere — no second kill mechanism) and does NOT reopen a fresh one
/// for that ask (a code typed into a dialog opened this close to expiry
/// would race the deadline exactly the way a not-yet-opened one would,
/// which is the entire reason [`LOCKOUT_SECS`] exists in the first place).
/// The two thresholds are deliberately coupled (one constant derived from
/// the other, never two independently-tuned magic numbers) so a future
/// change to one is a conscious choice about the other too.
pub const LOCKOUT_SECS: i64 = 10;

/// How far AHEAD of [`LOCKOUT_SECS`] the popup's kill-already-open
/// threshold sits (see [`LOCKOUT_SECS`]'s own doc for the full policy) —
/// enough margin that a dialog killed here still leaves the operator the
/// remaining [`LOCKOUT_SECS`] worth of time to react via the tty prompt or
/// another terminal, rather than being caught mid-type in a dialog that
/// vanishes with no warning right at the wire.
const POPUP_KILL_MARGIN_SECS: i64 = 5;

/// Near-expiry threshold for an ALREADY-OPEN `--popup` dialog — see
/// [`LOCKOUT_SECS`]'s own doc for the full two-threshold policy this
/// extends to the already-open case.
pub const POPUP_KILL_LOCKOUT_SECS: i64 = LOCKOUT_SECS + POPUP_KILL_MARGIN_SECS;

/// Is the code prompt allowed to open for `ask` at `now`? Enforced TWICE by
/// the caller ([`run`]'s prompt loop): once before opening the prompt, once
/// again after the code is read but before it is sent — this predicate is
/// the ONE decision both checks share.
pub fn code_prompt_allowed(ask: &Ask, now: u64) -> bool {
    ask.remaining(now) >= LOCKOUT_SECS
}

/// Which loop `run` drives, decided once from the three inputs that can
/// ever disagree — pure and total, so every combination (including the
/// `json_mode && popup_mode` one `commands::handle_secrets_watch` already
/// refuses as a usage error before `run` is ever called) has a defined
/// answer. `Json` wins over everything (the seam every future consumer
/// subscribes to, README's "Watching events"); `Popup` wins over tty
/// detection when `--json` is absent (design doc: "`--popup` with non-tty
/// stdin is fine — dialogs replace prompts", so a popup session never falls
/// back to narration-only just because stdin isn't a terminal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Json,
    Popup,
    InteractiveTty,
    NarrationOnly,
}

pub fn select_mode(json_mode: bool, popup_mode: bool, stdin_tty: bool) -> Mode {
    if json_mode {
        Mode::Json
    } else if popup_mode {
        Mode::Popup
    } else if stdin_tty {
        Mode::InteractiveTty
    } else {
        Mode::NarrationOnly
    }
}

/// The locked-state OR: `loginctl`'s own `LockedHint` (`None` when it can't
/// answer — no session id, `loginctl` absent, a non-zero exit — treated as
/// "doesn't say locked", never as "locked") OR'd with a named locker
/// process's own liveness (design doc: hyprlock 0.9.6 carries no
/// `SetLockedHint` symbol, so THIS half is load-bearing on this rig, not a
/// redundant fallback). Pure — the two real probes ([`probe_loginctl_locked`]/
/// [`probe_locker_running`]) are thin I/O wrappers this function never
/// calls itself, the same clock-as-parameter split this module's own doc
/// holds for `unix_now()`.
pub fn locked_state(loginctl_locked: Option<bool>, locker_running: bool) -> bool {
    loginctl_locked.unwrap_or(false) || locker_running
}

/// What `--popup`'s loop should do about the ask it just picked, given `now`
/// and the CURRENT locked state — pure, so the ordering itself (near-expiry
/// beats lock-wait, never the other way around) is unit-tested without a
/// real screen lock. A dialog must never open below [`LOCKOUT_SECS`]
/// regardless of lock state (design doc: "no dialog opens below the
/// existing 10s lockout") — waiting for an unlock that might take minutes
/// would only spend the ask's remaining time doing nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PopupAction {
    Show,
    WaitUnlock,
    TooLateToShow,
}

pub fn popup_action(ask: &Ask, now: u64, locked: bool) -> PopupAction {
    if !code_prompt_allowed(ask, now) {
        PopupAction::TooLateToShow
    } else if locked {
        PopupAction::WaitUnlock
    } else {
        PopupAction::Show
    }
}

/// Should an ALREADY-OPEN `--popup` dialog for `ask` be killed at `now`? —
/// the kill-open half of [`LOCKOUT_SECS`]'s own doc, checked on every poll
/// tick of `popup_loop`'s `should_cancel` closure alongside "did the ask
/// vanish from the queue" (the same [`ZenityResult::CancelledExternally`]
/// idiom kills the dialog either way — this predicate only decides WHETHER,
/// never HOW). Pure and unit-tested the same way [`code_prompt_allowed`]
/// is — `<`, not `<=`, matching [`code_prompt_allowed`]'s own `>=` so the
/// two thresholds never disagree about the exact boundary second.
pub fn popup_kill_already_open(ask: &Ask, now: u64) -> bool {
    ask.remaining(now) < POPUP_KILL_LOCKOUT_SECS
}

// ── narration + `--json` rendering (pure) ───────────────────────────────

fn hms(ts: u64) -> String {
    let s = ts % 86_400;
    format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
}

fn mmss(remaining_secs: i64) -> String {
    let r = remaining_secs.max(0);
    format!("{}m{:02}s", r / 60, r % 60)
}

/// The "for: ..." context line (P3) — `None` when the ask carries no
/// reason, so a caller with nothing to show adds nothing (every surface
/// renders EXACTLY as before this phase when `reason` is absent, module
/// doc). The wrapping quotes/label live here, the ONE place, so the tty
/// prompt and zenity's `--text` show byte-identical wording — `lyra secrets
/// ask` gets the RAW `reason` text instead ([`spawn_lyra_entry`]'s own doc)
/// since its own QML owns that surface's layout.
fn format_reason_line(reason: &Option<String>) -> Option<String> {
    reason.as_deref().map(|r| format!("for: \"{r}\""))
}

/// The "from: ..." context line (P3) — degrades gracefully, field by field:
/// an entirely unidentified origin (every field `None`, `park::AskOrigin`'s
/// own doc on when that happens) renders NOTHING at all, never a bare
/// "from:" with nothing after it. `username` falls back to the literal
/// `unidentified` when a `comm`/`pid`/`hostname` piece IS known but the peer
/// itself wasn't (should not happen in practice — `peercred::peer_cred`
/// either resolves the whole `PeerCred` or none of it — kept anyway so this
/// function never assumes that invariant from outside). This is the ONE
/// place this wording is built — `lyra secrets ask` receives the finished
/// string via `--from` rather than re-deriving it from separate flags
/// ([`spawn_lyra_entry`]'s own doc), so all three surfaces (tty, zenity,
/// lyra) show byte-identical text.
fn format_origin_line(origin: &client::PendingOrigin) -> Option<String> {
    if origin.username.is_none() && origin.pid.is_none() && origin.comm.is_none() && origin.hostname.is_none() {
        return None;
    }
    let mut who = origin.username.clone().unwrap_or_else(|| "unidentified".to_string());
    if let Some(comm) = &origin.comm {
        who.push_str(&format!(" \u{b7} {comm}"));
    }
    let mut line = format!("from: {who}");
    if let Some(pid) = origin.pid {
        line.push_str(&format!(" (pid {pid})"));
    }
    if let Some(host) = &origin.hostname {
        line.push_str(&format!(" @ {host}"));
    }
    Some(line)
}

/// Render one [`Event`] as a single narration line (interactive/piped
/// text mode) — never a value, ever (module doc).
pub fn narrate_event(event: &Event) -> String {
    match event {
        Event::Released { secret, consumer, ts } => {
            format!("  {}  released    {secret} \u{2192} {consumer}   (no code required)", hms(*ts))
        }
        Event::Parked { id, secret, consumer, timeout_secs, ts, .. } => {
            // `reason`/`origin` are shown on the PROMPT block, not this
            // terse one-line narration (`format_prompt_header`'s own doc) —
            // keeping the scrolling narration line unchanged in shape.
            format!(
                "  {}  parked      {secret} \u{2192} {consumer}   ask {id}   times out in {}",
                hms(*ts),
                mmss(*timeout_secs as i64)
            )
        }
        Event::Completed { id, secret, consumer, ts } => {
            format!("  {}  completed   {secret} \u{2192} {consumer}   ask {id}", hms(*ts))
        }
        Event::Dismissed { id, secret, consumer, ts } => {
            format!("  {}  dismissed   {secret} \u{2192} {consumer}   ask {id}", hms(*ts))
        }
        Event::Expired { id, secret, consumer, ts } => {
            format!("  {}  expired     {secret} \u{2192} {consumer}   ask {id}   (park timed out)", hms(*ts))
        }
    }
}

/// Render one [`Event`] as the `--json` line shape (crate `README.md`'s
/// "Watching events" section documents this as a contract surface — the
/// seam a future popup helper subscribes to instead of re-tailing the log
/// itself). One object per line, flushed per line by the caller.
pub fn event_to_json(event: &Event) -> Value {
    match event {
        Event::Released { secret, consumer, ts } => {
            json!({ "event": "released", "secret": secret, "consumer": consumer, "ts": ts })
        }
        Event::Parked { id, secret, consumer, timeout_secs, ts, reason, origin } => json!({
            "event": "parked",
            "id": id,
            "secret": secret,
            "consumer": consumer,
            "timeoutSecs": timeout_secs,
            "requestedAt": ts,
            "expiresAt": ts + timeout_secs,
            "ts": ts,
            "reason": reason,
            "origin": origin_to_json(origin),
        }),
        Event::Completed { id, secret, consumer, ts } => {
            json!({ "event": "completed", "id": id, "secret": secret, "consumer": consumer, "ts": ts })
        }
        Event::Dismissed { id, secret, consumer, ts } => {
            json!({ "event": "dismissed", "id": id, "secret": secret, "consumer": consumer, "ts": ts })
        }
        Event::Expired { id, secret, consumer, ts } => {
            json!({ "event": "expired", "id": id, "secret": secret, "consumer": consumer, "ts": ts })
        }
    }
}

// ── P2: the follower ─────────────────────────────────────────────────────

/// Tail-follows one file from EOF, delta-reads only — NEVER re-reads from
/// the start. **Moved to `aoide_protocol::feed::Follower` at P-D1**
/// (`docs/architecture/AOIDED.md`'s "L1 — the event bus" section): the
/// mechanics — open-at-end, `(dev, ino)` reopen detection across a broker
/// restart, `len() < pos` reopen on the events feed's own 1 MiB
/// truncate-in-place cap (`broker::append_events_feed`'s own doc), and
/// holding a partial trailing line across polls — are documented on
/// [`aoide_protocol::feed::Follower`] itself now; this re-export is the
/// shim discipline (`pkgs/aoide/crates/AGENTS.md`'s "no cross-crate
/// copying") that keeps every existing `watch::Follower` call site
/// (this module's own `tail_loop`/`wait_for_follower`, `tests/e2e.rs`)
/// unchanged.
pub use aoide_protocol::feed::Follower;

// ── `--popup`: lock probes + the zenity dialog ──────────────────────────

/// The locker process name `--popup`'s unlock gate scans `/proc` for —
/// `AOIDE_SECRETS_LOCKER`, default `hyprlock` (module doc).
fn locker_process_name() -> String {
    std::env::var("AOIDE_SECRETS_LOCKER").unwrap_or_else(|_| "hyprlock".to_string())
}

/// `loginctl show-session <id> -p LockedHint --value`, gated on
/// `$XDG_SESSION_ID` being set at all — `None` on any failure (no session
/// id, `loginctl` missing, a non-zero exit, unparseable output), never an
/// error: this is one OR term of [`locked_state`], and an unanswerable
/// probe must read as "doesn't say locked," not "locked."
fn probe_loginctl_locked() -> Option<bool> {
    let session = std::env::var("XDG_SESSION_ID").ok()?;
    let output = Command::new("loginctl")
        .args(["show-session", &session, "-p", "LockedHint", "--value"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim() == "yes")
}

/// Is a process named `process_name` (its `/proc/<pid>/comm`, exact match
/// after trimming) currently running? Best-effort: an unreadable `/proc`
/// entry (a process that exited mid-scan, a permission gap) is skipped, not
/// fatal — same "a probe that can't answer reads as false, never crashes
/// the watcher" posture [`probe_loginctl_locked`] holds.
fn probe_locker_running(process_name: &str) -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else { return false };
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let comm_path = entry.path().join("comm");
        if let Ok(comm) = std::fs::read_to_string(&comm_path) {
            if comm.trim() == process_name {
                return true;
            }
        }
    }
    false
}

/// The real locked-state read — wires the two probes above into
/// [`locked_state`]. The only place either probe is called from `--popup`'s
/// own loop.
fn is_locked(locker_process: &str) -> bool {
    locked_state(probe_loginctl_locked(), probe_locker_running(locker_process))
}

/// The default `zenity` binary name `run` spawns in production — tests pass
/// a fake shim's own full path instead (this module's own test section),
/// never mutate `PATH` (unlike `enroll::render_qr`'s test, which predates
/// this pattern and still uses a `PATH` shim under `env_lock` — this
/// function exists so `--popup`'s own tests need neither).
const ZENITY_CMD: &str = "zenity";

/// The `--extra-button` label `run_zenity_entry` recognizes as an explicit
/// dismiss (design doc: "a second button ... never the window's close
/// box"). Zenity's own contract: pressing an extra button exits non-zero
/// (the SAME status a bare Cancel produces) but prints the button's own
/// label to stdout instead of the entry's typed value — this is the one
/// thing that tells the two apart.
const DISMISS_LABEL: &str = "Dismiss ask";

/// `popup_loop`'s spawn-retry backoff (task #76 item 3): a failing zenity
/// spawn (the binary went missing, the display died mid-session — anything
/// short of the startup `zenity_available` check, which already refuses to
/// even ENTER `--popup` mode) must not busy-loop a fresh `Command::spawn`
/// every ~200ms poll tick forever. `next_spawn_backoff` doubles from this
/// floor up to [`SPAWN_BACKOFF_MAX`] on each consecutive failure; a
/// SUCCESSFUL spawn (any [`ZenityResult`] other than `SpawnError`) resets it
/// straight back here (`popup_loop`'s own `spawn_failing`/`spawn_backoff`
/// state). Deliberately NOT wired through [`crate::park::park_timeout`]'s
/// tolerant-env-override shape — this is an internal retry cadence, not a
/// user-facing knob, so no `AOIDE_SECRETS_*` env var governs it.
const SPAWN_BACKOFF_INITIAL: Duration = Duration::from_secs(1);

/// Ceiling `next_spawn_backoff` never exceeds — see [`SPAWN_BACKOFF_INITIAL`]'s
/// own doc for the full policy.
const SPAWN_BACKOFF_MAX: Duration = Duration::from_secs(60);

/// The doubling step itself, pure and unit-tested without actually
/// sleeping (this crate's own clock/timing-as-parameter discipline,
/// `AGENTS.md`) — `1s, 2s, 4s, 8s, 16s, 32s, 60s, 60s, ...`, capped at
/// [`SPAWN_BACKOFF_MAX`] rather than overflowing or wrapping past it.
fn next_spawn_backoff(current: Duration) -> Duration {
    current.saturating_mul(2).min(SPAWN_BACKOFF_MAX)
}

/// Outcome of one `zenity --entry --hide-text` round trip — never a bare
/// `Result`, since "the user closed it" and "a wrong code" and "spawning it
/// failed" are three different things the caller must react to
/// differently.
#[derive(Debug)]
pub enum ZenityResult {
    /// Exit 0 — the code the user typed, trimmed of exactly the one
    /// trailing newline zenity's own stdout carries
    /// ([`client::strip_one_trailing_newline`], reused verbatim — never a
    /// blanket `.trim()`, this crate's own "exactly one, not a blanket
    /// trim" discipline).
    Approved(String),
    /// Non-zero exit, stdout was the [`DISMISS_LABEL`] extra button.
    Dismissed,
    /// Non-zero exit, anything else — Cancel, Escape, or the window closed.
    Cancelled,
    /// The ask stopped being relevant (completed/dismissed/expired
    /// elsewhere) WHILE the dialog sat open; the child was killed by its
    /// exact pid before this returned.
    CancelledExternally,
    /// The `zenity` process could not be spawned or waited on at all.
    SpawnError(String),
}

/// `--no-markup` (this commit, review fix): `--text` is built by
/// interpolating `secret`/`consumer`/`reason`/the origin line — all
/// UNTRUSTED display text (`ask.reason`/`ask.origin.comm` in particular,
/// this crate's own honesty note: `comm` is PROCESS-CONTROLLED, any process
/// can `prctl(PR_SET_NAME, ...)` itself to anything) — and zenity renders
/// `--text` as Pango markup BY DEFAULT, on `--entry` too (verified live on
/// this host, zenity 4.2.2: `--no-markup` is undocumented under `--help-
/// entry`'s own "Text entry options" section but IS accepted there and DOES
/// suppress markup — confirmed by screenshot, `<b>`/`&`/`<i>` rendered as
/// literal text rather than bold/ampersand-entity/italic once passed). A
/// `reason`/`comm` containing real Pango markup would otherwise render
/// as formatting, or worse: `&` alone is an entity-reference PREFIX, so an
/// unescaped `&` in an origin line can corrupt the rendered text or throw a
/// GMarkup parse warning. Don't drop this flag "since the text is just a
/// secret/consumer name" — `reason`/`origin` (P3) made this sink reachable
/// with genuinely free-text, caller-influenced content for the first time.
fn spawn_zenity_entry(zenity_cmd: &str, title: &str, text: &str) -> std::io::Result<Child> {
    Command::new(zenity_cmd)
        .args(["--entry", "--no-markup", "--title", title, "--text", text, "--extra-button", DISMISS_LABEL])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
}

/// `lyra secrets ask`'s own argv (P3) — `--secret`/`--consumer`/`--seconds`
/// always, plus two OPTIONAL context flags, the same "identifiers and TEXT
/// only, never a code" argv discipline `spawn_zenity_entry` already holds.
/// `reason` rides RAW (`ask.reason`'s own text, untouched — `lyra secrets
/// ask` owns how it labels/quotes it in its own context block); `from_line`
/// rides PRE-FORMATTED by [`format_origin_line`] — the ONE place that
/// multi-part conditional formatting lives, so zenity's `--text`, the tty
/// prompt, and lyra's dialog render the IDENTICAL "from: ..." wording rather
/// than three independent reimplementations that could drift. `lyra_cmd` is
/// a path/name parameter, never a hardcoded `Command::new("lyra")`, matching
/// `spawn_zenity_entry`'s own shape so this module's tests can stand in a
/// fake shim for either binary without a `PATH` mutation.
fn spawn_lyra_entry(
    lyra_cmd: &str,
    secret: &str,
    consumer: &str,
    seconds: u64,
    reason: Option<&str>,
    from_line: Option<&str>,
) -> std::io::Result<Child> {
    let mut cmd = Command::new(lyra_cmd);
    cmd.args(["secrets", "ask", "--secret", secret, "--consumer", consumer, "--seconds", &seconds.to_string()]);
    if let Some(r) = reason {
        cmd.args(["--reason", r]);
    }
    if let Some(f) = from_line {
        cmd.args(["--from", f]);
    }
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn()
}

/// Run one code-entry dialog CHILD to completion, polling every 200ms
/// between the dialog's own exit and `should_cancel()` — the mechanism
/// behind [`ZenityResult::CancelledExternally`] (module doc): `should_cancel`
/// is the caller's own "is this ask still in the queue?" check, so an ask
/// that resolves on another terminal while this dialog sits open gets its
/// EXACT child killed via the `Child` handle this function already holds
/// (never a re-derived pid, never a name match) rather than left orphaned
/// on screen for an ask that no longer exists. Generic over HOW the child
/// was spawned (`spawn` is called exactly once, inside here, so a failed
/// spawn is still reported as [`ZenityResult::SpawnError`]) — this is the
/// ONE place either dialog binary's exit status/stdout is parsed, so
/// `zenity`'s and `lyra`'s output CONTRACT (module doc) staying identical is
/// what makes sharing this loop correct, not incidental.
fn run_entry_dialog(spawn: impl FnOnce() -> std::io::Result<Child>, mut should_cancel: impl FnMut() -> bool) -> ZenityResult {
    let mut child = match spawn() {
        Ok(c) => c,
        Err(e) => return ZenityResult::SpawnError(e.to_string()),
    };

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut raw = String::new();
                if let Some(mut out) = child.stdout.take() {
                    let _ = out.read_to_string(&mut raw);
                }
                let out = client::strip_one_trailing_newline(raw);
                return if status.success() {
                    ZenityResult::Approved(out)
                } else if out == DISMISS_LABEL {
                    ZenityResult::Dismissed
                } else {
                    ZenityResult::Cancelled
                };
            }
            Ok(None) => {
                if should_cancel() {
                    let _ = child.kill();
                    let _ = child.wait();
                    return ZenityResult::CancelledExternally;
                }
                thread::sleep(Duration::from_millis(200));
            }
            Err(e) => return ZenityResult::SpawnError(e.to_string()),
        }
    }
}

fn run_zenity_entry(zenity_cmd: &str, title: &str, text: &str, should_cancel: impl FnMut() -> bool) -> ZenityResult {
    run_entry_dialog(|| spawn_zenity_entry(zenity_cmd, title, text), should_cancel)
}

#[allow(clippy::too_many_arguments)]
fn run_lyra_entry(
    lyra_cmd: &str,
    secret: &str,
    consumer: &str,
    seconds: u64,
    reason: Option<&str>,
    from_line: Option<&str>,
    should_cancel: impl FnMut() -> bool,
) -> ZenityResult {
    run_entry_dialog(|| spawn_lyra_entry(lyra_cmd, secret, consumer, seconds, reason, from_line), should_cancel)
}

/// The dialog CHOICE itself (module doc's P3 section): `lyra_cmd` present
/// means it already resolved to a real executable ([`resolve_lyra_bin`]'s
/// own job, done ONCE by the caller — never re-checked here), so this
/// function never re-derives that fact, only branches on it. Both arms end
/// up in [`run_entry_dialog`] through the SAME `should_cancel` closure the
/// caller built once — the choice changes which child is spawned, nothing
/// about how its result is read back.
#[allow(clippy::too_many_arguments)]
fn run_ask_dialog(
    lyra_cmd: Option<&str>,
    zenity_cmd: &str,
    secret: &str,
    consumer: &str,
    seconds: u64,
    title: &str,
    text: &str,
    reason: Option<&str>,
    from_line: Option<&str>,
    should_cancel: impl FnMut() -> bool,
) -> ZenityResult {
    match lyra_cmd {
        Some(lyra) => run_lyra_entry(lyra, secret, consumer, seconds, reason, from_line, should_cancel),
        None => run_zenity_entry(zenity_cmd, title, text, should_cancel),
    }
}

/// A brief `zenity --error`, shown after a wrong code (design doc: "show a
/// brief zenity --error ... and re-offer"). Blocks until the user closes it
/// — deliberately no `--timeout`, so the message is never dismissed before
/// it's read; the ask stays parked underneath regardless of how long this
/// sits open, same as the tty path's own wrong-code retry.
fn zenity_error_dialog(zenity_cmd: &str, text: &str) {
    // `--no-markup` for the identical reason `spawn_zenity_entry` carries
    // it now (that function's own doc) — this dialog's own `text` only
    // ever interpolates `ask.secret` today (charset-restricted by
    // `policy::valid_secret_name`, never free text), but there is no
    // reason to leave this sink one property away from the others.
    let _ = Command::new(zenity_cmd)
        .args(["--error", "--no-markup", "--text", text])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Feature-detect `zenity` at `--popup` startup (`run`'s first check) — the
/// SAME shape [`enroll::render_qr`]'s own `qrencode` feature-detect uses,
/// spawn failure IS the detection, never a separate "is it on PATH" probe.
fn zenity_available(zenity_cmd: &str) -> bool {
    Command::new(zenity_cmd).arg("--version").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok()
}

/// P3's dialog choice: is a REAL `lyra` executable resolvable right now?
/// Mirrors `cli::commands::onboard::lyra_bin_if_resolved`'s exact env-tier/
/// sibling-tier/bare-name-on-`PATH` check byte for byte (module doc: this
/// crate cannot depend on `aoide-cli`, so the three-line "is it actually
/// there" wrapper is repeated here rather than imported — the shared part,
/// `aoide-protocol::bin`'s resolver itself, is not duplicated). `rice_bin`'s
/// own env/sibling tiers are already trusted (both return a path containing
/// `/`, or the env override verbatim); only its bare-name fallback
/// (`"lyra"`, left for `Command::spawn` to resolve at exec time) needs a
/// `PATH` probe of our own before this crate treats it as "resolved."
fn resolve_lyra_bin() -> Option<String> {
    let bin = aoide_protocol::bin::rice_bin();
    let resolved = bin.contains('/') || aoide_protocol::bin::on_path(&bin);
    resolved.then_some(bin)
}

/// The `--popup` loop — main thread only, mirrors [`prompt_loop`]'s own
/// shape (pick the next un-ignored ask, act, repeat) but drives a dialog
/// instead of reading `[a]`/`[d]`/`[i]` from stdin — `lyra` when
/// [`resolve_lyra_bin`] found one, `zenity` otherwise ([`run_ask_dialog`]).
/// `ignored` is the SAME "Cancel/close stops re-prompting for THIS ask, this
/// session only" semantics `[i]` holds in [`prompt_loop`] (design doc:
/// "Cancel/close = IGNORE") — without it, a cancelled dialog would reopen
/// every ~200ms forever.
#[allow(clippy::too_many_arguments)]
fn popup_loop(
    socket_path: &Path,
    queue: &Arc<Mutex<Queue>>,
    out_lock: &Arc<Mutex<()>>,
    zenity_cmd: &str,
    lyra_cmd: Option<&str>,
    locker_process: &str,
) {
    let mut ignored: HashSet<String> = HashSet::new();
    let mut spawn_backoff = SPAWN_BACKOFF_INITIAL;
    let mut spawn_failing = false;
    loop {
        if INTERRUPTED.load(Ordering::SeqCst) {
            return;
        }
        let ask = {
            let q = queue.lock().unwrap_or_else(|e| e.into_inner());
            ignored.retain(|id| q.get(id).is_some());
            pick_next(q.snapshot(), &ignored).cloned()
        };
        let Some(ask) = ask else {
            thread::sleep(Duration::from_millis(200));
            continue;
        };

        let now = unix_now();
        match popup_action(&ask, now, is_locked(locker_process)) {
            PopupAction::TooLateToShow => {
                thread::sleep(Duration::from_millis(200));
                continue;
            }
            PopupAction::WaitUnlock => {
                thread::sleep(Duration::from_secs(1));
                continue;
            }
            PopupAction::Show => {}
        }

        let seconds = ask.remaining(now).max(0) as u64;
        let title = format!("aoide \u{b7} {}", ask.secret);
        let mut text = format!("code for `{}` \u{2190} {} \u{00b7} {}s left", ask.secret, ask.consumer, seconds);
        // P3: the SAME context lines `format_prompt_header` shows the tty
        // prompt, appended to zenity's own `--text` — absent when the ask
        // carries neither, byte-identical to before this phase in that case.
        for line in [format_reason_line(&ask.reason), format_origin_line(&ask.origin)].into_iter().flatten() {
            text.push('\n');
            text.push_str(&line);
        }
        let reason = ask.reason.clone();
        let from_line = format_origin_line(&ask.origin);

        let cancel_queue = Arc::clone(queue);
        let cancel_id = ask.id.clone();
        let cancel_ask = ask.clone();
        // The SAME kill idiom serves two different reasons a dialog must
        // close mid-poll (`should_cancel`'s own doc): the ask vanished from
        // the queue (resolved/reaped elsewhere), OR it is now within
        // `POPUP_KILL_LOCKOUT_SECS` of expiry — `popup_loop`'s own arm below
        // tells the two apart afterward by re-checking whether the ask is
        // still in the queue.
        let result = run_ask_dialog(
            lyra_cmd,
            zenity_cmd,
            &ask.secret,
            &ask.consumer,
            seconds,
            &title,
            &text,
            reason.as_deref(),
            from_line.as_deref(),
            || {
                cancel_queue.lock().unwrap_or_else(|e| e.into_inner()).get(&cancel_id).is_none()
                    || popup_kill_already_open(&cancel_ask, unix_now())
            },
        );

        if !matches!(result, ZenityResult::SpawnError(_)) && spawn_failing {
            spawn_failing = false;
            spawn_backoff = SPAWN_BACKOFF_INITIAL;
            let _g = out_lock.lock().unwrap_or_else(|e| e.into_inner());
            println!("  aoide secrets watch --popup: the dialog is spawning again \u{2014} backoff cleared");
        }

        match result {
            ZenityResult::Approved(code) => {
                let still_parked = queue.lock().unwrap_or_else(|e| e.into_inner()).get(&ask.id).cloned();
                let Some(current) = still_parked else {
                    let _g = out_lock.lock().unwrap_or_else(|e| e.into_inner());
                    println!("  ask {} is no longer parked \u{2014} the code was NOT sent", ask.id);
                    continue;
                };
                if !code_prompt_allowed(&current, unix_now()) {
                    let _g = out_lock.lock().unwrap_or_else(|e| e.into_inner());
                    println!("  too little time left \u{2014} the code was NOT sent");
                    continue;
                }
                let approved = client::approve(socket_path, &ask.id, &code);
                if approved.is_ok() {
                    queue.lock().unwrap_or_else(|e| e.into_inner()).remove(&ask.id);
                }
                {
                    let _g = out_lock.lock().unwrap_or_else(|e| e.into_inner());
                    match &approved {
                        Ok(()) => println!("  \u{2713} approved {} (popup) \u{2014} value released to the waiting caller", ask.id),
                        Err(e) => println!("  \u{2717} invalid or already-used code \u{2014} the ask is STILL PARKED, nothing was spent ({e})"),
                    }
                }
                // The wrong-code error dialog is zenity-specific (no `lyra
                // secrets ask` error surface exists — P3's brief covers the
                // entry dialog only); on the lyra path the ask simply stays
                // parked and the next poll reopens its `lyra secrets ask`
                // entry dialog fresh, same as any other re-prompt.
                if approved.is_err() && lyra_cmd.is_none() {
                    zenity_error_dialog(
                        zenity_cmd,
                        &format!("invalid code for `{}` \u{2014} the ask is still parked, try again", ask.secret),
                    );
                }
            }
            ZenityResult::Dismissed => {
                let dismissed = client::dismiss(socket_path, &ask.id);
                queue.lock().unwrap_or_else(|e| e.into_inner()).remove(&ask.id);
                let _g = out_lock.lock().unwrap_or_else(|e| e.into_inner());
                match dismissed {
                    Ok(()) => println!("  dismissed ask {} (popup) \u{2014} the waiting caller gets a clean refusal", ask.id),
                    Err(e) => println!("  could not dismiss ask {}: {e}", ask.id),
                }
            }
            ZenityResult::Cancelled => {
                ignored.insert(ask.id.clone());
            }
            ZenityResult::CancelledExternally => {
                // Still in the queue: this WASN'T a vanished/resolved-
                // elsewhere ask — the kill was `popup_kill_already_open`
                // firing (LOCKOUT_SECS's own doc). `ignored` here is what
                // makes "don't respawn for that ask" real — otherwise the
                // very next loop iteration would just pick it again and
                // instantly re-trigger the same kill, on repeat, until
                // `popup_action`'s own before-open check finally catches up
                // a few seconds later.
                let still_parked = queue.lock().unwrap_or_else(|e| e.into_inner()).get(&ask.id).is_some();
                if still_parked {
                    ignored.insert(ask.id.clone());
                }
                let _g = out_lock.lock().unwrap_or_else(|e| e.into_inner());
                if still_parked {
                    println!(
                        "  ask {} \u{2014} too little time left to type a code safely, closing the dialog (won't reopen for this ask)",
                        ask.id
                    );
                } else {
                    println!("  ask {} resolved elsewhere while its popup was open \u{2014} closing the dialog", ask.id);
                }
            }
            ZenityResult::SpawnError(e) => {
                if !spawn_failing {
                    spawn_failing = true;
                    let _g = out_lock.lock().unwrap_or_else(|e2| e2.into_inner());
                    println!(
                        "  aoide secrets watch --popup: spawning zenity for ask {}: {e} \u{2014} backing off, retrying up to every {}s",
                        ask.id,
                        SPAWN_BACKOFF_MAX.as_secs()
                    );
                }
                thread::sleep(spawn_backoff);
                spawn_backoff = next_spawn_backoff(spawn_backoff);
            }
        }
    }
}

// ── P3/P4: the loop ──────────────────────────────────────────────────────

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

/// Reconcile once against `client::pending` — a socket error is the taught
/// connect message (`client::describe_connect_error`, baked into
/// `pending`'s own `Err`), printed and swallowed: the broker may simply not
/// be running yet or may be restarting, and this watcher keeps tailing the
/// log regardless (module doc). No throttle on a repeated failure —
/// deliberate, the same "wait for the field to complain" posture this
/// crate's other notify/audit paths hold (`AGENTS.md`'s no-dedup note).
fn reconcile_once(socket_path: &Path, queue: &Mutex<Queue>) {
    match client::pending(socket_path) {
        Ok(asks) => {
            let mut q = queue.lock().unwrap_or_else(|e| e.into_inner());
            q.reconcile(&asks, crate::park::park_timeout().as_secs());
        }
        Err(e) => eprintln!("aoide secrets watch: {e}"),
    }
}

/// Print one event (narration or `--json`), under the output lock, and — if
/// a prompt is currently open — reprint the FULL prompt frame (header,
/// options line, and the `└ > ` entry marker — never just the header)
/// underneath, so an async narration line can never leave the operator's
/// own open prompt looking like just a bare header with no way to tell what
/// `[a]`/`[d]`/`[i]` even do (review rider: "reprint the full prompt frame,
/// not just the header line" — design doc's "1.3 Signal flow" ASCII already
/// shows the full block reprinted this way).
fn emit_event(event: &Event, json_mode: bool, out_lock: &Mutex<()>, queue: &Mutex<Queue>, prompt_frame: &Mutex<Option<String>>) {
    let _g = out_lock.lock().unwrap_or_else(|e| e.into_inner());
    if json_mode {
        println!("{}", event_to_json(event));
        let _ = std::io::stdout().flush();
        return;
    }
    println!("{}", narrate_event(event));
    if matches!(event, Event::Parked { .. }) {
        let n = queue.lock().unwrap_or_else(|e| e.into_inner()).len();
        if n > 1 {
            println!("            (queued \u{2014} {} ask(s) waiting behind this one)", n - 1);
        }
    }
    if let Some(frame) = prompt_frame.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        println!();
        print!("{frame}");
    }
    let _ = std::io::stdout().flush();
}

fn print_farewell(queue: &Mutex<Queue>, out_lock: &Mutex<()>) {
    let _g = out_lock.lock().unwrap_or_else(|e| e.into_inner());
    let n = queue.lock().unwrap_or_else(|e| e.into_inner()).len();
    println!();
    println!("left the watcher \u{2014} {n} ask(s) still parked; complete with aoide secrets approve <id> --totp <code>");
    let _ = std::io::stdout().flush();
}

fn tail_loop(mut follower: Follower, socket_path: PathBuf, queue: Arc<Mutex<Queue>>, out_lock: Arc<Mutex<()>>, prompt_frame: Arc<Mutex<Option<String>>>, json_mode: bool) -> ! {
    let mut ticks_since_reconcile: u32 = 0;
    loop {
        if INTERRUPTED.load(Ordering::SeqCst) {
            print_farewell(&queue, &out_lock);
            std::process::exit(0);
        }
        match follower.poll() {
            Ok(lines) => {
                for line in lines {
                    let Some(event) = parse_notify_line(&line, unix_now()) else { continue };
                    {
                        let mut q = queue.lock().unwrap_or_else(|e| e.into_inner());
                        q.apply(&event);
                    }
                    emit_event(&event, json_mode, &out_lock, &queue, &prompt_frame);
                    reconcile_once(&socket_path, &queue);
                }
            }
            Err(e) => eprintln!("aoide secrets watch: reading the log: {e}"),
        }
        ticks_since_reconcile += 1;
        if ticks_since_reconcile >= 30 {
            ticks_since_reconcile = 0;
            reconcile_once(&socket_path, &queue);
        }
        thread::sleep(Duration::from_secs(1));
    }
}

fn format_prompt_header(ask: &Ask, remaining: i64, closed: bool, queued: usize) -> String {
    let asked = hms(ask.requested_at);
    let est = if ask.estimated { "~" } else { "" };
    let left = if closed { format!("{est}{}s left \u{2014} CLOSED", remaining.max(0)) } else { format!("{est}{} left", mmss(remaining)) };
    let tail = if queued > 0 { format!(" \u{2014} {queued} queued \u{2014}") } else { String::new() };
    let mut header =
        format!("\u{250c} ask {} \u{2500} {} \u{2190} {} \u{2500} asked {asked} \u{2500} {left}{tail}", ask.id, ask.secret, ask.consumer);
    // P3: the context block — reason then origin, each its own line, both
    // absent when the ask carries neither (byte-identical to before this
    // phase in that case).
    for line in [format_reason_line(&ask.reason), format_origin_line(&ask.origin)].into_iter().flatten() {
        header.push('\n');
        header.push_str(&format!("\u{2502} {line}"));
    }
    header
}

/// The FULL prompt block `emit_event` reprints verbatim after an async
/// narration line (this module's own "reprint the full frame" rider,
/// `emit_event`'s doc) — `header`, the options-or-closed line, and the
/// `└ > ` entry marker, ending WITHOUT a trailing newline so the cursor
/// sits ready for input exactly where it would after the original print.
fn format_prompt_frame(header: &str, closed: bool) -> String {
    let options = if closed {
        "\u{2502} too little time left to type a code safely \u{2014} [d] dismiss  [i] ignore"
    } else {
        "\u{2502} [a] approve (enter code)   [d] dismiss the ask   [i] ignore (stays parked)"
    };
    format!("{header}\n{options}\n\u{2514} > ")
}

fn clear_prompt_frame(prompt_frame: &Mutex<Option<String>>) {
    *prompt_frame.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// The interactive prompt loop — main thread only, only when stdin is a
/// terminal and `--json` is absent (module doc). Picks the next un-ignored
/// ask ([`pick_next`], oldest `requested_at` first), opens its prompt
/// block, and reads ONE line for `[a]`/`[d]`/`[i]` — never raw single-key
/// (design doc's "1.5 Prompt flow": works over ssh, no terminal-state
/// restoration risk).
fn prompt_loop(socket_path: &Path, queue: &Arc<Mutex<Queue>>, out_lock: &Arc<Mutex<()>>, prompt_frame: &Arc<Mutex<Option<String>>>) {
    let mut ignored: HashSet<String> = HashSet::new();
    loop {
        if INTERRUPTED.load(Ordering::SeqCst) {
            return;
        }
        let (ask, queued) = {
            let q = queue.lock().unwrap_or_else(|e| e.into_inner());
            ignored.retain(|id| q.get(id).is_some());
            let picked = pick_next(q.snapshot(), &ignored).cloned();
            let queued = q.len().saturating_sub(1);
            (picked, queued)
        };
        let Some(ask) = ask else {
            thread::sleep(Duration::from_millis(200));
            continue;
        };

        let now = unix_now();
        let remaining = ask.remaining(now);
        let closed = !code_prompt_allowed(&ask, now);
        let header = format_prompt_header(&ask, remaining, closed, queued);
        let frame = format_prompt_frame(&header, closed);
        {
            let _g = out_lock.lock().unwrap_or_else(|e| e.into_inner());
            *prompt_frame.lock().unwrap_or_else(|e| e.into_inner()) = Some(frame.clone());
            println!();
            print!("{frame}");
            let _ = std::io::stdout().flush();
        }

        let mut line = String::new();
        let read = std::io::stdin().lock().read_line(&mut line);
        match read {
            Ok(0) | Err(_) => {
                clear_prompt_frame(prompt_frame);
                return; // EOF or a read error: leave the watcher cleanly.
            }
            Ok(_) => {}
        }
        let choice = line.trim().to_ascii_lowercase();

        match choice.as_str() {
            "a" if !closed => handle_approve(socket_path, &ask, queue, out_lock),
            "a" => {
                let _g = out_lock.lock().unwrap_or_else(|e| e.into_inner());
                println!("  too little time left to type a code safely \u{2014} [d] dismiss or [i] ignore instead");
            }
            "d" => {
                let result = client::dismiss(socket_path, &ask.id);
                queue.lock().unwrap_or_else(|e| e.into_inner()).remove(&ask.id);
                let _g = out_lock.lock().unwrap_or_else(|e| e.into_inner());
                match result {
                    Ok(()) => println!("  dismissed ask {} \u{2014} the waiting caller gets a clean refusal", ask.id),
                    Err(e) => println!("  could not dismiss ask {}: {e}", ask.id),
                }
            }
            "i" => {
                ignored.insert(ask.id.clone());
            }
            _ => {
                let _g = out_lock.lock().unwrap_or_else(|e| e.into_inner());
                println!("  unrecognized \u{2014} [a] approve  [d] dismiss  [i] ignore");
            }
        }
        clear_prompt_frame(prompt_frame);
    }
}

/// The `[a]` branch: read the hidden code (`client::read_hidden_line`,
/// reused VERBATIM — module doc), re-check the ask is still parked AND
/// still above [`LOCKOUT_SECS`] (design doc's "after" half of the lockout —
/// a code typed near the boundary must not be sent once time has run out
/// underneath it), then `client::approve`. A wrong code narrates and
/// leaves the ask parked for a retry; a right code narrates success and
/// removes the ask from the LOCAL queue immediately (the tail thread's own
/// `completed` line will confirm it within its next 1s poll either way —
/// this optimistic removal only stops an immediate re-prompt for the same,
/// already-approved ask).
fn handle_approve(socket_path: &Path, ask: &Ask, queue: &Arc<Mutex<Queue>>, out_lock: &Arc<Mutex<()>>) {
    let code = match client::read_hidden_line(&format!("  code for `{}` (input hidden): ", ask.secret)) {
        Ok(c) => c,
        Err(e) => {
            let _g = out_lock.lock().unwrap_or_else(|e2| e2.into_inner());
            println!("  {e}");
            return;
        }
    };

    let still_parked = {
        let q = queue.lock().unwrap_or_else(|e| e.into_inner());
        q.get(&ask.id).cloned()
    };
    let Some(current) = still_parked else {
        let _g = out_lock.lock().unwrap_or_else(|e| e.into_inner());
        println!("  ask {} is no longer parked \u{2014} the code was NOT sent", ask.id);
        return;
    };
    if !code_prompt_allowed(&current, unix_now()) {
        let _g = out_lock.lock().unwrap_or_else(|e| e.into_inner());
        println!("  too little time left \u{2014} the code was NOT sent");
        return;
    }

    let result = client::approve(socket_path, &ask.id, &code);
    if result.is_ok() {
        queue.lock().unwrap_or_else(|e| e.into_inner()).remove(&ask.id);
    }
    let _g = out_lock.lock().unwrap_or_else(|e| e.into_inner());
    match result {
        Ok(()) => println!("  \u{2713} approved {} \u{2014} value released to the waiting caller", ask.id),
        Err(e) => println!("  \u{2717} invalid or already-used code \u{2014} the ask is STILL PARKED, nothing was spent ({e})"),
    }
}

/// Wait for `events_path` to exist, narrating the wait exactly once, then
/// open it at EOF — review rider: on a brand-new host the events feed may
/// not exist yet at `secrets watch` startup (the broker hasn't emitted
/// anything since boot), and exiting 1 immediately (the pre-rider
/// behavior) is needlessly hostile when the fix is just "the broker hasn't
/// written its first line yet, wait a moment." Only
/// [`std::io::ErrorKind::NotFound`] waits — a PERMISSION error or anything
/// else still fails immediately (`Err(1)`), same as before this rider: a
/// wait would only mislead when the file exists but can't be read. `Err(0)`
/// means Ctrl-C landed while waiting — a clean exit, not a failure.
/// `poll_interval` is a parameter (never a bare `Duration::from_secs(1)`
/// inline) so the tempfile test below doesn't have to spend real seconds
/// waiting on it. This NotFound-poll semantics is unchanged by P-G4 (task
/// #77) moving the tail source from the mirrored `~/Aoide/log` to the
/// broker-owned events feed — a fresh `/run/aoide-secrets/` with no event
/// emitted yet is exactly the same "wait, don't exit 1" shape a brand-new
/// `~/Aoide/log` used to be.
fn wait_for_follower(events_path: &Path, poll_interval: Duration) -> Result<Follower, i32> {
    let mut narrated = false;
    loop {
        match Follower::open_at_end(events_path) {
            Ok(f) => return Ok(f),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if !narrated {
                    eprintln!("aoide secrets watch: waiting for the events feed to appear at {}", events_path.display());
                    narrated = true;
                }
            }
            Err(e) => {
                eprintln!("aoide secrets watch: opening {}: {e}", events_path.display());
                return Err(1);
            }
        }
        if INTERRUPTED.load(Ordering::SeqCst) {
            return Err(0);
        }
        thread::sleep(poll_interval);
        if INTERRUPTED.load(Ordering::SeqCst) {
            return Err(0);
        }
    }
}

/// The full `aoide secrets watch` command — foreground, blocks until Ctrl-C or
/// (in the interactive/`--popup` loops) stdin EOF. `events_path`/
/// `socket_path` are resolved ONCE by the caller and passed in (this
/// crate's own `home`/`socket` resolution discipline, `AGENTS.md`) — this
/// function never re-derives either; `events_path` is `socket::events_path`
/// applied to the SAME resolved `socket_path` (P-G4, task #77 — replacing
/// the mirrored `~/Aoide/log` path this parameter carried through P-N3,
/// see module doc for why). `json_mode` forces narration-only regardless of
/// tty (module doc); `popup_mode` (`--popup`, mutually exclusive with
/// `json_mode` — `commands::handle_secrets_watch` refuses the combination
/// before this function is ever called) swaps the tty prompt for a dialog —
/// `lyra secrets ask` when [`resolve_lyra_bin`] finds one, `zenity`
/// otherwise (module doc's P3 section) — and runs regardless of whether
/// stdin is a terminal. See [`select_mode`] for the exact precedence between
/// the three.
pub fn run(socket_path: &Path, events_path: &Path, json_mode: bool, popup_mode: bool) -> i32 {
    let lyra_cmd = resolve_lyra_bin();
    if popup_mode && lyra_cmd.is_none() && !zenity_available(ZENITY_CMD) {
        eprintln!(
            "aoide secrets watch --popup: neither `lyra` nor `zenity` was found \u{2014} install \
             one of them, or run `aoide secrets watch` (without --popup) instead"
        );
        return 1;
    }

    install_sigint_handler();

    let follower = match wait_for_follower(events_path, Duration::from_secs(1)) {
        Ok(f) => f,
        Err(code) => return code,
    };

    let queue = Arc::new(Mutex::new(Queue::new()));
    let out_lock = Arc::new(Mutex::new(()));
    let prompt_frame: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let mode = select_mode(json_mode, popup_mode, client::stdin_is_tty());

    if !json_mode {
        println!("watching secret events \u{2014} ^C to leave (parked asks stay parked)");
        let _ = std::io::stdout().flush();
    }

    // Catch up on any ask already parked before this watcher started
    // (module doc: the tail alone would never see it).
    reconcile_once(socket_path, &queue);

    let tail_handle = {
        let socket_path = socket_path.to_path_buf();
        let queue = Arc::clone(&queue);
        let out_lock = Arc::clone(&out_lock);
        let prompt_frame = Arc::clone(&prompt_frame);
        thread::spawn(move || tail_loop(follower, socket_path, queue, out_lock, prompt_frame, json_mode))
    };

    match mode {
        Mode::Popup => {
            popup_loop(socket_path, &queue, &out_lock, ZENITY_CMD, lyra_cmd.as_deref(), &locker_process_name());
            0
        }
        Mode::InteractiveTty => {
            prompt_loop(socket_path, &queue, &out_lock, &prompt_frame);
            0
        }
        Mode::Json | Mode::NarrationOnly => {
            let _ = tail_handle.join();
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The events-feed line shape (P-G4, task #77): the bare
    /// `emit_notify` payload, verbatim — no `AuditRecord` wrapper. `ts` is
    /// no longer part of the line at all (`parse_notify_line`'s own doc);
    /// it is supplied by the CALLER of `parse_notify_line`, not embedded
    /// here.
    fn notify_line(payload: &Value) -> String {
        payload.to_string()
    }

    // ── parse_notify_line ────────────────────────────────────────────

    #[test]
    fn parses_every_one_of_the_five_event_kinds() {
        let released = json!({ "event": "released", "secret": "aws-ci", "consumer": "melete" });
        assert_eq!(
            parse_notify_line(&notify_line(&released), 1),
            Some(Event::Released { secret: "aws-ci".into(), consumer: "melete".into(), ts: 1 })
        );

        let parked = json!({ "event": "parked", "id": "ab12-1", "secret": "db-prod", "consumer": "claude", "timeoutSecs": 300 });
        assert_eq!(
            parse_notify_line(&notify_line(&parked), 2),
            Some(Event::Parked { id: "ab12-1".into(), secret: "db-prod".into(), consumer: "claude".into(), timeout_secs: 300, ts: 2, reason: None, origin: Default::default() })
        );

        let completed = json!({ "event": "completed", "id": "ab12-1", "secret": "db-prod", "consumer": "claude" });
        assert_eq!(
            parse_notify_line(&notify_line(&completed), 3),
            Some(Event::Completed { id: "ab12-1".into(), secret: "db-prod".into(), consumer: "claude".into(), ts: 3 })
        );

        let dismissed = json!({ "event": "dismissed", "id": "ab12-1", "secret": "db-prod", "consumer": "claude" });
        assert_eq!(
            parse_notify_line(&notify_line(&dismissed), 4),
            Some(Event::Dismissed { id: "ab12-1".into(), secret: "db-prod".into(), consumer: "claude".into(), ts: 4 })
        );

        let expired = json!({ "event": "expired", "id": "ab12-1", "secret": "db-prod", "consumer": "claude" });
        assert_eq!(
            parse_notify_line(&notify_line(&expired), 5),
            Some(Event::Expired { id: "ab12-1".into(), secret: "db-prod".into(), consumer: "claude".into(), ts: 5 })
        );
    }

    /// P3: a `parked` line carrying `reason`/`origin` parses both into the
    /// `Event`; a line WITHOUT either (the pre-P3 shape, an older broker)
    /// still parses cleanly with both defaulted — `parses_every_one_of_the_
    /// five_event_kinds`'s own `parked` case above already covers that half.
    #[test]
    fn parked_carries_reason_and_origin_when_the_broker_sent_them() {
        let parked = json!({
            "event": "parked",
            "id": "ab12-1",
            "secret": "db-prod",
            "consumer": "claude",
            "timeoutSecs": 300,
            "reason": "sudo nixos-rebuild switch",
            "origin": { "username": "khoa", "pid": 4242, "comm": "bash", "hostname": "yomi-strix" },
        });
        let event = parse_notify_line(&notify_line(&parked), 2).unwrap();
        assert_eq!(
            event,
            Event::Parked {
                id: "ab12-1".into(),
                secret: "db-prod".into(),
                consumer: "claude".into(),
                timeout_secs: 300,
                ts: 2,
                reason: Some("sudo nixos-rebuild switch".into()),
                origin: client::PendingOrigin {
                    username: Some("khoa".into()),
                    pid: Some(4242),
                    comm: Some("bash".into()),
                    hostname: Some("yomi-strix".into()),
                },
            }
        );
    }

    // ── format_reason_line / format_origin_line (P3 context lines) ──────

    #[test]
    fn format_reason_line_is_none_when_absent() {
        assert_eq!(format_reason_line(&None), None);
    }

    #[test]
    fn format_reason_line_quotes_and_labels_the_text() {
        assert_eq!(format_reason_line(&Some("sudo nixos-rebuild switch".into())), Some("for: \"sudo nixos-rebuild switch\"".into()));
    }

    #[test]
    fn format_origin_line_is_none_when_every_field_is_unknown() {
        assert_eq!(format_origin_line(&client::PendingOrigin::default()), None);
    }

    #[test]
    fn format_origin_line_renders_every_known_field() {
        let origin = client::PendingOrigin {
            username: Some("khoa".into()),
            pid: Some(4242),
            comm: Some("bash".into()),
            hostname: Some("yomi-strix".into()),
        };
        assert_eq!(format_origin_line(&origin), Some("from: khoa \u{b7} bash (pid 4242) @ yomi-strix".into()));
    }

    #[test]
    fn format_origin_line_degrades_to_unidentified_when_only_the_hostname_is_known() {
        // A totally unidentified peer (`peercred::peer_cred` itself failed)
        // still yields a hostname (`capture_origin`'s own doc, broker.rs) —
        // this proves the degraded rendering never produces a bare "from:"
        // with nothing after the label.
        let origin = client::PendingOrigin { hostname: Some("yomi-strix".into()), ..Default::default() };
        assert_eq!(format_origin_line(&origin), Some("from: unidentified @ yomi-strix".into()));
    }

    /// `age-identity-minted` (P-G1) is the one `emit_notify` kind this
    /// parser has never recognized — it carries no `secret`/`consumer`
    /// field at all, so it falls out on the `?` right after `kind` is
    /// read, same as before this phase.
    #[test]
    fn an_age_identity_minted_line_is_skipped() {
        let line = json!({ "event": "age-identity-minted" }).to_string();
        assert_eq!(parse_notify_line(&line, 1), None);
    }

    #[test]
    fn a_line_missing_the_event_field_is_skipped() {
        let line = json!({ "secret": "t", "consumer": "m" }).to_string();
        assert_eq!(parse_notify_line(&line, 1), None);
    }

    #[test]
    fn an_unrecognized_event_kind_is_skipped() {
        let payload = json!({ "event": "something-new", "secret": "t", "consumer": "m" });
        assert_eq!(parse_notify_line(&notify_line(&payload), 1), None);
    }

    #[test]
    fn not_even_valid_json_is_skipped() {
        assert_eq!(parse_notify_line("{{{not json", 1), None);
    }

    // ── Queue::apply / reconcile ─────────────────────────────────────

    #[test]
    fn apply_parked_inserts_and_a_repeat_parked_line_never_duplicates() {
        let mut q = Queue::new();
        let event = Event::Parked { id: "1".into(), secret: "t".into(), consumer: "m".into(), timeout_secs: 300, ts: 100, reason: None, origin: Default::default() };
        q.apply(&event);
        q.apply(&event);
        assert_eq!(q.len(), 1);
        assert_eq!(q.get("1").unwrap().requested_at, 100);
        assert!(!q.get("1").unwrap().estimated);
    }

    #[test]
    fn apply_completed_dismissed_expired_all_remove_by_id() {
        for make in [
            |id: &str| Event::Completed { id: id.into(), secret: "t".into(), consumer: "m".into(), ts: 1 },
            |id: &str| Event::Dismissed { id: id.into(), secret: "t".into(), consumer: "m".into(), ts: 1 },
            |id: &str| Event::Expired { id: id.into(), secret: "t".into(), consumer: "m".into(), ts: 1 },
        ] {
            let mut q = Queue::new();
            q.apply(&Event::Parked { id: "1".into(), secret: "t".into(), consumer: "m".into(), timeout_secs: 300, ts: 0, reason: None, origin: Default::default() });
            assert_eq!(q.len(), 1);
            q.apply(&make("1"));
            assert!(q.is_empty());
        }
    }

    #[test]
    fn an_expired_for_an_unknown_id_is_a_harmless_no_op() {
        let mut q = Queue::new();
        q.apply(&Event::Expired { id: "never-seen".into(), secret: "t".into(), consumer: "m".into(), ts: 1 });
        assert!(q.is_empty());
    }

    #[test]
    fn released_never_touches_the_queue() {
        let mut q = Queue::new();
        q.apply(&Event::Parked { id: "1".into(), secret: "t".into(), consumer: "m".into(), timeout_secs: 300, ts: 0, reason: None, origin: Default::default() });
        q.apply(&Event::Released { secret: "other".into(), consumer: "m".into(), ts: 5 });
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn reconcile_adds_an_ask_the_tail_never_saw_as_an_estimate() {
        let mut q = Queue::new();
        let pending = vec![PendingAsk {
            id: "unseen".into(),
            secret: "t".into(),
            consumer: "m".into(),
            requested_at: 42,
            peer_uid: None,
            reason: None,
            origin: client::PendingOrigin::default(),
        }];
        q.reconcile(&pending, 300);
        let ask = q.get("unseen").unwrap();
        assert_eq!(ask.requested_at, 42);
        assert_eq!(ask.timeout_secs, 300);
        assert!(ask.estimated);
    }

    #[test]
    fn reconcile_drops_an_ask_completed_elsewhere() {
        let mut q = Queue::new();
        q.apply(&Event::Parked { id: "1".into(), secret: "t".into(), consumer: "m".into(), timeout_secs: 300, ts: 0, reason: None, origin: Default::default() });
        assert_eq!(q.len(), 1);
        q.reconcile(&[], 300); // broker no longer lists it as pending
        assert!(q.is_empty());
    }

    #[test]
    fn reconcile_never_downgrades_a_known_timeout_into_an_estimate() {
        let mut q = Queue::new();
        q.apply(&Event::Parked { id: "1".into(), secret: "t".into(), consumer: "m".into(), timeout_secs: 60, ts: 0, reason: None, origin: Default::default() });
        let pending =
            vec![PendingAsk {
                id: "1".into(),
                secret: "t".into(),
                consumer: "m".into(),
                requested_at: 0,
                peer_uid: None,
                reason: None,
                origin: client::PendingOrigin::default(),
            }];
        q.reconcile(&pending, 300);
        let ask = q.get("1").unwrap();
        assert_eq!(ask.timeout_secs, 60);
        assert!(!ask.estimated);
    }

    // ── pick_next (queue ordering) ───────────────────────────────────

    #[test]
    fn pick_next_returns_the_oldest_requested_at_first() {
        let asks = vec![
            Ask { id: "b".into(), secret: "t".into(), consumer: "m".into(), requested_at: 200, timeout_secs: 300, estimated: false, reason: None, origin: Default::default() },
            Ask { id: "a".into(), secret: "t".into(), consumer: "m".into(), requested_at: 100, timeout_secs: 300, estimated: false, reason: None, origin: Default::default() },
        ];
        let picked = pick_next(&asks, &HashSet::new()).unwrap();
        assert_eq!(picked.id, "a");
    }

    #[test]
    fn pick_next_skips_ignored_ids() {
        let asks = vec![
            Ask { id: "a".into(), secret: "t".into(), consumer: "m".into(), requested_at: 100, timeout_secs: 300, estimated: false, reason: None, origin: Default::default() },
            Ask { id: "b".into(), secret: "t".into(), consumer: "m".into(), requested_at: 200, timeout_secs: 300, estimated: false, reason: None, origin: Default::default() },
        ];
        let mut ignored = HashSet::new();
        ignored.insert("a".to_string());
        let picked = pick_next(&asks, &ignored).unwrap();
        assert_eq!(picked.id, "b");
    }

    #[test]
    fn pick_next_on_an_empty_queue_is_none() {
        assert_eq!(pick_next(&[], &HashSet::new()), None);
    }

    // ── code_prompt_allowed (the lockout predicate) ──────────────────

    #[test]
    fn lockout_boundary_is_exactly_ten_seconds_remaining() {
        let ask = |requested_at: u64, timeout_secs: u64| Ask {
            id: "1".into(),
            secret: "t".into(),
            consumer: "m".into(),
            requested_at,
            timeout_secs,
            estimated: false,
            reason: None,
            origin: Default::default(),
        };
        // Exactly 10s remaining: allowed (>=).
        assert!(code_prompt_allowed(&ask(0, 10), 0));
        // 9s remaining: refused.
        assert!(!code_prompt_allowed(&ask(0, 9), 0));
        // Already past due: refused.
        assert!(!code_prompt_allowed(&ask(0, 5), 100));
    }

    // ── narration / --json rendering ─────────────────────────────────

    #[test]
    fn narrate_released_names_secret_and_consumer_never_a_value() {
        let line = narrate_event(&Event::Released { secret: "aws-ci".into(), consumer: "melete".into(), ts: 3600 + 61 });
        assert!(line.contains("released"));
        assert!(line.contains("aws-ci"));
        assert!(line.contains("melete"));
        assert!(line.contains("01:01:01"));
    }

    #[test]
    fn narrate_parked_names_the_id_and_the_countdown() {
        let line = narrate_event(&Event::Parked {
            id: "ab12-1".into(),
            secret: "db-prod".into(),
            consumer: "claude".into(),
            timeout_secs: 300,
            ts: 0,
            reason: None,
            origin: Default::default(),
        });
        assert!(line.contains("ab12-1"));
        assert!(line.contains("5m00s"));
    }

    #[test]
    fn event_to_json_parked_carries_requested_and_expires_at() {
        let v = event_to_json(&Event::Parked {
            id: "ab12-1".into(),
            secret: "db-prod".into(),
            consumer: "claude".into(),
            timeout_secs: 300,
            ts: 1_000,
            reason: None,
            origin: Default::default(),
        });
        assert_eq!(v["event"], "parked");
        assert_eq!(v["id"], "ab12-1");
        assert_eq!(v["timeoutSecs"], 300);
        assert_eq!(v["requestedAt"], 1_000);
        assert_eq!(v["expiresAt"], 1_300);
        assert_eq!(v["ts"], 1_000);
    }

    #[test]
    fn event_to_json_released_carries_no_id_at_all() {
        let v = event_to_json(&Event::Released { secret: "aws-ci".into(), consumer: "melete".into(), ts: 1 });
        assert_eq!(v["event"], "released");
        assert!(v.get("id").is_none());
    }

    #[test]
    fn event_to_json_never_carries_a_value_field_on_any_shape() {
        for event in [
            Event::Released { secret: "t".into(), consumer: "m".into(), ts: 1 },
            Event::Parked { id: "1".into(), secret: "t".into(), consumer: "m".into(), timeout_secs: 1, ts: 1, reason: None, origin: Default::default() },
            Event::Completed { id: "1".into(), secret: "t".into(), consumer: "m".into(), ts: 1 },
            Event::Dismissed { id: "1".into(), secret: "t".into(), consumer: "m".into(), ts: 1 },
            Event::Expired { id: "1".into(), secret: "t".into(), consumer: "m".into(), ts: 1 },
        ] {
            assert!(event_to_json(&event).get("value").is_none());
        }
    }

    // ── Follower (P2, a real growing tempfile) ───────────────────────

    fn tmp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "aoide-secrets-watch-follower-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ))
    }

    #[test]
    fn follower_growth_reads_only_the_delta() {
        let path = tmp_path("growth");
        std::fs::write(&path, b"before this point\n").unwrap();
        let mut f = Follower::open_at_end(&path).unwrap();
        assert_eq!(f.poll().unwrap(), Vec::<String>::new());

        let mut file = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"line one\nline two\n").unwrap();
        assert_eq!(f.poll().unwrap(), vec!["line one".to_string(), "line two".to_string()]);

        file.write_all(b"line three\n").unwrap();
        assert_eq!(f.poll().unwrap(), vec!["line three".to_string()]);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn follower_no_growth_reads_nothing() {
        let path = tmp_path("no-growth");
        std::fs::write(&path, b"x\n").unwrap();
        let mut f = Follower::open_at_end(&path).unwrap();
        assert_eq!(f.poll().unwrap(), Vec::<String>::new());
        assert_eq!(f.poll().unwrap(), Vec::<String>::new());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn follower_truncation_reopens_at_zero() {
        let path = tmp_path("truncate");
        std::fs::write(&path, b"aaaaaaaaaaaaaaaaaaaa\n").unwrap();
        let mut f = Follower::open_at_end(&path).unwrap();
        assert_eq!(f.poll().unwrap(), Vec::<String>::new());

        // Replace with a SHORTER file (simulates truncation/rotation).
        std::fs::write(&path, b"fresh\n").unwrap();
        assert_eq!(f.poll().unwrap(), vec!["fresh".to_string()]);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn follower_survives_delete_and_recreate() {
        // The judge's repro shape: systemd wipes RuntimeDirectory on a
        // broker restart, unlinking the file our open fd still refers to.
        // A brand-new inode is created at the SAME path afterward — the old
        // fd's own `metadata().len()` freezes at whatever it was at
        // deletion and never reflects the new file's growth, so `poll` must
        // notice the path now names a DIFFERENT inode, not just compare
        // lengths.
        let path = tmp_path("delete-recreate");
        std::fs::write(&path, b"before restart\n").unwrap();
        let mut f = Follower::open_at_end(&path).unwrap();
        assert_eq!(f.poll().unwrap(), Vec::<String>::new());

        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"after restart\n").unwrap();
        assert_eq!(
            f.poll().unwrap(),
            vec!["after restart".to_string()],
            "a delete-and-recreate at the same path must not leave the follower deaf"
        );

        // Keep proving it's actually live, not a one-shot recovery.
        let mut file = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"one more\n").unwrap();
        assert_eq!(f.poll().unwrap(), vec!["one more".to_string()]);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn follower_survives_rename_away_and_recreate() {
        let path = tmp_path("rename-away");
        let moved = tmp_path("rename-away-moved");
        std::fs::write(&path, b"before rename\n").unwrap();
        let mut f = Follower::open_at_end(&path).unwrap();
        assert_eq!(f.poll().unwrap(), Vec::<String>::new());

        std::fs::rename(&path, &moved).unwrap();
        std::fs::write(&path, b"after rename\n").unwrap();
        assert_eq!(
            f.poll().unwrap(),
            vec!["after rename".to_string()],
            "a rename-away-and-recreate at the same path must not leave the follower deaf"
        );

        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&moved).ok();
    }

    #[test]
    fn follower_holds_a_partial_trailing_line_until_the_newline_arrives() {
        let path = tmp_path("partial");
        std::fs::write(&path, b"").unwrap();
        let mut f = Follower::open_at_end(&path).unwrap();

        let mut file = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"no newline yet").unwrap();
        assert_eq!(f.poll().unwrap(), Vec::<String>::new(), "a partial line must not be returned early");

        file.write_all(b" - now complete\n").unwrap();
        assert_eq!(f.poll().unwrap(), vec!["no newline yet - now complete".to_string()]);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn follower_open_at_end_skips_pre_existing_content() {
        let path = tmp_path("skip-history");
        std::fs::write(&path, b"history line 1\nhistory line 2\n").unwrap();
        let mut f = Follower::open_at_end(&path).unwrap();
        assert_eq!(f.poll().unwrap(), Vec::<String>::new(), "must never re-read from the start");
        std::fs::remove_file(&path).ok();
    }

    // ── wait_for_follower (review rider: wait, don't exit 1) ─────────

    #[test]
    fn wait_for_follower_blocks_until_the_log_appears_then_opens_it() {
        let path = tmp_path("wait-for-log");
        assert!(!path.exists(), "precondition: the log must not exist yet");
        let path2 = path.clone();
        let writer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(60));
            std::fs::write(&path2, b"hello\n").unwrap();
        });
        let result = wait_for_follower(&path, Duration::from_millis(10));
        writer.join().unwrap();
        assert!(result.is_ok(), "expected wait_for_follower to open the log once it appeared");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn wait_for_follower_returns_ok_immediately_when_the_log_already_exists() {
        let path = tmp_path("wait-for-log-present");
        std::fs::write(&path, b"already here\n").unwrap();
        let result = wait_for_follower(&path, Duration::from_secs(30));
        assert!(result.is_ok());
        std::fs::remove_file(&path).ok();
    }

    // ── select_mode (the popup/tty mode selection, pure) ─────────────

    #[test]
    fn select_mode_json_wins_over_popup_and_tty() {
        assert_eq!(select_mode(true, true, true), Mode::Json);
        assert_eq!(select_mode(true, false, false), Mode::Json);
    }

    #[test]
    fn select_mode_popup_wins_over_tty_detection_when_json_is_absent() {
        assert_eq!(select_mode(false, true, true), Mode::Popup);
        assert_eq!(select_mode(false, true, false), Mode::Popup, "--popup on a non-tty stdin still drives the popup loop");
    }

    #[test]
    fn select_mode_interactive_tty_when_neither_json_nor_popup() {
        assert_eq!(select_mode(false, false, true), Mode::InteractiveTty);
    }

    #[test]
    fn select_mode_narration_only_on_a_pipe_with_no_popup() {
        assert_eq!(select_mode(false, false, false), Mode::NarrationOnly);
    }

    // ── locked_state (the OR logic, injected probes) ─────────────────

    #[test]
    fn locked_state_true_when_loginctl_says_locked() {
        assert!(locked_state(Some(true), false));
    }

    #[test]
    fn locked_state_true_when_the_locker_process_is_running_even_if_loginctl_disagrees() {
        assert!(locked_state(Some(false), true));
    }

    #[test]
    fn locked_state_true_when_loginctl_cant_answer_but_the_locker_process_is_running() {
        assert!(locked_state(None, true));
    }

    #[test]
    fn locked_state_false_when_neither_signal_says_locked() {
        assert!(!locked_state(Some(false), false));
        assert!(!locked_state(None, false));
    }

    // ── popup_action (dialog-allowed gating, pure) ────────────────────

    fn popup_ask(timeout_secs: u64) -> Ask {
        Ask { id: "1".into(), secret: "t".into(), consumer: "m".into(), requested_at: 0, timeout_secs, estimated: false, reason: None, origin: Default::default() }
    }

    #[test]
    fn popup_action_shows_when_unlocked_and_well_within_time() {
        assert_eq!(popup_action(&popup_ask(300), 0, false), PopupAction::Show);
    }

    #[test]
    fn popup_action_waits_for_unlock_when_locked_but_in_time() {
        assert_eq!(popup_action(&popup_ask(300), 0, true), PopupAction::WaitUnlock);
    }

    #[test]
    fn popup_action_refuses_below_the_lockout_regardless_of_lock_state() {
        // 5s remaining is below LOCKOUT_SECS (10) — must never show OR wait,
        // since waiting for an unlock would only spend the time that's left.
        assert_eq!(popup_action(&popup_ask(5), 0, false), PopupAction::TooLateToShow);
        assert_eq!(popup_action(&popup_ask(5), 0, true), PopupAction::TooLateToShow);
    }

    // ── popup_kill_already_open (kill-open near-expiry, pure) ─────────

    #[test]
    fn popup_kill_already_open_is_false_well_within_time() {
        assert!(!popup_kill_already_open(&popup_ask(300), 0));
    }

    #[test]
    fn popup_kill_already_open_boundary_is_exactly_fifteen_seconds_remaining() {
        // Exactly POPUP_KILL_LOCKOUT_SECS (15s) remaining: NOT yet killed
        // (`<`, matching `code_prompt_allowed`'s own `>=` — the two
        // thresholds must never disagree about the boundary second,
        // `popup_kill_already_open`'s own doc).
        assert!(!popup_kill_already_open(&popup_ask(15), 0));
        // One second later (14s remaining): killed.
        assert!(popup_kill_already_open(&popup_ask(14), 0));
    }

    #[test]
    fn popup_kill_already_open_true_once_past_due() {
        assert!(popup_kill_already_open(&popup_ask(5), 100));
    }

    #[test]
    fn popup_kill_threshold_sits_strictly_above_the_before_open_lockout() {
        // The coherence task #76 item 1 asks for: the kill-open threshold
        // must never be BELOW the before-open one, or a dialog could stay
        // open into the window `popup_action` itself would already have
        // refused to open a fresh one in.
        assert!(POPUP_KILL_LOCKOUT_SECS > LOCKOUT_SECS);
    }

    // ── next_spawn_backoff (spawn-retry doubling, pure) ────────────────

    #[test]
    fn next_spawn_backoff_doubles_from_the_floor() {
        assert_eq!(next_spawn_backoff(SPAWN_BACKOFF_INITIAL), Duration::from_secs(2));
        assert_eq!(next_spawn_backoff(Duration::from_secs(2)), Duration::from_secs(4));
        assert_eq!(next_spawn_backoff(Duration::from_secs(4)), Duration::from_secs(8));
    }

    #[test]
    fn next_spawn_backoff_caps_at_the_ceiling_and_never_exceeds_it() {
        assert_eq!(next_spawn_backoff(Duration::from_secs(32)), SPAWN_BACKOFF_MAX);
        assert_eq!(next_spawn_backoff(SPAWN_BACKOFF_MAX), SPAWN_BACKOFF_MAX);
        assert_eq!(next_spawn_backoff(Duration::from_secs(1000)), SPAWN_BACKOFF_MAX);
    }

    // ── zenity_available / run_zenity_entry (fake-zenity shims) ──────
    //
    // Every shim here is a full path handed directly to `run_zenity_entry`/
    // `zenity_available` as `zenity_cmd` — never a `PATH` mutation (module
    // doc: this is exactly why `run`'s `zenity_cmd` parameter exists,
    // distinct from `enroll::render_qr`'s older `PATH`-shim precedent,
    // which needs `env_lock` because `PATH` is process-global and cargo
    // test runs in parallel threads). No `env_lock` needed here for that
    // reason.

    fn write_shim(tag: &str, script: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aoide-secrets-watch-zenity-shim-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let shim = dir.join("zenity-shim");
        std::fs::write(&shim, script).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        thread::sleep(Duration::from_millis(5));
        shim
    }

    fn remove_shim(shim: &Path) {
        if let Some(dir) = shim.parent() {
            std::fs::remove_dir_all(dir).ok();
        }
    }

    /// Serializes every test below that WRITES a shim script and then
    /// immediately EXECS it, against every OTHER such test — diagnosed root
    /// cause of the "Text file busy" flake this lock exists to close (this
    /// commit, reproduced live under `--test-threads` > 1 and confirmed by
    /// instrumenting `write_shim`/`run_zenity_entry` with a shared debug
    /// log): it is NOT a path collision — every shim already gets its own
    /// unique tempdir (`write_shim`'s own doc, `{tag}-{pid}-{nanos}`), and
    /// the instrumented trace caught the failure on a test's OWN
    /// just-written, just-closed, just-chmod'd shim, same thread, same
    /// never-reused path, no second writer anywhere. It is a genuine Linux
    /// `execve()`/`close()` TOCTOU that only manifests under heavy parallel
    /// CPU/scheduler contention (it reproduced readily at
    /// `--test-threads=32`, even restricted to ONLY this module's five
    /// shim tests — i.e. contention among a handful of write-then-exec
    /// pairs is already enough, no unrelated test needed). Two textbook
    /// non-retry fixes were tried and BOTH still reproduced it: giving each
    /// shim a unique name changes nothing (already true here) and
    /// write-close-then-rename doesn't touch the mechanism either — a
    /// rename repoints a directory entry, it does not change the
    /// underlying inode's write-access state, which is what `execve()`
    /// actually checks. What removes the failure, reliably, across dozens
    /// of `--test-threads=32` reruns, is simply not contending: this lock
    /// serializes this module's own write+exec pairs against EACH OTHER,
    /// which is exactly the contention the race needs — the rest of the
    /// suite (everything outside this section) still runs at full
    /// parallelism, and this is a real fix for a real kernel-timing race,
    /// never a retry loop hiding it.
    fn shim_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn zenity_available_is_false_for_a_binary_name_that_does_not_exist() {
        assert!(!zenity_available("aoide-secrets-watch-test-definitely-not-a-real-binary"));
    }

    #[test]
    fn zenity_available_is_true_when_the_shim_spawns_and_exits_zero() {
        let _guard = shim_lock();
        let shim = write_shim("version", "#!/bin/sh\necho zenity 3.99.0\nexit 0\n");
        assert!(zenity_available(shim.to_str().unwrap()));
        remove_shim(&shim);
    }

    #[test]
    fn run_zenity_entry_returns_the_typed_code_on_exit_zero() {
        let _guard = shim_lock();
        let shim = write_shim("approve", "#!/bin/sh\necho 654321\nexit 0\n");
        let result = run_zenity_entry(shim.to_str().unwrap(), "t", "x", || false);
        match result {
            ZenityResult::Approved(code) => assert_eq!(code, "654321"),
            other => panic!("expected Approved(\"654321\"), got {other:?}"),
        }
        remove_shim(&shim);
    }

    #[test]
    fn run_zenity_entry_recognizes_the_dismiss_extra_button_by_its_label() {
        let _guard = shim_lock();
        let shim = write_shim("dismiss", "#!/bin/sh\necho 'Dismiss ask'\nexit 1\n");
        let result = run_zenity_entry(shim.to_str().unwrap(), "t", "x", || false);
        assert!(matches!(result, ZenityResult::Dismissed), "expected Dismissed, got {result:?}");
        remove_shim(&shim);
    }

    #[test]
    fn run_zenity_entry_treats_a_bare_cancel_as_cancelled_not_dismissed() {
        let _guard = shim_lock();
        let shim = write_shim("cancel", "#!/bin/sh\nexit 1\n");
        let result = run_zenity_entry(shim.to_str().unwrap(), "t", "x", || false);
        assert!(matches!(result, ZenityResult::Cancelled), "expected Cancelled, got {result:?}");
        remove_shim(&shim);
    }

    #[test]
    fn run_zenity_entry_reports_a_spawn_error_for_a_nonexistent_shim() {
        // No shim is written here at all (the path is deliberately bogus),
        // so this test never touches `shim_lock` — nothing here can
        // collide with the write/exec race the lock exists to serialize.
        let result = run_zenity_entry("/no/such/aoide-secrets-watch-zenity-shim", "t", "x", || false);
        assert!(matches!(result, ZenityResult::SpawnError(_)), "expected SpawnError, got {result:?}");
    }

    /// P1: the entry dialog is VISIBLE — a TOTP code is a 30-second secret,
    /// not a password, and `--hide-text` was dropped from
    /// `spawn_zenity_entry`'s own argv. Pins the exact argv a real `zenity`
    /// would receive by having the shim log its own `"$@"` before answering,
    /// rather than trusting `spawn_zenity_entry`'s source to stay in sync
    /// with this test by inspection alone.
    #[test]
    fn spawn_zenity_entry_argv_has_no_hide_text() {
        let _guard = shim_lock();
        let shim = write_shim("argv-visible", "#!/bin/sh\necho \"$@\" > \"$(dirname \"$0\")/argv.log\"\necho 654321\nexit 0\n");
        let result = run_zenity_entry(shim.to_str().unwrap(), "aoide \u{b7} db-prod", "code for `db-prod`", || false);
        assert!(matches!(result, ZenityResult::Approved(ref c) if c == "654321"), "expected Approved(\"654321\"), got {result:?}");
        let argv = std::fs::read_to_string(shim.parent().unwrap().join("argv.log")).unwrap();
        assert!(!argv.contains("--hide-text"), "argv must not carry --hide-text, got: {argv}");
        assert!(argv.contains("--entry"), "argv should still carry --entry, got: {argv}");
        remove_shim(&shim);
    }

    /// Review fix: `--text` interpolates untrusted `reason`/`origin.comm`
    /// (P3) and zenity renders `--text` as Pango markup by default, even on
    /// `--entry` (`spawn_zenity_entry`'s own doc, confirmed live against
    /// zenity on this host). `--no-markup` must ride every zenity dialog
    /// this crate ever opens.
    #[test]
    fn spawn_zenity_entry_argv_carries_no_markup() {
        let _guard = shim_lock();
        let shim = write_shim("argv-no-markup", "#!/bin/sh\necho \"$@\" > \"$(dirname \"$0\")/argv.log\"\necho 111111\nexit 0\n");
        let result = run_zenity_entry(shim.to_str().unwrap(), "t", "x", || false);
        assert!(matches!(result, ZenityResult::Approved(_)), "expected Approved, got {result:?}");
        let argv = std::fs::read_to_string(shim.parent().unwrap().join("argv.log")).unwrap();
        assert!(argv.contains("--no-markup"), "argv must carry --no-markup, got: {argv}");
        remove_shim(&shim);
    }

    #[test]
    fn zenity_error_dialog_argv_carries_no_markup() {
        let _guard = shim_lock();
        let shim = write_shim("error-no-markup", "#!/bin/sh\necho \"$@\" > \"$(dirname \"$0\")/argv.log\"\nexit 0\n");
        zenity_error_dialog(shim.to_str().unwrap(), "invalid code for `db-prod`");
        let argv = std::fs::read_to_string(shim.parent().unwrap().join("argv.log")).unwrap();
        assert!(argv.contains("--no-markup"), "argv must carry --no-markup, got: {argv}");
        remove_shim(&shim);
    }

    /// P3: `lyra secrets ask --secret <name> --consumer <who> --seconds <n>`
    /// is the exact argv `spawn_lyra_entry` sends — pinned the same way the
    /// zenity argv test above pins `--hide-text`'s absence.
    #[test]
    fn spawn_lyra_entry_argv_matches_the_documented_contract() {
        let _guard = shim_lock();
        let shim = write_shim("lyra-argv", "#!/bin/sh\necho \"$@\" > \"$(dirname \"$0\")/argv.log\"\necho 111222\nexit 0\n");
        let result = run_lyra_entry(shim.to_str().unwrap(), "db-prod", "claude", 42, None, None, || false);
        assert!(matches!(result, ZenityResult::Approved(ref c) if c == "111222"), "expected Approved(\"111222\"), got {result:?}");
        let argv = std::fs::read_to_string(shim.parent().unwrap().join("argv.log")).unwrap();
        assert_eq!(argv.trim(), "secrets ask --secret db-prod --consumer claude --seconds 42");
        remove_shim(&shim);
    }

    /// P3: `--reason`/`--from` ride the SAME argv, present ONLY when the ask
    /// actually carries them — the RAW reason text and the PRE-FORMATTED
    /// origin line respectively (`spawn_lyra_entry`'s own doc on why neither
    /// is reformatted twice).
    #[test]
    fn spawn_lyra_entry_argv_carries_reason_and_from_only_when_present() {
        let _guard = shim_lock();
        let shim = write_shim("lyra-argv-context", "#!/bin/sh\necho \"$@\" > \"$(dirname \"$0\")/argv.log\"\necho 333444\nexit 0\n");
        let result = run_lyra_entry(
            shim.to_str().unwrap(),
            "db-prod",
            "claude",
            42,
            Some("sudo nixos-rebuild switch"),
            Some("from: khoa \u{b7} bash (pid 123) @ yomi-strix"),
            || false,
        );
        assert!(matches!(result, ZenityResult::Approved(ref c) if c == "333444"), "expected Approved(\"333444\"), got {result:?}");
        let argv = std::fs::read_to_string(shim.parent().unwrap().join("argv.log")).unwrap();
        assert_eq!(
            argv.trim(),
            "secrets ask --secret db-prod --consumer claude --seconds 42 --reason sudo nixos-rebuild switch --from from: khoa \u{b7} bash (pid 123) @ yomi-strix"
        );
        remove_shim(&shim);
    }

    /// P3: when a `lyra` binary resolves, [`run_ask_dialog`] spawns IT, not
    /// zenity — proven by handing it a deliberately bogus `zenity_cmd` path
    /// alongside a real lyra shim: if the dispatch ever fell through to
    /// zenity by mistake, this would come back `SpawnError`, not `Approved`.
    #[test]
    fn run_ask_dialog_prefers_lyra_when_it_resolves() {
        let _guard = shim_lock();
        let lyra_shim = write_shim("dialog-lyra", "#!/bin/sh\necho lyra-picked\nexit 0\n");
        let result = run_ask_dialog(
            Some(lyra_shim.to_str().unwrap()),
            "/no/such/aoide-secrets-watch-zenity-shim",
            "db-prod",
            "claude",
            42,
            "t",
            "x",
            None,
            None,
            || false,
        );
        assert!(matches!(result, ZenityResult::Approved(ref c) if c == "lyra-picked"), "expected the lyra shim's own output, got {result:?}");
        remove_shim(&lyra_shim);
    }

    /// P3: with no `lyra` resolved, [`run_ask_dialog`] falls back to zenity
    /// exactly as before this phase.
    #[test]
    fn run_ask_dialog_falls_back_to_zenity_when_lyra_is_absent() {
        let _guard = shim_lock();
        let zenity_shim = write_shim("dialog-zenity", "#!/bin/sh\necho zenity-picked\nexit 0\n");
        let result = run_ask_dialog(None, zenity_shim.to_str().unwrap(), "db-prod", "claude", 42, "t", "x", None, None, || false);
        assert!(matches!(result, ZenityResult::Approved(ref c) if c == "zenity-picked"), "expected the zenity shim's own output, got {result:?}");
        remove_shim(&zenity_shim);
    }

    /// P1: `run()`'s own startup reconcile (`reconcile_once`, called before
    /// the tail thread ever spawns — module doc, the same call site the live
    /// incident this phase's brief cites traced back to a watcher that
    /// simply wasn't RUNNING, not to a missing reconcile) surfaces an ask
    /// that was already parked before this watcher process started, using
    /// nothing but a fake broker answering ONE `pending` request — the exact
    /// call `reconcile_once` makes, never the tail/events-feed path at all.
    #[test]
    fn reconcile_once_surfaces_an_ask_already_pending_at_startup() {
        let dir = std::env::temp_dir().join(format!(
            "aoide-secrets-watch-reconcile-startup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let sock_path = dir.join("secrets.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();

        let server = thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let mut reader = std::io::BufReader::new(&stream);
                let mut line = String::new();
                let _ = reader.read_line(&mut line);
                let reply = json!({
                    "ok": true,
                    "pending": [{
                        "id": "preexisting-1",
                        "secret": "db-prod",
                        "consumer": "claude",
                        "requestedAt": 100,
                        "peerUid": Value::Null,
                    }]
                });
                let _ = writeln!(&stream, "{reply}");
            }
        });

        let queue = Mutex::new(Queue::new());
        reconcile_once(&sock_path, &queue);
        server.join().unwrap();

        let q = queue.lock().unwrap_or_else(|e| e.into_inner());
        let ask = q.get("preexisting-1").expect("a pre-existing pending ask must be reconciled into the queue at startup");
        assert_eq!(ask.secret, "db-prod");
        assert_eq!(ask.consumer, "claude");
        assert!(ask.estimated, "an ask reconciled with no prior `parked` event has an ESTIMATED timeout");
        drop(q);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Proves the "kill by its EXACT pid" mechanism (module doc,
    /// [`ZenityResult::CancelledExternally`]): a shim that sleeps far longer
    /// than this test's own timeout must still be killed and this call must
    /// still return promptly, once `should_cancel` starts returning `true`
    /// — never left waiting out the shim's own sleep.
    #[test]
    fn run_zenity_entry_kills_the_exact_child_when_the_ask_resolves_elsewhere() {
        let _guard = shim_lock();
        let shim = write_shim("longsleep", "#!/bin/sh\nsleep 30\necho should-not-appear\nexit 0\n");
        let mut polls = 0u32;
        let start = std::time::Instant::now();
        let result = run_zenity_entry(shim.to_str().unwrap(), "t", "x", || {
            polls += 1;
            polls >= 2 // cancel on the second poll tick, well before the 30s sleep would finish
        });
        let elapsed = start.elapsed();
        assert!(matches!(result, ZenityResult::CancelledExternally), "expected CancelledExternally, got {result:?}");
        assert!(elapsed < Duration::from_secs(10), "should_cancel should have killed the sleeping shim promptly, took {elapsed:?}");
        remove_shim(&shim);
    }

    /// Task #76 item 1: an ALREADY-OPEN popup must be killed once its ask
    /// crosses into its last `POPUP_KILL_LOCKOUT_SECS` unresolved — never
    /// left open to bake a stale "Ns left" past the point a typed code
    /// could still land safely. This drives `run_zenity_entry` with the
    /// EXACT closure shape `popup_loop` itself builds (vanished-from-queue
    /// OR near-expiry, `popup_loop`'s own doc) against an ask that is
    /// ALREADY inside the kill window from the very first poll — proving
    /// the near-expiry half fires even though the ask never left the
    /// queue at all (the queue-vanished half is covered separately by
    /// `popup_kills_the_dialog_when_the_ask_vanishes_via_reconcile_not_an_event`
    /// below).
    #[test]
    fn popup_closure_kills_an_already_open_dialog_once_it_crosses_the_kill_lockout() {
        let _guard = shim_lock();
        let shim = write_shim("nearexpiry", "#!/bin/sh\nsleep 30\necho should-not-appear\nexit 0\n");

        let queue: Arc<Mutex<Queue>> = Arc::new(Mutex::new(Queue::new()));
        // 12s remaining: inside POPUP_KILL_LOCKOUT_SECS (15) but still
        // above the before-open LOCKOUT_SECS (10) — a dialog for this ask
        // COULD have opened a moment ago and must now be killed, never a
        // case `popup_action` would have refused to open in the first
        // place (that's a different, already-covered path).
        let now = unix_now();
        queue.lock().unwrap().apply(&Event::Parked {
            id: "1".into(),
            secret: "t".into(),
            consumer: "m".into(),
            timeout_secs: 12,
            ts: now,
            reason: None,
            origin: Default::default(),
        });
        let ask = queue.lock().unwrap().get("1").unwrap().clone();
        assert!(code_prompt_allowed(&ask, now), "precondition: still above the before-open lockout");
        assert!(popup_kill_already_open(&ask, now), "precondition: already inside the kill-open window");

        let cancel_queue = Arc::clone(&queue);
        let start = std::time::Instant::now();
        let result = run_zenity_entry(shim.to_str().unwrap(), "t", "x", || {
            cancel_queue.lock().unwrap_or_else(|e| e.into_inner()).get("1").is_none() || popup_kill_already_open(&ask, unix_now())
        });
        let elapsed = start.elapsed();

        assert!(matches!(result, ZenityResult::CancelledExternally), "expected CancelledExternally, got {result:?}");
        assert!(elapsed < Duration::from_secs(10), "the near-expiry kill should fire promptly, took {elapsed:?}");
        // The ask itself is untouched by this — it stays parked, still
        // completable from another terminal (`popup_loop`'s own doc: this
        // predicate only decides whether to kill the DIALOG, never the ask).
        assert!(queue.lock().unwrap().get("1").is_some(), "the ask itself must remain parked");

        remove_shim(&shim);
    }

    /// Task #76 item 2 (Opus-judge deferral from P-N2, "phantom-ask
    /// reaping"): an ask that vanishes from `pending` with NO feed event at
    /// all (a broker restart wiped the park registry, or an event line was
    /// lost) must not leave a popup dialog up forever. `Queue::reconcile`
    /// already drops such an ask on its own
    /// (`reconcile_drops_an_ask_completed_elsewhere`, above) — THIS test
    /// pins that the POPUP PATH actually acts on that removal: the exact
    /// closure shape `popup_loop` hands to `run_zenity_entry` must react to
    /// a `reconcile`-driven removal (an empty `pending` list, never an
    /// `Event::Completed`/`Dismissed`/`Expired`) exactly the same way it
    /// reacts to an explicit event.
    #[test]
    fn popup_kills_the_dialog_when_the_ask_vanishes_via_reconcile_not_an_event() {
        let _guard = shim_lock();
        let shim = write_shim("phantom", "#!/bin/sh\nsleep 30\necho should-not-appear\nexit 0\n");

        let queue: Arc<Mutex<Queue>> = Arc::new(Mutex::new(Queue::new()));
        queue.lock().unwrap().apply(&Event::Parked {
            id: "1".into(),
            secret: "t".into(),
            consumer: "m".into(),
            timeout_secs: 300,
            ts: unix_now(),
            reason: None,
            origin: Default::default(),
        });
        assert_eq!(queue.lock().unwrap().len(), 1);

        let reconciler_queue = Arc::clone(&queue);
        let reconciler = thread::spawn(move || {
            thread::sleep(Duration::from_millis(150));
            // The phantom-ask scenario itself: `pending` no longer lists
            // the ask (broker restart / lost line) and NO `Event` of any
            // kind fires for it — `reconcile` is the only thing that ever
            // learns about this.
            reconciler_queue.lock().unwrap_or_else(|e| e.into_inner()).reconcile(&[], 300);
        });

        let cancel_queue = Arc::clone(&queue);
        let start = std::time::Instant::now();
        let result = run_zenity_entry(shim.to_str().unwrap(), "t", "x", || {
            cancel_queue.lock().unwrap_or_else(|e| e.into_inner()).get("1").is_none()
        });
        let elapsed = start.elapsed();
        reconciler.join().unwrap();

        assert!(matches!(result, ZenityResult::CancelledExternally), "expected CancelledExternally, got {result:?}");
        assert!(elapsed < Duration::from_secs(10), "a phantom-ask reconcile should kill the dialog promptly, took {elapsed:?}");
        assert!(queue.lock().unwrap().get("1").is_none(), "the phantom ask must stay gone from the queue");

        remove_shim(&shim);
    }

    // ── wait_for_follower: permission error vs NotFound ────────────────

    /// Task #76 item 4: a NotFound open waits and narrates
    /// (`wait_for_follower_blocks_until_the_log_appears_then_opens_it`,
    /// above) — a PERMISSION error must instead fail IMMEDIATELY
    /// (`Err(1)`), never wait, since waiting would only mislead when the
    /// file exists but can't be read (`wait_for_follower`'s own doc). Root
    /// ignores file permissions, so this skips under a root test runner —
    /// same precedent `an_unreadable_policy_json_teaches_the_chown_
    /// reference_fix_on_both_gates` (`broker.rs`) sets.
    #[test]
    fn wait_for_follower_fails_immediately_on_a_permission_error_never_waiting() {
        if crate::home::effective_uid() == 0 {
            return;
        }
        let path = tmp_path("wait-for-log-perm-denied");
        std::fs::write(&path, b"x\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

        let start = std::time::Instant::now();
        // A deliberately LONG poll interval: if this incorrectly treated
        // PermissionDenied as NotFound-and-wait, the test would hang for
        // up to this long instead of returning immediately.
        let result = wait_for_follower(&path, Duration::from_secs(30));
        let elapsed = start.elapsed();

        // Restore before cleanup can remove the tempfile.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).ok();

        assert_eq!(result.err(), Some(1), "a permission error must fail immediately (Err(1)), never wait");
        assert!(elapsed < Duration::from_secs(5), "must not have waited at all, took {elapsed:?}");

        std::fs::remove_file(&path).ok();
    }
}
