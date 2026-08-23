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
//! **`--popup` (tracker #71 Part 2, this commit)** swaps the tty prompt for
//! a `zenity --entry --hide-text` dialog on each parked ask — the CHILD's
//! own stdout pipe carries the typed code straight into [`client::approve`],
//! never argv (`Command::new`'s args carry only prompt TEXT, never the
//! code). `zenity` is a runtime shell-out declared BY NAME (the plugin
//! philosophy, root `AGENTS.md` house rule 7) — zero new Cargo dependencies,
//! same feature-detection shape `enroll::render_qr` already uses for
//! `qrencode`. Popups are UNLOCK-GATED ([`locked_state`]: `loginctl
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
//! popup, stays a reasonable LATER addition as a consumer of this verb's
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
use std::fs::File;
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
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
    Parked { id: String, secret: String, consumer: String, timeout_secs: u64, ts: u64 },
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
            Some(Event::Parked { id, secret, consumer, timeout_secs, ts })
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
            Event::Parked { id, secret, consumer, timeout_secs, ts } => {
                if !self.asks.iter().any(|a| &a.id == id) {
                    self.asks.push(Ask {
                        id: id.clone(),
                        secret: secret.clone(),
                        consumer: consumer.clone(),
                        requested_at: *ts,
                        timeout_secs: *timeout_secs,
                        estimated: false,
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
/// mid-flight).
pub const LOCKOUT_SECS: i64 = 10;

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

// ── narration + `--json` rendering (pure) ───────────────────────────────

fn hms(ts: u64) -> String {
    let s = ts % 86_400;
    format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
}

fn mmss(remaining_secs: i64) -> String {
    let r = remaining_secs.max(0);
    format!("{}m{:02}s", r / 60, r % 60)
}

/// Render one [`Event`] as a single narration line (interactive/piped
/// text mode) — never a value, ever (module doc).
pub fn narrate_event(event: &Event) -> String {
    match event {
        Event::Released { secret, consumer, ts } => {
            format!("  {}  released    {secret} \u{2192} {consumer}   (no code required)", hms(*ts))
        }
        Event::Parked { id, secret, consumer, timeout_secs, ts } => {
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
        Event::Parked { id, secret, consumer, timeout_secs, ts } => json!({
            "event": "parked",
            "id": id,
            "secret": secret,
            "consumer": consumer,
            "timeoutSecs": timeout_secs,
            "requestedAt": ts,
            "expiresAt": ts + timeout_secs,
            "ts": ts,
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
/// the start. As of P-G4 (task #77) this follows the broker-owned events
/// feed, capped at 1 MiB and truncated back to empty IN PLACE rather than
/// rotated (`broker::append_events_feed`'s own doc) — the `len() < pos`
/// branch below is what makes that truncation transparent to a live
/// watcher, reopening at 0 the same way it would for any other shrink. A
/// partial trailing line (no `\n` yet) is held across polls, never parsed
/// early.
pub struct Follower {
    path: PathBuf,
    file: File,
    pos: u64,
    partial: String,
}

impl Follower {
    /// Open `path`, seek to its CURRENT end, and start following from
    /// there — history before this call is never read.
    pub fn open_at_end(path: &Path) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        Ok(Self { path: path.to_path_buf(), file, pos: len, partial: String::new() })
    }

    /// One poll: `stat(2)` the file, and if it grew, read exactly the new
    /// bytes and return every COMPLETE line found (a trailing partial line
    /// is held for the next poll). No growth returns an empty `Vec` — no
    /// read syscall at all. `len() < pos` means the file was truncated or
    /// replaced (a rotation) — reopen and start again from 0 rather than
    /// sit at a now-meaningless offset forever.
    pub fn poll(&mut self) -> std::io::Result<Vec<String>> {
        let len = self.file.metadata()?.len();
        if len < self.pos {
            self.file = File::open(&self.path)?;
            self.pos = 0;
            self.partial.clear();
        }
        let len = self.file.metadata()?.len();
        if len == self.pos {
            return Ok(Vec::new());
        }
        self.file.seek(SeekFrom::Start(self.pos))?;
        let mut buf = Vec::new();
        (&self.file).take(len - self.pos).read_to_end(&mut buf)?;
        self.pos += buf.len() as u64;
        self.partial.push_str(&String::from_utf8_lossy(&buf));

        let mut lines = Vec::new();
        while let Some(idx) = self.partial.find('\n') {
            let line: String = self.partial.drain(..=idx).collect();
            lines.push(line.trim_end_matches('\n').to_string());
        }
        Ok(lines)
    }
}

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

fn spawn_zenity_entry(zenity_cmd: &str, title: &str, text: &str) -> std::io::Result<Child> {
    Command::new(zenity_cmd)
        .args(["--entry", "--hide-text", "--title", title, "--text", text, "--extra-button", DISMISS_LABEL])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
}

/// Run one zenity code-entry dialog to completion, polling every 200ms
/// between the dialog's own exit and `should_cancel()` — the mechanism
/// behind [`ZenityResult::CancelledExternally`] (module doc): `should_cancel`
/// is the caller's own "is this ask still in the queue?" check, so an ask
/// that resolves on another terminal while this dialog sits open gets its
/// EXACT child killed via the `Child` handle this function already holds
/// (never a re-derived pid, never a name match) rather than left orphaned
/// on screen for an ask that no longer exists.
fn run_zenity_entry(zenity_cmd: &str, title: &str, text: &str, mut should_cancel: impl FnMut() -> bool) -> ZenityResult {
    let mut child = match spawn_zenity_entry(zenity_cmd, title, text) {
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

/// A brief `zenity --error`, shown after a wrong code (design doc: "show a
/// brief zenity --error ... and re-offer"). Blocks until the user closes it
/// — deliberately no `--timeout`, so the message is never dismissed before
/// it's read; the ask stays parked underneath regardless of how long this
/// sits open, same as the tty path's own wrong-code retry.
fn zenity_error_dialog(zenity_cmd: &str, text: &str) {
    let _ = Command::new(zenity_cmd)
        .args(["--error", "--text", text])
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

/// The `--popup` loop — main thread only, mirrors [`prompt_loop`]'s own
/// shape (pick the next un-ignored ask, act, repeat) but drives a zenity
/// dialog instead of reading `[a]`/`[d]`/`[i]` from stdin. `ignored` is the
/// SAME "Cancel/close stops re-prompting for THIS ask, this session only"
/// semantics `[i]` holds in [`prompt_loop`] (design doc: "Cancel/close =
/// IGNORE") — without it, a cancelled dialog would reopen every ~200ms
/// forever.
fn popup_loop(socket_path: &Path, queue: &Arc<Mutex<Queue>>, out_lock: &Arc<Mutex<()>>, zenity_cmd: &str, locker_process: &str) {
    let mut ignored: HashSet<String> = HashSet::new();
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

        let title = format!("aoide \u{b7} {}", ask.secret);
        let text = format!("code for `{}` \u{2190} {} \u{00b7} {}s left", ask.secret, ask.consumer, ask.remaining(now).max(0));

        let cancel_queue = Arc::clone(queue);
        let cancel_id = ask.id.clone();
        let result =
            run_zenity_entry(zenity_cmd, &title, &text, || cancel_queue.lock().unwrap_or_else(|e| e.into_inner()).get(&cancel_id).is_none());

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
                if approved.is_err() {
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
                let _g = out_lock.lock().unwrap_or_else(|e| e.into_inner());
                println!("  ask {} resolved elsewhere while its popup was open \u{2014} closing the dialog", ask.id);
            }
            ZenityResult::SpawnError(e) => {
                let _g = out_lock.lock().unwrap_or_else(|e2| e2.into_inner());
                println!("  aoide secrets watch --popup: spawning zenity for ask {}: {e}", ask.id);
                drop(_g);
                thread::sleep(Duration::from_secs(1));
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
    format!("\u{250c} ask {} \u{2500} {} \u{2190} {} \u{2500} asked {asked} \u{2500} {left}{tail}", ask.id, ask.secret, ask.consumer)
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

/// The full `aoide secrets watch` verb — foreground, blocks until Ctrl-C or
/// (in the interactive/`--popup` loops) stdin EOF. `events_path`/
/// `socket_path` are resolved ONCE by the caller and passed in (this
/// crate's own `home`/`socket` resolution discipline, `AGENTS.md`) — this
/// function never re-derives either; `events_path` is `socket::events_path`
/// applied to the SAME resolved `socket_path` (P-G4, task #77 — replacing
/// the mirrored `~/Aoide/log` path this parameter carried through P-N3,
/// see module doc for why). `json_mode` forces narration-only regardless of
/// tty (module doc); `popup_mode` (`--popup`, mutually exclusive with
/// `json_mode` — `commands::handle_secrets_watch` refuses the combination
/// before this function is ever called) swaps the tty prompt for a zenity
/// dialog and runs regardless of whether stdin is a terminal. See
/// [`select_mode`] for the exact precedence between the three.
pub fn run(socket_path: &Path, events_path: &Path, json_mode: bool, popup_mode: bool) -> i32 {
    if popup_mode && !zenity_available(ZENITY_CMD) {
        eprintln!(
            "aoide secrets watch --popup: `zenity` not found on PATH \u{2014} install zenity, or run \
             `aoide secrets watch` (without --popup) instead"
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
            popup_loop(socket_path, &queue, &out_lock, ZENITY_CMD, &locker_process_name());
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
            Some(Event::Parked { id: "ab12-1".into(), secret: "db-prod".into(), consumer: "claude".into(), timeout_secs: 300, ts: 2 })
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
        let event = Event::Parked { id: "1".into(), secret: "t".into(), consumer: "m".into(), timeout_secs: 300, ts: 100 };
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
            q.apply(&Event::Parked { id: "1".into(), secret: "t".into(), consumer: "m".into(), timeout_secs: 300, ts: 0 });
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
        q.apply(&Event::Parked { id: "1".into(), secret: "t".into(), consumer: "m".into(), timeout_secs: 300, ts: 0 });
        q.apply(&Event::Released { secret: "other".into(), consumer: "m".into(), ts: 5 });
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn reconcile_adds_an_ask_the_tail_never_saw_as_an_estimate() {
        let mut q = Queue::new();
        let pending = vec![PendingAsk { id: "unseen".into(), secret: "t".into(), consumer: "m".into(), requested_at: 42 }];
        q.reconcile(&pending, 300);
        let ask = q.get("unseen").unwrap();
        assert_eq!(ask.requested_at, 42);
        assert_eq!(ask.timeout_secs, 300);
        assert!(ask.estimated);
    }

    #[test]
    fn reconcile_drops_an_ask_completed_elsewhere() {
        let mut q = Queue::new();
        q.apply(&Event::Parked { id: "1".into(), secret: "t".into(), consumer: "m".into(), timeout_secs: 300, ts: 0 });
        assert_eq!(q.len(), 1);
        q.reconcile(&[], 300); // broker no longer lists it as pending
        assert!(q.is_empty());
    }

    #[test]
    fn reconcile_never_downgrades_a_known_timeout_into_an_estimate() {
        let mut q = Queue::new();
        q.apply(&Event::Parked { id: "1".into(), secret: "t".into(), consumer: "m".into(), timeout_secs: 60, ts: 0 });
        let pending = vec![PendingAsk { id: "1".into(), secret: "t".into(), consumer: "m".into(), requested_at: 0 }];
        q.reconcile(&pending, 300);
        let ask = q.get("1").unwrap();
        assert_eq!(ask.timeout_secs, 60);
        assert!(!ask.estimated);
    }

    // ── pick_next (queue ordering) ───────────────────────────────────

    #[test]
    fn pick_next_returns_the_oldest_requested_at_first() {
        let asks = vec![
            Ask { id: "b".into(), secret: "t".into(), consumer: "m".into(), requested_at: 200, timeout_secs: 300, estimated: false },
            Ask { id: "a".into(), secret: "t".into(), consumer: "m".into(), requested_at: 100, timeout_secs: 300, estimated: false },
        ];
        let picked = pick_next(&asks, &HashSet::new()).unwrap();
        assert_eq!(picked.id, "a");
    }

    #[test]
    fn pick_next_skips_ignored_ids() {
        let asks = vec![
            Ask { id: "a".into(), secret: "t".into(), consumer: "m".into(), requested_at: 100, timeout_secs: 300, estimated: false },
            Ask { id: "b".into(), secret: "t".into(), consumer: "m".into(), requested_at: 200, timeout_secs: 300, estimated: false },
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
            Event::Parked { id: "1".into(), secret: "t".into(), consumer: "m".into(), timeout_secs: 1, ts: 1 },
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
        Ask { id: "1".into(), secret: "t".into(), consumer: "m".into(), requested_at: 0, timeout_secs, estimated: false }
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
        shim
    }

    fn remove_shim(shim: &Path) {
        if let Some(dir) = shim.parent() {
            std::fs::remove_dir_all(dir).ok();
        }
    }

    #[test]
    fn zenity_available_is_false_for_a_binary_name_that_does_not_exist() {
        assert!(!zenity_available("aoide-secrets-watch-test-definitely-not-a-real-binary"));
    }

    #[test]
    fn zenity_available_is_true_when_the_shim_spawns_and_exits_zero() {
        let shim = write_shim("version", "#!/bin/sh\necho zenity 3.99.0\nexit 0\n");
        assert!(zenity_available(shim.to_str().unwrap()));
        remove_shim(&shim);
    }

    #[test]
    fn run_zenity_entry_returns_the_typed_code_on_exit_zero() {
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
        let shim = write_shim("dismiss", "#!/bin/sh\necho 'Dismiss ask'\nexit 1\n");
        let result = run_zenity_entry(shim.to_str().unwrap(), "t", "x", || false);
        assert!(matches!(result, ZenityResult::Dismissed), "expected Dismissed, got {result:?}");
        remove_shim(&shim);
    }

    #[test]
    fn run_zenity_entry_treats_a_bare_cancel_as_cancelled_not_dismissed() {
        let shim = write_shim("cancel", "#!/bin/sh\nexit 1\n");
        let result = run_zenity_entry(shim.to_str().unwrap(), "t", "x", || false);
        assert!(matches!(result, ZenityResult::Cancelled), "expected Cancelled, got {result:?}");
        remove_shim(&shim);
    }

    #[test]
    fn run_zenity_entry_reports_a_spawn_error_for_a_nonexistent_shim() {
        let result = run_zenity_entry("/no/such/aoide-secrets-watch-zenity-shim", "t", "x", || false);
        assert!(matches!(result, ZenityResult::SpawnError(_)), "expected SpawnError, got {result:?}");
    }

    /// Proves the "kill by its EXACT pid" mechanism (module doc,
    /// [`ZenityResult::CancelledExternally`]): a shim that sleeps far longer
    /// than this test's own timeout must still be killed and this call must
    /// still return promptly, once `should_cancel` starts returning `true`
    /// — never left waiting out the shim's own sleep.
    #[test]
    fn run_zenity_entry_kills_the_exact_child_when_the_ask_resolves_elsewhere() {
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
}
