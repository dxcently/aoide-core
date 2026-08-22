//! `aoide secrets watch` — a foreground, line-mode terminal surface (design
//! doc: tracker #71 Part 1) that tail-follows the mirrored aoide log,
//! narrates every broker event, and — when stdin is a terminal and `--json`
//! is absent — prompts inline for each parked ask: approve with a hidden
//! TOTP code, dismiss it outright, or ignore it (leaving it parked for any
//! other terminal). This is the sixth I/O-carrying module in the crate
//! (`AGENTS.md`'s "I/O is confined to six named modules" invariant, updated
//! there in the same commit as this file) — `broker`/`client`/`store`/
//! `backend`/`enroll` are the other five.
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
//! reason). [`Follower`] is the one piece of real file I/O (tail-follow
//! `AGENTS.md`'s mirrored-log discipline: open once, seek to EOF, delta
//! reads only — the log is tens of MB and unrotated, so this NEVER re-reads
//! from the start). [`run`] wires both together behind two threads sharing
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// ── P1: the pure fold ───────────────────────────────────────────────────

/// One broker notification, parsed from a mirrored-log line — the exact
/// five shapes `broker::emit_notify` writes (crate `README.md`'s "Broker
/// notifications"). `ts` is the OUTER `AuditRecord`'s own timestamp (the
/// instant the broker wrote the line), reused as `requestedAt` for a
/// freshly-seen `Parked` ask — the notify fires right at park time, so the
/// two are the same instant in practice.
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

/// Parse ONE mirrored-log line into an [`Event`] — pure, total, and never
/// panics. Filters to `class == "secret" && command == "secrets.notify"`
/// (every other line, e.g. a `graph.session.hook` audit line, returns
/// `None`); the `message` field rides as a JSON *string* on the wire
/// (`AuditRecord::message: String`), so it is parsed as JSON itself, never
/// regex-matched. A malformed line — bad outer JSON, bad inner JSON, an
/// unrecognized `event` kind, a missing required field — returns `None`
/// rather than erroring; the caller (the tail loop) skips it and moves on,
/// same posture as every other log consumer in this crate.
pub fn parse_notify_line(line: &str) -> Option<Event> {
    let record: Value = serde_json::from_str(line).ok()?;
    if record.get("class").and_then(Value::as_str) != Some("secret") {
        return None;
    }
    if record.get("command").and_then(Value::as_str) != Some("secrets.notify") {
        return None;
    }
    let ts = record.get("ts").and_then(Value::as_u64)?;
    let message = record.get("message").and_then(Value::as_str)?;
    let payload: Value = serde_json::from_str(message).ok()?;
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
/// the start (module doc: the mirrored log is tens of MB, unrotated, and
/// churns constantly from every agent tool call's own `graph.session.hook`
/// line). A partial trailing line (no `\n` yet) is held across polls, never
/// parsed early.
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
/// a prompt is currently open — reprint its header underneath so the
/// operator's own open prompt is never lost in the scrollback (design
/// doc's "1.3 Signal flow").
fn emit_event(event: &Event, json_mode: bool, out_lock: &Mutex<()>, queue: &Mutex<Queue>, prompt_header: &Mutex<Option<String>>) {
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
    if let Some(header) = prompt_header.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        println!();
        println!("{header}");
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

fn tail_loop(mut follower: Follower, socket_path: PathBuf, queue: Arc<Mutex<Queue>>, out_lock: Arc<Mutex<()>>, prompt_header: Arc<Mutex<Option<String>>>, json_mode: bool) -> ! {
    let mut ticks_since_reconcile: u32 = 0;
    loop {
        if INTERRUPTED.load(Ordering::SeqCst) {
            print_farewell(&queue, &out_lock);
            std::process::exit(0);
        }
        match follower.poll() {
            Ok(lines) => {
                for line in lines {
                    let Some(event) = parse_notify_line(&line) else { continue };
                    {
                        let mut q = queue.lock().unwrap_or_else(|e| e.into_inner());
                        q.apply(&event);
                    }
                    emit_event(&event, json_mode, &out_lock, &queue, &prompt_header);
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

fn clear_header(prompt_header: &Mutex<Option<String>>) {
    *prompt_header.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// The interactive prompt loop — main thread only, only when stdin is a
/// terminal and `--json` is absent (module doc). Picks the next un-ignored
/// ask ([`pick_next`], oldest `requested_at` first), opens its prompt
/// block, and reads ONE line for `[a]`/`[d]`/`[i]` — never raw single-key
/// (design doc's "1.5 Prompt flow": works over ssh, no terminal-state
/// restoration risk).
fn prompt_loop(socket_path: &Path, queue: &Arc<Mutex<Queue>>, out_lock: &Arc<Mutex<()>>, prompt_header: &Arc<Mutex<Option<String>>>) {
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
        {
            let _g = out_lock.lock().unwrap_or_else(|e| e.into_inner());
            *prompt_header.lock().unwrap_or_else(|e| e.into_inner()) = Some(header.clone());
            println!();
            println!("{header}");
            if closed {
                println!("\u{2502} too little time left to type a code safely \u{2014} [d] dismiss  [i] ignore");
            } else {
                println!("\u{2502} [a] approve (enter code)   [d] dismiss the ask   [i] ignore (stays parked)");
            }
            print!("\u{2514} > ");
            let _ = std::io::stdout().flush();
        }

        let mut line = String::new();
        let read = std::io::stdin().lock().read_line(&mut line);
        match read {
            Ok(0) | Err(_) => {
                clear_header(prompt_header);
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
        clear_header(prompt_header);
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

/// The full `aoide secrets watch` verb — foreground, blocks until Ctrl-C or
/// (in the interactive prompt) stdin EOF. `audit_log`/`socket_path` are
/// resolved ONCE by the caller and passed in (this crate's own
/// `home`/`socket` resolution discipline, `AGENTS.md`) — this function
/// never re-derives either. `json_mode` forces narration-only regardless of
/// tty (module doc); otherwise narration-only is whatever
/// `client::stdin_is_tty` says.
pub fn run(socket_path: &Path, audit_log: &Path, json_mode: bool) -> i32 {
    let follower = match Follower::open_at_end(audit_log) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("aoide secrets watch: opening {}: {e}", audit_log.display());
            return 1;
        }
    };

    install_sigint_handler();

    let queue = Arc::new(Mutex::new(Queue::new()));
    let out_lock = Arc::new(Mutex::new(()));
    let prompt_header: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let interactive = !json_mode && client::stdin_is_tty();

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
        let prompt_header = Arc::clone(&prompt_header);
        thread::spawn(move || tail_loop(follower, socket_path, queue, out_lock, prompt_header, json_mode))
    };

    if interactive {
        prompt_loop(socket_path, &queue, &out_lock, &prompt_header);
        0
    } else {
        let _ = tail_handle.join();
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notify_line(ts: u64, kind: &str, payload: &Value) -> String {
        json!({
            "ts": ts,
            "door": "daemon",
            "class": "secret",
            "command": "secrets.notify",
            "status": kind,
            "message": payload.to_string(),
        })
        .to_string()
    }

    // ── parse_notify_line ────────────────────────────────────────────

    #[test]
    fn parses_every_one_of_the_five_event_kinds() {
        let released = json!({ "event": "released", "secret": "aws-ci", "consumer": "melete" });
        assert_eq!(
            parse_notify_line(&notify_line(1, "released", &released)),
            Some(Event::Released { secret: "aws-ci".into(), consumer: "melete".into(), ts: 1 })
        );

        let parked = json!({ "event": "parked", "id": "ab12-1", "secret": "db-prod", "consumer": "claude", "timeoutSecs": 300 });
        assert_eq!(
            parse_notify_line(&notify_line(2, "parked", &parked)),
            Some(Event::Parked { id: "ab12-1".into(), secret: "db-prod".into(), consumer: "claude".into(), timeout_secs: 300, ts: 2 })
        );

        let completed = json!({ "event": "completed", "id": "ab12-1", "secret": "db-prod", "consumer": "claude" });
        assert_eq!(
            parse_notify_line(&notify_line(3, "completed", &completed)),
            Some(Event::Completed { id: "ab12-1".into(), secret: "db-prod".into(), consumer: "claude".into(), ts: 3 })
        );

        let dismissed = json!({ "event": "dismissed", "id": "ab12-1", "secret": "db-prod", "consumer": "claude" });
        assert_eq!(
            parse_notify_line(&notify_line(4, "dismissed", &dismissed)),
            Some(Event::Dismissed { id: "ab12-1".into(), secret: "db-prod".into(), consumer: "claude".into(), ts: 4 })
        );

        let expired = json!({ "event": "expired", "id": "ab12-1", "secret": "db-prod", "consumer": "claude" });
        assert_eq!(
            parse_notify_line(&notify_line(5, "expired", &expired)),
            Some(Event::Expired { id: "ab12-1".into(), secret: "db-prod".into(), consumer: "claude".into(), ts: 5 })
        );
    }

    #[test]
    fn a_graph_session_hook_line_is_ignored() {
        let line = json!({
            "ts": 1, "door": "cli", "class": "audit", "command": "graph.session.hook",
            "status": "ok", "message": "hook fired",
        })
        .to_string();
        assert_eq!(parse_notify_line(&line), None);
    }

    #[test]
    fn a_malformed_message_is_skipped_not_fatal() {
        let line = json!({
            "ts": 1, "door": "daemon", "class": "secret", "command": "secrets.notify",
            "status": "parked", "message": "not valid json at all {{{",
        })
        .to_string();
        assert_eq!(parse_notify_line(&line), None);
    }

    #[test]
    fn an_unrecognized_event_kind_is_skipped() {
        let payload = json!({ "event": "something-new", "secret": "t", "consumer": "m" });
        assert_eq!(parse_notify_line(&notify_line(1, "something-new", &payload)), None);
    }

    #[test]
    fn not_even_valid_outer_json_is_skipped() {
        assert_eq!(parse_notify_line("{{{not json"), None);
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
}
