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
//! `--popup` (this phase's own arm; not yet built here — see the doc on
//! [`run`]) is REFUSED up front when `zenity` isn't installed, the same
//! "refuse before ever entering popup mode" gate `aoide_secrets::watch::run`
//! already holds for its own two dialog binaries. `--popup`+`--json`
//! together is refused one layer up, by `handle_peer_pair_watch`
//! (`aoide_client::commands`) — the same split `aoide_secrets::commands::
//! handle_secrets_watch`/`aoide_server::commands::handle_events_tail`
//! already hold between "gate the door and the flag combo" (the
//! dispatched handler) and "run the blocking loop" (this module,
//! special-cased in `cli`'s own `run_cli`).

use aoide_protocol::dialog::zenity_available;
use aoide_protocol::feed::Follower;
use serde_json::{json, Value};
use std::io::Write;
use std::path::Path;
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
/// `--popup` mode — `aoide_secrets::watch::ZENITY_CMD`'s exact shape,
/// re-declared here rather than imported (a `&str` constant carries no
/// "no cross-crate copying" weight the way a moved TYPE or FUNCTION does,
/// and `aoide-client` has no reason to depend on `aoide-secrets` for one
/// literal). The confirm-dialog spawn itself (this phase's popup arm)
/// reuses this same constant rather than declaring a second one.
pub(crate) const ZENITY_CMD: &str = "zenity";

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

/// Is `p` actionable RIGHT NOW — worth a `peer pair approve`/(this
/// phase's popup)? An inbound entry only once it carries a SAS (unrevealed
/// means nothing to confirm yet, `approve_inbound`'s own `awaiting-reveal`
/// refusal); an outbound entry only once it reached `awaiting-confirm`
/// (`awaiting-approval` means the PEER hasn't approved yet — nothing on
/// THIS end to confirm, `approve_outbound`'s own refusal).
pub fn actionable(p: &Pending) -> bool {
    match p.direction.as_str() {
        "inbound" => p.sas.is_some(),
        "outbound" => p.state.as_deref() == Some("awaiting-confirm"),
        _ => false,
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
/// installed** — this phase lands the watcher core only; the actual
/// confirm-dialog spawn (P-P5's popup arm, this SAME function, a
/// following change) is what will branch on `popup_mode` past this
/// guard. Until then, `--popup` and a bare invocation behave identically
/// past the guard: both narrate an actionable request rather than
/// popping a dialog — `--popup`'s own dialog is additive, never a
/// prerequisite for a correct, complete watcher.
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

        if last_reconcile.elapsed() >= RECONCILE_INTERVAL {
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
}
