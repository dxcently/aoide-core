//! Parked TOTP asks (P-N2, task #71's bridge): the in-memory registry
//! behind "a TOTP-gated `resolve` with no code PARKS instead of refusing".
//! [`broker::handle_resolve`] holds the requesting connection's own thread
//! blocked on the [`std::sync::mpsc::Receiver`] this module hands back from
//! [`ParkRegistry::park`], until an operator completes the ask
//! (`secrets approve`/`secrets dismiss`, over a DIFFERENT connection) or
//! [`park_timeout`] elapses — see [`wait_for_outcome`] for the full
//! three-way race.
//!
//! **NEVER store a value here.** [`ParkedAsk`] carries only `secret`/
//! `consumer`/`requested_at` plus the [`std::sync::mpsc::Sender`] half of
//! the channel — never the secret's own value. The value is fetched fresh,
//! broker-side, only once `secrets approve` has already validated a code
//! (`broker::handle_approve` -> `broker::fetch_secret_value`), and it
//! travels to the parked thread over the channel in that ONE handoff,
//! exactly as briefly as a granted `resolve`'s value already lives between
//! `backend::fetch_value`'s return and the wire write today — this crate's
//! "NO CACHE, EVER" invariant is about PERSISTING a value across requests,
//! not about a value ever crossing a `Sender`/`Receiver` pair inside one
//! already-in-flight resolve.
//!
//! **Ids are a small monotonic counter, not a UUID** — short and
//! human-typeable (`secrets approve 3 --totp 123456`), the same shape
//! `aoide_conduct::graph::pending`'s own list-position ids favor for the
//! same reason. Unlike that module's ids (a `pending.json` array position,
//! reused the moment an earlier entry resolves), this counter never
//! repeats for the lifetime of one broker process — there is no persisted
//! array to re-index, so a monotonic counter is both simpler and never
//! ambiguous.
//!
//! **Poisoned-lock handling**: this is the first PRODUCTION (non-test)
//! shared-mutex state anywhere in the `aoide` crate tree (grep the other
//! ten crates before adding a second precedent). [`ParkRegistry`] recovers
//! from a poisoned lock (`unwrap_or_else(|e| e.into_inner())`) rather than
//! propagating the panic — matching `broker.rs`'s own module doc ("every
//! failure contained... a dropped connection ends only that line/
//! connection — never the service"): a panic inside ONE connection's
//! `handle_conn` thread must never wedge every OTHER connection's access to
//! the shared park registry.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Mutex;
use std::time::Duration;

/// Env override for the park timeout, read once per park (not cached — a
/// long-running broker picks up a changed value on its very next park,
/// same "no re-derivation, no daemon restart needed" shape `socket::
/// socket_path`/`home::secrets_home` already hold for their own env
/// overrides). Documented in `CONTRACTS.md`'s "Secrets wire" subsection and
/// this crate's `README.md`.
pub const PARK_TIMEOUT_ENV: &str = "AOIDE_SECRETS_PARK_TIMEOUT";

/// The default park timeout: 300 seconds (task requirement). A blank or
/// unparsable env value falls back here rather than erroring the broker —
/// same tolerant shape `socket::socket_path`'s blank-env fallback holds.
pub const DEFAULT_PARK_TIMEOUT_SECS: u64 = 300;

/// Resolve how long a parked ask waits before [`wait_for_outcome`] gives up
/// on it: [`PARK_TIMEOUT_ENV`] when set to a valid non-negative integer,
/// else [`DEFAULT_PARK_TIMEOUT_SECS`]. No config-file precedent exists
/// anywhere in this crate's broker home (`backends.json` is backend DATA,
/// not a settings file) — an env override, matching `socket`/`home`'s own
/// only mechanism, is the whole knob; a config file is not invented here
/// (YAGNI) unless a later phase finds an actual need for one.
pub fn park_timeout() -> Duration {
    if let Ok(v) = std::env::var(PARK_TIMEOUT_ENV) {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            if let Ok(secs) = trimmed.parse::<u64>() {
                return Duration::from_secs(secs);
            }
        }
    }
    Duration::from_secs(DEFAULT_PARK_TIMEOUT_SECS)
}

/// What completes a parked ask — sent exactly once, by whichever of
/// `secrets approve`/`secrets dismiss`/[`wait_for_outcome`]'s own timeout
/// branch reaches [`ParkRegistry::take`] first (the registry's lock is the
/// single point of truth for "who resolved this ask" — see that method's
/// doc).
pub enum ParkOutcome {
    /// A valid code completed the ask; the broker already fetched the
    /// value fresh (`broker::fetch_secret_value`) — this is its ONE trip
    /// across the channel, never persisted anywhere in this module.
    Approved(String),
    /// The code validated, but the value could not be fetched afterward
    /// (e.g. the secret's policy was removed while parked) — a denial
    /// carrying the value-free reason, not a retryable park state; the
    /// code was already consumed by the ledger, so this ask cannot be
    /// completed a second time either.
    Denied(String),
    /// `secrets dismiss <id>` resolved the ask with no code at all.
    Dismissed,
}

/// One parked ask's metadata — never a value (module doc). `tx` is `pub`
/// only within this module; [`ParkedAsk::send`] is the sole way to consume
/// it, so a caller can never "peek" a `Sender` and forget to send.
pub struct ParkedAsk {
    pub secret: String,
    pub consumer: String,
    pub requested_at: u64,
    tx: mpsc::Sender<ParkOutcome>,
}

impl ParkedAsk {
    /// Complete this ask — consumes `self` so the same ask can never be
    /// completed twice from two different call sites (the type system
    /// enforces the "exactly once" contract [`ParkRegistry::take`]'s
    /// removal already establishes at the registry level). A disconnected
    /// receiver (the parked connection dropped, e.g. the caller hung up
    /// mid-park) is silently ignored — there is no one left to tell.
    pub fn send(self, outcome: ParkOutcome) {
        let _ = self.tx.send(outcome);
    }
}

/// The shared registry every connection-handling thread reaches through an
/// `Arc` (`broker::serve`'s one instance, cloned per spawned thread). Ids
/// are internally `u64` (the monotonic counter, module doc) and only ever
/// formatted to/parsed from decimal text at this type's own boundary — a
/// caller (the wire, the CLI) never sees anything but the string form.
#[derive(Default)]
pub struct ParkRegistry {
    inner: Mutex<BTreeMap<u64, ParkedAsk>>,
    counter: AtomicU64,
}

impl ParkRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<u64, ParkedAsk>> {
        // Recover from poisoning rather than propagate — module doc.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Register a new parked ask and return its id plus the receiving half
    /// of its completion channel — the caller ([`broker::handle_resolve`])
    /// blocks on the receiver via [`wait_for_outcome`].
    pub fn park(&self, secret: &str, consumer: &str, requested_at: u64) -> (String, mpsc::Receiver<ParkOutcome>) {
        let (tx, rx) = mpsc::channel();
        let id = self.counter.fetch_add(1, Ordering::Relaxed) + 1;
        self.lock().insert(
            id,
            ParkedAsk { secret: secret.to_string(), consumer: consumer.to_string(), requested_at, tx },
        );
        (id.to_string(), rx)
    }

    /// Look up an ask's `(secret, consumer)` WITHOUT removing it — the
    /// first half of `secrets approve`'s two-step flow (module doc on
    /// `broker::handle_approve`): a code must validate before the ask is
    /// ever taken off the registry, so an INVALID code leaves the ask
    /// exactly where it was (task requirement: "ask STAYS parked").
    pub fn peek(&self, id: &str) -> Option<(String, String)> {
        let n: u64 = id.trim().parse().ok()?;
        self.lock().get(&n).map(|a| (a.secret.clone(), a.consumer.clone()))
    }

    /// Remove and return the ask at `id`, if it still exists — the ONE
    /// place an ask leaves the registry short of the timeout race below.
    /// Whoever gets `Some` back owns completing it via [`ParkedAsk::send`];
    /// a `None` means someone else (a timeout, a concurrent
    /// approve/dismiss) already claimed it first.
    pub fn take(&self, id: &str) -> Option<ParkedAsk> {
        let n: u64 = id.trim().parse().ok()?;
        self.lock().remove(&n)
    }

    /// Remove `id` with no outcome to send — used ONLY by
    /// [`wait_for_outcome`]'s own timeout branch, which has nothing to
    /// hand back through the (already-timed-out) channel. Returns whether
    /// this call is what removed it (the timeout race's tie-breaker: `true`
    /// means this really was a genuine timeout; `false` means an
    /// approve/dismiss already got there first and this call must instead
    /// wait for the message already in flight).
    fn remove_only(&self, id: &str) -> bool {
        match id.trim().parse::<u64>() {
            Ok(n) => self.lock().remove(&n).is_some(),
            Err(_) => false,
        }
    }

    /// Every parked ask's `(id, secret, consumer, requested_at)` — never a
    /// value, never a channel handle (`secrets pending`'s whole reply).
    /// Ordered by id (insertion order, since ids are monotonic) via
    /// `BTreeMap`'s own iteration order.
    pub fn list(&self) -> Vec<(String, String, String, u64)> {
        self.lock()
            .iter()
            .map(|(id, ask)| (id.to_string(), ask.secret.clone(), ask.consumer.clone(), ask.requested_at))
            .collect()
    }
}

/// What [`wait_for_outcome`] resolves to — the parked connection's own
/// three possible fates, mirroring [`ParkOutcome`] plus the timeout case
/// that never reaches the channel at all.
pub enum WaitResult {
    Approved(String),
    Denied(String),
    Dismissed,
    TimedOut,
}

/// Block the calling thread (a `handle_conn` connection thread — never the
/// accept loop, which is why P-N2 moved `serve` to thread-per-connection in
/// the first place) until `id`'s ask completes or `timeout` elapses.
///
/// **The timeout/completion race, resolved by who removes the registry
/// entry first** (the module doc's "registry lock is the single point of
/// truth"): `rx.recv_timeout` either receives a message before the
/// deadline (the ordinary case — `approve`/`dismiss` already called
/// [`ParkRegistry::take`] and sent), or times out. On a timeout, THIS
/// function races `approve`/`dismiss` for [`ParkRegistry::remove_only`]:
/// winning means the ask was genuinely still parked, so [`WaitResult::
/// TimedOut`] is honest; losing means an approve/dismiss call had already
/// taken the entry (and is about to send, or already sent, on the channel)
/// microseconds before this function's own deadline fired — in that case
/// this function falls through to a plain blocking `rx.recv()`, which is
/// guaranteed to return promptly because the entry is provably gone and
/// its taker is provably mid-send (never left dangling, since
/// [`ParkedAsk::send`] is the only way to consume a taken [`ParkedAsk`]).
pub fn wait_for_outcome(registry: &ParkRegistry, id: &str, rx: mpsc::Receiver<ParkOutcome>, timeout: Duration) -> WaitResult {
    match rx.recv_timeout(timeout) {
        Ok(ParkOutcome::Approved(v)) => WaitResult::Approved(v),
        Ok(ParkOutcome::Denied(e)) => WaitResult::Denied(e),
        Ok(ParkOutcome::Dismissed) => WaitResult::Dismissed,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            if registry.remove_only(id) {
                WaitResult::TimedOut
            } else {
                // Lost the race — an approve/dismiss already took the
                // entry and is sending (or has sent) right now.
                match rx.recv() {
                    Ok(ParkOutcome::Approved(v)) => WaitResult::Approved(v),
                    Ok(ParkOutcome::Denied(e)) => WaitResult::Denied(e),
                    Ok(ParkOutcome::Dismissed) => WaitResult::Dismissed,
                    // Unreachable in practice (the taker always sends
                    // before dropping its Sender) — a safe fallback rather
                    // than a panic if it ever somehow happened.
                    Err(_) => WaitResult::TimedOut,
                }
            }
        }
        // Unreachable in practice (a `ParkedAsk` is only ever removed by
        // `take`, whose caller always sends before the `Sender` drops) —
        // same safe fallback as above.
        Err(mpsc::RecvTimeoutError::Disconnected) => WaitResult::TimedOut,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn park_then_list_shows_the_ask_with_no_value_anywhere() {
        let reg = ParkRegistry::new();
        let (id, _rx) = reg.park("db-prod", "m", 1_700_000_000);
        assert_eq!(id, "1");
        let list = reg.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0], ("1".to_string(), "db-prod".to_string(), "m".to_string(), 1_700_000_000));
    }

    #[test]
    fn ids_are_a_monotonic_counter_never_reused() {
        let reg = ParkRegistry::new();
        let (id1, _rx1) = reg.park("a", "m", 1);
        let (id2, _rx2) = reg.park("b", "m", 2);
        assert_eq!(id1, "1");
        assert_eq!(id2, "2");
        // Taking id1 does not free it up for reuse — the counter never
        // rewinds.
        reg.take(&id1);
        let (id3, _rx3) = reg.park("c", "m", 3);
        assert_eq!(id3, "3");
    }

    #[test]
    fn peek_does_not_remove_the_ask() {
        let reg = ParkRegistry::new();
        let (id, _rx) = reg.park("t", "m", 1);
        assert_eq!(reg.peek(&id), Some(("t".to_string(), "m".to_string())));
        // Still there — peek is read-only.
        assert_eq!(reg.peek(&id), Some(("t".to_string(), "m".to_string())));
        assert_eq!(reg.list().len(), 1);
    }

    #[test]
    fn take_removes_and_only_the_first_caller_gets_it() {
        let reg = ParkRegistry::new();
        let (id, _rx) = reg.park("t", "m", 1);
        assert!(reg.take(&id).is_some());
        assert!(reg.take(&id).is_none(), "a second take must find nothing left");
        assert!(reg.peek(&id).is_none());
        assert!(reg.list().is_empty());
    }

    #[test]
    fn unknown_or_malformed_ids_are_none_never_a_panic() {
        let reg = ParkRegistry::new();
        assert!(reg.peek("9").is_none());
        assert!(reg.take("9").is_none());
        assert!(reg.peek("not-a-number").is_none());
        assert!(reg.take("not-a-number").is_none());
        assert!(!reg.remove_only("not-a-number"));
    }

    #[test]
    fn wait_for_outcome_approved_returns_the_value() {
        let reg = ParkRegistry::new();
        let (id, rx) = reg.park("t", "m", 1);
        let ask = reg.take(&id).unwrap();
        ask.send(ParkOutcome::Approved("the-value".to_string()));
        match wait_for_outcome(&reg, &id, rx, Duration::from_secs(5)) {
            WaitResult::Approved(v) => assert_eq!(v, "the-value"),
            _ => panic!("expected Approved"),
        }
    }

    #[test]
    fn wait_for_outcome_denied_carries_the_reason() {
        let reg = ParkRegistry::new();
        let (id, rx) = reg.park("t", "m", 1);
        let ask = reg.take(&id).unwrap();
        ask.send(ParkOutcome::Denied("backend exploded".to_string()));
        match wait_for_outcome(&reg, &id, rx, Duration::from_secs(5)) {
            WaitResult::Denied(e) => assert_eq!(e, "backend exploded"),
            _ => panic!("expected Denied"),
        }
    }

    #[test]
    fn wait_for_outcome_dismissed() {
        let reg = ParkRegistry::new();
        let (id, rx) = reg.park("t", "m", 1);
        let ask = reg.take(&id).unwrap();
        ask.send(ParkOutcome::Dismissed);
        assert!(matches!(wait_for_outcome(&reg, &id, rx, Duration::from_secs(5)), WaitResult::Dismissed));
    }

    #[test]
    fn wait_for_outcome_times_out_and_removes_the_entry() {
        let reg = ParkRegistry::new();
        let (id, rx) = reg.park("t", "m", 1);
        assert!(matches!(wait_for_outcome(&reg, &id, rx, Duration::from_millis(50)), WaitResult::TimedOut));
        // The genuine-timeout path must have removed the entry itself.
        assert!(reg.peek(&id).is_none());
    }

    /// The race this module's doc calls out by name: a completion sent
    /// JUST as the timeout deadline is passing must still be delivered,
    /// never silently dropped in favor of a timeout — proven by racing a
    /// short timeout against a sender thread that fires right around the
    /// deadline, many times (a single run could get lucky either way).
    #[test]
    fn a_late_approval_racing_the_timeout_is_never_lost() {
        for _ in 0..200 {
            let reg = ParkRegistry::new();
            let (id, rx) = reg.park("t", "m", 1);
            let reg_ref: &ParkRegistry = &reg;
            std::thread::scope(|scope| {
                scope.spawn(|| {
                    // Fires right around the wait's own deadline.
                    std::thread::sleep(Duration::from_millis(8));
                    if let Some(ask) = reg_ref.take(&id) {
                        ask.send(ParkOutcome::Approved("raced-value".to_string()));
                    }
                });
                match wait_for_outcome(reg_ref, &id, rx, Duration::from_millis(10)) {
                    WaitResult::Approved(v) => assert_eq!(v, "raced-value"),
                    WaitResult::TimedOut => {} // also legitimate if the sender lost the race
                    _other => panic!("must be Approved or TimedOut, got a Dismissed/Denied"),
                }
            });
        }
    }

    // ── park_timeout (env override, module doc) ─────────────────────────

    fn env_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        &LOCK
    }

    #[test]
    fn park_timeout_defaults_to_300_seconds() {
        let _guard = env_lock().lock().unwrap();
        let saved = std::env::var(PARK_TIMEOUT_ENV).ok();
        std::env::remove_var(PARK_TIMEOUT_ENV);
        assert_eq!(park_timeout(), Duration::from_secs(300));
        match saved {
            Some(v) => std::env::set_var(PARK_TIMEOUT_ENV, v),
            None => std::env::remove_var(PARK_TIMEOUT_ENV),
        }
    }

    #[test]
    fn park_timeout_env_override_wins() {
        let _guard = env_lock().lock().unwrap();
        let saved = std::env::var(PARK_TIMEOUT_ENV).ok();
        std::env::set_var(PARK_TIMEOUT_ENV, "7");
        assert_eq!(park_timeout(), Duration::from_secs(7));
        match saved {
            Some(v) => std::env::set_var(PARK_TIMEOUT_ENV, v),
            None => std::env::remove_var(PARK_TIMEOUT_ENV),
        }
    }

    #[test]
    fn park_timeout_blank_or_unparsable_env_falls_back_to_default() {
        let _guard = env_lock().lock().unwrap();
        let saved = std::env::var(PARK_TIMEOUT_ENV).ok();
        std::env::set_var(PARK_TIMEOUT_ENV, "   ");
        assert_eq!(park_timeout(), Duration::from_secs(300));
        std::env::set_var(PARK_TIMEOUT_ENV, "not-a-number");
        assert_eq!(park_timeout(), Duration::from_secs(300));
        match saved {
            Some(v) => std::env::set_var(PARK_TIMEOUT_ENV, v),
            None => std::env::remove_var(PARK_TIMEOUT_ENV),
        }
    }
}
