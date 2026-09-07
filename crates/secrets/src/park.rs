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
//! human-typeable (`secrets approve 3f2a-3 --totp 123456`), the same shape
//! `aoide_conduct::graph::pending`'s own list-position ids favor for the
//! same reason. Unlike that module's ids (a `pending.json` array position,
//! reused the moment an earlier entry resolves), this counter never
//! repeats for the lifetime of one broker process — there is no persisted
//! array to re-index, so a monotonic counter is both simpler and never
//! ambiguous.
//!
//! **Ids carry a 4-hex-char per-process NONCE prefix (`<nonce>-<n>`, P-N2c
//! FIX 4) — never a bare number.** The counter restarts at 1 on every
//! broker restart; without a nonce, an id an operator is still holding
//! from BEFORE a restart (typed into a terminal, or just slow to act)
//! could silently `approve`/`dismiss` a totally DIFFERENT ask that
//! happened to land on the same bare number after the restart. The nonce
//! ([`random_nonce`], 2 bytes off `/dev/urandom` — the same zero-new-deps
//! precedent `enroll::generate_secret` already holds) is generated ONCE
//! per [`ParkRegistry`] (one per broker process lifetime, `broker::serve`'s
//! own doc), so a stale id from a previous process almost never carries
//! the current process's nonce and is correctly refused as unknown
//! ([`ParkRegistry::peek`]/[`ParkRegistry::take`] parse the id against
//! THIS registry's own nonce, module doc's own boundary) — the existing
//! "unknown pending id" error, not a new error shape.
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
use std::io::Read;
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

/// Env override for the registry-wide max PARKED asks at once (P-N2c FIX
/// 3b — a deploy-blocker hardening, not a normal-path limit): every parked
/// connection holds one `handle_conn` thread open for up to the full park
/// timeout, so an unbounded queue of them is an unbounded thread count.
pub const PARK_CAP_ENV: &str = "AOIDE_SECRETS_PARK_CAP";

/// The default park cap: 32 concurrently parked asks (task requirement).
/// Same tolerant-fallback shape as [`park_timeout`] — a blank/unparsable
/// env value falls back here rather than erroring the broker.
pub const DEFAULT_PARK_CAP: usize = 32;

/// Resolve the registry-wide park cap: [`PARK_CAP_ENV`] when set to a valid
/// positive integer, else [`DEFAULT_PARK_CAP`]. Read once per park attempt,
/// same "no re-derivation, no daemon restart needed" shape [`park_timeout`]
/// already holds.
pub fn park_cap() -> usize {
    if let Ok(v) = std::env::var(PARK_CAP_ENV) {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            if let Ok(cap) = trimmed.parse::<usize>() {
                if cap > 0 {
                    return cap;
                }
            }
        }
    }
    DEFAULT_PARK_CAP
}

/// A 4-hex-char per-process nonce, prefixed onto every id [`ParkRegistry`]
/// hands out (module doc, P-N2c FIX 4) — 2 bytes off `/dev/urandom` (the
/// same zero-new-deps precedent `enroll::generate_secret` already holds;
/// never blocks on Linux once the kernel's CSPRNG is seeded, same
/// justification that function's own doc gives), formatted lowercase hex.
/// Falls back to a fixed `"0000"` on any read failure rather than
/// panicking the broker over a syscall going sideways (`enroll::
/// local_hostname`'s own "never block startup on this" precedent) — this
/// nonce only needs to usually DIFFER across restarts, not resist a
/// determined attacker, so a degraded-but-non-fatal fallback is
/// acceptable, unlike the TOTP secret itself.
fn random_nonce() -> String {
    let mut buf = [0u8; 2];
    match std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut buf)) {
        Ok(()) => format!("{:02x}{:02x}", buf[0], buf[1]),
        Err(_) => "0000".to_string(),
    }
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
///
/// `peer_uid` (task #73) is the ORIGINAL requesting connection's
/// kernel-truth `SO_PEERCRED` uid, stamped ONCE at park time
/// (`ParkRegistry::park_if_room`'s own caller, `broker::handle_resolve`) —
/// `None` when that connection's node cred could not be read
/// (`peercred::peer_cred`'s own "unidentified, never a panic" contract).
/// This is the one fact `broker::handle_dismiss`'s authorization check
/// (#73) is keyed on: an ordinary caller may only dismiss an ask whose
/// STAMPED `peer_uid` matches its OWN connection's node uid, never a
/// self-asserted claim.
pub struct ParkedAsk {
    pub secret: String,
    pub consumer: String,
    pub requested_at: u64,
    pub peer_uid: Option<u32>,
    /// Untrusted, optional, DISPLAY-ONLY context for why this ask exists —
    /// the wire's `resolve.reason` field, self-asserted exactly like
    /// `consumer` (no different honesty story than that field already
    /// carries). Never gates anything, never interpreted as anything but
    /// text a human reads on a dialog/prompt (`broker.rs`'s module doc).
    pub reason: Option<String>,
    /// WHO/WHERE this ask's requesting connection came from, captured ONCE
    /// at park time — see [`AskOrigin`]'s own doc.
    pub origin: AskOrigin,
    tx: mpsc::Sender<ParkOutcome>,
}

/// The "origin line" a popup/prompt surface shows alongside `reason` (P3:
/// "from: `<username>` \u{b7} `<comm>` (pid `<pid>`) @ `<hostname>`") —
/// every field best-effort and DISPLAY-ONLY, never a gate (the raw kernel
/// `uid` on [`ParkedAsk::peer_uid`] is the ONE field here with any
/// authorization weight, and it already lives on `ParkedAsk` directly,
/// unchanged by this struct existing). `username` and `comm` both trace
/// back to `SO_PEERCRED`'s own `uid`/`pid` (`peercred::username_for_uid`/
/// `peercred::read_comm`), captured by the broker at the SAME park-time
/// instant `peer_uid` itself is stamped — a pid can exit and be reused long
/// before an ask resolves or a dialog renders it, so this must never be
/// re-read later. `comm` in particular is PROCESS-CONTROLLED, untrusted
/// text (`prctl(PR_SET_NAME, ...)` lets any process name itself anything) —
/// render it, never interpret it, the same posture `reason`/`consumer`
/// already hold. `hostname` is the broker's OWN host (`enroll::
/// local_hostname`) — constant across every ask on one broker process, but
/// carried per-ask anyway (never assumed by a remote surface) so a future
/// non-local entry point (`AGENTS.md`'s `Policy::remote` note) can name
/// which host actually parked an ask once one exists; today every asker is
/// local, so this is always the same string as the broker's own hostname.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AskOrigin {
    pub username: Option<String>,
    pub pid: Option<i32>,
    pub comm: Option<String>,
    pub hostname: Option<String>,
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
/// formatted to/parsed from `<nonce>-<n>` text at this type's own boundary
/// (`format_id`/`parse_id`) — a caller (the wire, the CLI) never sees
/// anything but the string form.
pub struct ParkRegistry {
    inner: Mutex<BTreeMap<u64, ParkedAsk>>,
    counter: AtomicU64,
    /// This registry's own per-process nonce (module doc, FIX 4) — fixed
    /// for the registry's whole lifetime, generated once in [`Self::new`].
    nonce: String,
}

impl Default for ParkRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ParkRegistry {
    pub fn new() -> Self {
        Self { inner: Mutex::new(BTreeMap::new()), counter: AtomicU64::new(0), nonce: random_nonce() }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<u64, ParkedAsk>> {
        // Recover from poisoning rather than propagate — module doc.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn format_id(&self, n: u64) -> String {
        format!("{}-{n}", self.nonce)
    }

    /// Parse a wire/CLI id string back into this registry's own internal
    /// key — the id must carry THIS registry's exact nonce prefix (module
    /// doc, FIX 4); anything else (malformed, a bare number, a DIFFERENT
    /// process's nonce from before a restart) is `None`, which every
    /// caller below already treats as "unknown pending id" — no new error
    /// shape needed for the stale-id case.
    fn parse_id(&self, id: &str) -> Option<u64> {
        id.trim().strip_prefix(self.nonce.as_str())?.strip_prefix('-')?.parse().ok()
    }

    /// Register a new parked ask and return its id plus the receiving half
    /// of its completion channel — the caller ([`broker::handle_resolve`])
    /// blocks on the receiver via [`wait_for_outcome`]. Uncapped — the
    /// registry-wide limit lives in [`Self::park_if_room`], which this
    /// delegates to with an effectively-unbounded cap; every existing
    /// caller (tests, and any future one with no cap concern) keeps this
    /// simpler unconditional signature.
    pub fn park(&self, secret: &str, consumer: &str, requested_at: u64) -> (String, mpsc::Receiver<ParkOutcome>) {
        self.park_if_room(secret, consumer, requested_at, usize::MAX, None, None, AskOrigin::default())
            .expect("an unbounded park (cap = usize::MAX) must never refuse")
    }

    /// [`Self::park`]'s cap-aware sibling (P-N2c FIX 3b) — `broker::
    /// handle_resolve` is the one production call site, passing
    /// [`park_cap`]'s resolved limit and (task #73) the requesting
    /// connection's own `SO_PEERCRED` uid, stamped onto the [`ParkedAsk`]
    /// for `broker::handle_dismiss`'s later authorization check
    /// (`peer_uid`'s own doc on [`ParkedAsk`]). Checks-then-inserts under
    /// the SAME lock acquisition (never a separate `len()` check followed
    /// by a second locked insert) so two threads racing the last open slot
    /// can never both succeed and overrun the cap by one. Returns `None`
    /// when the registry is already at `cap` — the caller falls back to the
    /// immediate pre-park refusal (the `wait:false` text) rather than
    /// growing the queue further.
    #[allow(clippy::too_many_arguments)]
    pub fn park_if_room(
        &self,
        secret: &str,
        consumer: &str,
        requested_at: u64,
        cap: usize,
        peer_uid: Option<u32>,
        reason: Option<&str>,
        origin: AskOrigin,
    ) -> Option<(String, mpsc::Receiver<ParkOutcome>)> {
        let (tx, rx) = mpsc::channel();
        let mut guard = self.lock();
        if guard.len() >= cap {
            return None;
        }
        let n = self.counter.fetch_add(1, Ordering::Relaxed) + 1;
        guard.insert(
            n,
            ParkedAsk {
                secret: secret.to_string(),
                consumer: consumer.to_string(),
                requested_at,
                peer_uid,
                reason: reason.map(str::to_string),
                origin,
                tx,
            },
        );
        drop(guard);
        Some((self.format_id(n), rx))
    }

    /// Look up an ask's `(secret, consumer, peer_uid)` WITHOUT removing it
    /// — the first half of `secrets approve`'s two-step flow (module doc on
    /// `broker::handle_approve`): a code must validate before the ask is
    /// ever taken off the registry, so an INVALID code leaves the ask
    /// exactly where it was (task requirement: "ask STAYS parked"). Also
    /// the read `broker::handle_dismiss` (task #73) uses to check
    /// authorization BEFORE removing the ask, so a refused dismiss leaves
    /// it exactly where it was too.
    pub fn peek(&self, id: &str) -> Option<(String, String, Option<u32>)> {
        let n = self.parse_id(id)?;
        self.lock().get(&n).map(|a| (a.secret.clone(), a.consumer.clone(), a.peer_uid))
    }

    /// Remove and return the ask at `id`, if it still exists — the ONE
    /// place an ask leaves the registry short of the timeout race below.
    /// Whoever gets `Some` back owns completing it via [`ParkedAsk::send`];
    /// a `None` means someone else (a timeout, a concurrent
    /// approve/dismiss) already claimed it first.
    pub fn take(&self, id: &str) -> Option<ParkedAsk> {
        let n = self.parse_id(id)?;
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
        match self.parse_id(id) {
            Some(n) => self.lock().remove(&n).is_some(),
            None => false,
        }
    }

    /// Every parked ask's `(id, secret, consumer, requested_at, peer_uid,
    /// reason, origin)` — never a value, never a channel handle (`secrets
    /// pending`'s whole reply). `peer_uid` (task #73) is additive over the
    /// pre-#73 shape — the kernel-truth uid stamped at park time, `None`
    /// when it couldn't be read. `reason`/`origin` are additive again — the
    /// wire's optional, self-asserted/best-effort, display-only context
    /// (`ParkedAsk`'s own doc, `AskOrigin`'s own doc). Ordered by the
    /// internal counter (insertion order, since it's monotonic) via
    /// `BTreeMap`'s own iteration order — the nonce prefix is constant
    /// across every entry in one registry, so formatting it on afterward
    /// never disturbs that order.
    pub fn list(&self) -> Vec<(String, String, String, u64, Option<u32>, Option<String>, AskOrigin)> {
        self.lock()
            .iter()
            .map(|(id, ask)| {
                (
                    self.format_id(*id),
                    ask.secret.clone(),
                    ask.consumer.clone(),
                    ask.requested_at,
                    ask.peer_uid,
                    ask.reason.clone(),
                    ask.origin.clone(),
                )
            })
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
/// EXPECTED to return promptly, since the entry is provably gone and its
/// taker is committed to eventually sending (never left dangling, since
/// [`ParkedAsk::send`] is the only way to consume a taken [`ParkedAsk`]).
/// **This is an assumption, not a proof, and it can be wrong: the taker on
/// the `approve` path runs a backend shell-out (`broker::
/// fetch_secret_value`) BETWEEN `take` and `send`** — a hung/slow backend
/// command means this `recv()` blocks for as long as that shell-out does,
/// not "promptly." `dismiss`'s taker sends immediately after `take` with
/// no I/O in between, so this gap is `approve`-specific and already
/// narrow (the race window itself is microseconds). **Task #74 bounds it:**
/// every backend shell-out now routes through `backend::run_backend_command`,
/// which kills and reports a wedged template after `backend::
/// backend_timeout()` (default 10s) rather than blocking forever — so this
/// `recv()` is bounded by that same ceiling in the worst case, no longer
/// truly unbounded, even though it is still not "promptly" in the sub-second
/// sense the happy path holds.
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
        // Ids carry a per-process nonce prefix (`<nonce>-<n>`, FIX 4) — not
        // a bare number — so this asserts the SHAPE (a `-` splitting a
        // non-empty nonce from the counter) rather than a literal "1".
        assert!(id.ends_with("-1"), "expected a `<nonce>-1` shaped id, got {id:?}");
        assert!(id.len() > "-1".len(), "the nonce half must be non-empty: {id:?}");
        let list = reg.list();
        assert_eq!(list.len(), 1);
        // `park` (unbounded, no node info) always stamps `None` — only
        // `park_if_room`'s real production caller (`broker::handle_resolve`)
        // ever supplies a node uid.
        assert_eq!(list[0], (id, "db-prod".to_string(), "m".to_string(), 1_700_000_000, None, None, AskOrigin::default()));
    }

    #[test]
    fn ids_are_a_monotonic_counter_never_reused() {
        let reg = ParkRegistry::new();
        let (id1, _rx1) = reg.park("a", "m", 1);
        let (id2, _rx2) = reg.park("b", "m", 2);
        assert!(id1.ends_with("-1"), "{id1:?}");
        assert!(id2.ends_with("-2"), "{id2:?}");
        // Same registry -> same nonce prefix on every id it hands out.
        let nonce1 = id1.strip_suffix("-1").unwrap();
        let nonce2 = id2.strip_suffix("-2").unwrap();
        assert_eq!(nonce1, nonce2, "one registry must use ONE nonce for its whole lifetime");
        // Taking id1 does not free it up for reuse — the counter never
        // rewinds.
        reg.take(&id1);
        let (id3, _rx3) = reg.park("c", "m", 3);
        assert!(id3.ends_with("-3"), "{id3:?}");
    }

    /// A held id carrying a DIFFERENT nonce (e.g. from before a broker
    /// restart) but the SAME numeric suffix must be refused exactly like
    /// any other unknown id, never accidentally matched against the wrong
    /// ask (FIX 4's whole point) — deterministic (flips one hex digit of
    /// the real nonce), not a coin-flip collision test.
    #[test]
    fn a_foreign_or_stale_nonce_prefix_is_unknown_never_misrouted() {
        let reg = ParkRegistry::new();
        let (id, _rx) = reg.park("secret-a", "m", 1);
        let (real_nonce, suffix) = id.rsplit_once('-').unwrap();
        let mut chars: Vec<char> = real_nonce.chars().collect();
        chars[0] = if chars[0] == '0' { '1' } else { '0' };
        let foreign_id = format!("{}-{suffix}", chars.into_iter().collect::<String>());
        assert_ne!(foreign_id, id);
        assert!(reg.peek(&foreign_id).is_none(), "a foreign-nonce id must never resolve, even with the right suffix");
        assert!(reg.take(&foreign_id).is_none());
        // The genuine id still works.
        assert!(reg.peek(&id).is_some());
    }

    #[test]
    fn park_if_room_refuses_beyond_the_cap_and_admits_again_after_a_take() {
        let reg = ParkRegistry::new();
        assert!(reg.park_if_room("a", "m", 1, 2, None, None, AskOrigin::default()).is_some());
        assert!(reg.park_if_room("b", "m", 2, 2, None, None, AskOrigin::default()).is_some());
        assert!(reg.park_if_room("c", "m", 3, 2, None, None, AskOrigin::default()).is_none(), "a third park must refuse at cap 2");
        assert_eq!(reg.list().len(), 2);

        // Freeing one slot (a take, as approve/dismiss/timeout would do)
        // lets the next park through again.
        let first_id = reg.list().into_iter().next().unwrap().0;
        reg.take(&first_id);
        assert!(reg.park_if_room("d", "m", 4, 2, None, None, AskOrigin::default()).is_some());
    }

    #[test]
    fn peek_does_not_remove_the_ask() {
        let reg = ParkRegistry::new();
        let (id, _rx) = reg.park("t", "m", 1);
        assert_eq!(reg.peek(&id), Some(("t".to_string(), "m".to_string(), None)));
        // Still there — peek is read-only.
        assert_eq!(reg.peek(&id), Some(("t".to_string(), "m".to_string(), None)));
        assert_eq!(reg.list().len(), 1);
    }

    // ── peer_uid (task #73) ─────────────────────────────────────────────

    #[test]
    fn park_if_room_stamps_the_given_node_uid_and_peek_returns_it() {
        let reg = ParkRegistry::new();
        let (id, _rx) = reg.park_if_room("t", "m", 1, usize::MAX, Some(4242), None, AskOrigin::default()).unwrap();
        assert_eq!(reg.peek(&id), Some(("t".to_string(), "m".to_string(), Some(4242))));
        let list = reg.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].4, Some(4242));
    }

    #[test]
    fn park_if_room_stamps_the_given_reason_and_origin_and_list_returns_them() {
        let reg = ParkRegistry::new();
        let origin =
            AskOrigin { username: Some("khoa".into()), pid: Some(4242), comm: Some("bash".into()), hostname: Some("yomi-strix".into()) };
        let (id, _rx) = reg.park_if_room("t", "m", 1, usize::MAX, Some(4242), Some("sudo nixos-rebuild switch"), origin.clone()).unwrap();
        let list = reg.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].0, id);
        assert_eq!(list[0].5, Some("sudo nixos-rebuild switch".to_string()));
        assert_eq!(list[0].6, origin);
    }

    #[test]
    fn park_if_room_with_no_node_uid_stamps_none() {
        let reg = ParkRegistry::new();
        let (id, _rx) = reg.park_if_room("t", "m", 1, usize::MAX, None, None, AskOrigin::default()).unwrap();
        assert_eq!(reg.peek(&id), Some(("t".to_string(), "m".to_string(), None)));
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
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
