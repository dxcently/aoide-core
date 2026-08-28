//! `peer discover`/`peer invite`'s shared UDP sweep (P-P6 + task #120,
//! `docs/architecture/PAIRING.md`'s "Discovery (advertise-but-locked)"
//! section): bind `0.0.0.0:aoide_storage::advertise::PORT`, listen for a
//! bounded window, validate + dedupe every line heard
//! (`aoide_storage::advertise::parse_and_validate`), and hand back the
//! freshest advertisement per instance plus a count of what was dropped
//! as malformed.
//!
//! **Broadcast needs no join** (task #120's #106 fix — the original
//! multicast group never crossed the User's router): a plain unbound-
//! address bind on the fixed port receives broadcast and unicast
//! datagrams alike, so there is no group membership, no interface
//! pinning, and no multicast-capability probing anywhere in this module.
//!
//! **Discovery is read-only.** This module never writes `state/peers.json`
//! — it doesn't even import `peer_store` for writing anything, only
//! `aoide_storage::advertise` for the wire format. The pairing ceremony
//! (`commands::run_pair_request`, shared by `peer pair request` and `peer
//! invite`) is the only thing in this crate that ever commits a peer
//! record.
//!
//! **No resident listener.** Every call to [`run_sweep`] is one bounded,
//! on-demand sweep that returns once its own deadline passes — the same
//! "hearing is on-demand" stance PAIRING.md states for the feature as a
//! whole.
//!
//! **Pure fold, impure socket** (the same split `aoide-server::a2a`'s own
//! `route`/`handle_connection` holds): [`fold_heard`] is a pure function
//! over one already-validated [`aoide_storage::advertise::Advertisement`],
//! so the dedupe/freshest-wins/bounded-cache logic is unit-testable with
//! no socket at all; [`run_sweep`] is the thin real-I/O wrapper around it.
//! [`resolve_invite_target`] is the same shape one layer up: `peer
//! invite`'s zero/one/many-match resolution against an already-swept
//! [`SweepResult`], pure so its refusal shapes are testable without a real
//! network sweep.

use std::collections::HashMap;
use std::net::{Ipv4Addr, UdpSocket};
use std::time::{Duration, Instant};

use aoide_storage::advertise::{self, Advertisement};

/// The default `--secs` window for `peer discover`/`peer invite` when the
/// caller doesn't override it (PAIRING.md: "listens briefly (default a few
/// seconds)"; the brief: "default ~4").
pub const DEFAULT_SWEEP_SECS: u64 = 4;

/// Hard cap on DISTINCT entries one sweep will hold — the bounded cache
/// (task #120): a hostile LAN box spraying advertisements under endless
/// fabricated names must never grow this fold without limit. Generous for
/// any real fleet; a line arriving once the cap is hit under a NEW key is
/// dropped and counted, exactly like a malformed one.
pub const MAX_HEARD: usize = 64;

/// One advertisement's freshest-seen state, keyed by
/// (`name`, [`src_addr`](Heard::src_addr)).
///
/// `src_addr` is the UDP packet's own source IP (`recv_from`'s
/// `SocketAddr`, `.ip()` only — no port) — an OBSERVATION this process
/// made directly, never a claim the advertiser typed into the wire line
/// (`Advertisement` itself carries no such field and never will: its
/// `host` is the advertiser's CLAIM, kept for display and for composing an
/// `ssh://user@host` marker by name instead of by lease; `src_addr` is the
/// one field on `Heard` that tells the truth about where the packet
/// actually came from, and the address `peer invite` actually uses).
#[derive(Debug, Clone, PartialEq)]
pub struct Heard {
    pub advertisement: Advertisement,
    /// Always a dotted-quad IPv4 literal today: `run_sweep` binds
    /// `Ipv4Addr::UNSPECIFIED`, so `recv_from` can never yield a v6
    /// source.
    pub src_addr: String,
    pub first_heard: String,
    pub last_heard: String,
    pub count: u32,
}

/// The result of one sweep: every distinct (name, source) heard, plus how
/// many raw lines were dropped — malformed, or over the [`MAX_HEARD`]
/// bound — never their content (house rule 4), only the count.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SweepResult {
    pub heard: Vec<Heard>,
    pub dropped: u32,
}

/// Fold ONE already-validated advertisement into `state`, keyed by
/// (`name`, `src_addr`) — pure. Returns `false` (the caller counts a
/// drop) when the key is new and the fold already holds [`MAX_HEARD`]
/// entries. A re-heard key updates `last_heard`/`count` and REPLACES the
/// stored advertisement content (a restarted advertiser may claim a new
/// host/user; the freshest sighting's fields win). Two boxes claiming the
/// same name stay two entries — dedupe never merges by name alone, so an
/// impostor beside the real thing is VISIBLE, and `resolve_invite_target`
/// below calls it ambiguous. `now` is the caller's own timestamp
/// (`aoide_storage::time::now_iso_utc`), threaded in rather than read here
/// so a test can pin exact `first_heard`/`last_heard` values.
fn fold_heard(
    state: &mut HashMap<(String, String), Heard>,
    a: Advertisement,
    src_addr: &str,
    now: &str,
) -> bool {
    let key = (a.name.clone(), src_addr.to_string());
    if let Some(h) = state.get_mut(&key) {
        h.advertisement = a;
        h.last_heard = now.to_string();
        h.count += 1;
        return true;
    }
    if state.len() >= MAX_HEARD {
        return false;
    }
    state.insert(
        key,
        Heard {
            advertisement: a,
            src_addr: src_addr.to_string(),
            first_heard: now.to_string(),
            last_heard: now.to_string(),
            count: 1,
        },
    );
    true
}

/// Bind `0.0.0.0:`[`advertise::PORT`] and listen for `secs` seconds,
/// validating and dedupe-folding every line heard
/// ([`advertise::parse_and_validate`]). Real network I/O — a bind failure
/// (the port already bound by another sweep, a network lockdown, …)
/// surfaces as `Err` rather than an empty result, so a caller can tell
/// "heard nothing" apart from "couldn't even listen." Bounded by a short
/// per-read timeout so the deadline is honored even when nothing ever
/// arrives — never a blocking `recv_from` with no timeout at all.
pub fn run_sweep(secs: u64) -> std::io::Result<SweepResult> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, advertise::PORT))?;
    socket.set_read_timeout(Some(Duration::from_millis(200)))?;

    let mut state: HashMap<(String, String), Heard> = HashMap::new();
    let mut dropped = 0u32;
    // checked: `Instant + Duration` panics on overflow, and `secs` is
    // operator input (`--secs`) — an absurd value earns an error, not a crash.
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(secs))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--secs is too large to make a deadline",
            )
        })?;
    let mut buf = [0u8; advertise::MAX_LINE_BYTES + 1];
    while Instant::now() < deadline {
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                let now = aoide_storage::time::now_iso_utc();
                let src_addr = src.ip().to_string();
                let outcome = std::str::from_utf8(&buf[..n]).map_err(|_| ()).and_then(|line| advertise::parse_and_validate(line).map_err(|_| ()));
                match outcome {
                    Ok(a) => {
                        if !fold_heard(&mut state, a, &src_addr, &now) {
                            dropped += 1;
                        }
                    }
                    Err(()) => dropped += 1,
                }
            }
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => continue,
            Err(e) => return Err(e),
        }
    }

    let mut heard: Vec<Heard> = state.into_values().collect();
    heard.sort_by(|a, b| a.advertisement.name.cmp(&b.advertisement.name).then(a.src_addr.cmp(&b.src_addr)));
    Ok(SweepResult { heard, dropped })
}

/// Render one [`run_sweep`] I/O failure as the taught error line `peer
/// discover`/`peer invite` print — one function, so the two handlers never
/// drift apart. The case worth teaching is the fixed port already held
/// (another sweep in flight — sweeps bind the ONE well-known port, by
/// design): the bare errno reads as noise, so name the condition instead
/// of parroting the OS.
pub fn describe_sweep_error(e: &std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::AddrInUse {
        format!(
            "listening for discovery advertisements: UDP port {} is already bound ({e}) — \
             another `peer discover`/`peer invite` sweep is likely in flight on this box; \
             retry when it finishes",
            advertise::PORT
        )
    } else {
        format!("listening for discovery advertisements: {e}")
    }
}

/// Why `peer invite <name>` can't proceed straight to the ceremony —
/// mirrors the shape `handle_peer_pair_request`'s own refusals already
/// take (a reason string plus the taught detail), kept as a typed enum
/// here so the command handler builds the exact `Outcome` shape without
/// re-deriving the message text in two places.
#[derive(Debug, Clone, PartialEq)]
pub enum InviteResolveError {
    NoMatch { heard: Vec<String> },
    Ambiguous { heard: Vec<String> },
}

/// Resolve `<name>` against an already-swept [`SweepResult`] — pure, so
/// `peer invite`'s zero/one/many-match refusal logic is testable with no
/// real socket. Dedupe is by (name, source address) (`run_sweep`'s own
/// fold), so two entries sharing a `name` here are genuinely two different
/// boxes claiming the same nickname — PAIRING.md's own "ambiguous... =
/// taught error" case, not a sweep artifact. `heard` in both error
/// variants lists every name actually heard this sweep (never raw
/// advertisement content beyond the already-validated `name` field —
/// house rule 4).
pub fn resolve_invite_target(heard: &[Heard], name: &str) -> Result<Heard, InviteResolveError> {
    let all_names: Vec<String> = heard.iter().map(|h| h.advertisement.name.clone()).collect();
    let matches: Vec<&Heard> = heard.iter().filter(|h| h.advertisement.name == name).collect();
    match matches.as_slice() {
        [one] => Ok((*one).clone()),
        [] => Err(InviteResolveError::NoMatch { heard: all_names }),
        _ => Err(InviteResolveError::Ambiguous { heard: all_names }),
    }
}

/// Whether `peer invite`'s resolved target is THIS instance — the
/// self-invite guard, checked two independent ways, either sufficient:
/// (1) the heard advertisement's `name` equals this instance's own
/// advertised name (the exact value this box's own `a2a serve` puts on
/// the wire — a broadcast loops back to its own sender, so a box that
/// advertises always hears itself); (2) the observed source address is a
/// bare loopback literal (a datagram that could only have come from this
/// box). The wire deliberately carries no fingerprint (rendezvous, not
/// authentication), so identity-based self-detection is gone WITH it — a
/// same-named impostor that slips past this guard still cannot survive
/// the ceremony's mutual SAS confirmation, which stays the one trust
/// gate. Pure: `own_name` is passed in rather than resolved here so this
/// stays testable with no env dependency.
pub fn is_self_target(heard: &Heard, own_name: &str) -> bool {
    if !own_name.is_empty() && heard.advertisement.name == own_name {
        return true;
    }
    matches!(heard.src_addr.as_str(), "localhost" | "127.0.0.1" | "::1")
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn advertisement(name: &str, host: &str, user: &str) -> Advertisement {
        aoide_storage::advertise::build(name, host, user)
    }

    fn heard(name: &str, src: &str) -> Heard {
        Heard {
            advertisement: advertisement(name, name, "khoa"),
            src_addr: src.into(),
            first_heard: "T0".into(),
            last_heard: "T0".into(),
            count: 1,
        }
    }

    #[test]
    fn fold_heard_dedupes_by_name_and_source_and_keeps_the_freshest_fields() {
        let mut state = HashMap::new();
        assert!(fold_heard(&mut state, advertisement("box-a", "box-a", "khoa"), "192.168.1.10", "2026-08-25T00:00:00Z"));
        let key = ("box-a".to_string(), "192.168.1.10".to_string());
        assert_eq!(state.len(), 1);
        assert_eq!(state[&key].count, 1);
        assert_eq!(state[&key].first_heard, "2026-08-25T00:00:00Z");

        // Re-heard, same name + source, a NEW claimed host/user (the
        // advertiser restarted reconfigured) — freshest fields win, count
        // increments, `first_heard` is untouched.
        assert!(fold_heard(&mut state, advertisement("box-a", "box-a.lan", "agent"), "192.168.1.10", "2026-08-25T00:00:30Z"));
        assert_eq!(state.len(), 1, "same (name, source) never becomes a second entry");
        assert_eq!(state[&key].advertisement.host, "box-a.lan", "freshest host claim wins");
        assert_eq!(state[&key].advertisement.user, "agent", "freshest user claim wins");
        assert_eq!(state[&key].first_heard, "2026-08-25T00:00:00Z", "first_heard is never overwritten");
        assert_eq!(state[&key].last_heard, "2026-08-25T00:00:30Z");
        assert_eq!(state[&key].count, 2);
    }

    #[test]
    fn fold_heard_keeps_two_sources_separate_even_under_the_same_name() {
        // Two DIFFERENT boxes claiming the same nickname — dedupe is by
        // (name, source), never by name alone, so both survive the fold;
        // it's `resolve_invite_target` (below) that later calls this
        // ambiguous.
        let mut state = HashMap::new();
        assert!(fold_heard(&mut state, advertisement("box-a", "real", "khoa"), "192.168.1.10", "T0"));
        assert!(fold_heard(&mut state, advertisement("box-a", "impostor", "khoa"), "192.168.1.66", "T0"));
        assert_eq!(state.len(), 2);
    }

    #[test]
    fn fold_heard_is_bounded_new_keys_past_the_cap_are_refused_but_reheard_keys_still_fold() {
        let mut state = HashMap::new();
        for i in 0..MAX_HEARD {
            assert!(fold_heard(&mut state, advertisement(&format!("box-{i}"), "h", "khoa"), "192.168.1.10", "T0"));
        }
        assert_eq!(state.len(), MAX_HEARD);

        // A hostile flood's next fabricated name is refused — the caller
        // counts it dropped.
        assert!(!fold_heard(&mut state, advertisement("box-flood", "h", "khoa"), "192.168.1.66", "T0"));
        assert_eq!(state.len(), MAX_HEARD);

        // An ALREADY-HELD key still updates at the cap — the bound stops
        // growth, never freshness.
        assert!(fold_heard(&mut state, advertisement("box-0", "h2", "khoa"), "192.168.1.10", "T1"));
        let key = ("box-0".to_string(), "192.168.1.10".to_string());
        assert_eq!(state[&key].count, 2);
        assert_eq!(state[&key].advertisement.host, "h2");
    }

    #[test]
    fn resolve_invite_target_single_match_succeeds() {
        let hits = vec![heard("yomi-strix", "192.168.1.202")];
        let hit = resolve_invite_target(&hits, "yomi-strix").unwrap();
        assert_eq!(hit.advertisement.name, "yomi-strix");
        assert_eq!(hit.src_addr, "192.168.1.202", "resolve_invite_target returns the whole Heard, src_addr included for free");
    }

    #[test]
    fn resolve_invite_target_no_match_lists_every_name_actually_heard() {
        let hits = vec![heard("box-a", "192.168.1.10"), heard("box-b", "192.168.1.11")];
        let err = resolve_invite_target(&hits, "ghost").unwrap_err();
        match err {
            InviteResolveError::NoMatch { heard } => {
                assert_eq!(heard, vec!["box-a".to_string(), "box-b".to_string()]);
            }
            other => panic!("expected NoMatch, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invite_target_empty_sweep_is_also_a_no_match_with_an_empty_heard_list() {
        let err = resolve_invite_target(&[], "anyone").unwrap_err();
        assert_eq!(err, InviteResolveError::NoMatch { heard: vec![] });
    }

    #[test]
    fn resolve_invite_target_ambiguous_when_two_sources_share_a_name() {
        let hits = vec![heard("box-a", "192.168.1.10"), heard("box-a", "192.168.1.66")];
        let err = resolve_invite_target(&hits, "box-a").unwrap_err();
        match err {
            InviteResolveError::Ambiguous { heard } => assert_eq!(heard, vec!["box-a".to_string(), "box-a".to_string()]),
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    #[test]
    fn describe_sweep_error_teaches_the_port_already_bound_condition() {
        // EADDRINUSE — another sweep already holds the one fixed port.
        // Pure string logic, no socket: runs everywhere.
        let e = std::io::Error::from_raw_os_error(98);
        let msg = describe_sweep_error(&e);
        assert!(msg.contains("already bound"), "{msg}");
        assert!(msg.contains(&advertise::PORT.to_string()), "the taught line names the port: {msg}");
    }

    #[test]
    fn describe_sweep_error_passes_an_unrelated_error_through_untaught() {
        let e = std::io::Error::from_raw_os_error(13); // EACCES
        let msg = describe_sweep_error(&e);
        assert!(msg.starts_with("listening for discovery advertisements: "), "{msg}");
        assert!(!msg.contains("already bound"), "{msg}");
    }

    /// Real UDP round trip over the loopback path — runs by default
    /// everywhere, the nix build sandbox included: a datagram sent to
    /// `127.0.0.1:PORT` reaches a `0.0.0.0:PORT` listener with no
    /// broadcast route, no group membership, and no physical interface
    /// involved, which is exactly what the #106 fix bought (the old
    /// multicast join needed ENODEV probe-gating here). The REAL broadcast
    /// self-hear — `send_once`'s `255.255.255.255` datagram arriving back
    /// on the same box — is a live-box check (`docs/architecture/
    /// PAIRING.md`'s "Discovery" section), not something a sandboxed
    /// network namespace can carry.
    ///
    /// This is the shape of test that would have caught task #98: a sender
    /// racing this crate's own `run_sweep` on the same real network stack,
    /// not a mocked socket.
    ///
    /// **#126: takes `env_lock` for its whole body**, the SAME lock
    /// `commands.rs`'s own `peer discover` sweep tests already hold via
    /// `with_peer_state` — all three tests bind the ONE fixed
    /// `advertise::PORT` (there is no ephemeral-port form of this test: it
    /// exists specifically to prove a REAL line sent to the REAL advertised
    /// port is heard, `run_sweep`'s own doc). Without this, `cargo test`'s
    /// default parallel scheduling could run this test concurrently with
    /// either of `commands.rs`'s, both binding the same port, and the loser
    /// panics on a live `EADDRINUSE` — a real production case
    /// (`describe_sweep_error`'s own taught message below), just not one
    /// this crate's own tests should ever manufacture against themselves.
    #[test]
    fn run_sweep_hears_an_advertisement_sent_over_the_real_loopback_stack() {
        let _guard = crate::env_lock().lock().unwrap();
        let sent = advertise::build("test-sender", "test-sender", "khoa");
        let line = advertise::encode(&sent).expect("a well-formed test advertisement always encodes");

        // A background sender racing `run_sweep`'s listen window below —
        // resent on a short tick since we don't know exactly when the sweep
        // starts listening, mirroring `send_once`'s own
        // fresh-socket-per-send shape rather than holding one open.
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sender_stop = stop.clone();
        let sender = std::thread::spawn(move || {
            while !sender_stop.load(std::sync::atomic::Ordering::Relaxed) {
                if let Ok(socket) = UdpSocket::bind(("127.0.0.1", 0)) {
                    let _ = socket.send_to(line.as_bytes(), ("127.0.0.1", advertise::PORT));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });

        let result = run_sweep(3).expect("binding 0.0.0.0 on the fixed port needs no capability a sandbox lacks");
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        sender.join().expect("sender thread must not panic");

        assert_eq!(result.dropped, 0, "every sent line is well-formed and must validate: {result:?}");
        assert!(
            result.heard.iter().any(|h| h.advertisement == sent),
            "expected to hear the advertisement actually sent over the loopback stack in this \
             sweep window; got {:?} — check for another process holding UDP {} before \
             suspecting the socket code",
            result.heard,
            advertise::PORT
        );
        let hit = result.heard.iter().find(|h| h.advertisement == sent).unwrap();
        assert_eq!(hit.src_addr, "127.0.0.1", "src_addr is the packet's OBSERVED source");
    }

    // ── `is_self_target` — the self-invite guard. ────────────────────────

    #[test]
    fn is_self_target_true_when_the_heard_name_is_this_instances_own() {
        assert!(is_self_target(&heard("yomi-strix", "192.168.1.5"), "yomi-strix"));
    }

    #[test]
    fn is_self_target_true_when_the_observed_source_is_loopback() {
        // A different name, but the datagram came from loopback — it could
        // only have originated on this box.
        assert!(is_self_target(&heard("box-a", "127.0.0.1"), "yomi-strix"));
    }

    #[test]
    fn is_self_target_false_for_a_genuine_other_peer() {
        assert!(!is_self_target(&heard("box-a", "192.168.1.202"), "yomi-strix"));
    }

    #[test]
    fn is_self_target_never_matches_an_empty_own_name() {
        // An empty own-name (a pathological resolver result) must not make
        // every advertisement look like self.
        assert!(!is_self_target(&heard("box-a", "192.168.1.202"), ""));
    }
}
