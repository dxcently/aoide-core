//! `peer discover`/`peer invite`'s shared multicast sweep (P-P6,
//! `docs/architecture/PAIRING.md`'s "Discovery (advertise-but-locked)"
//! section): join `aoide_storage::beacon::GROUP`/`PORT`, listen for a
//! bounded window, validate + dedupe every line heard
//! (`aoide_storage::beacon::parse_and_validate`), and hand back the
//! freshest beacon per fingerprint plus a count of what was dropped as
//! malformed.
//!
//! **Discovery is read-only.** This module never writes `state/peers.json`
//! — it doesn't even import `peer_store` for writing anything, only
//! `aoide_storage::beacon` for the wire format. The pairing ceremony
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
//! over one already-validated [`aoide_storage::beacon::Beacon`], so the
//! dedupe-by-fingerprint/freshest-wins logic is unit-testable with no
//! socket at all; [`run_sweep`] is the thin real-I/O wrapper around it.
//! [`resolve_invite_target`] is the same shape one layer up: `peer
//! invite`'s zero/one/many-match resolution against an already-swept
//! [`SweepResult`], pure so its refusal shapes are testable without a real
//! network sweep.

use std::collections::HashMap;
use std::net::{Ipv4Addr, UdpSocket};
use std::time::{Duration, Instant};

use aoide_storage::beacon::{self, Beacon};

/// The default `--secs` window for `peer discover`/`peer invite` when the
/// caller doesn't override it (PAIRING.md: "listens briefly (default a few
/// seconds)"; the brief: "default ~4").
pub const DEFAULT_SWEEP_SECS: u64 = 4;

/// One beacon's freshest-seen state, keyed by fingerprint (PAIRING.md:
/// "dedupes by fingerprint").
#[derive(Debug, Clone, PartialEq)]
pub struct Heard {
    pub beacon: Beacon,
    pub first_heard: String,
    pub last_heard: String,
    pub count: u32,
}

/// The result of one sweep: every distinct fingerprint heard, plus how many
/// raw lines were dropped as malformed — never their content (house rule
/// 4), only the count.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SweepResult {
    pub heard: Vec<Heard>,
    pub dropped: u32,
}

/// Fold ONE already-validated beacon into `state`, keyed by fingerprint —
/// pure. A re-heard fingerprint updates `last_heard`/`count` and REPLACES
/// the stored beacon content (a restarted advertiser may have a new `url`;
/// the freshest sighting's fields win, matching "dedupe by fingerprint,
/// keeping the freshest" rather than freezing whatever was heard first).
/// `now` is the caller's own timestamp
/// (`aoide_storage::time::now_iso_utc`), threaded in rather than read here
/// so a test can pin exact `first_heard`/`last_heard` values.
fn fold_heard(state: &mut HashMap<String, Heard>, b: Beacon, now: &str) {
    state
        .entry(b.fpr.clone())
        .and_modify(|h| {
            h.beacon = b.clone();
            h.last_heard = now.to_string();
            h.count += 1;
        })
        .or_insert_with(|| Heard {
            beacon: b,
            first_heard: now.to_string(),
            last_heard: now.to_string(),
            count: 1,
        });
}

/// Join [`beacon::GROUP`]/[`beacon::PORT`] and listen for `secs` seconds,
/// validating and dedupe-folding every line heard
/// ([`beacon::parse_and_validate`]). Real network I/O — a bind/join
/// failure (no multicast support in this network namespace, the port
/// already bound, …) surfaces as `Err` rather than an empty result, so a
/// caller can tell "heard nothing" apart from "couldn't even listen."
/// Bounded by a short per-read timeout so the deadline is honored even
/// when nothing ever arrives — never a blocking `recv_from` with no
/// timeout at all.
pub fn run_sweep(secs: u64) -> std::io::Result<SweepResult> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, beacon::PORT))?;
    let group: Ipv4Addr = beacon::GROUP
        .parse()
        .expect("aoide_storage::beacon::GROUP is a pinned, valid IPv4 literal");
    socket.join_multicast_v4(&group, &Ipv4Addr::UNSPECIFIED)?;
    socket.set_read_timeout(Some(Duration::from_millis(200)))?;

    let mut state: HashMap<String, Heard> = HashMap::new();
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
    let mut buf = [0u8; beacon::MAX_LINE_BYTES + 1];
    while Instant::now() < deadline {
        match socket.recv_from(&mut buf) {
            Ok((n, _src)) => {
                let now = aoide_storage::time::now_iso_utc();
                let outcome = std::str::from_utf8(&buf[..n]).map_err(|_| ()).and_then(|line| beacon::parse_and_validate(line).map_err(|_| ()));
                match outcome {
                    Ok(b) => fold_heard(&mut state, b, &now),
                    Err(()) => dropped += 1,
                }
            }
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => continue,
            Err(e) => return Err(e),
        }
    }

    let mut heard: Vec<Heard> = state.into_values().collect();
    heard.sort_by(|a, b| a.beacon.name.cmp(&b.beacon.name).then(a.beacon.fpr.cmp(&b.beacon.fpr)));
    Ok(SweepResult { heard, dropped })
}

/// Whether this bind/`join_multicast_v4` failure means "this network
/// namespace has no multicast-capable interface" rather than a genuine
/// defect: ENODEV (the nix build sandbox's loopback-only namespace refuses
/// the join itself, not just delivery — no `std::io::ErrorKind` maps to
/// it, hence the raw errno), EADDRNOTAVAIL, or EPERM under a network
/// lockdown.
fn is_no_multicast_here(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::PermissionDenied
    ) || e.raw_os_error() == Some(19) // ENODEV
}

/// Render one [`run_sweep`] I/O failure as the taught error line `peer
/// discover`/`peer invite` print — one function, so the two handlers never
/// drift apart. The case worth teaching is a multicast-less host
/// ([`is_no_multicast_here`]): the bare errno reads as noise ("No such
/// device"), so name the condition and what discovery actually needs
/// instead of parroting the OS.
pub fn describe_sweep_error(e: &std::io::Error) -> String {
    if is_no_multicast_here(e) {
        format!(
            "listening for discovery beacons: this host has no multicast-capable network \
             interface ({e}) — discovery listens on the LAN multicast group {}:{}, which a \
             bare-loopback or sandboxed network namespace cannot join",
            beacon::GROUP,
            beacon::PORT
        )
    } else {
        format!("listening for discovery beacons: {e}")
    }
}

/// Test-only capability probe: can this network namespace join
/// [`beacon::GROUP`] at all? Binds an ephemeral scratch socket (never
/// [`beacon::PORT`] — the probe must not fight a real sweep for the fixed
/// port) and attempts the same `join_multicast_v4` [`run_sweep`] performs.
/// A [`is_no_multicast_here`] failure is "no multicast here" (the nix
/// build sandbox); any OTHER join failure returns `true` so the real test
/// runs and surfaces it rather than being silently skipped.
#[cfg(test)]
pub(crate) fn multicast_capable() -> bool {
    let Ok(socket) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
        return false;
    };
    let group: Ipv4Addr = beacon::GROUP
        .parse()
        .expect("aoide_storage::beacon::GROUP is a pinned, valid IPv4 literal");
    match socket.join_multicast_v4(&group, &Ipv4Addr::UNSPECIFIED) {
        Ok(()) => true,
        Err(e) => !is_no_multicast_here(&e),
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
/// real socket. Dedupe is already by FINGERPRINT (`run_sweep`'s own fold),
/// so two entries sharing a `name` here are genuinely two different
/// identities claiming the same nickname — PAIRING.md's own "ambiguous...
/// = taught error" case, not a sweep artifact. `heard` in both error
/// variants lists every name actually heard this sweep (never raw beacon
/// content beyond the already-validated `name` field — house rule 4).
pub fn resolve_invite_target(heard: &[Heard], name: &str) -> Result<Heard, InviteResolveError> {
    let all_names: Vec<String> = heard.iter().map(|h| h.beacon.name.clone()).collect();
    let matches: Vec<&Heard> = heard.iter().filter(|h| h.beacon.name == name).collect();
    match matches.as_slice() {
        [one] => Ok((*one).clone()),
        [] => Err(InviteResolveError::NoMatch { heard: all_names }),
        _ => Err(InviteResolveError::Ambiguous { heard: all_names }),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn beacon(name: &str, fpr: &str, url: &str) -> Beacon {
        aoide_storage::beacon::build(name, fpr, url)
    }

    #[test]
    fn fold_heard_dedupes_by_fingerprint_and_keeps_the_freshest_fields() {
        let mut state = HashMap::new();
        let fpr = "aa:bb:cc:dd:ee:ff:00:11";
        fold_heard(&mut state, beacon("box-a", fpr, "http://box-a:8710/"), "2026-08-25T00:00:00Z");
        assert_eq!(state.len(), 1);
        assert_eq!(state[fpr].count, 1);
        assert_eq!(state[fpr].first_heard, "2026-08-25T00:00:00Z");
        assert_eq!(state[fpr].last_heard, "2026-08-25T00:00:00Z");

        // Re-heard, same fingerprint, a NEW url (e.g. the advertiser
        // restarted on a different port) — freshest fields win, count
        // increments, `first_heard` is untouched.
        fold_heard(&mut state, beacon("box-a", fpr, "http://box-a:9999/"), "2026-08-25T00:00:30Z");
        assert_eq!(state.len(), 1, "same fingerprint never becomes a second entry");
        assert_eq!(state[fpr].beacon.url, "http://box-a:9999/", "freshest url wins");
        assert_eq!(state[fpr].first_heard, "2026-08-25T00:00:00Z", "first_heard is never overwritten");
        assert_eq!(state[fpr].last_heard, "2026-08-25T00:00:30Z");
        assert_eq!(state[fpr].count, 2);
    }

    #[test]
    fn fold_heard_keeps_two_distinct_fingerprints_separate_even_under_the_same_name() {
        // Two DIFFERENT identities claiming the same nickname — dedupe is
        // by fingerprint, never by name, so both survive the fold; it's
        // `resolve_invite_target` (below) that later calls this ambiguous.
        let mut state = HashMap::new();
        fold_heard(&mut state, beacon("box-a", "aa:aa:aa:aa:aa:aa:aa:aa", "http://real:8710/"), "T0");
        fold_heard(&mut state, beacon("box-a", "bb:bb:bb:bb:bb:bb:bb:bb", "http://impostor:8710/"), "T0");
        assert_eq!(state.len(), 2);
    }

    #[test]
    fn resolve_invite_target_single_match_succeeds() {
        let heard = vec![Heard {
            beacon: beacon("yomi-strix", "aa:bb:cc:dd:ee:ff:00:11", "http://yomi-strix:8710/"),
            first_heard: "T0".into(),
            last_heard: "T0".into(),
            count: 1,
        }];
        let hit = resolve_invite_target(&heard, "yomi-strix").unwrap();
        assert_eq!(hit.beacon.name, "yomi-strix");
        assert_eq!(hit.beacon.url, "http://yomi-strix:8710/");
    }

    #[test]
    fn resolve_invite_target_no_match_lists_every_name_actually_heard() {
        let heard = vec![
            Heard { beacon: beacon("box-a", "aa:aa:aa:aa:aa:aa:aa:aa", "http://a/"), first_heard: "T0".into(), last_heard: "T0".into(), count: 1 },
            Heard { beacon: beacon("box-b", "bb:bb:bb:bb:bb:bb:bb:bb", "http://b/"), first_heard: "T0".into(), last_heard: "T0".into(), count: 1 },
        ];
        let err = resolve_invite_target(&heard, "ghost").unwrap_err();
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
    fn describe_sweep_error_teaches_the_no_multicast_condition_for_enodev() {
        // ENODEV — what `join_multicast_v4` returns in a loopback-only
        // network namespace (the nix build sandbox). Pure string logic, no
        // socket: runs everywhere.
        let e = std::io::Error::from_raw_os_error(19);
        let msg = describe_sweep_error(&e);
        assert!(msg.contains("no multicast-capable network interface"), "{msg}");
        assert!(msg.contains(beacon::GROUP), "the taught line names the group: {msg}");
        assert!(msg.contains("No such device"), "the raw OS error stays visible: {msg}");
    }

    #[test]
    fn describe_sweep_error_passes_an_unrelated_error_through_untaught() {
        // EADDRINUSE (the fixed port already bound) is a genuine local
        // conflict, not a missing capability — no multicast lecture.
        let e = std::io::Error::from_raw_os_error(98);
        let msg = describe_sweep_error(&e);
        assert!(msg.starts_with("listening for discovery beacons: "), "{msg}");
        assert!(!msg.contains("multicast-capable"), "{msg}");
    }

    /// Real UDP multicast round trip, probe-gated exactly like `multicast_
    /// capable`'s other callers (`commands::tests::peer_discover_*`) — skips
    /// cleanly in the nix build sandbox (ENODEV on the join) but RUNS by
    /// default in a dev shell or on a real box, unlike `crates/cli/tests/
    /// discovery_connectivity.rs`'s heavier `#[ignore]`'d round trip, which
    /// needs an explicit `--ignored` flag nobody passes in routine use.
    ///
    /// This is the shape of test that would have caught task #98: a sender
    /// that mirrors `aoide-server::discovery::send_once` exactly (a fresh
    /// ephemeral socket, `UdpSocket::bind(("0.0.0.0", 0))`, no interface
    /// pinning — the real production send path, not a loopback shortcut)
    /// racing against this crate's own `run_sweep` on the SAME real network
    /// stack. Loopback-only round trips (this file's other tests, and the
    /// P-P6 test plan's original "beacon round-trip on loopback multicast"
    /// note) can never catch a host firewall dropping inbound UDP on a
    /// physical interface, because loopback traffic never reaches a
    /// per-interface firewall rule at all — see `docs/architecture/
    /// PAIRING.md`'s "Discovery" section for the diagnosis this test now
    /// stands guard for.
    #[test]
    fn run_sweep_hears_a_beacon_sent_over_the_real_network_stack() {
        if !multicast_capable() {
            eprintln!(
                "skipping run_sweep_hears_a_beacon_sent_over_the_real_network_stack: no \
                 multicast-capable interface in this network namespace (the nix build sandbox)"
            );
            return;
        }

        let sent = beacon::build("test-sender", "aa:bb:cc:dd:ee:ff:00:11", "http://test-sender:8710/");
        let line = beacon::encode(&sent).expect("a well-formed test beacon always encodes");

        // A background sender racing `run_sweep`'s listen window below —
        // resent on a short tick since we don't know exactly when the sweep
        // starts listening, mirroring `send_once`'s own fresh-socket-per-send
        // shape rather than holding one open.
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sender_stop = stop.clone();
        let sender = std::thread::spawn(move || {
            while !sender_stop.load(std::sync::atomic::Ordering::Relaxed) {
                if let Ok(socket) = UdpSocket::bind(("0.0.0.0", 0)) {
                    let _ = socket.send_to(line.as_bytes(), (beacon::GROUP, beacon::PORT));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });

        let result = run_sweep(3).expect("a network namespace that just passed multicast_capable must not fail to bind/join");
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        sender.join().expect("sender thread must not panic");

        assert_eq!(result.dropped, 0, "every sent line is well-formed and must validate: {result:?}");
        assert!(
            result.heard.iter().any(|h| h.beacon == sent),
            "expected to hear the beacon actually sent over the real network stack in this \
             sweep window; got {:?} — on a real box (not the nix build sandbox) this means the \
             beacon never made it from sender to listener. Check the host firewall for inbound \
             UDP {} before suspecting the socket code (docs/architecture/PAIRING.md's \
             \"Discovery\" section covers the diagnosis)",
            result.heard,
            beacon::PORT
        );
    }

    #[test]
    fn resolve_invite_target_ambiguous_when_two_fingerprints_share_a_name() {
        let heard = vec![
            Heard { beacon: beacon("box-a", "aa:aa:aa:aa:aa:aa:aa:aa", "http://real:8710/"), first_heard: "T0".into(), last_heard: "T0".into(), count: 1 },
            Heard { beacon: beacon("box-a", "bb:bb:bb:bb:bb:bb:bb:bb", "http://impostor:8710/"), first_heard: "T0".into(), last_heard: "T0".into(), count: 1 },
        ];
        let err = resolve_invite_target(&heard, "box-a").unwrap_err();
        match err {
            InviteResolveError::Ambiguous { heard } => assert_eq!(heard, vec!["box-a".to_string(), "box-a".to_string()]),
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }
}
