//! Real UDP multicast round trip for the discovery beacon (P-P6,
//! `docs/architecture/PAIRING.md`'s "Discovery (advertise-but-locked)"
//! section) — same "genuine network, not a mock" priority
//! `peer_connectivity.rs` already holds for the pairing ceremony, and the
//! SAME `#[ignore]`'d-not-skipped reasoning: this drives a REAL
//! `aoide-server::discovery::spawn_advertiser` background thread sending
//! REAL UDP datagrams to a REAL multicast group, and a REAL
//! `aoide-client::discover::run_sweep` joining that same group and
//! listening on a REAL socket.
//!
//! **`#[ignore]`'d, not skipped**: `pkgs/aoide/default.nix`'s package
//! derivation runs `cargo test` inside nix's sandboxed `checkPhase`, which
//! has no network at all — multicast doubly so, since it also needs a
//! loopback interface with multicast routing enabled, which a minimal
//! build sandbox may not provide even when plain loopback TCP (this
//! crate's OTHER ignored tests) works. Run explicitly with
//! `cargo test -p aoide-cli --test discovery_connectivity -- --ignored
//! --test-threads=1` — single-threaded because `run_sweep` binds the ONE
//! fixed beacon port (`aoide_storage::beacon::PORT`); two sweeps racing in
//! the same process would just fight over the same bind.
//!
//! Every OTHER shape this phase's tests need — beacon serialize/validate,
//! the malformed-variant drops, dedupe-by-fingerprint, `peer invite`'s
//! zero/one/many-match resolution, the advertise knob's off-by-default
//! precedence, `peer discover` never writing `state/peers.json`, and
//! `peer invite`'s single-match branch calling the identical
//! `run_pair_request` `peer pair request` runs — is proven WITHOUT a real
//! socket, in `aoide-storage::beacon::tests`, `aoide-client::
//! discover::tests`, `aoide-client::commands::tests::peer_discover_*`/
//! `peer_invite_tail_and_peer_pair_request_are_the_same_function_not_two_copies`,
//! and `aoide-server::a2a::tests::resolve_discovery_advertise_*`
//! respectively (the "test the socket layer behind a seam" half of the
//! brief's own test list). The one shape in that list that still needs a
//! real socket — the `peer_discover_*` no-write tests bind+join the group
//! to reach `run_sweep`'s Ok path, though they need no real beacon — is
//! probe-gated rather than `#[ignore]`'d: `aoide-client::discover::
//! multicast_capable` attempts the same `join_multicast_v4` on a scratch
//! socket, and the tests skip with a note where the join itself is
//! refused (the sandbox's loopback-only namespace fails it with ENODEV).
//! This file holds only the two tests that
//! genuinely need a live network: the bare advertise→discover round trip
//! above, and the full `peer invite`-drives-a-real-pairing-ceremony round
//! trip below it. Both bind the ONE fixed beacon port
//! (`aoide_storage::beacon::PORT`) via `run_sweep`, so both this file's
//! tests — and `--test-threads=1` — stay required even with two of them:
//! two sweeps racing in the same process would just fight over the same
//! bind.

use aoide::dispatch::{dispatch, registry, Invocation};
use aoide_protocol::Door;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Poll (never a blind sleep as the ASSERTION) until a real TCP connect
/// succeeds — same idiom `peer_connectivity.rs`'s own `wait_for_tcp_up`
/// uses, duplicated here rather than shared since integration test files
/// in this crate are separate compilation units (that file's own header
/// comment notes the same constraint).
fn wait_for_tcp_up(host_port: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if std::net::TcpStream::connect(host_port).is_ok() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("server at {host_port} never came up within 5s");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn unique_root(tag: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "aoide-discovery-connectivity-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn setup_env(root: &Path) {
    std::env::set_var("AOIDE_STAGE_DIR", root.join("stage"));
    std::env::set_var("AOIDE_STATE_DIR", root.join("state"));
    std::env::set_var("XDG_RUNTIME_DIR", root);
    std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
    std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
}

fn cli_invocation(path: &[&str], args: &[&str], flags: &[(&str, &str)]) -> Invocation {
    Invocation {
        path: path.iter().map(|s| s.to_string()).collect(),
        args: args.iter().map(|s| s.to_string()).collect(),
        flags: flags.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        door: Door::Cli,
    }
}

/// Poll (never a blind sleep as the ASSERTION) until `run_sweep` reports at
/// least one heard fingerprint or a deadline passes — the advertiser's own
/// ~30s cadence is too slow for a test, so [`aoide_server::discovery::
/// spawn_advertiser`] is driven directly here rather than through a real
/// `a2a serve` launch (proven separately, and NOT over real network, by
/// `aoide-server::a2a::tests::resolve_discovery_advertise_*`).
#[test]
#[ignore = "real UDP multicast — no network in the nix sandbox; run with --ignored"]
fn advertise_then_discover_and_invite_resolve_round_trip_over_real_multicast() {
    let _guard = aoide_test_support::env_lock().lock().unwrap();

    let name = "discovery-connectivity-test-box";
    let fpr = "aa:bb:cc:dd:ee:ff:00:11";
    let url = "http://discovery-connectivity-test-box:8710/";

    // A real background thread sending real UDP datagrams — dropped at the
    // end of the test process, same "no explicit shutdown needed" shape
    // `aoide-server::discovery`'s own module doc states.
    let _advertiser = aoide_server::discovery::spawn_advertiser(name, fpr, url);

    // `spawn_advertiser`'s first tick fires immediately (no initial sleep
    // before the first `send_once`), so a short sweep window is enough —
    // widened a little past the bare minimum to absorb real scheduling
    // jitter on a loaded box, still nowhere near the ~30s steady-state
    // cadence.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last = aoide_client::discover::SweepResult::default();
    while Instant::now() < deadline {
        match aoide_client::discover::run_sweep(3) {
            Ok(swept) => {
                last = swept;
                if !last.heard.is_empty() {
                    break;
                }
            }
            Err(e) => panic!("run_sweep returned a real I/O error rather than an empty result: {e}"),
        }
    }

    assert_eq!(last.heard.len(), 1, "exactly one distinct fingerprint heard; got {:?}", last.heard);
    let heard = &last.heard[0];
    assert_eq!(heard.beacon.name, name);
    assert_eq!(heard.beacon.fpr, fpr);
    assert_eq!(heard.beacon.url, url);
    assert!(heard.count >= 1);

    // `peer invite`'s own real-network half: the SAME already-swept
    // result, resolved by name — proves the discover→resolve pipeline
    // `handle_peer_invite` drives, without needing a second real A2A door
    // up to prove the (already-shared, already-tested) `run_pair_request`
    // tail.
    let hit = aoide_client::discover::resolve_invite_target(&last.heard, name)
        .unwrap_or_else(|e| panic!("expected exactly one real match for `{name}`, got {e:?}"));
    assert_eq!(hit.beacon.url, url);

    // A name genuinely never advertised is still a clean, taught refusal
    // against the SAME real sweep — never a hang, never a panic.
    let miss = aoide_client::discover::resolve_invite_target(&last.heard, "nobody-advertised-this-name");
    assert!(matches!(miss, Err(aoide_client::discover::InviteResolveError::NoMatch { .. })));
}

/// `peer invite`'s single-match path must reach the EXACT same
/// `run_pair_request` body `peer pair request` itself runs (client/
/// AGENTS.md's own invariant on this). `aoide-client`'s own unit tests
/// (`commands::tests::
/// peer_invite_tail_and_peer_pair_request_are_the_same_function_not_two_copies`)
/// prove this without a network, by calling both entry points against an
/// unreachable door and diffing the outcome. What THAT test can't reach is
/// the wiring in between — `handle_peer_invite`'s own discover → resolve
/// pipeline actually producing a real `Heard` to feed the shared function.
/// This test closes that gap for real: a REAL second A2A door ("peer B",
/// same loopback-bind pattern `peer_connectivity.rs` already uses), its
/// REAL discovery beacon (a real UDP multicast send naming B's REAL url),
/// and `aoide peer invite <name> --yes` dispatched exactly as an operator
/// would type it — then the SAME observable state change `peer pair
/// request` itself produces is asserted directly: an outbound pairing
/// request parked in `peer-pairing-outbound.json`, pointed at B's real url.
#[test]
#[ignore = "real UDP multicast + real loopback TCP — no network in the nix sandbox; run with --ignored"]
fn peer_invite_single_match_reaches_the_shared_run_pair_request_over_real_multicast_and_tcp() {
    let _guard = aoide_test_support::env_lock().lock().unwrap();
    let root = unique_root("invite-ceremony");
    setup_env(&root);

    // Peer B: a real loopback A2A door — genuine accept loop, genuine
    // HTTP/1.1 parsing, genuine JSON-RPC dispatch, no mock.
    let port_b = free_port();
    std::thread::spawn(move || {
        let _ = aoide::a2a::serve(
            "127.0.0.1",
            port_b,
            &PathBuf::from("/dev/null"),
            "",
            "beacon-peer-b",
            "",
            "",
            Path::new("/tmp/aoide-a2a-discovery-connectivity-unused.sock"),
            false,
            registry(),
        );
    });
    wait_for_tcp_up(&format!("127.0.0.1:{port_b}"));
    let peer_b_url = format!("http://127.0.0.1:{port_b}/");

    // Advertise B's REAL door url over a real beacon — the exact wire
    // `discover::run_sweep` on the invite side parses.
    let name = "beacon-peer-b";
    let fpr = "aa:bb:cc:dd:ee:ff:00:11";
    let _advertiser = aoide_server::discovery::spawn_advertiser(name, fpr, &peer_b_url);

    // `peer invite` end to end — the exact command an operator types.
    // `--secs 20` covers both the advertiser's real send jitter and this
    // sandbox's (established, in the ignored test above) unreliable
    // multicast delivery.
    let invite_out = dispatch(&cli_invocation(&["peer", "invite"], &[name], &[("yes", "true"), ("secs", "20")]));
    assert_eq!(invite_out.status, aoide_protocol::output::Status::Ok, "{}", invite_out.message);

    // The SAME state change `peer pair request` itself would produce: an
    // outbound entry parked for `name`, pointed at B's REAL url — proving
    // `handle_peer_invite` actually ran `run_pair_request`'s body, not
    // merely returned an `Ok` status some other way.
    let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap_or(0);
    let outbound = aoide_storage::pairing::list_outbound(now_epoch);
    assert_eq!(outbound.len(), 1, "exactly one parked outbound request: {outbound:?}");
    assert_eq!(outbound[0].name, name);
    assert_eq!(outbound[0].url, peer_b_url);

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}
