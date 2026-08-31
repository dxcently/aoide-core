//! Real UDP broadcast round trip for the discovery advertisement (P-P6 +
//! task #120, `docs/architecture/PAIRING.md`'s "Discovery
//! (advertise-but-locked)" section) — same "genuine network, not a mock"
//! priority `peer_connectivity.rs` already holds for the pairing ceremony,
//! and the SAME `#[ignore]`'d-not-skipped reasoning: this drives a REAL
//! `aoide-server::discovery::spawn_advertiser` background thread sending
//! REAL UDP datagrams to the limited-broadcast address, and a REAL
//! `aoide-client::discover::run_sweep` listening on a REAL socket. A
//! loopback-only network namespace (the nix build sandbox) has no
//! broadcast route at all, so the send never leaves `send_once`'s
//! log-and-drop path there.
//!
//! **`#[ignore]`'d, not skipped**: `pkgs/aoide/default.nix`'s package
//! derivation runs `cargo test` inside nix's sandboxed `checkPhase`, which
//! has no network. Run explicitly with
//! `cargo test -p aoide-cli --test discovery_connectivity -- --ignored
//! --test-threads=1` — single-threaded because `run_sweep` binds the ONE
//! fixed advertisement port (`aoide_storage::advertise::PORT`); two sweeps
//! racing in the same process would just fight over the same bind.
//!
//! Every OTHER shape this feature's tests need — advertisement
//! serialize/validate, the malformed-variant drops, the bounded
//! dedupe-by-(name, source) fold, `pair`'s hostname arm's
//! zero/one/many-match resolution, the advertise switch's off-by-default
//! idempotence, `peer discover` never writing `state/peers.json`, the
//! loopback-path sweep round trip, and `pair`'s hostname arm calling
//! the identical `run_pair_request` its url arm runs — is proven WITHOUT
//! leaving the sandbox, in `aoide-storage::advertise::tests`,
//! `aoide-client::discover::tests` (whose
//! `run_sweep_hears_an_advertisement_sent_over_the_real_loopback_stack`
//! exercises the real socket over loopback, un-gated), `aoide-client::
//! commands::tests::peer_discover_*`/`peer_advertise_*`/
//! `peer_pair_hostname_arm_and_url_arm_are_the_same_function_not_two_copies`,
//! and `aoide-server::a2a::tests::resolve_discovery_advertise_*`. This
//! file holds only the two tests that genuinely need a live, routable
//! network: the bare advertise→discover round trip over real broadcast,
//! and the full `pair <hostname>`-drives-a-real-pairing-ceremony
//! round trip below it.

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

/// Poll (never a blind sleep as the ASSERTION) until `run_sweep` reports
/// at least one heard advertisement or a deadline passes — the
/// advertiser's own ~30s cadence is too slow for a test, so
/// [`aoide_server::discovery::spawn_advertiser`] is driven directly here
/// (with its launch-time force flag, so no switch file is involved)
/// rather than through a real `a2a serve` launch.
#[test]
#[ignore = "real UDP broadcast — no network in the nix sandbox; run with --ignored"]
fn advertise_then_discover_and_invite_resolve_round_trip_over_real_broadcast() {
    let _guard = aoide_test_support::env_lock().lock().unwrap();

    let name = "discovery-connectivity-test-box";
    let host = "discovery-connectivity-test-box";
    let user = "khoa";

    // A real background thread sending real UDP broadcast datagrams —
    // dropped at the end of the test process, same "no explicit shutdown
    // needed" shape `aoide-server::discovery`'s own module doc states.
    let _advertiser = aoide_server::discovery::spawn_advertiser(name, host, user, true);

    // `spawn_advertiser`'s first tick fires immediately (no initial sleep
    // before the first send), so a short sweep window is enough — widened
    // a little past the bare minimum to absorb real scheduling jitter on a
    // loaded box, still nowhere near the ~30s steady-state cadence.
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

    assert_eq!(last.heard.len(), 1, "exactly one distinct instance heard; got {:?}", last.heard);
    let heard = &last.heard[0];
    assert_eq!(heard.advertisement.name, name);
    assert_eq!(heard.advertisement.host, host);
    assert_eq!(heard.advertisement.user, user);
    assert!(heard.count >= 1);

    // `pair`'s hostname arm's own real-network half: the SAME
    // already-swept result, resolved by name — proves the discover→resolve
    // pipeline `pair_via_hostname` drives, without needing a second real
    // A2A door up to prove the (already-shared, already-tested)
    // `run_pair_request` tail.
    let hit = aoide_client::discover::resolve_invite_target(&last.heard, name)
        .unwrap_or_else(|e| panic!("expected exactly one real match for `{name}`, got {e:?}"));
    assert_eq!(hit.advertisement.user, user);

    // A name genuinely never advertised is still a clean, taught refusal
    // against the SAME real sweep — never a hang, never a panic.
    let miss = aoide_client::discover::resolve_invite_target(&last.heard, "nobody-advertised-this-name");
    assert!(matches!(miss, Err(aoide_client::discover::InviteResolveError::NoMatch { .. })));
}

/// `pair`'s hostname arm's single-match path must reach the EXACT
/// same `run_pair_request` body its url arm runs (client/AGENTS.md's own
/// invariant on this). `aoide-client`'s own unit tests (`commands::tests::
/// peer_pair_hostname_arm_and_url_arm_are_the_same_function_not_two_copies`)
/// prove this without a network, by calling both arms against an
/// unreachable door and diffing the outcome. What THAT test can't reach is
/// the wiring in between — `pair_via_hostname`'s own discover → resolve
/// pipeline actually producing a real `Heard` to feed the shared function.
/// This test closes that gap for real: a REAL second A2A door ("peer B"),
/// its REAL discovery advertisement, and `aoide pair <name> --yes`
/// dispatched exactly as an operator would type it — then the SAME
/// observable state change the url arm itself produces is asserted
/// directly: an outbound pairing request parked in
/// `peer-pairing-outbound.json`, pointed at the OBSERVED-address dial url
/// `pair_via_hostname` composed.
///
/// Two accommodations for the advertisement carrying no door URL (task
/// #120), both confined to this `#[ignore]`'d file: `AOIDE_A2A_PORT` is
/// pinned to peer B's ephemeral port so `pair_via_hostname`'s
/// `default_a2a_port` dial resolves to the door that actually exists, and
/// peer B binds `0.0.0.0` — a broadcast's observed source is this box's
/// own interface address, so a loopback-bound door would be unreachable at
/// the composed target. A routable bind is a TEST harness necessity here,
/// never a deployment shape (doors stay loopback-bound; `docs/
/// architecture/PAIRING.md`'s Transport section).
#[test]
#[ignore = "real UDP broadcast + real TCP on a routable bind — no network in the nix sandbox; run with --ignored"]
fn peer_pair_hostname_arm_single_match_reaches_the_shared_run_pair_request_over_real_broadcast_and_tcp() {
    let _guard = aoide_test_support::env_lock().lock().unwrap();
    let root = unique_root("invite-ceremony");
    setup_env(&root);

    // Peer B: a real A2A door — genuine accept loop, genuine HTTP/1.1
    // parsing, genuine JSON-RPC dispatch, no mock.
    let port_b = free_port();
    std::env::set_var("AOIDE_A2A_PORT", port_b.to_string());
    std::thread::spawn(move || {
        let _ = aoide::a2a::serve(
            "0.0.0.0",
            port_b,
            &PathBuf::from("/dev/null"),
            "",
            "advertise-peer-b",
            "",
            "",
            Path::new("/tmp/aoide-a2a-discovery-connectivity-unused.sock"),
            false,
            registry(),
        );
    });
    wait_for_tcp_up(&format!("127.0.0.1:{port_b}"));

    // Advertise B by name + ssh hop over a real broadcast — the exact wire
    // `discover::run_sweep` on the pairing side parses. The name must
    // differ from this box's own hostname or `pair`'s self-guard
    // (rightly) refuses it.
    let name = "advertise-peer-b";
    let _advertiser = aoide_server::discovery::spawn_advertiser(name, "peer-b-host", "khoa", true);

    // `pair <hostname>` end to end — the exact command an operator
    // types. `--secs 20` covers the advertiser's real send jitter on a
    // loaded box.
    // --wait 0: this test asserts the PARKED entry (nobody will ever
    // approve advertise-peer-b), so it drives the detached shape.
    let pair_out = dispatch(&cli_invocation(&["pair"], &[name], &[("yes", "true"), ("secs", "20"), ("wait", "0")]));
    assert_eq!(pair_out.status, aoide_protocol::output::Status::Ok, "{}", pair_out.message);

    // The SAME state change the url arm itself would produce: an
    // outbound entry parked for `name` — proving `pair_via_hostname`
    // actually ran `run_pair_request`'s body, not merely returned an `Ok`
    // status some other way. Its url is the OBSERVED-source dial target on
    // the pinned port, never anything off the wire line.
    let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap_or(0);
    let outbound = aoide_storage::pairing::list_outbound(now_epoch);
    assert_eq!(outbound.len(), 1, "exactly one parked outbound request: {outbound:?}");
    assert_eq!(outbound[0].name, name);
    assert!(
        outbound[0].url.ends_with(&format!(":{port_b}/")),
        "the dial url {} carries the pinned door port {port_b}",
        outbound[0].url
    );

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_A2A_PORT");
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}
