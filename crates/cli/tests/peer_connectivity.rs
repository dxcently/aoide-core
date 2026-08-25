//! Real two-instance, same-network connectivity proof for the peer
//! federation feature (CONTRACTS.md §7) — owner-directed priority
//! (2026-08-14): a genuine end-to-end round trip, not mocked HTTP.
//!
//! Two ACTUAL A2A servers are bound to two different `127.0.0.1:<port>`
//! addresses. `127.0.0.1:A` and `127.0.0.1:B` legitimately simulate "two
//! boxes reachable on the same network" — same-subnet HTTP reachability is
//! same-subnet HTTP reachability whether the two addresses happen to share a
//! loopback interface or are two real LAN IPs; nothing in the protocol
//! (a JSON-RPC method over a plain URL) cares which. One is registered as a
//! peer of the "local" side via a REAL `aoide peer add <name> <url>` (a real
//! curl GET of the AgentCard), then pulled via a REAL `aoide peer pull` (a
//! real curl POST of `aoide/graphSummary`) — real bytes over a real socket,
//! a real cache write, a real graph fold. Both binds stay strictly loopback
//! (house rule: never bind non-loopback in this suite, never reach a real
//! second machine).
//!
//! WAN/NAT/VPN/tailnet reachability is explicitly OUT OF SCOPE for this
//! pass — a later, separate conversation the owner will direct. Nothing
//! here assumes or depends on tailnet-specific behavior; swap either
//! `127.0.0.1:<port>` below for any other reachable URL and the same code
//! path applies unchanged — the protocol is topology-blind by construction.
//!
//! **`#[ignore]`'d, not skipped**: both tests below do REAL loopback TCP
//! binds and shell out to a REAL `curl` — this crate's package derivation
//! (`pkgs/aoide/default.nix`) runs `cargo test` inside nix's sandboxed
//! `checkPhase`, which has no network and no `curl` on `PATH` ("Walking
//! skeleton: no live-system integration tests in the sandbox", that file's
//! own comment). `#[ignore]` keeps the hermetic package build green while
//! keeping this test 100% real (not a mock) for the environment it needs:
//! run explicitly with `cargo test -p aoide-cli --test peer_connectivity -- --ignored`
//! (confirmed passing in `nix develop #default`, which DOES have `curl` and
//! a real loopback network stack).

use aoide::dispatch::{dispatch, registry, Invocation};
use aoide_protocol::output::Status;
use aoide_protocol::Door;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn unique_root(tag: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "aoide-peer-connectivity-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Reserve a free loopback port: bind `:0`, read back what the OS assigned,
/// then drop the listener. A tiny re-bind race is acceptable in a test.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn cli_invocation(path: &[&str], args: &[&str], flags: &[(&str, &str)]) -> Invocation {
    Invocation {
        path: path.iter().map(|s| s.to_string()).collect(),
        args: args.iter().map(|s| s.to_string()).collect(),
        flags: flags.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        door: Door::Cli,
    }
}

/// Poll (never a blind sleep) until a real TCP connect to `host:port`
/// succeeds, or panic past a 5s deadline — the accept loop above runs on a
/// freshly spawned thread, so the test must not race its bind.
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

/// Isolate one test's env (`AOIDE_STAGE_DIR`/`AOIDE_STATE_DIR`/
/// `XDG_RUNTIME_DIR`/`AOIDE_AUDIT_LOG`) to a fresh tempdir. Every test in
/// this file runs single-threaded relative to env mutation (see the
/// `#[test]` attributes below — `cargo test` runs a crate's integration
/// tests in one process by default, and these two don't otherwise
/// interfere, but env vars are process-global, so each locks the same
/// mutex `aoide_test_support` provides).
fn setup_env(root: &std::path::Path) -> PathBuf {
    let stage = root.join("stage");
    std::fs::create_dir_all(&stage).unwrap();
    std::env::set_var("AOIDE_STAGE_DIR", &stage);
    std::env::set_var("AOIDE_STATE_DIR", root.join("state"));
    std::env::set_var("XDG_RUNTIME_DIR", root);
    std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
    std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
    stage
}

#[test]
#[ignore = "real loopback TCP + real curl — no network/curl in the nix sandbox; run with --ignored"]
fn peer_add_and_pull_round_trip_over_real_http_between_two_loopback_instances() {
    let _guard = aoide_test_support::env_lock().lock().unwrap();
    let root = unique_root("main");
    let _stage = setup_env(&root);

    // Seed a real, checkable node on the (shared, single-process) stage
    // BEFORE peer B starts serving, so B's FIRST graphSummary response
    // carries it. (The path must be a real absolute dir — `graph project
    // add` rejects anything else now — so it lives under this test's own
    // `root` and is removed with it.)
    let remote = root.join("remote");
    std::fs::create_dir_all(&remote).unwrap();
    let seed = dispatch(&cli_invocation(
        &["graph", "project", "add"],
        &["aoide-remote", remote.to_str().unwrap()],
        &[],
    ));
    assert_eq!(seed.status, Status::Ok, "{}", seed.message);

    // Bind peer "B"'s A2A door to a REAL loopback port and serve it on a
    // background thread — a genuine accept loop, genuine HTTP/1.1 parsing,
    // genuine JSON-RPC dispatch. Never bound non-loopback.
    let port_b = free_port();
    std::thread::spawn(move || {
        let _ = aoide::a2a::serve(
            "127.0.0.1",
            port_b,
            &PathBuf::from("/dev/null"),
            "",
            "yomi-strix",
            "",
            "",
            Path::new("/tmp/aoide-a2a-peer-connectivity-unused.sock"),
            registry(),
        );
    });
    wait_for_tcp_up(&format!("127.0.0.1:{port_b}"));
    let peer_url = format!("http://127.0.0.1:{port_b}/");

    // `peer add` — a REAL curl GET of B's `/.well-known/agent-card.json`
    // over real HTTP (verification-before-registering).
    let add_out = dispatch(&cli_invocation(&["peer", "add"], &["yomi-strix", &peer_url], &[]));
    assert_eq!(add_out.status, Status::Ok, "peer add: {}", add_out.message);
    let peers = aoide_storage::peer_store::load_peers();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].name, "yomi-strix");
    assert_eq!(peers[0].url, peer_url);

    // `peer pull` — a REAL curl POST of `aoide/graphSummary` over real HTTP.
    let pull_out = dispatch(&cli_invocation(&["peer", "pull"], &["yomi-strix"], &[]));
    assert_eq!(pull_out.status, Status::Ok, "peer pull: {}", pull_out.message);
    let results = pull_out.data.as_ref().unwrap()["results"].as_array().unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["ok"], true, "pull result: {results:?}");

    // The cache now holds B's ACTUAL served response — real bytes, not a
    // stub: B's instance name is exactly what `serve` was told to
    // advertise, and the graph carries the project registered before B
    // started serving.
    let cache = aoide_storage::peer_store::load_peer_cache("yomi-strix").expect("cache written");
    assert!(!cache.stale);
    assert_eq!(cache.instance.as_ref().unwrap()["name"], "yomi-strix");
    assert_eq!(cache.instance.as_ref().unwrap()["url"], peer_url);
    let graph = cache.graph.as_ref().unwrap();
    assert!(
        graph["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["id"] == "project:aoide-remote"),
        "the peer's REAL served graph round-tripped over real HTTP: {graph}"
    );

    // Mutate LOCAL state AFTER the pull — the cache is a frozen snapshot of
    // what B served AT PULL TIME, not a live join, so it must NOT pick up a
    // local-only change made afterward.
    let local = root.join("local");
    std::fs::create_dir_all(&local).unwrap();
    let mutate = dispatch(&cli_invocation(
        &["graph", "project", "add"],
        &["local-only", local.to_str().unwrap()],
        &[],
    ));
    assert_eq!(mutate.status, Status::Ok);

    // The fold: `graph view --json`'s resolved document now carries BOTH
    // local projects PLUS a `peer:yomi-strix` root node whose `children`
    // reflect the OLD (pre-mutation) snapshot only.
    let view_out = dispatch(&cli_invocation(&["graph", "view"], &[], &[("json", "true")]));
    assert_eq!(view_out.status, Status::Ok);
    let doc = view_out.data.as_ref().unwrap();
    let nodes = doc["nodes"].as_array().unwrap();
    assert!(nodes.iter().any(|n| n["id"] == "project:aoide-remote"));
    assert!(nodes.iter().any(|n| n["id"] == "project:local-only"));
    let peer_node = nodes
        .iter()
        .find(|n| n["id"] == "peer:yomi-strix")
        .expect("peer node folded into the LOCAL resolved graph document");
    assert_eq!(peer_node["state"], "fresh");
    let children = peer_node["children"]["nodes"].as_array().unwrap();
    assert!(
        children.iter().any(|n| n["id"] == "project:aoide-remote"),
        "the peer's cached subtree carries what B had at pull time: {children:?}"
    );
    assert!(
        !children.iter().any(|n| n["id"] == "project:local-only"),
        "the peer's cached subtree must NOT reflect a LOCAL mutation made after the pull \
         — it's a frozen cache from a real pull, not a live re-fetch: {children:?}"
    );

    // `peer status` reports it fresh, over the same real cache.
    let status_out = dispatch(&cli_invocation(&["peer", "status"], &[], &[]));
    assert_eq!(status_out.status, Status::Ok);
    let rows = status_out.data.as_ref().unwrap()["peers"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["name"], "yomi-strix");
    assert_eq!(rows[0]["state"], "fresh");

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}

#[test]
#[ignore = "real loopback TCP + real curl — no network/curl in the nix sandbox; run with --ignored"]
fn peer_add_against_an_unreachable_url_never_registers_and_pull_of_a_down_peer_marks_stale_without_breaking_others() {
    let _guard = aoide_test_support::env_lock().lock().unwrap();
    let root = unique_root("unreachable");
    let _stage = setup_env(&root);

    // `peer add` against a port NOTHING is listening on — a real, genuine
    // connection-refused, not a mock. It must never register.
    let dead_port = free_port(); // reserved, then dropped — nothing binds it
    let dead_url = format!("http://127.0.0.1:{dead_port}/");
    let add_out = dispatch(&cli_invocation(&["peer", "add"], &["ghost", &dead_url], &[]));
    assert_eq!(add_out.status, Status::Error, "an unreachable peer must fail peer add");
    assert!(
        aoide_storage::peer_store::load_peers().is_empty(),
        "a peer that fails AgentCard verification is never registered"
    );

    // Now register ONE real, reachable peer alongside a SECOND, registered
    // peer that is unreachable (its listener never came up) — `peer pull`
    // with no name pulls both, and the good one must succeed regardless of
    // the bad one.
    let port_b = free_port();
    std::thread::spawn(move || {
        let _ = aoide::a2a::serve(
            "127.0.0.1",
            port_b,
            &PathBuf::from("/dev/null"),
            "",
            "good-peer",
            "",
            "",
            Path::new("/tmp/aoide-a2a-peer-connectivity-unused.sock"),
            registry(),
        );
    });
    wait_for_tcp_up(&format!("127.0.0.1:{port_b}"));
    let good_url = format!("http://127.0.0.1:{port_b}/");
    let add_good = dispatch(&cli_invocation(&["peer", "add"], &["good", &good_url], &[]));
    assert_eq!(add_good.status, Status::Ok, "{}", add_good.message);

    // A second peer entry registered by hand pointing at a dead port (bypasses
    // `peer add`'s verification so we can exercise `peer pull`'s per-peer
    // failure isolation without a second live server).
    let mut peers = aoide_storage::peer_store::load_peers();
    peers.push(aoide_storage::peer_store::Peer {
        name: "flaky".to_string(),
        url: dead_url.clone(),
        autogate: false,
        token_file: None,
        bearer_secret: None,
        hub: false,
        added_at: aoide_storage::time::now_iso_utc(),
    });
    aoide_storage::peer_store::save_peers(&peers).unwrap();

    let pull_out = dispatch(&cli_invocation(&["peer", "pull"], &[], &[]));
    assert_eq!(pull_out.status, Status::Ok, "peer pull itself never errors over one bad peer: {}", pull_out.message);
    let results = pull_out.data.as_ref().unwrap()["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    let good_result = results.iter().find(|r| r["name"] == "good").unwrap();
    let flaky_result = results.iter().find(|r| r["name"] == "flaky").unwrap();
    assert_eq!(good_result["ok"], true, "the reachable peer still succeeds: {good_result:?}");
    assert_eq!(flaky_result["ok"], false, "the unreachable peer fails, but doesn't abort the batch");

    // The good peer's cache is fresh; the flaky one is stale but PRESENT
    // (never deleted, never silently dropped).
    let good_cache = aoide_storage::peer_store::load_peer_cache("good").unwrap();
    assert!(!good_cache.stale);
    let flaky_cache = aoide_storage::peer_store::load_peer_cache("flaky").unwrap();
    assert!(flaky_cache.stale);
    assert!(flaky_cache.last_error.is_some());

    // And the fold shows both: `good-peer` fresh with children, `flaky`
    // stale with none — never a crash, never a silently-dropped peer.
    let view_out = dispatch(&cli_invocation(&["graph", "view"], &[], &[("json", "true")]));
    let nodes = view_out.data.as_ref().unwrap()["nodes"].as_array().unwrap();
    let good_node = nodes.iter().find(|n| n["id"] == "peer:good").unwrap();
    assert_eq!(good_node["state"], "fresh");
    let flaky_node = nodes.iter().find(|n| n["id"] == "peer:flaky").unwrap();
    assert_eq!(flaky_node["state"], "stale");
    assert!(flaky_node.get("children").is_none());

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}

// ── Peer nickname validation — NOT `#[ignore]`'d: both handlers reject a
// ── bad name before ever reaching `run_curl`, so this needs no real network
// ── and runs in the ordinary sandboxed `cargo test` pass. ────────────────

#[test]
fn peer_add_rejects_a_path_traversal_name_without_touching_the_network_or_registry() {
    let _guard = aoide_test_support::env_lock().lock().unwrap();
    let root = unique_root("add-traversal");
    let _stage = setup_env(&root);

    // The url points at a port nothing listens on — if the name check didn't
    // short-circuit first, this would fail on the curl fetch instead, which
    // would also assert Error but for the WRONG reason; asserting
    // `invalid-name` specifically proves the traversal guard fired first.
    let out = dispatch(&cli_invocation(&["peer", "add"], &["../../evil", "http://127.0.0.1:1/"], &[]));
    assert_eq!(out.status, Status::Error);
    assert_eq!(out.data.unwrap()["reason"], "invalid-name");
    assert!(aoide_storage::peer_store::load_peers().is_empty(), "nothing registered");

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}

#[test]
fn peer_remove_rejects_a_path_traversal_name_before_touching_the_cache_file() {
    let _guard = aoide_test_support::env_lock().lock().unwrap();
    let root = unique_root("remove-traversal");
    let _stage = setup_env(&root);

    let out = dispatch(&cli_invocation(&["peer", "remove"], &["../../evil"], &[]));
    assert_eq!(out.status, Status::Error);
    assert_eq!(out.data.unwrap()["reason"], "invalid-name");

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}
