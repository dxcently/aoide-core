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
    // carries it. (The path must be a real absolute dir — `project
    // add` rejects anything else now — so it lives under this test's own
    // `root` and is removed with it.)
    let remote = root.join("remote");
    std::fs::create_dir_all(&remote).unwrap();
    let seed = dispatch(&cli_invocation(
        &["project", "add"],
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
            false,
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
        &["project", "add"],
        &["local-only", local.to_str().unwrap()],
        &[],
    ));
    assert_eq!(mutate.status, Status::Ok);

    // The fold: `graph --json`'s resolved document now carries BOTH
    // local projects PLUS a `peer:yomi-strix` root node whose `children`
    // reflect the OLD (pre-mutation) snapshot only.
    let view_out = dispatch(&cli_invocation(&["graph"], &[], &[("json", "true")]));
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
            false,
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
        pubkey: None,
        verified: false,
        allows: Vec::new(),
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
    let view_out = dispatch(&cli_invocation(&["graph"], &[], &[("json", "true")]));
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

/// `peer rm <name>` is a PARSER-LEVEL alias for `peer remove <name>`
/// (`aoide_protocol::door::ALIASES`) — never a second registered command.
/// Proves the alias end to end against the REAL registry: `door::parse`
/// resolves `peer rm ghost` to the canonical `peer.remove` path and hands it
/// the same `ghost` arg, dispatch actually runs `handle_peer_remove` (its
/// `unknown-peer` refusal is the tell — a parser bug that left `rm`
/// unresolved would fail as `unknown command`, not reach this handler at
/// all), and `schema --json` never grows a second `peer.rm` entry — the
/// alias is invisible to the schema, the golden snapshot, and every other
/// consumer of the registry.
#[test]
fn peer_rm_is_a_parser_alias_for_peer_remove_and_never_a_second_schema_entry() {
    let _guard = aoide_test_support::env_lock().lock().unwrap();
    let root = unique_root("rm-alias");
    let _stage = setup_env(&root);

    let (inv, _json) = aoide_protocol::door::parse(
        &["peer".to_string(), "rm".to_string(), "ghost".to_string()],
        Door::Cli,
        "aoide",
        registry(),
    )
    .expect("`peer rm ghost` must parse — the alias resolves to a real command path");
    assert_eq!(inv.path, vec!["peer", "remove"], "resolves to the CANONICAL path, never its own `peer.rm` path");
    assert_eq!(inv.args, vec!["ghost"]);

    let out = dispatch(&inv);
    assert_eq!(out.command, "peer.remove", "dispatch actually ran the `peer remove` handler");
    assert_eq!(out.status, Status::Error);
    assert_eq!(out.data.unwrap()["reason"], "unknown-peer");

    let dotted: Vec<String> = registry().commands().map(|c| c.dotted()).collect();
    assert!(dotted.iter().any(|p| p == "peer.remove"), "peer.remove must still be registered");
    assert!(!dotted.iter().any(|p| p == "peer.rm"), "the alias must never become a second schema entry");

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}

// ── The pairing ceremony's CLI half (P-P2) ───────────────────────────────

#[test]
fn peer_pair_request_rejects_an_invalid_name_without_touching_the_network_or_registry() {
    let _guard = aoide_test_support::env_lock().lock().unwrap();
    let root = unique_root("pair-request-invalid-name");
    let _stage = setup_env(&root);

    // Same short-circuit proof as `peer add`'s traversal test above: the
    // url points at a port nothing listens on, so a `reason: invalid-name`
    // (not a fetch error) proves the name check fired before any network
    // I/O or identity mint.
    let out = dispatch(&cli_invocation(
        &["peer", "pair", "request"],
        &["http://127.0.0.1:1/"],
        &[("name", "../../evil")],
    ));
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
fn peer_pair_request_with_no_url_is_a_usage_error() {
    let _guard = aoide_test_support::env_lock().lock().unwrap();
    let root = unique_root("pair-request-no-url");
    let _stage = setup_env(&root);

    let out = dispatch(&cli_invocation(&["peer", "pair", "request"], &[], &[]));
    assert_eq!(out.status, Status::Usage);

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}

#[test]
fn peer_pair_approve_and_reject_on_an_unknown_id_leave_no_record_change() {
    let _guard = aoide_test_support::env_lock().lock().unwrap();
    let root = unique_root("pair-unknown-id");
    let _stage = setup_env(&root);

    let approve = dispatch(&cli_invocation(&["peer", "pair", "approve"], &["nosuchid"], &[("yes", "true")]));
    assert_eq!(approve.status, Status::Error);
    assert_eq!(approve.data.unwrap()["reason"], "unknown-id");
    assert!(aoide_storage::peer_store::load_peers().is_empty(), "approve of an unknown id writes no peer");

    let reject = dispatch(&cli_invocation(&["peer", "pair", "reject"], &["nosuchid"], &[]));
    assert_eq!(reject.status, Status::Error);
    assert_eq!(reject.data.unwrap()["reason"], "unknown-id");
    assert!(aoide_storage::peer_store::load_peers().is_empty(), "reject of an unknown id writes no peer");

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}

#[test]
fn peer_pair_pending_on_an_empty_registry_is_ok_with_an_empty_list() {
    let _guard = aoide_test_support::env_lock().lock().unwrap();
    let root = unique_root("pair-pending-empty");
    let _stage = setup_env(&root);

    let out = dispatch(&cli_invocation(&["peer", "pair", "pending"], &[], &[]));
    assert_eq!(out.status, Status::Ok);
    assert_eq!(out.data.unwrap()["requests"].as_array().unwrap().len(), 0);

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}

// ── Review-bounce fix forward on cad70ad — direction-dispatching
// ── `peer pair approve`/`reject` (Finding 2) and the unrevealed-inbound
// ── refusal (Finding 1). These drive the storage-level `pairing` functions
// ── directly to park/transition entries (the same way the network-free
// ── tests above bypass `run_curl`), rather than standing up a real loopback
// ── A2A server — the ceremony's WIRE round trip is already proven end to
// ── end by `aoide-server`'s own
// ── `full_pairing_ceremony_request_reveal_pending_approve_confirm_writes_records_on_both_ends`
// ── test; what's under test here is the CLI's OWN direction dispatch atop
// ── an already-parked entry. ──────────────────────────────────────────────

#[test]
fn peer_pair_approve_on_an_unrevealed_inbound_entry_is_refused_with_awaiting_reveal() {
    let _guard = aoide_test_support::env_lock().lock().unwrap();
    let root = unique_root("pair-approve-unrevealed");
    let _stage = setup_env(&root);

    let now = aoide_storage::time::now_iso_utc();
    let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();
    let expires = aoide_storage::pairing::expires_at_from(now_epoch);
    let commit = aoide_storage::pairing::derive_commit(&"a".repeat(64), &"c".repeat(32));
    let entry = aoide_storage::pairing::park_inbound(&"a".repeat(64), "box-a", "127.0.0.1", "http://a/", &commit, &now, &expires).unwrap();
    assert!(entry.requester_nonce_hex.is_none(), "freshly parked, never revealed");

    let out = dispatch(&cli_invocation(&["peer", "pair", "approve"], &[entry.id.as_str()], &[("yes", "true")]));
    assert_eq!(out.status, Status::Error);
    assert_eq!(out.data.unwrap()["reason"], "awaiting-reveal");
    assert!(aoide_storage::peer_store::load_peers().is_empty(), "an unrevealed entry never commits a peer record");
    let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();
    assert_eq!(aoide_storage::pairing::list_inbound(now_epoch).len(), 1, "the entry stays parked — refusal, not a drop");

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}

#[test]
fn peer_pair_reject_on_an_outbound_entry_aborts_before_the_approvers_callback() {
    let _guard = aoide_test_support::env_lock().lock().unwrap();
    let root = unique_root("pair-reject-outbound-pre-callback");
    let _stage = setup_env(&root);

    let now = aoide_storage::time::now_iso_utc();
    let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();
    let expires = aoide_storage::pairing::expires_at_from(now_epoch);
    let entry = aoide_storage::pairing::OutboundPairingRequest {
        id: "abcd1234".to_string(),
        url: "http://b/".to_string(),
        name: "box-b".to_string(),
        pubkey_hex: "b".repeat(64),
        requester_nonce_hex: "c".repeat(32),
        approver_nonce_hex: "d".repeat(32),
        requested_at: now.clone(),
        expires_at: expires,
        state: aoide_storage::pairing::OutboundState::AwaitingApproval,
    };
    aoide_storage::pairing::park_outbound(entry).unwrap();

    let out = dispatch(&cli_invocation(&["peer", "pair", "reject"], &["abcd1234"], &[]));
    assert_eq!(out.status, Status::Ok, "{}", out.message);
    assert_eq!(out.data.as_ref().unwrap()["direction"], "outbound");
    assert!(aoide_storage::peer_store::load_peers().is_empty(), "reject writes no peer record");
    let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();
    assert!(aoide_storage::pairing::list_outbound(now_epoch).is_empty(), "the outbound entry is gone");

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}

#[test]
fn peer_pair_reject_on_an_outbound_entry_aborts_after_the_approvers_callback() {
    let _guard = aoide_test_support::env_lock().lock().unwrap();
    let root = unique_root("pair-reject-outbound-post-callback");
    let _stage = setup_env(&root);

    let now = aoide_storage::time::now_iso_utc();
    let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();
    let expires = aoide_storage::pairing::expires_at_from(now_epoch);
    let entry = aoide_storage::pairing::OutboundPairingRequest {
        id: "abcd5678".to_string(),
        url: "http://b/".to_string(),
        name: "box-b".to_string(),
        pubkey_hex: "b".repeat(64),
        requester_nonce_hex: "c".repeat(32),
        approver_nonce_hex: "d".repeat(32),
        requested_at: now.clone(),
        expires_at: expires,
        state: aoide_storage::pairing::OutboundState::AwaitingApproval,
    };
    aoide_storage::pairing::park_outbound(entry).unwrap();
    let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();
    let after_callback = aoide_storage::pairing::mark_outbound_awaiting_confirm("abcd5678", &"b".repeat(64), now_epoch).unwrap();
    assert_eq!(after_callback.state, aoide_storage::pairing::OutboundState::AwaitingConfirm);

    let out = dispatch(&cli_invocation(&["peer", "pair", "reject"], &["abcd5678"], &[]));
    assert_eq!(out.status, Status::Ok, "{}", out.message);
    assert_eq!(out.data.as_ref().unwrap()["direction"], "outbound");
    assert!(aoide_storage::peer_store::load_peers().is_empty(), "reject writes no peer record even mid-ceremony");
    assert!(aoide_storage::pairing::list_outbound(now_epoch).is_empty(), "the outbound entry is gone");

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}

#[test]
fn peer_pair_approve_on_an_outbound_entry_still_awaiting_the_peers_own_approval_is_refused() {
    let _guard = aoide_test_support::env_lock().lock().unwrap();
    let root = unique_root("pair-approve-outbound-too-early");
    let _stage = setup_env(&root);

    let now = aoide_storage::time::now_iso_utc();
    let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();
    let expires = aoide_storage::pairing::expires_at_from(now_epoch);
    let entry = aoide_storage::pairing::OutboundPairingRequest {
        id: "efgh1234".to_string(),
        url: "http://b/".to_string(),
        name: "box-b".to_string(),
        pubkey_hex: "b".repeat(64),
        requester_nonce_hex: "c".repeat(32),
        approver_nonce_hex: "d".repeat(32),
        requested_at: now.clone(),
        expires_at: expires,
        state: aoide_storage::pairing::OutboundState::AwaitingApproval,
    };
    aoide_storage::pairing::park_outbound(entry).unwrap();

    let out = dispatch(&cli_invocation(&["peer", "pair", "approve"], &["efgh1234"], &[("yes", "true")]));
    assert_eq!(out.status, Status::Error);
    assert_eq!(out.data.unwrap()["reason"], "awaiting-peer-approval");
    assert!(aoide_storage::peer_store::load_peers().is_empty());
    let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();
    assert_eq!(
        aoide_storage::pairing::list_outbound(now_epoch)[0].state,
        aoide_storage::pairing::OutboundState::AwaitingApproval,
        "a refused early confirm leaves the entry exactly where it was"
    );

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}

#[test]
fn peer_pair_approve_on_an_outbound_entry_awaiting_confirm_commits_with_yes() {
    let _guard = aoide_test_support::env_lock().lock().unwrap();
    let root = unique_root("pair-approve-outbound-confirm");
    let _stage = setup_env(&root);

    let (kp, _) = aoide_storage::identity::load_or_mint().unwrap();
    let own_pubkey = kp.info().pubkey_hex;

    let now = aoide_storage::time::now_iso_utc();
    let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();
    let expires = aoide_storage::pairing::expires_at_from(now_epoch);
    let entry = aoide_storage::pairing::OutboundPairingRequest {
        id: "ijkl1234".to_string(),
        url: "http://b/".to_string(),
        name: "box-b".to_string(),
        pubkey_hex: "b".repeat(64),
        requester_nonce_hex: "c".repeat(32),
        approver_nonce_hex: "d".repeat(32),
        requested_at: now.clone(),
        expires_at: expires,
        state: aoide_storage::pairing::OutboundState::AwaitingApproval,
    };
    aoide_storage::pairing::park_outbound(entry).unwrap();
    let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();
    aoide_storage::pairing::mark_outbound_awaiting_confirm("ijkl1234", &"b".repeat(64), now_epoch).unwrap();

    let expected_sas = aoide_storage::pairing::derive_sas(&own_pubkey, &"b".repeat(64), &"c".repeat(32), &"d".repeat(32));

    let out = dispatch(&cli_invocation(&["peer", "pair", "approve"], &["ijkl1234"], &[("yes", "true")]));
    assert_eq!(out.status, Status::Ok, "{}", out.message);
    let data = out.data.unwrap();
    assert_eq!(data["sas"], expected_sas);
    assert_eq!(data["direction"], "outbound");

    let peers = aoide_storage::peer_store::load_peers();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].name, "box-b");
    assert_eq!(peers[0].url, "http://b/");
    assert_eq!(peers[0].pubkey.as_deref(), Some("b".repeat(64).as_str()));
    assert_eq!(peers[0].verified, true);
    assert!(aoide_storage::pairing::list_outbound(now_epoch).is_empty(), "committed and removed from the outbound queue");

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}
