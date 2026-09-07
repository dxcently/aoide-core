//! Real two-instance, same-network connectivity proof for the node
//! federation feature (CONTRACTS.md §7) — owner-directed priority
//! (2026-08-14): a genuine end-to-end round trip, not mocked HTTP.
//!
//! Two ACTUAL A2A servers are bound to two different `127.0.0.1:<port>`
//! addresses. `127.0.0.1:A` and `127.0.0.1:B` legitimately simulate "two
//! boxes reachable on the same network" — same-subnet HTTP reachability is
//! same-subnet HTTP reachability whether the two addresses happen to share a
//! loopback interface or are two real LAN IPs; nothing in the protocol
//! (a JSON-RPC method over a plain URL) cares which. One is registered as a
//! node of the "local" side via a REAL `aoide node add <name> <url>` (a real
//! curl GET of the AgentCard), then pulled via a REAL `aoide node pull` (a
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
//! run explicitly with `cargo test -p aoide-cli --test node_connectivity -- --ignored`
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
        "aoide-node-connectivity-{tag}-{}-{}",
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
fn node_add_and_pull_round_trip_over_real_http_between_two_loopback_instances() {
    let _guard = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
    let root = unique_root("main");
    let _stage = setup_env(&root);

    // Seed a real, checkable node on the (shared, single-process) stage
    // BEFORE node B starts serving, so B's FIRST graphSummary response
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

    // Bind node "B"'s A2A door to a REAL loopback port and serve it on a
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
            Path::new("/tmp/aoide-a2a-node-connectivity-unused.sock"),
            false,
            registry(),
        );
    });
    wait_for_tcp_up(&format!("127.0.0.1:{port_b}"));
    let node_url = format!("http://127.0.0.1:{port_b}/");

    // `node add` — a REAL curl GET of B's `/.well-known/agent-card.json`
    // over real HTTP (verification-before-registering).
    let add_out = dispatch(&cli_invocation(&["node", "add"], &["yomi-strix", &node_url], &[]));
    assert_eq!(add_out.status, Status::Ok, "node add: {}", add_out.message);
    let nodes = aoide_storage::node_store::load_nodes();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].name, "yomi-strix");
    assert_eq!(nodes[0].url, node_url);

    // `node pull` — a REAL curl POST of `aoide/graphSummary` over real HTTP.
    let pull_out = dispatch(&cli_invocation(&["node", "pull"], &["yomi-strix"], &[]));
    assert_eq!(pull_out.status, Status::Ok, "node pull: {}", pull_out.message);
    let results = pull_out.data.as_ref().unwrap()["results"].as_array().unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["ok"], true, "pull result: {results:?}");

    // The cache now holds B's ACTUAL served response — real bytes, not a
    // stub: B's instance name is exactly what `serve` was told to
    // advertise, and the graph carries the project registered before B
    // started serving.
    let cache = aoide_storage::node_store::load_node_cache("yomi-strix").expect("cache written");
    assert!(!cache.stale);
    assert_eq!(cache.instance.as_ref().unwrap()["name"], "yomi-strix");
    assert_eq!(cache.instance.as_ref().unwrap()["url"], node_url);
    let graph = cache.graph.as_ref().unwrap();
    assert!(
        graph["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["id"] == "project:aoide-remote"),
        "the node's REAL served graph round-tripped over real HTTP: {graph}"
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
    // local projects PLUS a `node:yomi-strix` root node whose `children`
    // reflect the OLD (pre-mutation) snapshot only.
    let view_out = dispatch(&cli_invocation(&["graph"], &[], &[("json", "true")]));
    assert_eq!(view_out.status, Status::Ok);
    let doc = view_out.data.as_ref().unwrap();
    let nodes = doc["nodes"].as_array().unwrap();
    assert!(nodes.iter().any(|n| n["id"] == "project:aoide-remote"));
    assert!(nodes.iter().any(|n| n["id"] == "project:local-only"));
    let mesh_node = nodes
        .iter()
        .find(|n| n["id"] == "node:yomi-strix")
        .expect("mesh node folded into the LOCAL resolved graph document");
    assert_eq!(mesh_node["state"], "fresh");
    let children = mesh_node["children"]["nodes"].as_array().unwrap();
    assert!(
        children.iter().any(|n| n["id"] == "project:aoide-remote"),
        "the node's cached subtree carries what B had at pull time: {children:?}"
    );
    assert!(
        !children.iter().any(|n| n["id"] == "project:local-only"),
        "the node's cached subtree must NOT reflect a LOCAL mutation made after the pull \
         — it's a frozen cache from a real pull, not a live re-fetch: {children:?}"
    );

    // `node status` reports it fresh, over the same real cache.
    let status_out = dispatch(&cli_invocation(&["node", "status"], &[], &[]));
    assert_eq!(status_out.status, Status::Ok);
    let rows = status_out.data.as_ref().unwrap()["nodes"].as_array().unwrap();
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
fn node_add_against_an_unreachable_url_never_registers_and_pull_of_a_down_node_marks_stale_without_breaking_others() {
    let _guard = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
    let root = unique_root("unreachable");
    let _stage = setup_env(&root);

    // `node add` against a port NOTHING is listening on — a real, genuine
    // connection-refused, not a mock. It must never register.
    let dead_port = free_port(); // reserved, then dropped — nothing binds it
    let dead_url = format!("http://127.0.0.1:{dead_port}/");
    let add_out = dispatch(&cli_invocation(&["node", "add"], &["ghost", &dead_url], &[]));
    assert_eq!(add_out.status, Status::Error, "an unreachable node must fail node add");
    assert!(
        aoide_storage::node_store::load_nodes().is_empty(),
        "a node that fails AgentCard verification is never registered"
    );

    // Now register ONE real, reachable node alongside a SECOND, registered
    // node that is unreachable (its listener never came up) — `node pull`
    // with no name pulls both, and the good one must succeed regardless of
    // the bad one.
    let port_b = free_port();
    std::thread::spawn(move || {
        let _ = aoide::a2a::serve(
            "127.0.0.1",
            port_b,
            &PathBuf::from("/dev/null"),
            "",
            "good-node",
            "",
            "",
            Path::new("/tmp/aoide-a2a-node-connectivity-unused.sock"),
            false,
            registry(),
        );
    });
    wait_for_tcp_up(&format!("127.0.0.1:{port_b}"));
    let good_url = format!("http://127.0.0.1:{port_b}/");
    let add_good = dispatch(&cli_invocation(&["node", "add"], &["good", &good_url], &[]));
    assert_eq!(add_good.status, Status::Ok, "{}", add_good.message);

    // A second node entry registered by hand pointing at a dead port (bypasses
    // `node add`'s verification so we can exercise `node pull`'s per-node
    // failure isolation without a second live server).
    let mut nodes = aoide_storage::node_store::load_nodes();
    nodes.push(aoide_storage::node_store::Node {
        name: "flaky".to_string(),
        url: dead_url.clone(),
        autogate: false,
        token_file: None,
        bearer_secret: None,
        hub: false,
        pubkey: None,
        verified: false,
        allows: Vec::new(),
        via: None,
        added_at: aoide_storage::time::now_iso_utc(),
    });
    aoide_storage::node_store::save_nodes(&nodes).unwrap();

    let pull_out = dispatch(&cli_invocation(&["node", "pull"], &[], &[]));
    assert_eq!(pull_out.status, Status::Ok, "node pull itself never errors over one bad node: {}", pull_out.message);
    let results = pull_out.data.as_ref().unwrap()["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    let good_result = results.iter().find(|r| r["name"] == "good").unwrap();
    let flaky_result = results.iter().find(|r| r["name"] == "flaky").unwrap();
    assert_eq!(good_result["ok"], true, "the reachable node still succeeds: {good_result:?}");
    assert_eq!(flaky_result["ok"], false, "the unreachable node fails, but doesn't abort the batch");

    // The good node's cache is fresh; the flaky one is stale but PRESENT
    // (never deleted, never silently dropped).
    let good_cache = aoide_storage::node_store::load_node_cache("good").unwrap();
    assert!(!good_cache.stale);
    let flaky_cache = aoide_storage::node_store::load_node_cache("flaky").unwrap();
    assert!(flaky_cache.stale);
    assert!(flaky_cache.last_error.is_some());

    // And the fold shows both: `good-node` fresh with children, `flaky`
    // stale with none — never a crash, never a silently-dropped node.
    let view_out = dispatch(&cli_invocation(&["graph"], &[], &[("json", "true")]));
    let nodes = view_out.data.as_ref().unwrap()["nodes"].as_array().unwrap();
    let good_node = nodes.iter().find(|n| n["id"] == "node:good").unwrap();
    assert_eq!(good_node["state"], "fresh");
    let flaky_node = nodes.iter().find(|n| n["id"] == "node:flaky").unwrap();
    assert_eq!(flaky_node["state"], "stale");
    assert!(flaky_node.get("children").is_none());

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}

// ── Node nickname validation — NOT `#[ignore]`'d: both handlers reject a
// ── bad name before ever reaching `run_curl`, so this needs no real network
// ── and runs in the ordinary sandboxed `cargo test` pass. ────────────────

#[test]
fn node_add_rejects_a_path_traversal_name_without_touching_the_network_or_registry() {
    let _guard = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
    let root = unique_root("add-traversal");
    let _stage = setup_env(&root);

    // The url points at a port nothing listens on — if the name check didn't
    // short-circuit first, this would fail on the curl fetch instead, which
    // would also assert Error but for the WRONG reason; asserting
    // `invalid-name` specifically proves the traversal guard fired first.
    let out = dispatch(&cli_invocation(&["node", "add"], &["../../evil", "http://127.0.0.1:1/"], &[]));
    assert_eq!(out.status, Status::Error);
    assert_eq!(out.data.unwrap()["reason"], "invalid-name");
    assert!(aoide_storage::node_store::load_nodes().is_empty(), "nothing registered");

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}

#[test]
fn node_remove_rejects_a_path_traversal_name_before_touching_the_cache_file() {
    let _guard = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
    let root = unique_root("remove-traversal");
    let _stage = setup_env(&root);

    let out = dispatch(&cli_invocation(&["node", "remove"], &["../../evil"], &[]));
    assert_eq!(out.status, Status::Error);
    assert_eq!(out.data.unwrap()["reason"], "invalid-name");

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}

/// `node rm <name>` is a PARSER-LEVEL alias for `node remove <name>`
/// (`aoide_protocol::door::ALIASES`) — never a second registered command.
/// Proves the alias end to end against the REAL registry: `door::parse`
/// resolves `node rm ghost` to the canonical `node.remove` path and hands it
/// the same `ghost` arg, dispatch actually runs `handle_node_remove` (its
/// `unknown-node` refusal is the tell — a parser bug that left `rm`
/// unresolved would fail as `unknown command`, not reach this handler at
/// all), and `schema --json` never grows a second `node.rm` entry — the
/// alias is invisible to the schema, the golden snapshot, and every other
/// consumer of the registry.
#[test]
fn node_rm_is_a_parser_alias_for_node_remove_and_never_a_second_schema_entry() {
    let _guard = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
    let root = unique_root("rm-alias");
    let _stage = setup_env(&root);

    let (inv, _json) = aoide_protocol::door::parse(
        &["node".to_string(), "rm".to_string(), "ghost".to_string()],
        Door::Cli,
        "aoide",
        registry(),
    )
    .expect("`node rm ghost` must parse — the alias resolves to a real command path");
    assert_eq!(inv.path, vec!["node", "remove"], "resolves to the CANONICAL path, never its own `node.rm` path");
    assert_eq!(inv.args, vec!["ghost"]);

    let out = dispatch(&inv);
    assert_eq!(out.command, "node.remove", "dispatch actually ran the `node remove` handler");
    assert_eq!(out.status, Status::Error);
    assert_eq!(out.data.unwrap()["reason"], "unknown-node");

    let dotted: Vec<String> = registry().commands().map(|c| c.dotted()).collect();
    assert!(dotted.iter().any(|p| p == "node.remove"), "node.remove must still be registered");
    assert!(!dotted.iter().any(|p| p == "node.rm"), "the alias must never become a second schema entry");

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}

// ── The pairing ceremony's CLI half (P-P2) ───────────────────────────────

#[test]
fn node_pair_url_target_rejects_an_invalid_name_without_touching_the_network_or_registry() {
    let _guard = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
    let root = unique_root("pair-request-invalid-name");
    let _stage = setup_env(&root);

    // Same short-circuit proof as `node add`'s traversal test above: the
    // url points at a port nothing listens on, so a `reason: invalid-name`
    // (not a fetch error) proves the name check fired before any network
    // I/O or identity mint.
    let out = dispatch(&cli_invocation(
        &["pair"],
        &["http://127.0.0.1:1/"],
        &[("name", "../../evil")],
    ));
    assert_eq!(out.status, Status::Error);
    assert_eq!(out.data.unwrap()["reason"], "invalid-name");
    assert!(aoide_storage::node_store::load_nodes().is_empty(), "nothing registered");

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}

#[test]
fn bare_pair_off_a_tty_is_the_pending_listing() {
    let _guard = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
    let root = unique_root("pair-request-no-url");
    let _stage = setup_env(&root);

    // Task #135 P3': bare `pair` off a tty (test-harness stdio) is the
    // pending LISTING — the old `node pending`, which died into this —
    // never a usage error and never a hung menu.
    let out = dispatch(&cli_invocation(&["pair"], &[], &[]));
    assert_eq!(out.status, Status::Ok);
    assert_eq!(out.data.unwrap()["requests"].as_array().unwrap().len(), 0);

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}

/// The arity guard survives the collapse (review finding, P-PV2
/// follow-up, re-proven for `pair`): a second positional still parses —
/// `door::parse`'s own longest-prefix match (the REAL argv parser, not a
/// hand-built `Invocation`) resolves `pair request <url>` to the
/// 1-segment `pair` with `["request", "<url>"]` as ITS OWN two args — and
/// dispatching it refuses fast (well under a sweep window — proof no sweep
/// or dial ever ran), never silently treating "request" as a name to sweep
/// for while discarding the url.
#[test]
fn pair_with_a_second_positional_is_a_fast_taught_usage_error_never_a_silent_sweep() {
    let _guard = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
    let root = unique_root("pair-request-old-spelling");
    let _stage = setup_env(&root);

    let argv: Vec<String> = ["pair", "request", "http://127.0.0.1:1/"].iter().map(|s| s.to_string()).collect();
    let (inv, _json) = aoide_protocol::door::parse(&argv, Door::Cli, "aoide", registry())
        .expect("`pair request <url>` still parses — just not as its own command");
    assert_eq!(inv.path, vec!["pair"], "no `pair.request` path exists to match");
    assert_eq!(inv.args, vec!["request", "http://127.0.0.1:1/"], "both tokens land as pair's own args");

    let deadline = Instant::now() + Duration::from_secs(5);
    let out = dispatch(&inv);
    assert!(Instant::now() < deadline, "must refuse fast, never burn a sweep window on the discarded url");
    assert_eq!(out.status, Status::Usage, "{out:?}");
    assert!(out.data.is_none(), "no `reason` field — this refusal fires before either arm ever runs: {out:?}");
    assert!(out.message.contains("usage: aoide pair"), "{}", out.message);

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}

#[test]
fn pair_reject_on_an_unknown_id_leaves_no_record_change() {
    let _guard = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
    let root = unique_root("pair-unknown-id");
    let _stage = setup_env(&root);

    // The old `node pair approve nosuchid` unknown-id refusal is GONE by
    // design: under the one-command dispatch an unknown target means "request
    // a pair with that name", which is the feature, not a typo. `pair
    // reject` keeps the taught unknown-id error — there is nothing to
    // remove.
    let reject = dispatch(&cli_invocation(&["pair", "reject"], &["nosuchid"], &[]));
    assert_eq!(reject.status, Status::Error);
    assert_eq!(reject.data.unwrap()["reason"], "unknown-id");
    assert!(aoide_storage::node_store::load_nodes().is_empty(), "reject of an unknown id writes no node");

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}

// ── Review-bounce fix forward on cad70ad — direction-dispatching
// ── `pair`'s approve path and `pair reject` (Finding 2) and the unrevealed-inbound
// ── refusal (Finding 1). These drive the storage-level `pairing` functions
// ── directly to park/transition entries (the same way the network-free
// ── tests above bypass `run_curl`), rather than standing up a real loopback
// ── A2A server — the ceremony's WIRE round trip is already proven end to
// ── end by `aoide-server`'s own
// ── `full_pairing_ceremony_request_reveal_pending_approve_confirm_writes_records_on_both_ends`
// ── test; what's under test here is the CLI's OWN direction dispatch atop
// ── an already-parked entry. ──────────────────────────────────────────────

#[test]
fn node_pair_approve_on_an_unrevealed_inbound_entry_is_refused_with_awaiting_reveal() {
    let _guard = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
    let root = unique_root("pair-approve-unrevealed");
    let _stage = setup_env(&root);

    let now = aoide_storage::time::now_iso_utc();
    let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();
    let expires = aoide_storage::pairing::expires_at_from(now_epoch);
    let commit = aoide_storage::pairing::derive_commit(&"a".repeat(64), &"c".repeat(32));
    let (entry, _) = aoide_storage::pairing::park_inbound(&"a".repeat(64), "box-a", "127.0.0.1", "http://a/", &commit, &now, &expires, None).unwrap();
    assert!(entry.requester_nonce_hex.is_none(), "freshly parked, never revealed");

    let out = dispatch(&cli_invocation(&["pair"], &[entry.id.as_str()], &[("yes", "true"), ("wait", "0")]));
    assert_eq!(out.status, Status::Error);
    assert_eq!(out.data.unwrap()["reason"], "awaiting-reveal");
    assert!(aoide_storage::node_store::load_nodes().is_empty(), "an unrevealed entry never commits a node record");
    let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();
    assert_eq!(aoide_storage::pairing::list_inbound(now_epoch).len(), 1, "the entry stays parked — refusal, not a drop");

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}

#[test]
fn node_pair_reject_on_an_outbound_entry_aborts_before_the_approvers_callback() {
    let _guard = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        via: None,
        tries: 0,
    };
    aoide_storage::pairing::park_outbound(entry).unwrap();

    let out = dispatch(&cli_invocation(&["pair", "reject"], &["abcd1234"], &[]));
    assert_eq!(out.status, Status::Ok, "{}", out.message);
    assert_eq!(out.data.as_ref().unwrap()["direction"], "outbound");
    assert!(aoide_storage::node_store::load_nodes().is_empty(), "reject writes no node record");
    let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();
    assert!(aoide_storage::pairing::list_outbound(now_epoch).is_empty(), "the outbound entry is gone");

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}

#[test]
fn node_pair_reject_on_an_outbound_entry_aborts_after_the_approvers_callback() {
    let _guard = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        via: None,
        tries: 0,
    };
    aoide_storage::pairing::park_outbound(entry).unwrap();
    let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();
    let after_callback = aoide_storage::pairing::mark_outbound_awaiting_confirm("abcd5678", &"b".repeat(64), now_epoch).unwrap();
    assert_eq!(after_callback.state, aoide_storage::pairing::OutboundState::AwaitingConfirm);

    let out = dispatch(&cli_invocation(&["pair", "reject"], &["abcd5678"], &[]));
    assert_eq!(out.status, Status::Ok, "{}", out.message);
    assert_eq!(out.data.as_ref().unwrap()["direction"], "outbound");
    assert!(aoide_storage::node_store::load_nodes().is_empty(), "reject writes no node record even mid-ceremony");
    assert!(aoide_storage::pairing::list_outbound(now_epoch).is_empty(), "the outbound entry is gone");

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}

/// A minimal, real local `aoide/pairPoll` responder — ANY POST gets the
/// same canned JSON reply. Mirrors `wait_for_tcp_up`'s own "real listener,
/// no mock" posture one function up; `#[ignore]`'d callers are the ones
/// that use this (module doc: real curl, no `curl` on `PATH` in the nix
/// sandboxed `checkPhase`).
fn spawn_fake_pair_poll_server(body: &'static str) -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepter = listener.try_clone().unwrap();
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        loop {
            let Ok((mut stream, _)) = accepter.accept() else { break };
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            if n == 0 {
                continue;
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (listener, port)
}

/// Design A (task #119): `pair <target>` on an `awaiting-approval`
/// outbound entry now POLLS the approver's door (real curl, real socket —
/// the whole point is proving no callback is needed, only a forward dial)
/// instead of making a network-free local state check. `#[ignore]`'d for
/// the same reason this file's own real-HTTP round trip above is: no `curl`
/// on `PATH` in the nix sandboxed `checkPhase` (module doc) — run with
/// `--ignored` in `nix develop`.
#[test]
#[ignore = "real loopback TCP + real curl (Design A's poll) — no network/curl in the nix sandbox; run with --ignored"]
fn node_pair_approve_on_an_outbound_entry_still_awaiting_the_nodes_own_approval_is_refused() {
    let _guard = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
    let root = unique_root("pair-approve-outbound-too-early");
    let _stage = setup_env(&root);

    let (_listener, port) = spawn_fake_pair_poll_server(r#"{"jsonrpc":"2.0","id":1,"result":{"status":"pending"}}"#);

    let now = aoide_storage::time::now_iso_utc();
    let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();
    let expires = aoide_storage::pairing::expires_at_from(now_epoch);
    let entry = aoide_storage::pairing::OutboundPairingRequest {
        id: "efgh1234".to_string(),
        url: format!("http://127.0.0.1:{port}/"),
        name: "box-b".to_string(),
        pubkey_hex: "b".repeat(64),
        requester_nonce_hex: "c".repeat(32),
        approver_nonce_hex: "d".repeat(32),
        requested_at: now.clone(),
        expires_at: expires,
        state: aoide_storage::pairing::OutboundState::AwaitingApproval,
        via: None,
        tries: 0,
    };
    aoide_storage::pairing::park_outbound(entry).unwrap();

    // `--wait 0` is the ONE-SHOT poll (task #135 P2) — without it the resume
    // leg blocks the full default 600s against a server that only ever
    // answers "pending", then returns Ok-still-parked instead of this refusal.
    let out = dispatch(&cli_invocation(&["pair"], &["efgh1234"], &[("yes", "true"), ("wait", "0")]));
    assert_eq!(out.status, Status::Error, "{}", out.message);
    assert_eq!(out.data.unwrap()["reason"], "awaiting-node-approval");
    assert!(aoide_storage::node_store::load_nodes().is_empty());
    let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();
    assert_eq!(
        aoide_storage::pairing::list_outbound(now_epoch)[0].state,
        aoide_storage::pairing::OutboundState::AwaitingApproval,
        "a pending poll leaves the entry exactly where it was"
    );

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}

/// The mutual-code redesign (R1) replaced this leg's old bare `--yes`
/// confirm with a typed reply code gate — `commit_outbound` derives
/// `derive_reply_sas` from THIS process's own identity plus the entry's
/// stored transcript and only commits on a match, the exact mirror of the
/// approver's own `derive_sas` gate. `--yes` alone no longer reaches this
/// commit (see `..._with_yes_alone_is_the_taught_refusal` below); this
/// test now drives it with the correct scripted `--code`.
#[test]
fn node_pair_approve_on_an_outbound_entry_awaiting_confirm_commits_with_the_reply_code() {
    let _guard = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        // P-S4: the via this ceremony resolved at request time (a --via
        // flag, or node invite's observed src_addr) rides the parked
        // entry to this later, separate `pair <target>` invocation —
        // asserted below, committed onto the node record only here.
        via: Some("ssh://khoa@box-b".to_string()),
        tries: 0,
    };
    aoide_storage::pairing::park_outbound(entry).unwrap();
    let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();
    aoide_storage::pairing::mark_outbound_awaiting_confirm("ijkl1234", &"b".repeat(64), now_epoch).unwrap();

    let expected_reply_sas = aoide_storage::pairing::derive_reply_sas(&own_pubkey, &"b".repeat(64), &"c".repeat(32), &"d".repeat(32));

    let out = dispatch(&cli_invocation(&["pair"], &["ijkl1234"], &[("code", &expected_reply_sas), ("wait", "0")]));
    assert_eq!(out.status, Status::Ok, "{}", out.message);
    let data = out.data.unwrap();
    assert_eq!(data["replySas"], expected_reply_sas);
    assert_eq!(data["direction"], "outbound");

    let nodes = aoide_storage::node_store::load_nodes();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].name, "box-b");
    assert_eq!(nodes[0].url, "http://b/");
    assert_eq!(nodes[0].pubkey.as_deref(), Some("b".repeat(64).as_str()));
    assert_eq!(nodes[0].verified, true);
    assert_eq!(nodes[0].via.as_deref(), Some("ssh://khoa@box-b"), "the parked entry's via is committed onto the node record at approve time (P-S4)");
    assert!(aoide_storage::pairing::list_outbound(now_epoch).is_empty(), "committed and removed from the outbound queue");

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}

/// The mutual-code redesign (R1): `--yes` alone, with no `--code`, no
/// longer reaches this leg's commit at all — `outbound_gate_from` resolves
/// it to `CodeGate::Unavailable`, and `commit_outbound` refuses with a
/// taught error rather than either bypassing the gate (the old shape) or
/// silently prompting on a non-tty caller. Nothing commits, nothing is
/// removed from the queue, and no try is counted — the refusal fires
/// before `commit_outbound` ever compares a code.
#[test]
fn node_pair_approve_on_an_outbound_entry_awaiting_confirm_with_yes_alone_is_the_taught_refusal() {
    let _guard = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
    let root = unique_root("pair-approve-outbound-confirm-yes-alone");
    let _stage = setup_env(&root);

    let now = aoide_storage::time::now_iso_utc();
    let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();
    let expires = aoide_storage::pairing::expires_at_from(now_epoch);
    let entry = aoide_storage::pairing::OutboundPairingRequest {
        id: "ijkl5678".to_string(),
        url: "http://b/".to_string(),
        name: "box-b".to_string(),
        pubkey_hex: "b".repeat(64),
        requester_nonce_hex: "c".repeat(32),
        approver_nonce_hex: "d".repeat(32),
        requested_at: now.clone(),
        expires_at: expires,
        state: aoide_storage::pairing::OutboundState::AwaitingApproval,
        via: None,
        tries: 0,
    };
    aoide_storage::pairing::park_outbound(entry).unwrap();
    let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();
    aoide_storage::pairing::mark_outbound_awaiting_confirm("ijkl5678", &"b".repeat(64), now_epoch).unwrap();

    let out = dispatch(&cli_invocation(&["pair"], &["ijkl5678"], &[("yes", "true"), ("wait", "0")]));
    assert_eq!(out.status, Status::Usage, "{}", out.message);
    assert!(
        out.message.contains("does not bypass"),
        "the refusal must teach why --yes alone isn't enough here: {}",
        out.message
    );

    assert!(aoide_storage::node_store::load_nodes().is_empty(), "nothing was ever committed");
    let listed = aoide_storage::pairing::list_outbound(now_epoch);
    assert_eq!(listed.len(), 1, "the entry stays parked, never removed by a refused confirm");
    assert_eq!(listed[0].tries, 0, "a refusal with no code offered counts no try");

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}

/// Review finding (P-S4 follow-up): a plain re-pair with NO `--via` must
/// never wipe a `via` a previous ceremony (e.g. `node invite`) already
/// recorded — `set_node_via` is only called at all when the entry names
/// one, mirroring `upsert_paired_node`'s own "untouched unless this call
/// names a change" stance for `autogate`/`tokenFile`/`bearerSecret`/`hub`/
/// `allows`. Seeds `box-b` already paired WITH a `via` (as if a prior
/// `node invite` had run), then re-pairs it through an outbound entry
/// carrying `via: None` — the re-pair's own pubkey/url land as usual, but
/// the existing `via` must survive untouched. Driven through the CORRECT
/// `--code` (the mutual-code redesign, R1, made `--yes` alone insufficient
/// here — `..._with_yes_alone_is_the_taught_refusal` above covers that
/// half) so this test still isolates the property it exists for: the via
/// preservation, not the code gate.
#[test]
fn node_pair_approve_on_an_outbound_entry_with_no_via_leaves_a_previously_recorded_via_untouched() {
    let _guard = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
    let root = unique_root("pair-approve-outbound-preserves-via");
    let _stage = setup_env(&root);

    // box-b is already a VERIFIED node carrying a via from an earlier
    // ceremony (`node invite`'s own src_addr-derived default, in
    // practice) — this re-pair must not touch it.
    aoide_storage::node_store::save_nodes(&[aoide_storage::node_store::Node {
        name: "box-b".to_string(),
        url: "http://old-b/".to_string(),
        autogate: false,
        token_file: None,
        bearer_secret: None,
        hub: false,
        pubkey: Some("oldkey".repeat(8)),
        verified: true,
        allows: vec!["read".to_string(), "spawn".to_string()],
        via: Some("ssh://khoa@previously-recorded".to_string()),
        added_at: "2026-08-14T00:00:00Z".to_string(),
    }])
    .unwrap();

    let (kp, _) = aoide_storage::identity::load_or_mint().unwrap();
    let own_pubkey = kp.info().pubkey_hex;

    let now = aoide_storage::time::now_iso_utc();
    let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();
    let expires = aoide_storage::pairing::expires_at_from(now_epoch);
    let entry = aoide_storage::pairing::OutboundPairingRequest {
        id: "mnop1234".to_string(),
        url: "http://new-b/".to_string(),
        name: "box-b".to_string(),
        pubkey_hex: "e".repeat(64),
        requester_nonce_hex: "f".repeat(32),
        approver_nonce_hex: "1".repeat(32),
        requested_at: now.clone(),
        expires_at: expires,
        state: aoide_storage::pairing::OutboundState::AwaitingApproval,
        // The re-pair itself carries NO via — a plain `pair <url>`
        // with no `--via` this time.
        via: None,
        tries: 0,
    };
    aoide_storage::pairing::park_outbound(entry).unwrap();
    let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();
    aoide_storage::pairing::mark_outbound_awaiting_confirm("mnop1234", &"e".repeat(64), now_epoch).unwrap();

    let expected_reply_sas = aoide_storage::pairing::derive_reply_sas(&own_pubkey, &"e".repeat(64), &"f".repeat(32), &"1".repeat(32));

    let out = dispatch(&cli_invocation(&["pair"], &["mnop1234"], &[("code", &expected_reply_sas), ("wait", "0")]));
    assert_eq!(out.status, Status::Ok, "{}", out.message);
    let data = out.data.unwrap();
    assert_eq!(data["replySas"], expected_reply_sas);

    let nodes = aoide_storage::node_store::load_nodes();
    assert_eq!(nodes.len(), 1);
    // The re-pair's own fields DID land (pubkey/url replace on every
    // re-pair, per upsert_paired_node's own contract) —
    assert_eq!(nodes[0].url, "http://new-b/");
    assert_eq!(nodes[0].pubkey.as_deref(), Some("e".repeat(64).as_str()));
    // — but the via from the EARLIER ceremony survives this via-less
    // re-pair untouched, never silently cleared.
    assert_eq!(
        nodes[0].via.as_deref(),
        Some("ssh://khoa@previously-recorded"),
        "a via-less re-pair must never wipe a previously-recorded via"
    );

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
}
