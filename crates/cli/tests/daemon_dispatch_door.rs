//! Integration proof for P-D4 — the fourth door (`docs/architecture/
//! AOIDED.md`'s "L2" section and its own phase entry): the daemon socket's
//! `dispatch` op runs an `Invocation { door: Door::Daemon, .. }` through the
//! SAME `aoide::dispatch::dispatch` every other door already calls, against
//! the REAL, fully-assembled registry — "prove the door policy by test, not
//! new code" (the phase entry's own words: no daemon-specific policy table
//! exists anywhere).
//!
//! `aoide-server`'s own `daemon.rs` unit tests (`cargo test -p aoide-server`)
//! prove `handle_conn`'s WIRING with a fixture registry/dispatch fn — they
//! cannot prove real per-command policy, since the fully-assembled registry
//! only exists in THIS crate (the DI-seam invariant both crates' docs
//! state). This file is that proof, one connection per test, no fixed
//! sleeps — every wait below is either a bounded connect-retry or a single
//! blocking read on a socket the daemon is known to reply on.

use aoide::dispatch::{dispatch, registry};
use aoide_server::daemon::serve_daemon;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// A short path directly under `/tmp` — not `std::env::temp_dir()`, which
/// under a sandboxed `$TMPDIR` can already be a long nested path (task #75's
/// own SUN_LEN lesson; `aoide-server`'s own `daemon.rs` tests hold the same
/// discipline).
fn short_tmp(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    PathBuf::from(format!("/tmp/av-cli-dispatch-{tag}-{}-{nanos}", std::process::id()))
}

fn connect_retrying(socket_path: &Path) -> UnixStream {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match UnixStream::connect(socket_path) {
            Ok(s) => return s,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => panic!("could not connect to {socket_path:?} in time: {e}"),
        }
    }
}

fn read_one_line(reader: &mut impl BufRead) -> Value {
    let mut line = String::new();
    reader.read_line(&mut line).expect("reading a reply line");
    serde_json::from_str(line.trim()).unwrap_or_else(|e| panic!("reply line not JSON: {e}: {line:?}"))
}

/// Floor `$AOIDE_STAGE_DIR`/`$AOIDE_STATE_DIR` at a fresh private tempdir
/// once per test binary, unless a test already set them — the same safety
/// net `aoide-server`'s `env_lock()` carries, re-derived here because this
/// binary starts a REAL daemon whose `HandEditWatcher`/boot-resume paths
/// eagerly resolve `conducting_stage_dir()`, and (post-S1) that first
/// resolution MIGRATES the operator's real `~/Aoide/song/stage` when no
/// override is set (the exact production-state mutation
/// `conduct/src/lib.rs`'s own floor was built after being burned by).
fn floor_stage_env() {
    static FLOOR: std::sync::Once = std::sync::Once::new();
    FLOOR.call_once(|| {
        let base = short_tmp("env-floor");
        let _ = std::fs::create_dir_all(&base);
        if std::env::var_os("AOIDE_STAGE_DIR").is_none() {
            std::env::set_var("AOIDE_STAGE_DIR", base.join("stage"));
        }
        if std::env::var_os("AOIDE_STATE_DIR").is_none() {
            std::env::set_var("AOIDE_STATE_DIR", base.join("state"));
        }
        // LANE IDENTITY P-ID3 (G8 test below): a controllable, private
        // `$XDG_RUNTIME_DIR` so `conduct_socket_path`'s default resolution
        // (`/run/user/1000/aoide/...` otherwise) lands somewhere this test
        // binary actually owns — the same "floor before a real daemon
        // touches a shared default path" reasoning this function's own doc
        // already states for the stage/state dirs.
        if std::env::var_os("XDG_RUNTIME_DIR").is_none() {
            std::env::set_var("XDG_RUNTIME_DIR", base.join("run"));
        }
    });
}

/// Start a REAL `serve_daemon` — the real assembled `registry()`/`dispatch`
/// this crate's own `bin/aoided.rs` injects, not a fixture — on a fresh
/// short-path socket, and return a connected client stream plus both paths
/// (removed by each test at the end).
fn start_daemon(tag: &str) -> (UnixStream, PathBuf, PathBuf) {
    floor_stage_env();
    let socket_path = short_tmp(tag).with_extension("sock");
    let events_path = short_tmp(&format!("{tag}-events")).with_extension("jsonl");
    let sp = socket_path.clone();
    let ep = events_path.clone();
    std::thread::spawn(move || {
        let _ = serve_daemon(&sp, &ep, registry(), dispatch);
    });
    let stream = connect_retrying(&socket_path);
    (stream, socket_path, events_path)
}

/// Send one `{"op":"dispatch",...}` request over an already-connected
/// stream and return its `{"outcome": ...}` reply's `outcome` object.
fn send_dispatch(
    writer: &mut impl Write,
    reader: &mut impl BufRead,
    path: &[&str],
    args: &[&str],
    flags: &[(&str, &str)],
) -> Value {
    let req = json!({
        "v": 0,
        "op": "dispatch",
        "path": path,
        "args": args,
        "flags": flags.iter().cloned().collect::<std::collections::BTreeMap<&str, &str>>(),
    });
    writer.write_all(req.to_string().as_bytes()).unwrap();
    writer.write_all(b"\n").unwrap();
    let reply = read_one_line(reader);
    reply["outcome"].clone()
}

fn cleanup(socket_path: &Path, events_path: &Path) {
    std::fs::remove_file(socket_path).ok();
    std::fs::remove_file(events_path).ok();
}

/// A plain, implemented, ungated command (`guide`) dispatches over the daemon
/// door exactly as it does over CLI/MCP, and the single audit log gains a
/// `"door":"daemon"` record for it — `cli::dispatch::dispatch` appends this
/// on every call, door included, so this is the SAME code path every other
/// door's audit line comes from (`cli/src/dispatch.rs`).
#[test]
fn a_plain_command_dispatches_and_audits_door_daemon() {
    let (stream, socket_path, events_path) = start_daemon("plain");
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);

    let audit_log = short_tmp("plain-audit").with_extension("jsonl");
    let outcome = send_dispatch(&mut writer, &mut reader, &["guide"], &[], &[("audit-log", audit_log.to_str().unwrap())]);

    assert_eq!(outcome["status"], "ok", "{outcome}");
    assert_eq!(outcome["command"], "guide", "{outcome}");

    let contents = std::fs::read_to_string(&audit_log).expect("dispatch must have written the audit log");
    let audited = contents
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .any(|rec| rec["door"] == "daemon" && rec["command"] == "guide");
    assert!(audited, "expected a door:daemon audit record for `guide`, got:\n{contents}");

    cleanup(&socket_path, &events_path);
    std::fs::remove_file(&audit_log).ok();
}

/// A CLI-only secrets admin command (`secrets add`) refuses over the daemon
/// door with the SAME door-hint `Outcome` it already returns over MCP/A2A —
/// `secrets::commands::require_cli` is the ONE gate, unedited by this
/// phase, and it returns before `store::load_policies`/`save_policies` is
/// ever reached (`secrets/src/commands.rs`'s own doc).
///
/// "Mutates nothing" is asserted on DISK here, not taken on the strength of
/// that code-path comment alone (review nit on bb682da): `AOIDE_SECRETS_HOME`
/// is pointed at a fresh scratch dir before the refused dispatch, and both
/// `policy.json`'s bytes AND the scratch dir's very existence are checked
/// unchanged afterward — `store::save_policies` calls `create_dir_all` on
/// the secrets home before it ever writes the file, so even a mutation that
/// stopped short of a successful write would still leave a trace this test
/// catches. A future reorder of `require_cli` inside `handle_secrets_add`
/// (or any other admin handler swapped in here) fails THIS test, not just
/// a stale comment. Serialized under `aoide_test_support::env_lock()`
/// (`AOIDE_SECRETS_HOME` is process-global) and restored via `EnvSaver` so
/// a panic mid-test can't leak the override into a later test.
#[test]
fn a_cli_only_secrets_admin_command_refuses_with_the_door_hint_and_mutates_nothing_on_disk() {
    let _guard = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
    let _saver = aoide_test_support::EnvSaver::capture(&["AOIDE_SECRETS_HOME"]);
    let scratch_home = short_tmp("secadmin-home");
    std::env::set_var("AOIDE_SECRETS_HOME", &scratch_home);
    let policy_file = aoide_secrets::store::policy_path(&scratch_home);

    assert!(!scratch_home.exists(), "the scratch secrets home must start out absent");
    let before = std::fs::read(&policy_file).ok();

    let (stream, socket_path, events_path) = start_daemon("secadmin");
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);

    let outcome = send_dispatch(
        &mut writer,
        &mut reader,
        &["secrets", "add"],
        &["daemon-door-test-secret"],
        &[("backend", "age")],
    );

    assert_eq!(outcome["status"], "usage", "{outcome}");
    let message = outcome["message"].as_str().unwrap_or_default();
    assert!(message.contains("CLI-only"), "{outcome}");
    assert_eq!(outcome["command"], "secrets.add", "{outcome}");

    let after = std::fs::read(&policy_file).ok();
    assert_eq!(before, after, "the refused dispatch must not have touched {policy_file:?} at all");
    assert!(
        !scratch_home.exists(),
        "the refused dispatch must not have even created the secrets home directory"
    );

    cleanup(&socket_path, &events_path);
}

/// A gated command (`content approve`, gated + not-implemented) surfaces
/// `gated: true` over the daemon door exactly as `cli::dispatch::dispatch`
/// always marks it — admission stays the user's, on every door.
#[test]
fn a_gated_command_returns_gated_true() {
    let (stream, socket_path, events_path) = start_daemon("gated");
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);

    let outcome = send_dispatch(&mut writer, &mut reader, &["content", "approve"], &["/tmp/dusk"], &[]);

    assert_eq!(outcome["gated"], true, "{outcome}");
    assert_eq!(outcome["status"], "not-implemented", "{outcome}");

    cleanup(&socket_path, &events_path);
}

/// LANE IDENTITY P-ID3 (G8): a `send` dispatched over this SAME daemon door
/// — the REAL registry, the real `send` command, not a fixture — must never
/// resolve its sender ATTRIBUTION against THIS process's own ambient
/// `AOIDE_SESSION_ID`. `serve_daemon` runs `dispatch` on a thread inside
/// THIS test binary, so setting the env var here is not a stand-in for "the
/// daemon's own env" — for the real production shape (a resident `aoided`
/// process serving this exact socket op inside its own process), it is
/// literally the identical fact: whatever `AOIDE_SESSION_ID` `aoided` itself
/// happened to inherit at launch is exactly what a same-process
/// `std::env::var` read inside its `dispatch` call would see.
///
/// Deliberately no `--yes`, no autogate, and no `--from` on the wire — the
/// shape a genuinely unrelated same-uid process would produce by dispatching
/// a raw `send` request directly at this socket, bypassing `aoide send`'s
/// own CLI entirely. The GATE resolves the DAEMON's own `/proc` ancestry
/// (this test binary's, here — `init -> ... -> cargo-test`, matching no live
/// sealed session), so this was ALREADY held pending before the G8 fix; what
/// the fix changes is the pending entry's ATTRIBUTION, which is what this
/// test actually pins.
#[test]
fn a_daemon_dispatched_send_never_resolves_this_processs_own_ambient_session_id() {
    let _guard = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
    let _saver = aoide_test_support::EnvSaver::capture(&["AOIDE_SESSION_ID", "AOIDE_CONDUCT_AUTOGATE"]);
    std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
    // Stands in for whatever `aoided`'s OWN launch environment might carry —
    // a stray value a dispatched `send` must never pick up as if it were the
    // connecting caller's own attribution.
    std::env::set_var("AOIDE_SESSION_ID", "daemons-own-stray-session");
    floor_stage_env();

    let id = "g8-dispatch-target";
    let socket = aoide_conduct::graph::conduct_socket_path(id);
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    // Nothing must ever connect here — a wrongly-delivered send would.
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();

    let sf = aoide_conduct::graph::SessionsFile {
        schema_version: "0".to_string(),
        sessions: vec![aoide_conduct::graph::SessionRecord {
            session_id: id.to_string(),
            state: "idle".to_string(),
            conductable: Some(true),
            socket: Some(socket.to_string_lossy().into_owned()),
            ..Default::default()
        }],
    };
    aoide_conduct::graph::write_stage(&aoide_conduct::graph::sessions_path(), &sf).unwrap();

    let (stream, socket_path, events_path) = start_daemon("g8-send");
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);

    let outcome = send_dispatch(&mut writer, &mut reader, &["send"], &["hello"], &[("id", id)]);

    assert_eq!(outcome["status"], "ok", "{outcome}");
    assert_eq!(
        outcome["data"]["delivered"], false,
        "no --yes/autogate, and the daemon's own ancestry resolves no live session: this must be held pending, not delivered — {outcome}"
    );
    assert!(listener.accept().is_err(), "a gated send must never touch the target's socket");

    let pending: Value = serde_json::from_str(
        &std::fs::read_to_string(aoide_conduct::graph::pending_path()).expect("pending.json must exist"),
    )
    .unwrap();
    let entries = pending["pending"].as_array().unwrap();
    let mine = entries
        .iter()
        .find(|e| e["sessionId"] == id)
        .unwrap_or_else(|| panic!("no pending entry for `{id}`: {pending}"));
    assert!(
        mine.get("from").is_none() || mine["from"].is_null(),
        "the pending entry must carry NO attribution — the daemon's own ambient AOIDE_SESSION_ID must never leak in as if it were the caller's: {mine}"
    );

    cleanup(&socket_path, &events_path);
    let _ = std::fs::remove_file(&socket);
}

/// `mcp.serve`/`a2a.serve` never start a server inside the daemon process —
/// both handlers' non-Cli branch just reports how to raise the real thing,
/// and `run_cli`'s special-cased launch path (the ONLY place either command
/// actually blocks) is never reached from `serve_daemon`'s plain `dispatch`
/// call.
#[test]
fn mcp_serve_and_a2a_serve_return_their_non_cli_outcomes() {
    let (stream, socket_path, events_path) = start_daemon("servers");
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);

    let mcp_outcome = send_dispatch(&mut writer, &mut reader, &["mcp", "serve"], &[], &[]);
    assert_eq!(mcp_outcome["status"], "ok", "{mcp_outcome}");
    assert!(mcp_outcome["data"]["hint"].is_string(), "{mcp_outcome}");

    let a2a_outcome = send_dispatch(&mut writer, &mut reader, &["a2a", "serve"], &[], &[]);
    assert_eq!(a2a_outcome["status"], "ok", "{a2a_outcome}");
    assert_eq!(a2a_outcome["data"]["door"], "non-cli", "{a2a_outcome}");

    cleanup(&socket_path, &events_path);
}
