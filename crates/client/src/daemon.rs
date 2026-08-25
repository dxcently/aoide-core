//! The outbound half of the fourth door (P-D6, `docs/architecture/
//! AOIDED.md`'s "L4 — graph residency"): [`daemon_dispatch`] tries the
//! resident `aoided`'s `{"op":"dispatch"}` wire (P-D4's own framing,
//! `aoide_server::daemon`'s module doc) before a session-write handler falls
//! back to its pre-existing direct stage-write path.
//!
//! ## Why this isn't `aoide_server::daemon::socket_path()`
//!
//! `aoide-client` sits BELOW `aoide-server` in the crate DAG (`server`
//! depends on `conduct`, which depends on THIS crate — `pkgs/aoide/crates/
//! server/Cargo.toml`'s own dependency list), so importing the daemon's
//! socket resolver here would invert it. [`socket_path`] re-derives the
//! IDENTICAL `$AOIDE_DAEMON_SOCKET` → `$XDG_RUNTIME_DIR/aoide/aoided.sock`
//! convention instead — the same "a sibling convention re-derived rather
//! than imported" call `aoide_server::daemon::socket_path`'s own module doc
//! already makes for `aoide_conduct::graph::conduct_socket_path`.
//!
//! ## Why the connect isn't `aoide_secrets::client::connect_bounded`
//!
//! That function is the documented PRECEDENT for bounding a Unix-socket
//! connect (`aoide-secrets/AGENTS.md`'s "every `client.rs` socket op bounds
//! its connect" invariant) — checked first, per this phase's own brief —
//! but it is private to `secrets::client` (not even `pub(crate)`), built
//! for a socket whose accept backlog can legitimately saturate under
//! long-parked TOTP asks holding connections open for minutes at a time.
//! The daemon socket carries no such long-lived-connection producer (every
//! `dispatch` round trip is a single request/reply, `subscribe`'s own
//! long-lived connections aside), so [`connect_bounded`] below bounds the
//! connect with a plain background-thread-plus-channel race instead of
//! hand-rolling the `EINPROGRESS`/`EAGAIN` `libc` dance that function's own
//! doc explains at length — the SAME bounded-connect INTENT, a simpler
//! mechanism sized to this door's actual concurrency profile, no new crate
//! dependency (no `libc`, no `unsafe`), and no edge into `aoide-secrets`'
//! own module a generic utility doesn't belong inside.
//!
//! ## The contract
//!
//! [`daemon_dispatch`] returns `None` exactly when nothing usable answered
//! (no daemon listening, the connect timed out, or `inv.door` is already
//! [`Door::Daemon`] — see the doc below) — the caller's own existing
//! direct-path fallback runs unchanged in every one of those cases. Once a
//! connection is actually made, ANY further failure (a write error, a read
//! timeout, a malformed or `outcome`-less reply) becomes `Some(Outcome::
//! error(...))` instead — a daemon that answered but broke is a real
//! anomaly worth surfacing to the caller, not something to paper over by
//! silently falling back to the direct path (which would mask a daemon-side
//! bug behind an apparently-successful command).

use aoide_protocol::output::Outcome;
use aoide_protocol::{Door, Invocation};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

/// The connect half's budget (module doc) — short, since a live daemon on
/// the same host answers a Unix-socket connect near-instantly; a caller
/// paying this in the common "no daemon running" case still wants it small.
const CONNECT_TIMEOUT: Duration = Duration::from_millis(100);

/// The round trip's OWN budget, once connected — bounds the write+reply
/// read so a daemon that accepted a connection and then wedged (rather than
/// refusing outright) can never hang the calling process indefinitely. Not
/// part of the design doc's stated "~100ms budget" (that names the CONNECT
/// half only); generous enough for a routed handler's real file I/O to
/// finish under ordinary load.
const ROUND_TRIP_TIMEOUT: Duration = Duration::from_secs(2);

/// Resolve the daemon's own control socket — mirrors
/// `aoide_server::daemon::socket_path` exactly (module doc's "Why this
/// isn't..."): `$AOIDE_DAEMON_SOCKET` when set to a non-blank value, else
/// `$XDG_RUNTIME_DIR/aoide/aoided.sock`.
pub fn socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("AOIDE_DAEMON_SOCKET") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    runtime_dir().join("aoided.sock")
}

fn runtime_dir() -> PathBuf {
    let runtime = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/run/user/1000".into());
    PathBuf::from(runtime).join("aoide")
}

/// Bounded replacement for `UnixStream::connect` (module doc's "Why the
/// connect isn't..."): races the real (blocking) connect on a detached
/// thread against `timeout`. A connect that resolves AFTER the caller has
/// already given up just drops its result into a channel nobody reads —
/// the thread itself still exits the moment the OS call returns, it is
/// never left blocked forever.
fn connect_bounded(socket_path: &std::path::Path, timeout: Duration) -> Option<UnixStream> {
    let (tx, rx) = mpsc::channel();
    let sp = socket_path.to_path_buf();
    if std::thread::Builder::new().spawn(move || {
        let _ = tx.send(UnixStream::connect(&sp));
    }).is_err() {
        return None; // Could not even spawn the racer thread — treat as "no daemon."
    }
    match rx.recv_timeout(timeout) {
        Ok(Ok(stream)) => Some(stream),
        Ok(Err(_)) | Err(_) => None,
    }
}

/// Try the resident daemon's `dispatch` op for `inv`; `None` means the
/// caller's own direct stage-write path should run instead (module doc's
/// "The contract").
///
/// `inv.door == Door::Daemon` short-circuits to `None` immediately, with no
/// connect attempt at all — this is the reentrancy guard: the injected
/// `dispatch` fn the daemon's OWN `serve_daemon` calls IS `cli::dispatch::
/// dispatch`, the exact same function a routed handler runs under on the
/// CLIENT side, and `aoide_server::daemon::invocation_from_dispatch_request`
/// always stamps `Door::Daemon` on an invocation built from the wire — so a
/// handler running INSIDE the daemon (because a remote caller's request
/// just landed) always sees `Door::Daemon` and takes its direct path
/// unconditionally, rather than trying to connect to itself and recursing.
pub fn daemon_dispatch(inv: &Invocation) -> Option<Outcome> {
    if inv.door == Door::Daemon {
        return None;
    }

    let socket_path = socket_path();
    let mut stream = connect_bounded(&socket_path, CONNECT_TIMEOUT)?;
    if stream.set_read_timeout(Some(ROUND_TRIP_TIMEOUT)).is_err() {
        return Some(Outcome::error(inv.dotted(), "setting a read timeout on the daemon connection"));
    }

    let req = json!({
        "op": "dispatch",
        "path": inv.path,
        "args": inv.args,
        "flags": inv.flags,
    });
    let mut line = req.to_string();
    line.push('\n');
    if stream.write_all(line.as_bytes()).is_err() {
        return Some(Outcome::error(inv.dotted(), "writing the dispatch request to the daemon"));
    }

    let mut reader = BufReader::new(stream);
    let mut reply = String::new();
    match reader.read_line(&mut reply) {
        Ok(0) => Some(Outcome::error(inv.dotted(), "the daemon closed the connection with no reply")),
        Ok(_) => parse_dispatch_reply(inv, reply.trim()),
        Err(e) => Some(Outcome::error(inv.dotted(), format!("reading the daemon's dispatch reply: {e}"))),
    }
}

/// Pure parse of one `dispatch` reply line (split out of [`daemon_dispatch`]
/// for direct unit testing, no socket needed) — `{"outcome": <Outcome>}` on
/// success; anything else (malformed JSON, a `{"ok":false,...}` op-level
/// refusal, a missing/unparseable `outcome`) becomes an error `Outcome`
/// naming the raw reply rather than silently dropping it.
fn parse_dispatch_reply(inv: &Invocation, reply: &str) -> Option<Outcome> {
    let v: Value = match serde_json::from_str(reply) {
        Ok(v) => v,
        Err(e) => return Some(Outcome::error(inv.dotted(), format!("the daemon's dispatch reply was not valid JSON: {e}"))),
    };
    match v.get("outcome").cloned() {
        Some(o) => match serde_json::from_value::<Outcome>(o) {
            Ok(outcome) => Some(outcome),
            Err(e) => Some(Outcome::error(inv.dotted(), format!("the daemon's dispatch reply's `outcome` did not parse: {e}"))),
        },
        None => Some(Outcome::error(inv.dotted(), format!("the daemon's dispatch reply had no `outcome`: {reply}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aoide_protocol::output::Status;
    use std::collections::BTreeMap;
    use std::io::Read;
    use std::os::unix::net::UnixListener;

    fn short_tmp(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
        PathBuf::from(format!("/tmp/av-client-daemon-{tag}-{}-{nanos}", std::process::id()))
    }

    fn inv(path: &[&str], door: Door) -> Invocation {
        Invocation {
            path: path.iter().map(|s| s.to_string()).collect(),
            args: Vec::new(),
            flags: BTreeMap::new(),
            door,
        }
    }

    // ── socket_path ──────────────────────────────────────────────────────

    #[test]
    fn socket_path_honors_the_env_override() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_DAEMON_SOCKET").ok();
        std::env::set_var("AOIDE_DAEMON_SOCKET", "/tmp/example-override.sock");
        assert_eq!(socket_path(), PathBuf::from("/tmp/example-override.sock"));
        match saved {
            Some(v) => std::env::set_var("AOIDE_DAEMON_SOCKET", v),
            None => std::env::remove_var("AOIDE_DAEMON_SOCKET"),
        }
    }

    // ── daemon_dispatch: connect-or-None ────────────────────────────────

    #[test]
    fn daemon_dispatch_against_a_dead_socket_is_none() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_DAEMON_SOCKET").ok();
        std::env::set_var("AOIDE_DAEMON_SOCKET", short_tmp("dead"));
        let out = daemon_dispatch(&inv(&["graph", "session", "start"], Door::Cli));
        assert!(out.is_none(), "a dead socket must fall back, not error");
        match saved {
            Some(v) => std::env::set_var("AOIDE_DAEMON_SOCKET", v),
            None => std::env::remove_var("AOIDE_DAEMON_SOCKET"),
        }
    }

    /// The reentrancy guard: an invocation already stamped `Door::Daemon`
    /// never even attempts a connect, regardless of what's listening.
    #[test]
    fn daemon_dispatch_short_circuits_on_door_daemon() {
        let _guard = crate::env_lock().lock().unwrap();
        let socket_path = short_tmp("guard").with_extension("sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let sp = socket_path.clone();
        std::thread::spawn(move || {
            // If this ever got a connection, the guard failed — proven by
            // the assertion below never seeing a reply either way, since a
            // real accept+reply would race the test's own timeout.
            let _ = UnixListener::bind(&sp);
        });
        let saved = std::env::var("AOIDE_DAEMON_SOCKET").ok();
        std::env::set_var("AOIDE_DAEMON_SOCKET", &socket_path);
        let out = daemon_dispatch(&inv(&["graph", "session", "start"], Door::Daemon));
        assert!(out.is_none(), "Door::Daemon must never route further");
        match saved {
            Some(v) => std::env::set_var("AOIDE_DAEMON_SOCKET", v),
            None => std::env::remove_var("AOIDE_DAEMON_SOCKET"),
        }
        drop(listener);
        std::fs::remove_file(&socket_path).ok();
    }

    #[test]
    fn daemon_dispatch_round_trips_against_a_fake_daemon() {
        let _guard = crate::env_lock().lock().unwrap();
        let socket_path = short_tmp("roundtrip").with_extension("sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let handle = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let n = conn.read(&mut buf).unwrap();
            let req: Value = serde_json::from_slice(&buf[..n.max(1)]).unwrap_or_else(|_| {
                // A single read may not carry the whole line under load;
                // this test's request is short enough that one read always
                // covers it in practice, so this arm is defensive only.
                json!({})
            });
            assert_eq!(req["op"], "dispatch");
            assert_eq!(req["path"][0], "graph");
            let outcome = Outcome::ok("graph.session.start", "started session `t1`");
            let reply = json!({ "outcome": outcome });
            let mut line = reply.to_string();
            line.push('\n');
            conn.write_all(line.as_bytes()).unwrap();
        });

        let saved = std::env::var("AOIDE_DAEMON_SOCKET").ok();
        std::env::set_var("AOIDE_DAEMON_SOCKET", &socket_path);
        let out = daemon_dispatch(&inv(&["graph", "session", "start"], Door::Cli));
        match saved {
            Some(v) => std::env::set_var("AOIDE_DAEMON_SOCKET", v),
            None => std::env::remove_var("AOIDE_DAEMON_SOCKET"),
        }
        handle.join().unwrap();

        let out = out.expect("a live listener must answer Some(outcome)");
        assert_eq!(out.status, Status::Ok);
        assert_eq!(out.command, "graph.session.start");
        assert!(out.message.contains("t1"));

        std::fs::remove_file(&socket_path).ok();
    }

    #[test]
    fn daemon_dispatch_surfaces_a_post_connect_failure_as_an_error_outcome_not_none() {
        let _guard = crate::env_lock().lock().unwrap();
        let socket_path = short_tmp("badreply").with_extension("sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let handle = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = conn.read(&mut buf); // drain the request
            conn.write_all(b"not json at all\n").unwrap();
        });

        let saved = std::env::var("AOIDE_DAEMON_SOCKET").ok();
        std::env::set_var("AOIDE_DAEMON_SOCKET", &socket_path);
        let out = daemon_dispatch(&inv(&["graph", "session", "start"], Door::Cli));
        match saved {
            Some(v) => std::env::set_var("AOIDE_DAEMON_SOCKET", v),
            None => std::env::remove_var("AOIDE_DAEMON_SOCKET"),
        }
        handle.join().unwrap();

        let out = out.expect("a connected-but-broken daemon must surface an error, not fall back");
        assert_eq!(out.status, Status::Error);

        std::fs::remove_file(&socket_path).ok();
    }

    // ── parse_dispatch_reply: pure ──────────────────────────────────────

    #[test]
    fn parse_dispatch_reply_extracts_the_outcome() {
        let outcome = Outcome::ok("graph.reap", "nothing to reap");
        let reply = json!({ "outcome": outcome }).to_string();
        let out = parse_dispatch_reply(&inv(&["graph", "reap"], Door::Cli), &reply).unwrap();
        assert_eq!(out.status, Status::Ok);
        assert_eq!(out.command, "graph.reap");
    }

    #[test]
    fn parse_dispatch_reply_on_an_op_level_refusal_is_an_error_outcome() {
        let reply = json!({ "ok": false, "error": "malformed request: not valid JSON" }).to_string();
        let out = parse_dispatch_reply(&inv(&["graph", "reap"], Door::Cli), &reply).unwrap();
        assert_eq!(out.status, Status::Error);
        assert!(out.message.contains("ok"));
    }
}
