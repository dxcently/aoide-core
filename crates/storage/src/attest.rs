//! Kernel-attested caller identity — the ONE implementation of the
//! "peercred/self pid → real `/proc` ancestry → sealed session → verified
//! origin" lookup (LANE IDENTITY P-ID4, `docs/architecture/CONTRACTS.md`'s
//! identity section), shared by BOTH of its consumers: `aoide-conduct`'s
//! send gate (`graph/identity.rs`, which delegates its `verify_seal_over`/
//! `attested_sender` bodies here) and `aoide-secrets`' broker origin gate
//! (`broker.rs`'s `resolve_gate`, via [`attested_caller`]).
//!
//! **Why this crate.** The crate DAG forbids every other home:
//! `aoide-secrets` may never depend on `aoide-conduct` or `aoide-client`
//! (both sit ABOVE it — `client` already depends on `secrets`, `conduct`
//! on `client`), and the cross-crate copying ban (`crates/AGENTS.md`)
//! forbids a second copy of the walk growing inside `secrets`. This crate
//! already owns every ingredient: [`crate::records::SessionRecord`] (the
//! roster shape, `seal`/`sealedIssuedAt`/`origin` included),
//! [`crate::stage::sessions_path`]/[`crate::stage::load_stage`] (the roster
//! read), [`crate::sealed_id`] (the seal's canonical string + verify), and
//! [`crate::identity`] (the keypair the daemon mints seals with) — the walk
//! and the pubkey fetch are the last two pieces of the same credential,
//! landed beside the rest. `aoide-conduct`'s `graph/window.rs`
//! (`pid_ancestry`/`pid_starttime`) and `aoide-client`'s `daemon.rs`
//! (`socket_path`/`connect_bounded`/`daemon_seal_pubkey_hex`) keep their
//! public seams as thin delegates onto this module — call sites unchanged,
//! bodies in exactly one place.
//!
//! **The pubkey channel stays a LIVE round trip** (`CONTRACTS.md`'s
//! identity section, verbatim rule): the daemon's seal-signing public key
//! is fetched fresh over its `ping` reply's `sealPubkeyHex` field
//! ([`daemon_seal_pubkey_hex`]) — never cached, never read from a file. A
//! pubkey file sitting next to the same-uid-writable `sessions.json` it
//! vouches for would let whoever can forge a seal also forge the key that
//! verifies it. The corollary is an honesty boundary every consumer must
//! state: a caller that CANNOT reach the daemon socket resolves every pid
//! to `None` — UNIDENTIFIED, never "verified". For the send gate that is
//! fail-closed (pending); for the broker's origin gate it means the gate
//! keys only on POSITIVE attestation (see `aoide-secrets/broker.rs`). In
//! the packaged cross-uid deployment (`modules/nucleus/secrets.nix` runs
//! the broker as the `aoide-secrets` system user) both the daemon socket
//! (`0600` inside the operator's `0700` `$XDG_RUNTIME_DIR`) and the
//! operator's own `state/stage/sessions.json` are unreachable, so every
//! broker-side lookup resolves UNIDENTIFIED there — the origin gate bites
//! wherever the broker runs as the operator's own uid (the cargo-only/dev
//! reality `aoide-secrets/home.rs` documents), and a cross-uid attestation
//! channel is a deliberately-unbuilt later phase, not something improvised
//! here.
//!
//! **The pid-reuse defense rides through every path.** [`verify_seal_over`]
//! re-reads `/proc/<pid>/stat`'s starttime FRESH and reconstructs the
//! [`SealedIdentity`] from that live value — a stored starttime is never
//! trusted, and a mint-time degrade of `0` (a pid that had already
//! vanished) can never match a genuine live read (`CONTRACTS.md`: "no live
//! process ever reports starttime 0").

use crate::records::{SessionRecord, SessionsFile};
use crate::sealed_id::{verify_seal, SealedIdentity};
use aoide_protocol::state::canonical_state;
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

// ── /proc kernel facts ───────────────────────────────────────────────────

/// Read the parent pid of `pid` from `/proc/<pid>/stat`. The `comm` (2nd)
/// field is wrapped in parens and may itself contain spaces or `)`, so ppid
/// is parsed as the 2nd whitespace field AFTER the FINAL `)` (state, then
/// ppid) — the only robust way to split a stat line. `None` on any
/// read/parse miss.
fn parent_pid(pid: i32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = &stat[stat.rfind(')')? + 1..];
    let mut fields = after.split_whitespace();
    let _state = fields.next()?; // the process state char
    fields.next()?.parse().ok() // ppid
}

/// The pid-ancestry chain of `pid`, self first, walking up the ppid chain
/// via `/proc`. Bounded (a bad `/proc` or a self-parenting loop can never
/// spin) and stops at init (ppid ≤ 1) — the terminal is always a mid-chain
/// ancestor. Moved verbatim from `aoide_conduct::graph::window` (P-ID4's
/// seam lift, module doc); that module's `pid_ancestry` now delegates here.
pub fn pid_ancestry(pid: i32) -> Vec<i32> {
    let mut chain = Vec::new();
    let mut cur = pid;
    for _ in 0..64 {
        chain.push(cur);
        match parent_pid(cur) {
            Some(p) if p > 1 && p != cur => cur = p,
            _ => break,
        }
    }
    chain
}

/// Read `pid`'s start time (`/proc/<pid>/stat` field 22, 1-indexed —
/// `man proc(5)`) — the other half of the (pid, starttime) reuse-proof
/// identity a sealed credential is minted over. Same "split after the FINAL
/// `)`" parse [`parent_pid`] uses, extended one field further: after the
/// closing paren, `state`(3) and `ppid`(4) are the first two whitespace
/// fields, so `starttime`(22) sits at index `22 - 3 = 19` in that same
/// split. `None` on any read/parse miss (a vanished pid, a malformed
/// `/proc` line). Moved verbatim from `aoide_conduct::graph::window`
/// (P-ID4's seam lift); that module's `pid_starttime` now delegates here.
pub fn pid_starttime(pid: i32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = &stat[stat.rfind(')')? + 1..];
    after.split_whitespace().nth(22 - 3)?.parse().ok()
}

// ── seal verification over a live record ─────────────────────────────────

/// Reconstruct the exact [`SealedIdentity`] `rec.seal` was signed over and
/// check it against `pubkey_hex` (LANE IDENTITY P-ID2, lifted here at
/// P-ID4). Fail-closed on every incomplete/unrevalidatable shape, never
/// treated as "verified": no `pid` (never conductable), no
/// `seal`/`sealedIssuedAt` (never sealed), or a live `/proc/<pid>/stat`
/// read that comes back absent OR exactly `0` — a `0` starttime is
/// `mint_seal`'s own documented degrade for a pid that had ALREADY vanished
/// at mint time (`CONTRACTS.md`'s identity section: "no live process ever
/// reports starttime 0"), so a FRESH read landing on `0` here can only mean
/// the pid still doesn't exist, never a legitimate match.
/// `pid`/`sessionId`/`originClass` come straight off the record;
/// `pidStarttime` is RE-DERIVED fresh (never trusted from a stored value —
/// this is the pid-reuse defense: a stale mint-time value simply fails to
/// match a live process's real starttime).
pub fn verify_seal_over(rec: &SessionRecord, pubkey_hex: &str) -> bool {
    let (Some(pid), Some(seal_hex), Some(issued_at)) =
        (rec.pid, rec.seal.as_deref(), rec.sealed_issued_at)
    else {
        return false;
    };
    let starttime = match pid_starttime(pid as i32) {
        Some(t) if t != 0 => t,
        _ => return false,
    };
    let identity = SealedIdentity {
        session_id: rec.session_id.clone(),
        pid: pid as i32,
        pid_starttime: starttime,
        origin_class: rec.origin.clone().unwrap_or_default(),
        issued_at,
    };
    verify_seal(pubkey_hex, &identity, seal_hex)
}

// ── the ancestry walk ────────────────────────────────────────────────────

/// The shared walk core: `start_pid`'s real `/proc` ancestry, self-first,
/// nearest ancestor first, returning the FIRST live (`canonical_state !=
/// "done"`) session whose `pid` matches an ancestor AND whose `verify`
/// passes. Private — [`attested_session`] and [`attested_caller`] are the
/// two shapes callers consume.
fn attested_record<'a>(
    start_pid: i32,
    sessions: &'a [SessionRecord],
    verify: impl Fn(&SessionRecord) -> bool,
) -> Option<&'a SessionRecord> {
    for pid in pid_ancestry(start_pid) {
        if let Some(rec) = sessions.iter().find(|s| {
            s.pid == Some(pid as u32) && canonical_state(&s.state) != "done" && verify(s)
        }) {
            return Some(rec);
        }
    }
    None
}

/// The kernel-attested sender resolution (LANE IDENTITY P-ID2, lifted here
/// at P-ID4): walk `start_pid`'s real `/proc` ancestry (self-first, nearest
/// ancestor first) and return the `sessionId` of the FIRST live session
/// whose `pid` matches an ancestor AND whose seal `verify`s. A same-uid
/// attacker cannot forge this: it cannot alter its own real kernel
/// ancestry, and a `verify` that checks a genuine daemon signature cannot
/// be satisfied by hand-editing `sessions.json` alone.
///
/// `verify` is injected (never hard-codes a pubkey lookup here) so this
/// stays a PURE, exhaustively table-testable function — a real call site
/// supplies a closure fetching the daemon's live public key
/// ([`daemon_seal_pubkey_hex`]) and delegating to [`verify_seal_over`]; a
/// test supplies a fixed key or a canned bool. `None` when no ancestor
/// resolves — an "unidentified" caller; what a gate does with that is the
/// GATE's documented decision (the send gate fails closed to pending; the
/// broker's origin gate keys only on positive attestation — module doc).
pub fn attested_session(
    start_pid: i32,
    sessions: &[SessionRecord],
    verify: impl Fn(&SessionRecord) -> bool,
) -> Option<String> {
    attested_record(start_pid, sessions, verify).map(|rec| rec.session_id.clone())
}

/// The broker one-stop (LANE IDENTITY P-ID4): resolve `start_pid` (a
/// connection's kernel-truth `SO_PEERCRED` pid) to its POSITIVELY-attested
/// sealed session — live daemon pubkey fetched fresh, roster read off
/// `state/stage/sessions.json`, the walk verified via [`verify_seal_over`]
/// (fresh-starttime pid-reuse defense included). Returns `(sessionId,
/// originClass)` of the nearest verified ancestor session, or `None` on ANY
/// missing link — unreachable daemon, unreadable roster, no sealed ancestor,
/// a seal that fails verification. `None` always means UNIDENTIFIED, never
/// an error a caller should retry or trust differently.
pub fn attested_caller(start_pid: i32) -> Option<(String, String)> {
    let pubkey = daemon_seal_pubkey_hex()?;
    let roster: SessionsFile = crate::stage::load_stage(&crate::stage::sessions_path()).ok()?;
    attested_record(start_pid, &roster.sessions, |rec| verify_seal_over(rec, &pubkey))
        .map(|rec| (rec.session_id.clone(), rec.origin.clone().unwrap_or_default()))
}

/// Does `origin` mark a session as remote-node-spawned? The one place this
/// check lives, shared by `aoide-conduct`'s resurrect/registration gates and
/// `aoide-secrets`' broker origin gate (same DAG constraint as
/// [`attested_caller`] above) — a `node:<name>` origin is the current wire
/// shape (peer -> node rename); a `peer:<name>` origin is a session record
/// stamped before that rename and still on disk. Retire the `peer:` arm
/// once no session record predating the rename survives on any box.
pub fn is_node_origin(origin: &str) -> bool {
    origin.starts_with("node:") || origin.starts_with("peer:")
}

// ── the daemon pubkey channel ────────────────────────────────────────────

/// The connect half's budget — short, since a live daemon on the same host
/// answers a Unix-socket connect near-instantly; a caller paying this in
/// the common "no daemon running" case still wants it small. (Moved from
/// `aoide_client::daemon`, which re-uses it via delegation.)
pub const CONNECT_TIMEOUT: Duration = Duration::from_millis(100);

/// The round trip's OWN budget, once connected — bounds the write+reply
/// read so a daemon that accepted a connection and then wedged can never
/// hang the calling process indefinitely.
pub const ROUND_TRIP_TIMEOUT: Duration = Duration::from_secs(2);

/// Resolve the daemon's own control socket — `$AOIDE_DAEMON_SOCKET` when
/// set to a non-blank value, else `$XDG_RUNTIME_DIR/aoide/aoided.sock`.
/// `aoide_client::daemon::socket_path` delegates here (P-ID4's seam lift);
/// `aoide_server::daemon::socket_path` keeps its own bind-side copy of the
/// same convention, documented there as a deliberate mirror — untouched by
/// this move.
pub fn daemon_socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("AOIDE_DAEMON_SOCKET") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    let runtime = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/run/user/1000".into());
    PathBuf::from(runtime).join("aoide").join("aoided.sock")
}

/// Bound a Unix-socket connect with a background-thread-plus-channel race
/// (moved from `aoide_client::daemon`, same mechanism, same doc): `None`
/// when the connect fails or `timeout` elapses first — including the racer
/// thread failing to spawn at all, treated as "no daemon."
pub fn connect_bounded(socket_path: &Path, timeout: Duration) -> Option<UnixStream> {
    let (tx, rx) = mpsc::channel();
    let sp = socket_path.to_path_buf();
    if std::thread::Builder::new()
        .spawn(move || {
            let _ = tx.send(UnixStream::connect(&sp));
        })
        .is_err()
    {
        return None; // Could not even spawn the racer thread — treat as "no daemon."
    }
    match rx.recv_timeout(timeout) {
        Ok(Ok(stream)) => Some(stream),
        Ok(Err(_)) | Err(_) => None,
    }
}

/// The daemon's CURRENT seal-signing public key, fetched fresh over a
/// `ping` round trip (LANE IDENTITY P-ID2, moved here at P-ID4 —
/// `aoide_client::daemon::daemon_seal_pubkey_hex` delegates). `None`
/// covers every failure (no daemon listening, a connect/read timeout, a
/// malformed reply, a `sealPubkeyHex` that isn't a string) — never a
/// panic, never a fabricated key. A caller verifying a seal MUST treat
/// `None` as "cannot verify, so treat the caller as UNIDENTIFIED"; there
/// is no safe fallback for an unverifiable signature. Deliberately NOT
/// cached process-wide, and never a file read — module doc's "live round
/// trip" rule; the same-uid unlink-then-bind honesty note on this channel
/// lives in `CONTRACTS.md`'s identity section, unchanged by the move.
pub fn daemon_seal_pubkey_hex() -> Option<String> {
    let socket_path = daemon_socket_path();
    let stream = connect_bounded(&socket_path, CONNECT_TIMEOUT)?;
    if stream.set_read_timeout(Some(ROUND_TRIP_TIMEOUT)).is_err() {
        return None;
    }
    let mut writer = stream.try_clone().ok()?;
    if writer.write_all(b"{\"op\":\"ping\"}\n").is_err() {
        return None;
    }
    let mut reader = BufReader::new(stream);
    let mut reply = String::new();
    if reader.read_line(&mut reply).ok()? == 0 {
        return None;
    }
    let v: Value = serde_json::from_str(reply.trim()).ok()?;
    v.get("sealPubkeyHex").and_then(Value::as_str).map(str::to_string)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity;
    use crate::sealed_id::mint_seal;
    use std::os::unix::net::UnixListener;

    fn sealed_record(
        session_id: &str,
        pid: i32,
        origin: Option<&str>,
        kp: &identity::Keypair,
    ) -> SessionRecord {
        let starttime = pid_starttime(pid).expect("test pids must be real, live pids");
        let issued_at = 1_700_000_000;
        let sid = SealedIdentity {
            session_id: session_id.to_string(),
            pid,
            pid_starttime: starttime,
            origin_class: origin.unwrap_or("").to_string(),
            issued_at,
        };
        let seal = mint_seal(kp, &sid);
        SessionRecord {
            session_id: session_id.to_string(),
            state: "idle".to_string(),
            pid: Some(pid as u32),
            origin: origin.map(str::to_string),
            seal: Some(seal),
            sealed_issued_at: Some(issued_at),
            ..Default::default()
        }
    }

    /// A one-shot fake daemon: binds `path`, answers exactly one connection's
    /// first line with a canned `ping` reply carrying `pubkey_hex`.
    fn spawn_fake_daemon(path: &std::path::Path, pubkey_hex: &str) {
        let listener = UnixListener::bind(path).expect("bind fake daemon socket");
        let pk = pubkey_hex.to_string();
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                let _ = reader.read_line(&mut line);
                let reply = serde_json::json!({
                    "ok": true, "daemon": "aoided", "sealPubkeyHex": pk
                });
                let mut w = stream;
                let _ = w.write_all(format!("{reply}\n").as_bytes());
            }
        });
    }

    // ── /proc facts ──────────────────────────────────────────────────────

    #[test]
    fn pid_ancestry_starts_at_self_and_is_bounded() {
        let me = std::process::id() as i32;
        let chain = pid_ancestry(me);
        assert_eq!(chain.first(), Some(&me), "the walk is self-first");
        assert!(chain.len() <= 64, "the walk is bounded");
    }

    #[test]
    fn pid_starttime_reads_a_nonzero_value_for_our_own_real_pid() {
        let t = pid_starttime(std::process::id() as i32);
        assert!(t.is_some_and(|v| v > 0), "a live pid's starttime is always > 0, got {t:?}");
    }

    #[test]
    fn pid_starttime_is_none_for_a_pid_that_does_not_exist() {
        assert_eq!(pid_starttime(2_000_000_000), None);
    }

    // ── verify_seal_over ─────────────────────────────────────────────────

    #[test]
    fn verify_seal_over_accepts_a_genuine_seal_for_a_real_live_pid() {
        let kp = identity::mint_ephemeral().unwrap();
        let me = std::process::id() as i32;
        let rec = sealed_record("s1", me, Some("local"), &kp);
        assert!(verify_seal_over(&rec, &kp.info().pubkey_hex));
    }

    #[test]
    fn verify_seal_over_rejects_a_wrong_pubkey_a_missing_seal_and_a_vanished_pid() {
        let kp = identity::mint_ephemeral().unwrap();
        let other = identity::mint_ephemeral().unwrap();
        let me = std::process::id() as i32;

        let rec = sealed_record("s1", me, Some("local"), &kp);
        assert!(!verify_seal_over(&rec, &other.info().pubkey_hex), "wrong key");

        let unsealed = SessionRecord {
            session_id: "s1".to_string(),
            pid: Some(me as u32),
            ..Default::default()
        };
        assert!(!verify_seal_over(&unsealed, &kp.info().pubkey_hex), "no seal");

        let vanished = SessionRecord {
            session_id: "s1".to_string(),
            pid: Some(2_000_000_000),
            origin: Some("local".to_string()),
            seal: Some("whatever".to_string()),
            sealed_issued_at: Some(1_700_000_000),
            ..Default::default()
        };
        assert!(!verify_seal_over(&vanished, &kp.info().pubkey_hex), "vanished pid");
    }

    /// The pid-reuse defense through THIS crate's copy of the walk: a seal
    /// minted over a STALE starttime (here: the degraded `0`, but any
    /// non-live value behaves identically) can never verify, because the
    /// verifier re-derives starttime FRESH and reconstructs the identity
    /// from the live read, never the stored one.
    #[test]
    fn verify_seal_over_rejects_a_seal_minted_over_a_stale_starttime() {
        let kp = identity::mint_ephemeral().unwrap();
        let me = std::process::id() as i32;
        let stale = SealedIdentity {
            session_id: "s-stale".to_string(),
            pid: me,
            pid_starttime: 1, // a plausible-looking but WRONG (stale) starttime
            origin_class: "node:box-b".to_string(),
            issued_at: 1_700_000_000,
        };
        let rec = SessionRecord {
            session_id: "s-stale".to_string(),
            state: "idle".to_string(),
            pid: Some(me as u32),
            origin: Some("node:box-b".to_string()),
            seal: Some(mint_seal(&kp, &stale)),
            sealed_issued_at: Some(1_700_000_000),
            ..Default::default()
        };
        assert!(
            !verify_seal_over(&rec, &kp.info().pubkey_hex),
            "a seal over a stale starttime must fail against the fresh live read"
        );
    }

    // ── attested_session ─────────────────────────────────────────────────

    #[test]
    fn attested_session_finds_a_verified_self_ancestor() {
        let kp = identity::mint_ephemeral().unwrap();
        let me = std::process::id() as i32;
        let sessions = vec![sealed_record("orch", me, Some("local"), &kp)];
        let pubkey = kp.info().pubkey_hex;
        let found = attested_session(me, &sessions, |rec| verify_seal_over(rec, &pubkey));
        assert_eq!(found, Some("orch".to_string()));
    }

    #[test]
    fn attested_session_is_none_when_verify_fails_or_the_session_is_done() {
        let kp = identity::mint_ephemeral().unwrap();
        let me = std::process::id() as i32;
        let sessions = vec![sealed_record("orch", me, Some("local"), &kp)];
        assert_eq!(attested_session(me, &sessions, |_| false), None, "unverifiable never resolves");

        let done = vec![SessionRecord {
            session_id: "dead-orch".to_string(),
            state: "done".to_string(),
            pid: Some(me as u32),
            ..Default::default()
        }];
        assert_eq!(attested_session(me, &done, |_| true), None, "a done session never resolves");
        assert_eq!(attested_session(me, &[], |_| true), None, "an empty roster never resolves");
    }

    // ── daemon_seal_pubkey_hex / attested_caller ─────────────────────────

    fn short_tmp(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        PathBuf::from(format!("/tmp/av-attest-{tag}-{}-{nanos}", std::process::id()))
    }

    #[test]
    fn daemon_seal_pubkey_hex_round_trips_against_a_fake_daemon() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _s = aoide_test_support::EnvSaver::capture(&["AOIDE_DAEMON_SOCKET"]);
        let sock = short_tmp("ping");
        spawn_fake_daemon(&sock, &"a".repeat(64));
        std::env::set_var("AOIDE_DAEMON_SOCKET", &sock);
        assert_eq!(daemon_seal_pubkey_hex(), Some("a".repeat(64)));
        let _ = std::fs::remove_file(&sock);
    }

    #[test]
    fn daemon_seal_pubkey_hex_against_a_dead_socket_is_none() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _s = aoide_test_support::EnvSaver::capture(&["AOIDE_DAEMON_SOCKET"]);
        std::env::set_var("AOIDE_DAEMON_SOCKET", short_tmp("dead"));
        assert_eq!(daemon_seal_pubkey_hex(), None);
    }

    /// The full broker-side path in one test: kernel-truth pid (our own) →
    /// roster on disk → live pubkey off a (fake) daemon ping → verified
    /// origin. Also pins the fail-to-unidentified halves: a daemon serving
    /// the WRONG key, and no daemon at all, both resolve `None`.
    #[test]
    fn attested_caller_resolves_a_sealed_remote_origin_session_and_fails_to_none_otherwise() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _s = aoide_test_support::EnvSaver::capture(&["AOIDE_DAEMON_SOCKET", "AOIDE_STAGE_DIR"]);
        let root = aoide_test_support::unique_tmp("attest-caller");
        // `AOIDE_STAGE_DIR` (not `AOIDE_STATE_DIR`): the absolute override
        // returns from `fs::conducting_stage_dir` BEFORE its process-wide
        // migration `Once` fires — consuming that `Once` here would rob
        // `fs::tests`' migration tests of their first-call vantage.
        std::env::set_var("AOIDE_STAGE_DIR", &root);

        let kp = identity::mint_ephemeral().unwrap();
        let me = std::process::id() as i32;
        let roster = SessionsFile {
            schema_version: "0".to_string(),
            sessions: vec![sealed_record("remote-orch", me, Some("node:box-b"), &kp)],
        };
        std::fs::create_dir_all(crate::stage::sessions_path().parent().unwrap()).unwrap();
        crate::stage::write_stage(&crate::stage::sessions_path(), &roster).unwrap();

        // The genuine key: positively attested, origin included.
        let sock = short_tmp("caller-ok");
        spawn_fake_daemon(&sock, &kp.info().pubkey_hex);
        std::env::set_var("AOIDE_DAEMON_SOCKET", &sock);
        assert_eq!(
            attested_caller(me),
            Some(("remote-orch".to_string(), "node:box-b".to_string()))
        );
        let _ = std::fs::remove_file(&sock);

        // A daemon serving a DIFFERENT key: the seal fails verification —
        // unidentified, never a partial answer.
        let other = identity::mint_ephemeral().unwrap();
        let sock2 = short_tmp("caller-wrongkey");
        spawn_fake_daemon(&sock2, &other.info().pubkey_hex);
        std::env::set_var("AOIDE_DAEMON_SOCKET", &sock2);
        assert_eq!(attested_caller(me), None);
        let _ = std::fs::remove_file(&sock2);

        // No daemon at all: unidentified.
        std::env::set_var("AOIDE_DAEMON_SOCKET", short_tmp("caller-dead"));
        assert_eq!(attested_caller(me), None);

        let _ = std::fs::remove_dir_all(&root);
    }
}
