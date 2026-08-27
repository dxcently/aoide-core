//! The ssh child (ssh-transport lane, phase P-S3,
//! `docs/architecture/PAIRING.md`'s forthcoming Transport section): **the
//! ONE place `ssh` is ever spawned in this codebase.** `aoide_storage::
//! tunnel` (P-S2) owns the record's shape and every PURE helper around it —
//! this module owns the process: opening a forward, probing whether it
//! answers, reusing a still-live one, and closing it down.
//!
//! **Lifecycle in one line.** `open_or_reuse` loads a record for
//! `(session_id, key)`; a record whose pid is alive AND whose local port
//! answers is reused as-is (no second `ssh`); anything else is stale (dead
//! pid, or a live process nothing is listening through) and is discarded in
//! favor of a freshly spawned forward. `close`/`close_all_for_session` tear
//! a forward down and remove its record; P-S5 wires the session-end fast
//! path and the reaper's orphan-collecting backstop on top of these two.
//!
//! **The recycled-pid decision (`close`).** A record's `pid` was proven
//! alive by an earlier `aoide` invocation, possibly a long time ago — the
//! OS is free to hand that same integer to an unrelated process once the
//! real `ssh` child has exited. Killing on `pid` alone would then kill
//! whatever now holds it. The cheapest honest defense that doesn't require
//! a second registry is reading `/proc/<pid>/cmdline` and checking it is
//! actually an `ssh` invocation carrying THIS record's own `-L` spec
//! (`looks_like_our_ssh`) before ever signaling it — accepted, not "solved":
//! a process that coincidentally starts as `ssh` with the exact same
//! forward spec in the tiny window between this check and the `kill(2)`
//! call is a race nothing here defends against, and is judged small enough
//! (a fabricated coincidence, not an adversarial position on this box) not
//! to warrant a second layer.
//!
//! **The testability seam.** `open_or_reuse`'s actual `ssh` spawn is an
//! injected closure (`SpawnFn`), the same shape
//! `aoide_conduct::graph::who::PullFn` holds for its own live-probe seam —
//! re-derived here rather than imported, since `client` sits below
//! `conduct` in the crate DAG. Production wires the real `Command`;
//! `#[cfg(test)]` wires a fake that spawns an innocuous real child (`sleep`)
//! and optionally binds the target port itself, so every reuse/stale/
//! timeout branch below runs with no `ssh` anywhere in the test binary.

use aoide_storage::tunnel::{TunnelRecord, Via, TUNNEL_VERSION};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Env override for [`open_or_reuse`]'s bounded wait for a freshly spawned
/// forward to answer — the same "unparsable or zero falls back to the
/// default" shape `aoide_storage::pairing::pairing_timeout_secs` holds for
/// its own timeout knob, re-derived rather than imported since the two
/// live in different crates for unrelated reasons.
pub const TUNNEL_OPEN_TIMEOUT_ENV: &str = "AOIDE_TUNNEL_OPEN_TIMEOUT";

const DEFAULT_OPEN_TIMEOUT_SECS: u64 = 8;

/// How long a RECORD's already-open forward gets to answer a reuse probe —
/// deliberately much shorter than [`open_timeout`], since this is checking
/// "is it still there," not waiting for a fresh forward to come up.
const REUSE_PROBE_TIMEOUT: Duration = Duration::from_millis(300);

/// One tick of [`open_or_reuse`]'s poll-until-answers-or-deadline loop.
const OPEN_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// The injected spawn seam (module doc's "testability seam" note) —
/// `Arc<dyn Fn(...)>` so both the production closure and a test fake share
/// one type, mirroring `aoide_conduct::graph::who::PullFn`'s own shape.
/// Takes the already-chosen local port (not a return value) because the
/// caller must know it before the child exists, to build both the `-L`
/// spec and the post-spawn probe target from the same value.
type SpawnFn = Arc<dyn Fn(u16, &Via, &str, u16) -> Result<Child, String> + Send + Sync>;

/// Open a forward to `remote_host:remote_port` on `via`'s far box, or reuse
/// one already open for `(session_id, key)` — see the module doc's
/// lifecycle summary. Returns the LOCAL port a caller should now dial
/// `127.0.0.1:<port>` through.
pub fn open_or_reuse(
    session_id: &str,
    key: &str,
    via: &Via,
    remote_host: &str,
    remote_port: u16,
) -> Result<u16, String> {
    let spawn: SpawnFn = Arc::new(spawn_ssh);
    open_or_reuse_with(session_id, key, via, remote_host, remote_port, &spawn)
}

fn open_or_reuse_with(
    session_id: &str,
    key: &str,
    via: &Via,
    remote_host: &str,
    remote_port: u16,
    spawn: &SpawnFn,
) -> Result<u16, String> {
    if let Some(rec) = aoide_storage::tunnel::load(session_id, key) {
        if proc_exists(rec.pid) && probe_port(rec.local_port, REUSE_PROBE_TIMEOUT) {
            return Ok(rec.local_port);
        }
        // Stale: either the pid is gone, or something is still alive at
        // that pid but nothing answers the forward. Either way the record
        // is worthless as a dial target — remove it and open fresh. A
        // live-but-dead-port process is deliberately NOT killed here: this
        // function's job is "hand back a working port," not process
        // hygiene. An orphan left this way is exactly what `close` and the
        // reaper (P-S5) exist to collect.
        let _ = aoide_storage::tunnel::remove(session_id, key);
    }

    let local_port = free_local_port()?;
    let mut child = spawn(local_port, via, remote_host, remote_port)?;
    let pid = child.id();

    let deadline = Instant::now() + open_timeout();
    loop {
        if probe_port(local_port, Duration::from_millis(200)) {
            break;
        }
        // `ExitOnForwardFailure=yes` exists precisely so a doomed forward
        // (missing `authorized_keys`, an unreachable host, a refused
        // connection) makes `ssh` exit almost immediately instead of
        // hanging — checking for that exit here is what actually cashes
        // that in; without it, a request that could fail in under a
        // second would sit out the FULL deadline before this function
        // ever notices.
        if let Ok(Some(status)) = child.try_wait() {
            let _ = aoide_storage::tunnel::remove(session_id, key);
            return Err(exited_before_forward_error(via, remote_host, remote_port, status));
        }
        if Instant::now() >= deadline {
            // A hung/never-authorized child must never wedge the caller —
            // this deadline is the whole guard (R3). Kill AND reap: this
            // child was spawned in THIS process, moments ago, so (unlike
            // `close`'s cross-invocation case) a real `wait(2)` is both
            // possible and required to avoid leaving a zombie behind.
            let _ = child.kill();
            let _ = child.wait();
            let _ = aoide_storage::tunnel::remove(session_id, key);
            return Err(timeout_error(via, remote_host, remote_port, open_timeout()));
        }
        std::thread::sleep(OPEN_POLL_INTERVAL);
    }

    let record = TunnelRecord {
        schema_version: TUNNEL_VERSION.to_string(),
        session_id: session_id.to_string(),
        key: key.to_string(),
        ssh_target: via.to_string(),
        local_port,
        remote_host: remote_host.to_string(),
        remote_port,
        pid,
        opened_at: aoide_storage::time::now_iso_utc(),
    };
    aoide_storage::tunnel::save(&record)?;
    Ok(local_port)
}

/// Tear down the forward recorded for `(session_id, key)` and remove its
/// record. Idempotent on a record that is already gone. See the module
/// doc's "recycled-pid decision" for why a live pid is signaled ONLY after
/// [`looks_like_our_ssh`] confirms it is still this record's own child.
pub fn close(session_id: &str, key: &str) -> Result<(), String> {
    if let Some(rec) = aoide_storage::tunnel::load(session_id, key) {
        if proc_exists(rec.pid) && looks_like_our_ssh(rec.pid, rec.local_port, rec.remote_port) {
            terminate_pid(rec.pid);
        }
    }
    aoide_storage::tunnel::remove(session_id, key)
}

/// [`close`] every tunnel recorded for `session_id` — best-effort across
/// all of them (one record's removal failing does not stop the rest), the
/// last error (if any) surfaced to the caller.
pub fn close_all_for_session(session_id: &str) -> Result<(), String> {
    let mut last_err = None;
    for rec in aoide_storage::tunnel::list_records().into_iter().filter(|r| r.session_id == session_id) {
        if let Err(e) = close(session_id, &rec.key) {
            last_err = Some(e);
        }
    }
    match last_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

// ── process-liveness / signaling ────────────────────────────────────────

/// Is `pid` a live process? `aoide_conduct::reap::proc_exists`'s exact
/// two-line check, RE-DERIVED here rather than imported — `aoide-client`
/// sits below `aoide-conduct` in the crate DAG, the same reason
/// `aoide_storage::tunnel::runtime_dir` re-derives `conduct_socket_path`'s
/// convention instead of depending on it.
fn proc_exists(pid: u32) -> bool {
    std::path::Path::new("/proc").join(pid.to_string()).exists()
}

/// The module doc's "recycled-pid decision": read `/proc/<pid>/cmdline`
/// (NUL-separated argv) and confirm it is actually an `ssh` process
/// carrying THIS record's exact `-L <local_port>:<remote_host>:<remote_port>`
/// spec, before `close` ever signals it. A pid that no longer exists, or
/// whose cmdline is unreadable (already exited, permission denied), or
/// whose argv doesn't match, is NOT our ssh — `close` skips the signal and
/// just drops the record.
fn looks_like_our_ssh(pid: u32, local_port: u16, remote_port: u16) -> bool {
    let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    let args: Vec<String> = raw
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    let is_ssh = args.first().is_some_and(|a| a == "ssh" || a.ends_with("/ssh"));
    let spec = format!("{local_port}:127.0.0.1:{remote_port}");
    // The `-L` value itself may carry any host in its middle segment
    // (`spawn_ssh` below writes `remote_host` there); match on the
    // `<local_port>:` prefix plus the `:<remote_port>` suffix so a
    // non-default `remote_host` still matches, without re-deriving the
    // exact string `spawn_ssh` built.
    let l_prefix = format!("{local_port}:");
    let l_suffix = format!(":{remote_port}");
    let has_l_spec = args.iter().any(|a| {
        a == &spec || (a.starts_with(&l_prefix) && a.ends_with(&l_suffix))
    });
    is_ssh && has_l_spec
}

/// `SIGTERM` a pid already confirmed (by the caller) to be this record's
/// own `ssh` child, then wait — best-effort, not a real `wait(2)`: this
/// pid is not necessarily a child OF THIS PROCESS (a tunnel opened by an
/// earlier `aoide` invocation has no `Child` handle here to reap), so
/// "wait" means polling `/proc/<pid>` for its exit within a short bound, a
/// courtesy for the caller's own next action, never a guarantee.
fn terminate_pid(pid: u32) {
    // SAFETY: `pid` was just proven by `looks_like_our_ssh` to be this
    // record's own `ssh` child, never an arbitrary/unrelated process.
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_millis(500);
    while proc_exists(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
}

// ── local port / probe ──────────────────────────────────────────────────

/// Reserve a free loopback port: bind `:0`, read back what the OS assigned,
/// then drop the listener so `ssh -L` can bind it itself — the same
/// bind-read-back-drop idiom `cli/tests/peer_connectivity.rs::free_port`
/// already uses. The tiny re-bind race (R6) is accepted, the same way that
/// test accepts it; `ExitOnForwardFailure=yes` turns a lost race into a
/// clean, retryable spawn failure rather than a silent half-open tunnel.
fn free_local_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("reserve a local port: {e}"))?;
    listener.local_addr().map(|a| a.port()).map_err(|e| format!("read back the reserved port: {e}"))
}

/// Does a real TCP connect to `127.0.0.1:<port>` succeed within `timeout`?
/// The one liveness probe both the reuse check and the post-spawn poll
/// loop share.
fn probe_port(port: u16, timeout: Duration) -> bool {
    TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), timeout).is_ok()
}

fn open_timeout() -> Duration {
    Duration::from_secs(open_timeout_secs())
}

fn open_timeout_secs() -> u64 {
    if let Ok(v) = std::env::var(TUNNEL_OPEN_TIMEOUT_ENV) {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            if let Ok(secs) = trimmed.parse::<u64>() {
                if secs > 0 {
                    return secs;
                }
            }
        }
    }
    DEFAULT_OPEN_TIMEOUT_SECS
}

// ── the real ssh child ──────────────────────────────────────────────────

/// `via`'s ssh login: its own `user` segment when present, else `$USER`,
/// else `$LOGNAME`, else a taught refusal — never a guessed literal
/// (the ssh-transport plan's K4; no new env knob, `--via user@host`
/// already covers the override).
fn resolve_login(via: &Via) -> Result<String, String> {
    if let Some(u) = &via.user {
        return Ok(u.clone());
    }
    if let Ok(u) = std::env::var("USER") {
        if !u.trim().is_empty() {
            return Ok(u);
        }
    }
    if let Ok(u) = std::env::var("LOGNAME") {
        if !u.trim().is_empty() {
            return Ok(u);
        }
    }
    Err(format!(
        "no ssh login for `{via}` — neither $USER nor $LOGNAME is set; pass an explicit --via user@host"
    ))
}

/// The ONE place `Command::new("ssh")` is ever written. `BatchMode=yes` is
/// an invariant, not a preference (module/client-README note): it is the
/// mechanical form of "aoide never automates key setup" — no password or
/// host-key prompt can ever appear, so a missing `~/.ssh/authorized_keys`
/// entry on the far end fails fast (an exit, caught by
/// [`open_or_reuse_with`]'s own bounded poll) instead of hanging on a
/// prompt nothing here could ever answer.
fn spawn_ssh(local_port: u16, via: &Via, remote_host: &str, remote_port: u16) -> Result<Child, String> {
    let login = resolve_login(via)?;
    let mut cmd = Command::new("ssh");
    cmd.arg("-N")
        .arg("-T")
        .arg("-o")
        .arg("ExitOnForwardFailure=yes")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg(format!("ConnectTimeout={}", open_timeout_secs()))
        .arg("-o")
        .arg("ServerAliveInterval=15")
        .arg("-o")
        .arg("ServerAliveCountMax=3");
    if let Some(port) = via.port {
        cmd.arg("-p").arg(port.to_string());
    }
    cmd.arg("-L")
        .arg(format!("{local_port}:{remote_host}:{remote_port}"))
        .arg(format!("{login}@{}", via.host))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd.spawn().map_err(|e| format!("spawn `ssh` for {via}: {e}"))
}

/// The taught error `open_or_reuse_with` returns when a fresh forward never
/// answers before its deadline — names the ssh target, the direction it
/// was dialing, and the one-time `authorized_keys` step (aoide never
/// writes it for the operator).
fn timeout_error(via: &Via, remote_host: &str, remote_port: u16, waited: Duration) -> String {
    format!(
        "ssh tunnel to {via} timed out after {}s waiting for the forward to {remote_host}:{remote_port} \
         to answer — if this is the first time connecting to {via}, add this box's public key to \
         {via}'s ~/.ssh/authorized_keys (aoide never writes it for you) and retry",
        waited.as_secs()
    )
}

/// The taught error `open_or_reuse_with` returns when `ssh` itself exits
/// before the forward ever comes up — the fast-failure counterpart to
/// [`timeout_error`], reached only via the poll loop's `try_wait` check
/// above (a missing `authorized_keys` entry, a refused/unreachable host, or
/// `ExitOnForwardFailure` firing on its own).
fn exited_before_forward_error(
    via: &Via,
    remote_host: &str,
    remote_port: u16,
    status: std::process::ExitStatus,
) -> String {
    format!(
        "ssh to {via} exited ({status}) before the forward to {remote_host}:{remote_port} ever came up \
         — if this is the first time connecting to {via}, add this box's public key to {via}'s \
         ~/.ssh/authorized_keys (aoide never writes it for you) and retry"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    fn with_temp_runtime_dir<T>(tag: &str, f: impl FnOnce() -> T) -> T {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("XDG_RUNTIME_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-client-tunnel-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", &dir);

        let out = f();

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
        out
    }

    fn fixture(session_id: &str, key: &str, pid: u32, local_port: u16) -> TunnelRecord {
        TunnelRecord {
            schema_version: TUNNEL_VERSION.to_string(),
            session_id: session_id.to_string(),
            key: key.to_string(),
            ssh_target: "ssh://sakaki".to_string(),
            local_port,
            remote_host: "127.0.0.1".to_string(),
            remote_port: 8710,
            pid,
            opened_at: "2026-08-27T00:00:00Z".to_string(),
        }
    }

    fn bare_via(host: &str) -> Via {
        Via { user: None, host: host.to_string(), port: None }
    }

    /// A fake spawn that binds `local_port` itself (simulating a forward
    /// that comes up) and starts a genuine but ssh-free child (`sleep`) so
    /// the record it produces carries a real, killable pid. No `ssh`
    /// anywhere in this test binary.
    fn spawn_that_binds_the_port() -> SpawnFn {
        Arc::new(|local_port: u16, _via: &Via, _remote_host: &str, _remote_port: u16| {
            let listener = TcpListener::bind(("127.0.0.1", local_port)).map_err(|e| format!("test fake bind: {e}"))?;
            std::thread::spawn(move || {
                // A bound listener alone answers `connect()` (SYN/ACK) with
                // no `accept()` loop needed — held alive for the test.
                let _keep = listener;
                std::thread::sleep(Duration::from_secs(10));
            });
            Command::new("sleep").arg("10").spawn().map_err(|e| format!("test fake spawn: {e}"))
        })
    }

    /// A fake spawn that starts a real child but never opens the port —
    /// the timeout branch's fixture.
    fn spawn_that_never_binds() -> SpawnFn {
        Arc::new(|_local_port: u16, _via: &Via, _remote_host: &str, _remote_port: u16| {
            Command::new("sleep").arg("10").spawn().map_err(|e| format!("test fake spawn: {e}"))
        })
    }

    // ── open_or_reuse: reuse ────────────────────────────────────────────

    #[test]
    fn a_live_record_whose_port_answers_is_reused_without_a_second_spawn() {
        with_temp_runtime_dir("reuse", || {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            // kept alive for the whole closure so the reuse probe succeeds

            aoide_storage::tunnel::save(&fixture("sess-c", "sakaki", std::process::id(), port)).unwrap();

            let calls = Arc::new(AtomicUsize::new(0));
            let calls2 = calls.clone();
            let spawn: SpawnFn = Arc::new(move |_lp, _via, _rh, _rp| {
                calls2.fetch_add(1, Ordering::SeqCst);
                panic!("spawn must not be called when an existing record is reusable");
            });

            let via = bare_via("sakaki");
            let got = open_or_reuse_with("sess-c", "sakaki", &via, "127.0.0.1", 8710, &spawn).unwrap();
            assert_eq!(got, port);
            assert_eq!(calls.load(Ordering::SeqCst), 0, "the injected spawn must never run on a reuse");
            drop(listener);
        });
    }

    // ── open_or_reuse: stale — dead pid ─────────────────────────────────

    #[test]
    fn stale_record_with_a_dead_pid_is_removed_and_reopened() {
        with_temp_runtime_dir("dead-pid", || {
            // Well past any real pid_max — guaranteed not to be alive.
            aoide_storage::tunnel::save(&fixture("sess-a", "sakaki", 999_999_999, 1)).unwrap();

            let via = bare_via("sakaki");
            let spawn = spawn_that_binds_the_port();
            let port = open_or_reuse_with("sess-a", "sakaki", &via, "127.0.0.1", 8710, &spawn).unwrap();

            let saved = aoide_storage::tunnel::load("sess-a", "sakaki").unwrap();
            assert_eq!(saved.local_port, port);
            assert_ne!(saved.pid, 999_999_999);
        });
    }

    // ── open_or_reuse: stale — live pid, dead port ──────────────────────

    #[test]
    fn stale_record_with_a_live_pid_but_dead_port_is_removed_and_reopened() {
        with_temp_runtime_dir("live-pid-dead-port", || {
            let dead_port = {
                let l = TcpListener::bind("127.0.0.1:0").unwrap();
                l.local_addr().unwrap().port()
                // dropped: nothing listens here
            };
            // This TEST process's own pid is genuinely alive, but nothing
            // answers `dead_port` — the "live pid, dead port" case.
            aoide_storage::tunnel::save(&fixture("sess-b", "sakaki", std::process::id(), dead_port)).unwrap();

            let via = bare_via("sakaki");
            let spawn = spawn_that_binds_the_port();
            let port = open_or_reuse_with("sess-b", "sakaki", &via, "127.0.0.1", 8710, &spawn).unwrap();

            assert!(probe_port(port, Duration::from_millis(200)), "the fresh forward must actually answer");
            let saved = aoide_storage::tunnel::load("sess-b", "sakaki").unwrap();
            assert_eq!(saved.local_port, port);
        });
    }

    // ── open_or_reuse: timeout ───────────────────────────────────────────

    #[test]
    fn open_timeout_kills_the_child_and_leaves_no_record() {
        with_temp_runtime_dir("timeout", || {
            std::env::set_var(TUNNEL_OPEN_TIMEOUT_ENV, "1");

            let spawned_pid: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));
            let spawned_pid2 = spawned_pid.clone();
            let never_binds = spawn_that_never_binds();
            let spawn: SpawnFn = Arc::new(move |lp, via, rh, rp| {
                let child = never_binds(lp, via, rh, rp)?;
                *spawned_pid2.lock().unwrap() = Some(child.id());
                Ok(child)
            });

            let via = bare_via("nowhere-listening");
            let err = open_or_reuse_with("sess-d", "sakaki", &via, "127.0.0.1", 8710, &spawn).unwrap_err();
            assert!(err.contains("nowhere-listening"), "error must name the ssh target: {err}");
            assert!(err.contains("authorized_keys"), "error must teach the one-time setup step: {err}");

            assert!(aoide_storage::tunnel::load("sess-d", "sakaki").is_none(), "a timed-out open leaves no record");

            let pid = spawned_pid.lock().unwrap().expect("the injected spawn was called");
            assert!(!proc_exists(pid), "the timed-out child must be killed and reaped");

            std::env::remove_var(TUNNEL_OPEN_TIMEOUT_ENV);
        });
    }

    #[test]
    fn open_fails_fast_when_the_child_exits_before_the_forward_comes_up() {
        with_temp_runtime_dir("early-exit", || {
            // Left at the 8s default deliberately — the assertion below is
            // that this returns in well under that, not that a shorter
            // configured timeout coincidentally fired first.
            let spawn: SpawnFn = Arc::new(|_lp, _via, _rh, _rp| {
                Command::new("false").spawn().map_err(|e| format!("test fake spawn: {e}"))
            });

            let started = Instant::now();
            let via = bare_via("nowhere-listening");
            let err = open_or_reuse_with("sess-h", "sakaki", &via, "127.0.0.1", 8710, &spawn).unwrap_err();
            assert!(
                started.elapsed() < Duration::from_secs(3),
                "an already-exited child must fail fast, not wait out the full deadline: {:?}",
                started.elapsed()
            );
            assert!(err.contains("exited"), "error must say the child exited, not merely timed out: {err}");
            assert!(aoide_storage::tunnel::load("sess-h", "sakaki").is_none());
        });
    }

    // ── close ────────────────────────────────────────────────────────────

    #[test]
    fn close_removes_the_record_and_is_idempotent_on_a_missing_one() {
        with_temp_runtime_dir("close-idempotent", || {
            assert!(close("sess-e", "sakaki").is_ok(), "closing a missing record is a no-op Ok");

            // This test's own pid: alive, but (proven by the dedicated test
            // below) its cmdline is never mistaken for `ssh`, so `close`
            // must still remove the record without signaling this process.
            aoide_storage::tunnel::save(&fixture("sess-e", "sakaki", std::process::id(), 41234)).unwrap();

            assert!(close("sess-e", "sakaki").is_ok());
            assert!(aoide_storage::tunnel::load("sess-e", "sakaki").is_none());
            assert!(proc_exists(std::process::id()), "close must never signal an unrelated recycled-pid process");

            // Idempotent on the now-missing record.
            assert!(close("sess-e", "sakaki").is_ok());
        });
    }

    /// The recycled-pid decision, pinned directly: a pid alone is never
    /// enough to sign a process's death warrant. This test's own pid is
    /// alive but is manifestly not an `ssh` process carrying this `-L`
    /// spec, so the guard must refuse it.
    #[test]
    fn looks_like_our_ssh_refuses_a_pid_whose_cmdline_is_not_ssh() {
        assert!(!looks_like_our_ssh(std::process::id(), 41234, 8710));
    }

    #[test]
    fn close_all_for_session_only_touches_that_sessions_records() {
        with_temp_runtime_dir("close-all", || {
            aoide_storage::tunnel::save(&fixture("sess-f", "sakaki", std::process::id(), 1)).unwrap();
            aoide_storage::tunnel::save(&fixture("sess-f", "yomi", std::process::id(), 2)).unwrap();
            aoide_storage::tunnel::save(&fixture("sess-g", "sakaki", std::process::id(), 3)).unwrap();

            assert!(close_all_for_session("sess-f").is_ok());

            assert!(aoide_storage::tunnel::load("sess-f", "sakaki").is_none());
            assert!(aoide_storage::tunnel::load("sess-f", "yomi").is_none());
            assert!(aoide_storage::tunnel::load("sess-g", "sakaki").is_some(), "a different session's record is untouched");
        });
    }

    // ── pure helpers ─────────────────────────────────────────────────────

    #[test]
    fn probe_port_answers_only_when_something_is_listening() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(probe_port(port, Duration::from_millis(200)));

        let never_bound = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        assert!(!probe_port(never_bound, Duration::from_millis(200)));
    }

    #[test]
    fn free_local_port_returns_a_port_thats_bindable_again() {
        let port = free_local_port().unwrap();
        assert!(TcpListener::bind(("127.0.0.1", port)).is_ok(), "the reserved port must be free to rebind");
    }

    #[test]
    fn open_timeout_secs_falls_back_on_unparsable_or_zero() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var(TUNNEL_OPEN_TIMEOUT_ENV).ok();

        std::env::remove_var(TUNNEL_OPEN_TIMEOUT_ENV);
        assert_eq!(open_timeout_secs(), DEFAULT_OPEN_TIMEOUT_SECS);

        std::env::set_var(TUNNEL_OPEN_TIMEOUT_ENV, "0");
        assert_eq!(open_timeout_secs(), DEFAULT_OPEN_TIMEOUT_SECS);

        std::env::set_var(TUNNEL_OPEN_TIMEOUT_ENV, "not-a-number");
        assert_eq!(open_timeout_secs(), DEFAULT_OPEN_TIMEOUT_SECS);

        std::env::set_var(TUNNEL_OPEN_TIMEOUT_ENV, "3");
        assert_eq!(open_timeout_secs(), 3);

        match saved {
            Some(v) => std::env::set_var(TUNNEL_OPEN_TIMEOUT_ENV, v),
            None => std::env::remove_var(TUNNEL_OPEN_TIMEOUT_ENV),
        }
    }

    #[test]
    fn resolve_login_prefers_vias_own_user_then_env_then_refuses() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved_user = std::env::var("USER").ok();
        let saved_logname = std::env::var("LOGNAME").ok();

        let named = Via { user: Some("khoa".to_string()), host: "sakaki".to_string(), port: None };
        assert_eq!(resolve_login(&named).unwrap(), "khoa");

        let bare = bare_via("sakaki");
        std::env::set_var("USER", "envuser");
        std::env::remove_var("LOGNAME");
        assert_eq!(resolve_login(&bare).unwrap(), "envuser");

        std::env::remove_var("USER");
        std::env::set_var("LOGNAME", "lognameuser");
        assert_eq!(resolve_login(&bare).unwrap(), "lognameuser");

        std::env::remove_var("LOGNAME");
        assert!(resolve_login(&bare).is_err());

        match saved_user {
            Some(v) => std::env::set_var("USER", v),
            None => std::env::remove_var("USER"),
        }
        match saved_logname {
            Some(v) => std::env::set_var("LOGNAME", v),
            None => std::env::remove_var("LOGNAME"),
        }
    }
}
