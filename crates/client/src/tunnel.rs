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
//! a forward down and remove its record once the pid is CONFIRMED gone — a
//! child that survives the bounded kill keeps its record on disk instead,
//! so the name stays findable rather than becoming an untracked survivor;
//! P-S5 wires the session-end fast path and the reaper's orphan-collecting
//! backstop (which retries exactly such a survivor) on top of these two.
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
        // is worthless as a dial target and is about to be REPLACED by a
        // fresh one at this exact (session, key) — not merely deleted. A
        // live-but-dead-port old process must be killed here, not left for
        // `close`/the reaper (P-S5) to collect later: both of those can
        // only ever act on a pid they load FROM a record, and this record
        // is the only place the old pid was ever written down. Once the
        // fresh record below overwrites it, the old child becomes
        // PERMANENTLY untrackable — the same guarded kill `close` performs
        // (alive, AND still looks like this record's own `ssh`) runs on it
        // first. A genuinely dead pid costs nothing extra here:
        // `kill_if_still_our_ssh`'s own `proc_exists` check already turns
        // this into a no-op for the dead-pid case.
        kill_if_still_our_ssh(rec.pid, rec.local_port, rec.remote_port);
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
    aoide_storage::tunnel::save(&record).map_err(|e| {
        // A spawn that succeeded and even answered its own probe, but
        // whose record then failed to write, is otherwise an immediate,
        // untracked orphan: nothing will ever find this pid again once
        // this error propagates and no record exists to name it. Kill and
        // reap it before returning the error — the same courtesy the
        // timeout branch above already extends.
        let _ = child.kill();
        let _ = child.wait();
        e
    })?;
    Ok(local_port)
}

/// Tear down the forward recorded for `(session_id, key)` and remove its
/// record — but ONLY once [`kill_if_still_our_ssh`] confirms the pid is
/// actually gone. Idempotent on a record that is already gone. See the
/// module doc's "recycled-pid decision" for why a live pid is signaled ONLY
/// after [`looks_like_our_ssh`] confirms it is still this record's own
/// child.
///
/// A child that survives [`terminate_pid`]'s bounded `SIGTERM`+wait (a
/// stubborn or hung `ssh`) is NOT untracked here: the record is left in
/// place instead of being dropped, so the pid stays a name something can
/// still find. `close`/`close_all_for_session`/the reaper can only ever act
/// on a pid they load FROM a record (module doc, "recycled-pid decision") —
/// dropping the record on a mere kill ATTEMPT, rather than a confirmed
/// death, would make the survivor permanently invisible to everything,
/// including `aoide-conduct::reap::sweep_orphan_tunnels`'s own backstop.
/// That backstop already re-collects a roster-less record on its own
/// (`orphan_tunnel_candidates`'s settle window, P-S5) once this session
/// leaves the roster, so no new field is needed to mark a kept record for
/// retry — leaving it on disk is the whole mechanism.
pub fn close(session_id: &str, key: &str) -> Result<(), String> {
    if let Some(rec) = aoide_storage::tunnel::load(session_id, key) {
        if !kill_if_still_our_ssh(rec.pid, rec.local_port, rec.remote_port) {
            // Still alive and still ours — leave the record for a later
            // close/sweep to retry, per the doc above.
            return Ok(());
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

/// Kill `pid` if — and only if — it is still alive AND
/// [`looks_like_our_ssh`] still confirms it as `(local_port, remote_port)`'s
/// own `ssh` child (the module doc's "recycled-pid decision"). Shared by
/// [`close`] (tearing a forward down on purpose), `open_or_reuse_with`'s
/// stale-record path (a live-but-dead-port record is about to be
/// OVERWRITTEN by a fresh one at the same key — without this, the old
/// child would become permanently untrackable, since `close`/
/// `close_all_for_session`/the reaper can only ever act on a pid they load
/// FROM a record), and `aoide-conduct::reap::sweep_orphan_tunnels` (P-S5),
/// which loads a record whose SESSION is gone but whose pid still answers
/// `/proc` and needs the exact same guarded kill before the record is
/// unlinked out from under it. `pub` (not `pub(crate)`): `aoide-conduct`
/// sits above `aoide-client` in the crate DAG (`client/AGENTS.md`, "the
/// `conduct -> client` edge is load-bearing"), so the reaper reuses this
/// verbatim rather than re-implementing process-killing a second time.
///
/// Returns whether `pid` is now safe to forget — `true` when it was never
/// alive, was never actually this record's `ssh` (the recycled-pid case:
/// nothing here was ours to track in the first place), or WAS ours and is
/// now confirmed dead by [`terminate_pid`]'s bounded wait; `false` only when
/// it was confirmed ours and is STILL alive once that bound elapses (a
/// stubborn or hung child). [`close`] uses this to decide whether a record
/// may be dropped or must be kept for a later retry.
pub fn kill_if_still_our_ssh(pid: u32, local_port: u16, remote_port: u16) -> bool {
    if proc_exists(pid) && looks_like_our_ssh(pid, local_port, remote_port) {
        terminate_pid(pid);
        return !proc_exists(pid);
    }
    true
}

/// `SIGTERM` a pid already confirmed (by the caller) to be this record's
/// own `ssh` child, then reap it. Two REAP strategies, tried in order,
/// because this pid is not always a child OF THIS PROCESS: when it is (a
/// same-process open-then-close, or `open_or_reuse_with`'s own stale-reopen
/// path, both of which parented the child moments ago), a bounded
/// `waitpid(pid, WNOHANG)` poll performs a REAL `wait(2)` so no zombie is
/// left behind — the courtesy `Child::wait()` gives when a `Child` handle
/// is on hand, reproduced here without one. `ECHILD` (this pid is not, or
/// is no longer, a child of this process — the ordinary cross-invocation
/// case: an earlier `aoide` run opened it) means a real wait can never
/// succeed here at all; that, and any other `waitpid` failure, falls back
/// to the original best-effort courtesy of polling `/proc/<pid>` for its
/// exit within a short bound — never a guarantee, just a nicety for the
/// caller's own next action.
fn terminate_pid(pid: u32) {
    // SAFETY: `pid` was just proven by `looks_like_our_ssh` to be this
    // record's own `ssh` child, never an arbitrary/unrelated process.
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }

    let waitpid_deadline = Instant::now() + Duration::from_millis(500);
    let mut reaped = false;
    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: `pid` names a real process this call just signaled;
        // `&mut status` is a valid local; `WNOHANG` never blocks.
        let r = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
        if r == pid as libc::pid_t {
            reaped = true;
            break;
        }
        if r < 0 {
            // Most commonly ECHILD (not our child) — any negative return
            // means a real wait(2) on this pid cannot succeed from this
            // process; stop polling waitpid and fall through to the
            // /proc poll below.
            break;
        }
        if Instant::now() >= waitpid_deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    if !reaped {
        let proc_deadline = Instant::now() + Duration::from_millis(500);
        while proc_exists(pid) && Instant::now() < proc_deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
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
    use std::os::unix::process::CommandExt;
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

    /// A genuine child (`bash -c "read …"`, no `ssh` binary involved) whose
    /// `/proc/<pid>/cmdline` nonetheless reads EXACTLY like this record's
    /// own `ssh … -L <local_port>:<remote_host>:<remote_port> …` —
    /// `argv[0]` overridden to `"ssh"` via the `CommandExt::arg0` unix
    /// extension (Linux echoes whatever `argv[0]` an `execve` was given
    /// back through `/proc/<pid>/cmdline`, regardless of which binary
    /// actually ran), plus the exact `-L` spec string as a harmless extra
    /// positional parameter the script never reads.
    ///
    /// **Sandbox fix (review): a builtin busy-loop, not `sleep`, and
    /// `bash`, not `sh`.** The original fixture ran `sh -c "sleep <n>"` —
    /// green in the dev shell but deterministic-fail in the nix build
    /// sandbox's check phase, `looks_like_our_ssh` false there even though
    /// the child was genuinely alive: some shell in that environment's
    /// `sh` resolution was, one way or another, discarding the
    /// caller-supplied `argv[0]` before this process's own
    /// `/proc/<pid>/cmdline` was ever read. Two independent hardenings,
    /// either one alone would have covered this fixture's actual failure
    /// mode, kept together since neither carries a downside: (1) the `-c`
    /// script is `while :; do :; done` — `:`/`while` are shell BUILTINS,
    /// never a separate program the shell could hand off to via an
    /// exec-replaces-self optimization the way `sleep` (a real external
    /// binary) could — a builtin-only script never gives a shell a reason
    /// to replace its own process image, so the `-c` invocation's own
    /// `argv[0]` can never be discarded out from under it, in ANY shell,
    /// ANY environment. This ALSO means the child blocks with no
    /// dependency on a pipe or file descriptor this process holds open —
    /// load-bearing, since both call sites below immediately `drop` their
    /// own `Child` handle to mirror "no `Child` in this process at all,
    /// only the pid on disk" (a `read`-on-piped-stdin design would EOF and
    /// exit the instant that handle dropped, closing this side of the
    /// pipe). (2) `bash`, named explicitly rather than resolved via a bare
    /// `sh` PATH lookup — `sh` is the one name a build sandbox is most
    /// likely to alias/wrap specially for legacy shebang compatibility;
    /// `bash` is the actual interpreter underneath either way (confirmed:
    /// this environment's own `sh` is itself a `bin/sh -> bash` symlink),
    /// so naming it directly loses nothing while sidestepping whatever
    /// indirection is specific to the bare `sh` name. This is what lets
    /// `looks_like_our_ssh` — and therefore `kill_if_still_our_ssh`/
    /// `terminate_pid` — be exercised against a REAL, killable, genuinely
    /// alive process, with no real `ssh` anywhere in this test binary; a
    /// spin loop's brief CPU cost is negligible — every caller kills it
    /// within the same test, well under a second.
    fn spawn_fake_ssh_argv(local_port: u16, remote_host: &str, remote_port: u16) -> Result<Child, String> {
        let spec = format!("{local_port}:{remote_host}:{remote_port}");
        Command::new("bash")
            .arg0("ssh")
            .arg("-c")
            .arg("while :; do :; done")
            .arg("aoide-test-marker")
            .arg(spec)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("test fake ssh-argv spawn: {e}"))
    }

    /// Same shape and same sandbox-safety reasoning as
    /// [`spawn_fake_ssh_argv`] (a builtin-only `-c` script, `argv[0]`
    /// overridden to `"ssh"` via `CommandExt::arg0`, `bash` named directly)
    /// — but traps `SIGTERM` away first, and only AFTER installing the trap
    /// writes `ready_marker` (`:` and `>` are shell builtins too, so this
    /// stays exec-free). The fixture for
    /// `close_keeps_the_record_when_the_child_survives_the_bounded_kill`:
    /// real `ssh` never ignores `SIGTERM`, but `terminate_pid` only ever
    /// sends one, so a stubborn/hung real child is the case this proves
    /// `close` no longer mishandles. The marker exists so the TEST can wait
    /// for the trap to actually be live before ever signaling the child —
    /// without it, a signal sent the instant after `spawn()` returns could
    /// race the child's own `trap` builtin and kill it the ordinary way,
    /// making the test flaky rather than proving anything.
    fn spawn_fake_ssh_argv_ignoring_sigterm(
        local_port: u16,
        remote_host: &str,
        remote_port: u16,
        ready_marker: &std::path::Path,
    ) -> Result<Child, String> {
        let spec = format!("{local_port}:{remote_host}:{remote_port}");
        let script = format!("trap '' TERM; : > {:?}; while :; do :; done", ready_marker);
        Command::new("bash")
            .arg0("ssh")
            .arg("-c")
            .arg(&script)
            .arg("aoide-test-marker")
            .arg(spec)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("test fake ssh-argv (SIGTERM-immune) spawn: {e}"))
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

    /// Review finding (HIGH, R2): a stale "live pid, dead port" record used
    /// to be silently overwritten — the OLD ssh child was never killed, and
    /// once its record was gone it became permanently untrackable (`close`/
    /// `close_all_for_session`/the reaper can only ever act on a pid they
    /// load FROM a record). This pins the fix: the old child — a genuine
    /// process whose cmdline actually matches `looks_like_our_ssh` — must
    /// be dead before the reopen's fresh record lands.
    #[test]
    fn stale_reopen_kills_the_old_ssh_child_before_overwriting_its_record() {
        with_temp_runtime_dir("stale-reopen-kills-old", || {
            let dead_port = {
                let l = TcpListener::bind("127.0.0.1:0").unwrap();
                l.local_addr().unwrap().port()
                // dropped: nothing listens here
            };
            let old_child = spawn_fake_ssh_argv(dead_port, "127.0.0.1", 8710).unwrap();
            let old_pid = old_child.id();
            // No `.wait()` on `old_child` — the record (not this handle)
            // is what `open_or_reuse_with` acts on, the same shape a
            // tunnel opened by an EARLIER `aoide` invocation holds (no
            // `Child` in this process at all, only the pid on disk).
            drop(old_child);

            aoide_storage::tunnel::save(&fixture("sess-i", "sakaki", old_pid, dead_port)).unwrap();
            assert!(proc_exists(old_pid), "the old fake ssh child must be alive before reopen runs");
            assert!(
                looks_like_our_ssh(old_pid, dead_port, 8710),
                "the fixture must actually pass the same guard `close` uses, or this test proves nothing"
            );

            let via = bare_via("sakaki");
            let spawn = spawn_that_binds_the_port();
            let port = open_or_reuse_with("sess-i", "sakaki", &via, "127.0.0.1", 8710, &spawn).unwrap();

            assert_ne!(port, dead_port);
            assert!(!proc_exists(old_pid), "the old, replaced ssh child must be killed, never merely orphaned");
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

    /// Review finding (MEDIUM): `terminate_pid` used to only poll `/proc`
    /// after `SIGTERM`, never `waitpid` — harmless when the pid belongs to
    /// an earlier `aoide` invocation (this process was never its parent,
    /// so no zombie is ours to leave), but a real zombie when `open` and
    /// `close` run in the SAME process, since nothing else ever reaps a
    /// child THIS process itself spawned. Proves the fix does a REAL
    /// `wait(2)`, not just "vanished from /proc" (a zombie still has a
    /// `/proc/<pid>` entry): a second `waitpid` on the same pid, run by
    /// this test AFTER `close`, must itself fail — nothing left to wait
    /// for, because `close` already collected it.
    #[test]
    fn close_on_a_same_process_child_actually_reaps_it_leaving_no_zombie() {
        with_temp_runtime_dir("close-reaps", || {
            let local_port = free_local_port().unwrap();
            let child = spawn_fake_ssh_argv(local_port, "127.0.0.1", 8710).unwrap();
            let pid = child.id();
            // Dropped with no `.wait()` — exactly the shape
            // `open_or_reuse_with`'s own success path leaves behind (the
            // `Child` goes out of scope once the record is saved), so
            // `close` genuinely has only a bare pid to work with, even
            // though — unlike the ordinary cross-invocation case — this
            // pid IS a child of this very process.
            drop(child);

            aoide_storage::tunnel::save(&fixture("sess-j", "sakaki", pid, local_port)).unwrap();
            assert!(proc_exists(pid));

            assert!(close("sess-j", "sakaki").is_ok());

            let mut status: libc::c_int = 0;
            // SAFETY: `pid` and `&mut status` are valid; `WNOHANG` never blocks.
            let r = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
            assert!(r < 0, "a second waitpid on an already-reaped child must fail — nothing left to reap: r={r}");
            assert!(!proc_exists(pid), "the child must be fully gone, not lingering as a zombie");
        });
    }

    /// Task #104: `close` used to `SIGTERM` the recorded pid via
    /// `kill_if_still_our_ssh` and then unconditionally remove the record,
    /// whether or not the process was actually confirmed dead. A child that
    /// survives `terminate_pid`'s bounded `SIGTERM`+wait (real `ssh` never
    /// does; this fixture traps `SIGTERM` away to force the worst case)
    /// then lost its record on that path — `sweep_orphan_tunnels`/
    /// `list_records` only ever walk EXISTING records, so the survivor
    /// became permanently invisible to the reaper, a resident daemon by
    /// omission. Pins the fix both ways: the record survives `close` while
    /// the child is still alive, and a LATER `close` — once the child is
    /// actually gone — finally removes it, proving the kept record really
    /// is retryable and not just permanently stuck either.
    #[test]
    fn close_keeps_the_record_when_the_child_survives_the_bounded_kill() {
        with_temp_runtime_dir("close-survivor", || {
            let local_port = free_local_port().unwrap();
            let ready_marker = std::env::temp_dir()
                .join(format!("aoide-client-tunnel-close-survivor-ready-{}", std::process::id()));
            let _ = std::fs::remove_file(&ready_marker);

            let child =
                spawn_fake_ssh_argv_ignoring_sigterm(local_port, "127.0.0.1", 8710, &ready_marker).unwrap();
            let pid = child.id();
            // No `.wait()` — the record, not this handle, is what `close`
            // acts on (the same cross-invocation shape every other fixture
            // here uses).
            drop(child);

            // Wait for the marker the script writes only AFTER its `trap`
            // has run — see the fixture's own doc for why this, not a fixed
            // sleep, is what actually closes the signal race.
            let ready_deadline = Instant::now() + Duration::from_secs(2);
            while !ready_marker.exists() && Instant::now() < ready_deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(ready_marker.exists(), "the fixture child never reported its trap as installed");
            let _ = std::fs::remove_file(&ready_marker);

            aoide_storage::tunnel::save(&fixture("sess-k", "sakaki", pid, local_port)).unwrap();
            assert!(proc_exists(pid), "the fixture child must be alive before close runs");

            assert!(
                close("sess-k", "sakaki").is_ok(),
                "a stubborn child must never turn close into an error"
            );

            assert!(
                proc_exists(pid),
                "the fixture traps SIGTERM on purpose — it must still be alive after close's bounded kill"
            );
            assert!(
                aoide_storage::tunnel::load("sess-k", "sakaki").is_some(),
                "a survivor's record must stay on disk for a later retry, never silently dropped"
            );

            // Force the child dead (SIGKILL cannot be trapped) and reap it
            // with a real, blocking `waitpid` so no zombie is left behind —
            // this process IS its parent, the same reason `terminate_pid`
            // itself does a real `wait(2)` in the same-process case.
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
            let mut status: libc::c_int = 0;
            unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
            assert!(!proc_exists(pid), "a fully reaped pid must not exist under /proc");

            assert!(close("sess-k", "sakaki").is_ok());
            assert!(
                aoide_storage::tunnel::load("sess-k", "sakaki").is_none(),
                "once the child is confirmed gone, a later close must finally remove the record"
            );
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
