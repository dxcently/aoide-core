//! The `secrets exec` client — RELEASE TO CLIENT, the plan's one subtle
//! decision (this crate's README's "Release-to-client flow"). The broker
//! never execs the agent's command: it runs as the secrets uid (wrong cwd/
//! env, and the child would inherit secrets privileges). Instead THIS
//! process — running as the CALLING uid — resolves the secret over the
//! socket, then execs the wrapped command itself, `Stdio::inherit()`
//! throughout.
//!
//! The resolved value exists ONLY as a local `String` here, from
//! [`resolve`]'s return to the `.env(...)` call inside
//! [`spawn_with_secret`] — never argv, never an `Outcome`/JSON envelope,
//! never either audit log (both audit lines are written BROKER-side,
//! before the value is ever released — see `broker`'s module doc).
//! [`resolve`] extracts the value straight out of the reply's
//! `serde_json::Value` into that local `String`; there is no
//! `#[derive(Serialize)]` struct anywhere in this crate with a `value`
//! field for it to land on (this crate's `AGENTS.md` invariant) — a
//! `serde_json::Value` read at the use site, not a named reusable type, is
//! the shape that honors it.
//!
//! **`put` (P-V4c, `secrets put <name>`) is the write-side mirror, and
//! flows the OTHER direction**: [`run_put`] reads the value from THIS
//! process's own stdin (stdin-only intake — never argv, never a `--value`
//! flag) into a local `String`, hands it straight to [`put`], which builds
//! the wire request with `serde_json::json!` at the point of use (same
//! rule as `resolve`'s request — never a `#[derive(Serialize)]` struct)
//! and sends it. `put`'s reply carries no value at all (just `{"ok":true}`
//! or `{"ok":false,"error":...}`), so unlike `exec`, `secrets put` is a
//! PLAIN registered handler (`commands::handle_secrets_put`), not a
//! `cli`-crate `special`-hook case: nothing about its control flow needs
//! to bypass the generic `Outcome` envelope or return a spawned child's
//! own exit code (`commands.rs`'s own module doc justifies this choice
//! next to `serve`/`exec`/`enroll`'s).
//!
//! **P-V4e: `run_put` prompts and hides input when stdin is a terminal.**
//! A piped/redirected stdin (`printf %s hunter2 | aoide secrets put t`,
//! the historical shape, and every existing test/script) is BYTE-IDENTICAL
//! to before — [`stdin_is_tty`] is false in that case and `run_put` falls
//! straight through to the old `read_to_string` path, untouched. Only when
//! stdin IS a terminal ([`stdin_is_tty`] true — `libc::isatty` on fd 0,
//! already a dependency via `enroll::local_hostname`'s `gethostname`, no
//! new crate) does [`read_hidden_line`] take over, which prompts and hides
//! input on STDERR (never stdout — stdout stays clean for scripting).
//! **P-I1: the hiding mechanism is `aoide_protocol::pick::hidden_input`**
//! (`inquire::Password`, ONBOARD.md's prompt substrate section) — this
//! function used to clear `ECHO` on stdin's own `termios` by hand and
//! restore it unconditionally afterward; that hand-rolled dance moved into
//! `aoide-protocol`, the ONE crate this workspace lets depend on `inquire`
//! directly, and `read_hidden_line`'s own name/signature/call sites are
//! untouched by the move.
//!
//! **P-67: `run_put` warns and confirms before an overwrite.** The
//! existence check is BROKER-SIDE — the client never fetches a value to
//! find out (that would be a `resolve`-shaped leak on an op that isn't
//! `resolve`, and a client-side file peek is impossible anyway, since the
//! client never runs as the secrets uid). [`put`] now takes an `overwrite`
//! bool and reports whether the broker's reply carries the distinct
//! `{"exists":true}` refusal via [`PutError::Exists`] — never inferred by
//! matching the `error` string's prose. `run_put`'s flow:
//! - The value is read from stdin EXACTLY as before (tty-hidden or piped),
//!   held in a local `String`, and the first `put` attempt sends
//!   `overwrite: force` (the new `--force` flag, `commands::
//!   handle_secrets_put`) — `--force` therefore skips the confirmation on
//!   BOTH a tty and a pipe, storing on the first round trip either way.
//! - A [`PutError::Exists`] refusal (only reachable when `force` was
//!   false) branches on [`stdin_is_tty`] a SECOND time: on a tty, it
//!   prints a `y/N` confirmation prompt (unhidden — a yes/no answer isn't
//!   sensitive) to stderr and reads one line; `y`/`yes` (case-insensitive)
//!   re-sends the SAME in-memory value with `overwrite: true` (the caller
//!   is never asked to retype it), anything else — including EOF, `read_line`
//!   returning `Ok(0)` — aborts with an "unchanged" message. On a non-tty
//!   stdin, there is no one to ask, so it refuses outright and teaches the
//!   `--force` spelling ([`non_tty_exists_message`], a plain pure function
//!   so this refusal is testable without faking a tty — module doc's own
//!   "pure-testable" requirement).
//! - The value NEVER touches argv, a log line, or a cache at any point in
//!   this flow — it exists only as `run_put`'s own local `String`, exactly
//!   as before this feature, just potentially handed to [`put`] TWICE
//!   instead of once.

use aoide_protocol::Invocation;
use serde_json::{json, Value};
use std::io;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

/// Map a `UnixStream::connect` failure against the broker socket into an
/// actionable message — pure (an injected [`io::Error`], no real socket),
/// so this is fully unit-tested without a live broker. This IS the exact
/// wall the User hit live (this task's own report): a bare "Permission
/// denied (os error 13)" with zero indication of what to do about it.
///
/// [`io::ErrorKind::PermissionDenied`]: the caller's own login session
/// isn't in the broker's `aoide-secrets-access` group yet — group
/// membership is login-scoped (`README.md`'s "Deployment" section), so a
/// `usermod -aG`/nix-module rebuild done from *this* shell never applies
/// until either a fresh login or an `sg` re-exec picks it up. Both fixes
/// are taught, since either genuinely works and which is more convenient
/// depends on the caller.
///
/// [`io::ErrorKind::NotFound`]/[`io::ErrorKind::ConnectionRefused`]: nothing
/// is listening at `socket_path` at all — the broker isn't running, or the
/// resolved path doesn't match the deployed one (`socket.rs`'s module doc:
/// `AOIDE_SECRETS_SOCKET`, or its `/run/aoide-secrets/secrets.sock`
/// default).
///
/// Every other `io::ErrorKind` (a transient `EMFILE`, an unreadable
/// destination directory, ...) rides through with just the socket path
/// prefixed — unchanged from before this function existed — rather than
/// guessing at a fix this function has no evidence for.
fn describe_connect_error(socket_path: &Path, err: &io::Error, reinvoke: &str) -> String {
    match err.kind() {
        io::ErrorKind::PermissionDenied => format!(
            "connecting to the secrets broker at {}: permission denied — this session isn't in the \
             `aoide-secrets-access` group yet (group membership is login-scoped: joining the group \
             doesn't apply to an already-open shell). Fix: run `sg aoide-secrets-access -c '{reinvoke}'` \
             in THIS session, or log out and back in so a fresh session picks up the group.",
            socket_path.display()
        ),
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => format!(
            "connecting to the secrets broker at {}: {err} — the broker doesn't look like it's running \
             (or the socket path is wrong). Check `systemctl status aoide-secrets-serve`, or set \
             AOIDE_SECRETS_SOCKET if this host's broker socket lives somewhere else.",
            socket_path.display()
        ),
        _ => format!("connecting to the secrets broker at {}: {err}", socket_path.display()),
    }
}

/// The bound on the CONNECT half of every socket op this module makes
/// (rider task, alongside #75/#81/#82). `UnixStream::connect` alone can
/// block indefinitely if the broker's accept BACKLOG is saturated — every
/// `resolve` on a `requireTotp` secret can legitimately hold its own
/// connection parked for up to `park::park_timeout()` (default 300s), so a
/// burst of callers hitting an already-busy broker can queue at the kernel
/// listen-backlog level, before the broker's own thread-per-connection
/// accept loop (`broker.rs`'s module doc) ever gets a chance to shed load.
/// Every read this module already bounds (`resolve_bounded`'s
/// `set_read_timeout`) or leaves unbounded (`resolve`/`put`/`pending`/
/// `approve`/`dismiss` — an interactive human is expected to wait for
/// those); this constant closes the ONE gap none of them closed: the
/// connect itself. Fixed, no env override (unlike `BACKEND_TIMEOUT_ENV`/
/// `PARK_TIMEOUT_ENV`) — this is a defensive bound against a saturated
/// backlog, not an operational knob anyone has needed to tune yet; add one
/// the same tolerant-parsing way if that changes.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Put `fd` into (or out of) non-blocking mode — same `fcntl(F_GETFL)`/
/// `fcntl(F_SETFL)` idiom `backend::set_nonblocking` already uses for a
/// backend child's output pipes, applied here to a socket fd instead.
fn set_fd_nonblocking(fd: RawFd, nonblocking: bool) {
    // SAFETY: `fd` is a fd this function's caller owns for the duration of
    // this call (a freshly created socket, never shared); `fcntl(F_GETFL)`/
    // `fcntl(F_SETFL)` are ordinary, always-defined operations on any fd
    // this process holds.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        if flags >= 0 {
            let next = if nonblocking { flags | libc::O_NONBLOCK } else { flags & !libc::O_NONBLOCK };
            libc::fcntl(fd, libc::F_SETFL, next);
        }
    }
}

/// Build a `sockaddr_un` for `path` — `Err` if the path is too long for
/// `sun_path` (the same hard cap `AF_UNIX` addresses have always had, no
/// different from what `UnixStream::connect` would itself refuse).
fn unix_sockaddr(path: &Path) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    let bytes = path.as_os_str().as_bytes();
    // SAFETY-ADJACENT (not unsafe, just a real constraint): `sun_path` is a
    // fixed-size buffer; this crate's own callers (short, fixed socket
    // paths — `socket::socket_path`'s own doc) never come close, but a
    // caller-supplied path is still checked rather than silently truncated.
    if bytes.len() >= 108 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "path too long for a unix socket address"));
    }
    // SAFETY: `sockaddr_un` is a plain-old-data C struct — zero-initializing
    // it (a valid bit pattern for every field) and then writing only the
    // fields below is the standard idiom for building one from Rust.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (dst, &src) in addr.sun_path.iter_mut().zip(bytes.iter()) {
        *dst = src as libc::c_char;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;
    Ok((addr, len))
}

/// Short sleep between retries of the raw `connect(2)` syscall itself,
/// on `EAGAIN` (review-bounce fix, this commit — see [`connect_bounded`]'s
/// own doc for why `EAGAIN` gets a retry loop rather than `poll()`).
const CONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(15);

/// Bounded replacement for `UnixStream::connect`, over TWO genuinely
/// different failure shapes a nonblocking `connect(2)` to an `AF_UNIX`
/// socket can return — `std`'s `UnixStream` has no `connect_timeout`
/// (unlike `TcpStream`), so both are hand-rolled on top of `libc` (already
/// a dependency, `Cargo.toml`'s own doc comment — zero new deps, the house
/// rule):
///
/// - **`EINPROGRESS`**: the kernel accepted the attempt and queued it — a
///   real half-open state exists, so `poll(POLLOUT)` is the right
///   primitive to wait on it, then `SO_ERROR` says whether it actually
///   succeeded.
/// - **`EAGAIN`**: on Linux, a saturated `AF_UNIX` listen backlog makes
///   `connect(2)` return `EAGAIN` IMMEDIATELY, never `EINPROGRESS` —
///   there is no half-open connection and no fd event to `poll()` for,
///   only a rejected ATTEMPT (review-bounce fix, this commit: the first
///   version of this function only special-cased `EINPROGRESS` and fell
///   through everything else, `EAGAIN` included, straight to an immediate
///   hard error — making the exact saturated-backlog scenario this
///   function exists for WORSE than the old blocking `UnixStream::connect`,
///   which would have slept in the kernel's `unix_wait_for_peer()` and
///   succeeded once a slot freed). The fix is to retry the `connect(2)`
///   SYSCALL ITSELF on a short interval ([`CONNECT_RETRY_INTERVAL`]),
///   bounded by the same overall `timeout` budget — not to poll a fd for
///   an event that will never arrive.
///
/// Every caller in this module gets the identical `io::Result<UnixStream>`
/// shape `UnixStream::connect` already returned, so every existing
/// `.map_err(describe_connect_error(...))` call site needed no change
/// beyond the function name.
fn connect_bounded(socket_path: &Path, timeout: Duration) -> io::Result<UnixStream> {
    let (addr, addr_len) = unix_sockaddr(socket_path)?;

    // SAFETY: a fresh AF_UNIX/SOCK_STREAM fd this function exclusively owns
    // from here on — handed to `UnixStream::from_raw_fd` on every success
    // path below, `libc::close`d on every error path, never both.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    set_fd_nonblocking(fd, true);

    let deadline = std::time::Instant::now() + timeout;

    // Phase 1: attempt the syscall itself, retrying on `EAGAIN`/`EINTR`
    // (both are about the ATTEMPT, not a queued connection) until it
    // either succeeds outright, reports `EINPROGRESS` (a real half-open
    // state — falls out of this loop into phase 2 below), or fails for
    // real.
    loop {
        // SAFETY: `addr`/`addr_len` describe a valid, fully-initialized
        // `sockaddr_un` for this exact `fd`'s own address family.
        let rc = unsafe { libc::connect(fd, &addr as *const libc::sockaddr_un as *const libc::sockaddr, addr_len) };
        if rc == 0 {
            set_fd_nonblocking(fd, false);
            // SAFETY: `fd` is connected and owned solely by this function
            // up to this point; handing it to `UnixStream` transfers that
            // ownership exactly once.
            return Ok(unsafe { UnixStream::from_raw_fd(fd) });
        }

        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINPROGRESS) => break,
            Some(libc::EAGAIN) => {
                let now = std::time::Instant::now();
                if now >= deadline {
                    // SAFETY: `fd` was never handed to anything else.
                    unsafe { libc::close(fd) };
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("timed out after {timeout:?} connecting (the broker's connection backlog is saturated)"),
                    ));
                }
                std::thread::sleep(CONNECT_RETRY_INTERVAL.min(deadline - now));
                continue;
            }
            Some(libc::EINTR) => continue, // the syscall itself was interrupted — just retry it
            _ => {
                // SAFETY: `fd` was never handed to anything else.
                unsafe { libc::close(fd) };
                return Err(err);
            }
        }
    }

    // Phase 2: `EINPROGRESS` — a real half-open connection exists now, so
    // `poll(POLLOUT)` is the right wait primitive, bounded by whatever's
    // left of `timeout`. `EINTR` here means the `poll()` CALL itself was
    // interrupted (not the connection) — recompute the remaining budget
    // and poll again, rather than surfacing `Interrupted` to the caller.
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            // SAFETY: `fd` was never handed to anything else.
            unsafe { libc::close(fd) };
            return Err(io::Error::new(io::ErrorKind::TimedOut, format!("timed out after {timeout:?}")));
        }
        let millis = i32::try_from(remaining.as_millis()).unwrap_or(i32::MAX).max(1);
        let mut pfd = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
        // SAFETY: `pfd` names exactly the one fd this function owns,
        // polled for exactly one event.
        let poll_rc = unsafe { libc::poll(&mut pfd, 1, millis) };
        if poll_rc == 0 {
            // SAFETY: `fd` was never handed to anything else.
            unsafe { libc::close(fd) };
            return Err(io::Error::new(io::ErrorKind::TimedOut, format!("timed out after {timeout:?}")));
        }
        if poll_rc < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            // SAFETY: `fd` was never handed to anything else.
            unsafe { libc::close(fd) };
            return Err(e);
        }
        break;
    }

    // The connect finished one way or the other — SO_ERROR says which.
    let mut sock_err: libc::c_int = 0;
    let mut sock_err_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `sock_err`/`sock_err_len` are correctly sized, exclusively
    // owned out-params for `SO_ERROR` on this function's own `fd`.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            &mut sock_err as *mut libc::c_int as *mut libc::c_void,
            &mut sock_err_len,
        )
    };
    if rc < 0 {
        let e = io::Error::last_os_error();
        // SAFETY: `fd` was never handed to anything else.
        unsafe { libc::close(fd) };
        return Err(e);
    }
    if sock_err != 0 {
        // SAFETY: `fd` was never handed to anything else.
        unsafe { libc::close(fd) };
        return Err(io::Error::from_raw_os_error(sock_err));
    }

    set_fd_nonblocking(fd, false);
    // SAFETY: same as the immediate-success path above.
    Ok(unsafe { UnixStream::from_raw_fd(fd) })
}

/// Parsed `secrets exec` arguments — pure, no I/O, fully unit-testable
/// without a running broker.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecArgs {
    pub consumer: String,
    pub secret: String,
    pub var: String,
    pub totp: Option<String>,
    pub cmd: Vec<String>,
    /// Optional, self-asserted, DISPLAY-ONLY context for a popup/prompt
    /// surface to show ("release `db-prod` for: sudo nixos-rebuild switch")
    /// — `--reason` when the caller gave one, else [`derive_reason`]'s own
    /// auto-derivation from `cmd` (same discipline `argv0` already holds:
    /// never a value, never an env var, never gates anything).
    pub reason: Option<String>,
}

/// The env-var name a bare `--secret <name>` (no explicit `:VAR`) injects
/// under: the secret name, uppercased, `-` -> `_` (`db-prod` -> `DB_PROD`)
/// — the "documented default derivation" the phase brief calls for.
pub fn default_var_name(secret: &str) -> String {
    secret.to_uppercase().replace('-', "_")
}

/// Parse `aoide secrets exec --as <consumer> --secret <name>[:VAR] [--totp N]
/// -- <cmd>` out of an already-parsed [`Invocation`]. `inv.args` is exactly
/// the wrapped command + its args — `aoide_protocol::door::parse` already
/// treats a bare `--` as ending flag parsing, so everything after it
/// arrives here verbatim as positionals (that module's own doc).
/// `secrets exec`'s own usage line — printed alongside every specific
/// missing/malformed-argument message below, never a generic usage dump on
/// its own (task: name WHICH flag is wrong AND show this command's usage).
pub const EXEC_USAGE: &str = "usage: secrets exec --as <consumer> --secret <name>[:VAR] [--totp NNNNNN] -- <cmd>";

pub fn parse_exec_args(inv: &Invocation) -> Result<ExecArgs, String> {
    let consumer = inv
        .flags
        .get("as")
        .cloned()
        .ok_or_else(|| format!("secrets exec: missing --as <consumer> — {EXEC_USAGE}"))?;
    let secret_flag = inv
        .flags
        .get("secret")
        .cloned()
        .ok_or_else(|| format!("secrets exec: missing --secret <name>[:VAR] — {EXEC_USAGE}"))?;
    let (secret, var) = match secret_flag.split_once(':') {
        Some((n, v)) if !v.is_empty() => (n.to_string(), v.to_string()),
        _ => {
            let n = secret_flag.trim_end_matches(':').to_string();
            let derived = default_var_name(&n);
            (n, derived)
        }
    };
    if !crate::policy::valid_secret_name(&secret) {
        return Err(format!(
            "invalid secret name `{secret}` (must be lowercase [a-z0-9-], no leading/trailing/doubled \
             hyphen) — {EXEC_USAGE}"
        ));
    }
    let totp = inv.flags.get("totp").cloned();
    let cmd = inv.args.clone();
    if cmd.is_empty() {
        return Err(format!("secrets exec: missing a command after `--` — {EXEC_USAGE}"));
    }
    let reason = inv.flags.get("reason").cloned().or_else(|| derive_reason(&cmd));
    Ok(ExecArgs { consumer, secret, var, totp, cmd, reason })
}

/// Auto-derived when `--reason` is omitted: the wrapped command's own argv,
/// space-joined, truncated to ~60 chars — the SAME display-only discipline
/// `argv0` already holds on the wire (never a value, never an env var,
/// never gates anything; a popup/prompt surface simply shows it — see
/// `ExecArgs::reason`'s own doc). `None` only when `cmd` itself is empty
/// (never reached in practice — `parse_exec_args` already refuses an empty
/// `cmd` before this is called — but this function stays honest on its own
/// rather than assuming that invariant from outside).
fn derive_reason(cmd: &[String]) -> Option<String> {
    if cmd.is_empty() {
        return None;
    }
    let joined = cmd.join(" ");
    const MAX_CHARS: usize = 60;
    if joined.chars().count() <= MAX_CHARS {
        Some(joined)
    } else {
        let truncated: String = joined.chars().take(MAX_CHARS.saturating_sub(1)).collect();
        Some(format!("{truncated}\u{2026}"))
    }
}

/// Connect to `socket_path`, send ONE `resolve` request, read the wire's
/// FINAL reply line ([`read_final_reply`] — zero or more interim lines may
/// come first, P-N2c FIX 1), and return the value or a value-free error
/// message.
pub fn resolve(
    socket_path: &Path,
    secret: &str,
    consumer: &str,
    totp: Option<&str>,
    argv0: Option<&str>,
    reason: Option<&str>,
) -> Result<String, String> {
    let mut stream = connect_bounded(socket_path, CONNECT_TIMEOUT).map_err(|e| {
        describe_connect_error(
            socket_path,
            &e,
            &format!("aoide secrets exec --as {consumer} --secret {secret} -- ..."),
        )
    })?;

    let mut req = json!({ "op": "resolve", "secret": secret, "consumer": consumer });
    if let Some(t) = totp {
        req["totp"] = Value::String(t.to_string());
    }
    if let Some(a) = argv0 {
        req["argv0"] = Value::String(a.to_string());
    }
    // Optional, self-asserted, DISPLAY-ONLY context for why this ask exists
    // (`ExecArgs::reason`'s own doc) — a popup/prompt surface shows it
    // alongside the parked ask; the broker never gates on it.
    if let Some(r) = reason {
        req["reason"] = Value::String(r.to_string());
    }
    let mut line = req.to_string();
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .map_err(|e| format!("writing to the secrets broker: {e}"))?;

    let mut reader = BufReader::new(stream);
    let reply = read_final_reply(&mut reader)?;

    if reply.get("ok").and_then(Value::as_bool) == Some(true) {
        reply
            .get("value")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| "the secrets broker's reply had no `value`".to_string())
    } else {
        Err(reply
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("the secrets broker denied the request")
            .to_string())
    }
}

/// Read wire lines until the FINAL (non-interim) reply — the framing
/// contract P-N2c FIX 1 establishes (`CONTRACTS.md`'s Transport paragraph,
/// `broker.rs`'s module doc): "one request line -> zero or more interim
/// lines (`"interim":true`) -> exactly one final reply line." Every
/// interim line is surfaced via [`announce_interim`] (STDERR only, never
/// stdout — stdout stays clean for scripting) and then discarded; the
/// first line WITHOUT `"interim":true` is the final reply this function
/// returns. Only [`resolve`] can ever receive an interim line today (the
/// only op that parks) — kept as its own function rather than inlined so a
/// future op gaining interim lines reuses this loop instead of
/// re-deriving it.
fn read_final_reply(reader: &mut impl BufRead) -> Result<Value, String> {
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).map_err(|e| format!("reading from the secrets broker: {e}"))?;
        if line.trim().is_empty() {
            return Err("the secrets broker closed the connection with no reply".to_string());
        }
        let value: Value = serde_json::from_str(line.trim())
            .map_err(|e| format!("the secrets broker sent an unparseable reply: {e}"))?;
        if value.get("interim").and_then(Value::as_bool) == Some(true) {
            announce_interim(&value);
            continue;
        }
        return Ok(value);
    }
}

/// Resolve a secret's value BOUNDED — an explicit socket read `timeout`
/// PLUS `wait:false` on the wire — for a caller with no human to type a
/// TOTP code and that must never hang waiting for one (task #84: the A2A
/// door's inbound bearer check, and its outbound client's per-peer bearer
/// presentation — see `crates/server/src/a2a.rs`'s consumers of this
/// function). Two independent bounds, not one:
///
/// - `wait:false` is the wire's OWN documented escape hatch for exactly
///   this caller shape (`CONTRACTS.md`'s "Secrets wire" section) — a
///   `requireTotp` secret with no `automation`-open exemption for the
///   asserted `consumer` denies IMMEDIATELY instead of parking, so the
///   deployed, automation-open happy path never even reaches the timeout
///   below at all.
/// - `timeout` (via `UnixStream::set_read_timeout`, set BEFORE the request
///   is written) caps the socket READ regardless of why the broker might
///   still be slow to answer — a defense-in-depth second bound, not the
///   primary mechanism.
///
/// **NO CACHING**: every call is a fresh connect → one request → one reply.
/// Nothing this function returns is ever stored anywhere by it; the caller
/// owns the value for exactly as long as its own request needs it — this
/// crate's "NO CACHE, EVER" invariant, extended to every caller of this
/// function exactly as it already binds [`resolve`]/`secrets exec`.
pub fn resolve_bounded(
    socket_path: &Path,
    secret: &str,
    consumer: &str,
    timeout: Duration,
) -> Result<String, String> {
    let mut stream = connect_bounded(socket_path, CONNECT_TIMEOUT).map_err(|e| {
        describe_connect_error(
            socket_path,
            &e,
            &format!("aoide secrets exec --as {consumer} --secret {secret} -- ..."),
        )
    })?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| format!("setting a read timeout on the secrets broker connection at {}: {e}", socket_path.display()))?;

    let req = json!({ "op": "resolve", "secret": secret, "consumer": consumer, "wait": false });
    let mut line = req.to_string();
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .map_err(|e| format!("writing to the secrets broker: {e}"))?;

    let mut reader = BufReader::new(stream);
    let reply = read_final_reply(&mut reader)?;

    if reply.get("ok").and_then(Value::as_bool) == Some(true) {
        reply
            .get("value")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| "the secrets broker's reply had no `value`".to_string())
    } else {
        Err(reply
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("the secrets broker denied the request")
            .to_string())
    }
}

/// Surface ONE interim line to the human at the terminal — STDERR only,
/// never stdout (module doc's own discipline). Today the only interim
/// shape the broker ever sends is a park announcement
/// (`{"interim":true,"parked":true,"id":...,"timeoutSecs":...}`) — this
/// only prints for THAT shape; an interim line with a different shape (a
/// future mode) is still safely consumed by [`read_final_reply`]'s loop
/// even when this function has nothing to say about it yet.
fn announce_interim(value: &Value) {
    if value.get("parked").and_then(Value::as_bool) == Some(true) {
        let id = value.get("id").and_then(Value::as_str).unwrap_or("?");
        let timeout_secs = value.get("timeoutSecs").and_then(Value::as_u64).unwrap_or(0);
        eprintln!(
            "parked as ask {id} — complete with: aoide secrets approve {id} --totp <code>  (or dismiss {id}); \
             times out in {timeout_secs}s"
        );
    }
}

/// A [`put`] failure, distinguishing the P-67 "already has a stored value"
/// refusal from every other error — via the wire's `exists` FLAG, never by
/// matching text out of the `error` string (the task's own requirement:
/// "distinguishable WITHOUT string-matching prose").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PutError {
    /// `overwrite` was false/absent and the secret already has a stored
    /// value (the broker's `{"ok":false,"exists":true,...}` reply).
    Exists,
    /// Every other denial/error — connect failures, "secret not found", a
    /// backend problem, ... — value-free, same as before this feature.
    Other(String),
}

impl std::fmt::Display for PutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PutError::Exists => write!(f, "secret already has a stored value"),
            PutError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

/// Connect to `socket_path`, send ONE `put` request carrying `value` and
/// `overwrite`, read ONE reply line, and return whether an existing value
/// was REPLACED (`true`) or this was a first-ever store (`false`) — or a
/// [`PutError`] otherwise. Mirrors [`resolve`]'s one-shot socket shape;
/// `overwrite` only rides the wire when `true` (absent means false — wire
/// compat, `broker.rs`'s module doc), same discipline `resolve`'s optional
/// `totp`/`argv0` fields already hold.
pub fn put(socket_path: &Path, secret: &str, value: &str, overwrite: bool) -> Result<bool, PutError> {
    let mut stream = connect_bounded(socket_path, CONNECT_TIMEOUT).map_err(|e| {
        PutError::Other(describe_connect_error(socket_path, &e, &format!("aoide secrets put {secret}")))
    })?;

    let mut req = json!({ "op": "put", "secret": secret, "value": value });
    if overwrite {
        req["overwrite"] = Value::Bool(true);
    }
    let mut line = req.to_string();
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .map_err(|e| PutError::Other(format!("writing to the secrets broker: {e}")))?;

    let mut reader = BufReader::new(stream);
    let mut reply_line = String::new();
    reader
        .read_line(&mut reply_line)
        .map_err(|e| PutError::Other(format!("reading from the secrets broker: {e}")))?;
    if reply_line.trim().is_empty() {
        return Err(PutError::Other("the secrets broker closed the connection with no reply".to_string()));
    }
    let reply: Value = serde_json::from_str(reply_line.trim())
        .map_err(|e| PutError::Other(format!("the secrets broker sent an unparseable reply: {e}")))?;

    if reply.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(reply.get("replaced").and_then(Value::as_bool).unwrap_or(false))
    } else if reply.get("exists").and_then(Value::as_bool) == Some(true) {
        Err(PutError::Exists)
    } else {
        Err(PutError::Other(
            reply
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("the secrets broker denied the request")
                .to_string(),
        ))
    }
}

/// Task #79: whether [`admin_request`]'s CONNECT attempt hit "nothing is
/// listening" (`io::ErrorKind::NotFound`: no socket file at all;
/// `ConnectionRefused`: a stale socket file with nothing behind it) — the
/// ONLY two cases `commands.rs`'s admin commands fall back to their
/// direct-write path on ([`NoSocket`](AdminError::NoSocket)). Every other
/// failure — a different connect error, a write/read failure, an
/// unparseable reply, or the broker's own `{"ok":false}` domain denial
/// (a bad admin-identity peer uid, "no policy for secret x", a poisoned
/// `policy.json`) — is [`Other`](AdminError::Other) and MUST be reported,
/// never silently downgraded to a direct write: a live-but-sick daemon (a
/// permission error, a saturated backlog `connect_bounded` gave up
/// waiting on, or — the case this gate exists for — an authoritative
/// denial from the single-writer daemon) must never be bypassed into a
/// TOCTOU race against a direct write landing underneath it. This is the
/// SAME two-way split [`PutError`] already draws for `put`'s own
/// `exists`-vs-everything-else distinction, extended here for a different
/// pair of cases.
pub enum AdminError {
    NoSocket,
    Other(String),
}

/// Task #79: connect to `socket_path`, send ONE `{"op":"admin",...}`
/// request (`req` already carries `op` and `command` — every field
/// `commands.rs`'s admin commands need to send, this function adds none of
/// its own), read ONE reply line, and return the parsed reply `Value` on
/// `{"ok":true}` — the caller (`commands.rs`) reads `message`/`changed`
/// off it exactly the way it would from a [`crate::admin::AdminOutcome`]
/// on the direct-write path, so the two paths report through the same
/// shape. See [`AdminError`] for the fallback-vs-report split; this is the
/// ONE place that split is decided; a new admin command added later sends its
/// own `req` through this SAME function, never a hand-rolled write/read
/// pair.
pub fn admin_request(socket_path: &Path, req: Value) -> Result<Value, AdminError> {
    let mut stream = connect_bounded(socket_path, CONNECT_TIMEOUT).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => AdminError::NoSocket,
        _ => AdminError::Other(describe_connect_error(socket_path, &e, "aoide secrets <admin command> ...")),
    })?;

    let mut line = req.to_string();
    line.push('\n');
    stream.write_all(line.as_bytes()).map_err(|e| AdminError::Other(format!("writing to the secrets broker: {e}")))?;

    let mut reader = BufReader::new(stream);
    let mut reply_line = String::new();
    reader
        .read_line(&mut reply_line)
        .map_err(|e| AdminError::Other(format!("reading from the secrets broker: {e}")))?;
    if reply_line.trim().is_empty() {
        return Err(AdminError::Other("the secrets broker closed the connection with no reply".to_string()));
    }
    let reply: Value = serde_json::from_str(reply_line.trim())
        .map_err(|e| AdminError::Other(format!("the secrets broker sent an unparseable reply: {e}")))?;

    if reply.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(reply)
    } else {
        Err(AdminError::Other(
            reply.get("error").and_then(Value::as_str).unwrap_or("the secrets broker denied the request").to_string(),
        ))
    }
}

/// One parked ask, as `secrets pending` lists it — id/secret/consumer/
/// requestedAt/peerUid ONLY, never a value (mirrors the wire's own
/// `pending` reply shape, `broker.rs`'s module doc's wire table).
/// `peer_uid` (task #73) is the kernel-truth `SO_PEERCRED` uid stamped at
/// park time — additive over the pre-#73 wire shape, `None` both when the
/// field is entirely absent (an older broker) and when the broker sent an
/// explicit `null` (an unidentified connection at park time) — a caller of
/// this struct has no need to tell those two apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAsk {
    pub id: String,
    pub secret: String,
    pub consumer: String,
    pub requested_at: u64,
    pub peer_uid: Option<u32>,
    /// Additive over the pre-P3 shape (`peer_uid`'s own precedent, task
    /// #73) — the wire's optional, self-asserted, display-only
    /// `resolve.reason`, `None` when the caller sent none.
    pub reason: Option<String>,
    /// Additive again — best-effort "who/where this ask came from"
    /// (`park::AskOrigin`'s own doc), captured broker-side at park time.
    pub origin: PendingOrigin,
}

/// The wire-parsed mirror of `park::AskOrigin` — every field best-effort and
/// DISPLAY-ONLY (that struct's own doc); kept as this crate's own client-side
/// type rather than reusing `park::AskOrigin` directly since a wire reply is
/// parsed data, not the broker's own in-memory registry row.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PendingOrigin {
    pub username: Option<String>,
    pub pid: Option<i64>,
    pub comm: Option<String>,
    pub hostname: Option<String>,
}

/// Connect to `socket_path`, send ONE `pending` request, read ONE reply
/// line, and return every parked ask — value-free by construction (the
/// wire's `pending` reply never carries one; this simply reads the fields
/// that ARE there).
pub fn pending(socket_path: &Path) -> Result<Vec<PendingAsk>, String> {
    let mut stream = connect_bounded(socket_path, CONNECT_TIMEOUT)
        .map_err(|e| describe_connect_error(socket_path, &e, "aoide secrets pending"))?;

    let line = json!({ "op": "pending" }).to_string() + "\n";
    stream.write_all(line.as_bytes()).map_err(|e| format!("writing to the secrets broker: {e}"))?;

    let mut reader = BufReader::new(stream);
    let mut reply_line = String::new();
    reader.read_line(&mut reply_line).map_err(|e| format!("reading from the secrets broker: {e}"))?;
    if reply_line.trim().is_empty() {
        return Err("the secrets broker closed the connection with no reply".to_string());
    }
    let reply: Value = serde_json::from_str(reply_line.trim())
        .map_err(|e| format!("the secrets broker sent an unparseable reply: {e}"))?;

    if reply.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(reply
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("the secrets broker denied the request")
            .to_string());
    }
    let asks = reply
        .get("pending")
        .and_then(Value::as_array)
        .ok_or_else(|| "the secrets broker's reply had no `pending` array".to_string())?;
    asks.iter()
        .map(|a| {
            Ok(PendingAsk {
                id: a.get("id").and_then(Value::as_str).ok_or("a pending entry had no `id`")?.to_string(),
                secret: a
                    .get("secret")
                    .and_then(Value::as_str)
                    .ok_or("a pending entry had no `secret`")?
                    .to_string(),
                consumer: a
                    .get("consumer")
                    .and_then(Value::as_str)
                    .ok_or("a pending entry had no `consumer`")?
                    .to_string(),
                requested_at: a
                    .get("requestedAt")
                    .and_then(Value::as_u64)
                    .ok_or("a pending entry had no `requestedAt`")?,
                // #73: additive — absent (an older broker) and an explicit
                // `null` (unidentified at park time) both read as `None`.
                peer_uid: a.get("peerUid").and_then(Value::as_u64).map(|u| u as u32),
                // P3: additive again — same absent-or-null tolerance.
                reason: a.get("reason").and_then(Value::as_str).map(str::to_string),
                origin: a
                    .get("origin")
                    .map(|o| PendingOrigin {
                        username: o.get("username").and_then(Value::as_str).map(str::to_string),
                        pid: o.get("pid").and_then(Value::as_i64),
                        comm: o.get("comm").and_then(Value::as_str).map(str::to_string),
                        hostname: o.get("hostname").and_then(Value::as_str).map(str::to_string),
                    })
                    .unwrap_or_default(),
            })
        })
        .collect::<Result<Vec<_>, &str>>()
        .map_err(str::to_string)
}

/// Connect to `socket_path`, send ONE `approve` request carrying `id` and
/// `totp`, read ONE reply line. Success is `{"ok":true}` only — never a
/// value (the value went down the ORIGINAL parked connection, broker-side;
/// this function's own reply can't carry it because the wire reply it reads
/// never has one, `handle_approve`'s own doc). An invalid/expired code, or
/// an unknown id, comes back as a value-free `Err`.
pub fn approve(socket_path: &Path, id: &str, totp: &str) -> Result<(), String> {
    let mut stream = connect_bounded(socket_path, CONNECT_TIMEOUT)
        .map_err(|e| describe_connect_error(socket_path, &e, &format!("aoide secrets approve {id} --totp ...")))?;

    let line = json!({ "op": "approve", "id": id, "totp": totp }).to_string() + "\n";
    stream.write_all(line.as_bytes()).map_err(|e| format!("writing to the secrets broker: {e}"))?;

    let mut reader = BufReader::new(stream);
    let mut reply_line = String::new();
    reader.read_line(&mut reply_line).map_err(|e| format!("reading from the secrets broker: {e}"))?;
    if reply_line.trim().is_empty() {
        return Err("the secrets broker closed the connection with no reply".to_string());
    }
    let reply: Value = serde_json::from_str(reply_line.trim())
        .map_err(|e| format!("the secrets broker sent an unparseable reply: {e}"))?;

    if reply.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(())
    } else {
        Err(reply
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("the secrets broker denied the request")
            .to_string())
    }
}

/// Connect to `socket_path`, send ONE `dismiss` request carrying `id`, read
/// ONE reply line. An unknown id is a taught error (`handle_dismiss`'s own
/// doc), value-free either way.
pub fn dismiss(socket_path: &Path, id: &str) -> Result<(), String> {
    let mut stream = connect_bounded(socket_path, CONNECT_TIMEOUT)
        .map_err(|e| describe_connect_error(socket_path, &e, &format!("aoide secrets dismiss {id}")))?;

    let line = json!({ "op": "dismiss", "id": id }).to_string() + "\n";
    stream.write_all(line.as_bytes()).map_err(|e| format!("writing to the secrets broker: {e}"))?;

    let mut reader = BufReader::new(stream);
    let mut reply_line = String::new();
    reader.read_line(&mut reply_line).map_err(|e| format!("reading from the secrets broker: {e}"))?;
    if reply_line.trim().is_empty() {
        return Err("the secrets broker closed the connection with no reply".to_string());
    }
    let reply: Value = serde_json::from_str(reply_line.trim())
        .map_err(|e| format!("the secrets broker sent an unparseable reply: {e}"))?;

    if reply.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(())
    } else {
        Err(reply
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("the secrets broker denied the request")
            .to_string())
    }
}

/// Is stdin a terminal? `libc::isatty` on fd 0 — the branch point between
/// the historical pipe path and P-V4e's hidden-input prompt (module doc).
/// `pub(crate)` since `watch.rs` (this crate's line-mode broker-event
/// surface) needs the SAME tty branch point to decide narration-only vs.
/// prompting — widened per `pkgs/aoide/crates/AGENTS.md`'s "no cross-crate
/// copying" rule, applied in-crate: reach into the existing seam, never
/// fork a second `isatty` call site.
pub(crate) fn stdin_is_tty() -> bool {
    unsafe { libc::isatty(0) != 0 }
}

/// Strip exactly ONE trailing `\n`, never a blanket `.trim_end()` — moved
/// to `aoide_protocol::dialog::strip_one_trailing_newline` at P-P5 (F5,
/// pure extraction: a SECOND consumer, `aoide-client`'s own popup arm,
/// needed the identical trim without duplicating it). `pub(crate)` shim:
/// `watch.rs`'s `--popup` dialog-output reader — now living inside
/// `aoide_protocol::dialog::run_entry_dialog` itself — trims through the
/// SAME function; this re-export keeps every existing call at this path
/// ([`read_hidden_line`] no longer needs it itself, P-I1, but this stays
/// the one seam any OTHER stdout-line trim in this crate reaches for)
/// byte-identical. `run_entry_dialog` itself moved too (F5), so its own
/// call now reaches the function directly, unqualified, inside
/// `aoide_protocol::dialog` — leaving no live call site AT this path
/// today; kept anyway as the shim the "no cross-crate copying" discipline
/// asks for, for the next stdout-line trim this crate reaches for.
#[allow(unused_imports)]
pub(crate) use aoide_protocol::dialog::strip_one_trailing_newline;

/// Read one line of hidden input on the real terminal — the tty half of
/// [`run_put`]'s prompt (module doc). Retrofit (ONBOARD.md's prompt
/// substrate section, P-I1) onto `aoide_protocol::pick::hidden_input`
/// (`inquire::Password`, hidden display mode, no confirmation — the
/// crate's own AGENTS.md invariant that `inquire` never enters this crate
/// directly holds: the dependency lives in `aoide-protocol` alone), which
/// replaced the hand-rolled `libc::termios` echo-disable this function used
/// to do itself. The name, `pub(crate)` visibility, and every call site are
/// UNCHANGED — this is the one seam `run_put` and `watch.rs`'s approve
/// prompt already reused VERBATIM, so retrofitting its body is the whole
/// fix; neither caller needed an edit.
pub(crate) fn read_hidden_line(prompt: &str) -> Result<String, String> {
    aoide_protocol::pick::hidden_input(prompt)
}

/// The non-tty "exists" refusal message (P-67) — a plain pure function so
/// it's testable without faking a tty (module doc). Teaches the exact
/// `--force` spelling: there is no one to ask for a `y/N` confirmation
/// when stdin is a pipe, so this refuses outright rather than guessing.
fn non_tty_exists_message(secret: &str) -> String {
    format!(
        "secret `{secret}` already has a stored value — refusing to overwrite it from a non-interactive \
         stdin without confirmation. Re-run with --force to overwrite: printf %s <value> | aoide secrets put \
         {secret} --force"
    )
}

/// Prompt `y/N` on stderr and read ONE line from stdin, unhidden (a yes/no
/// answer isn't sensitive, unlike the value itself). `true` only for
/// `y`/`yes` (case-insensitive, surrounding whitespace trimmed); EOF
/// (`read_line` returning `Ok(0)`) and every other input default to `false`
/// — the task's own "default No" requirement.
fn confirm_overwrite(secret: &str) -> Result<bool, String> {
    eprint!("secret `{secret}` already has a stored value — overwrite? [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let read = std::io::stdin().lock().read_line(&mut line).map_err(|e| format!("reading confirmation from stdin: {e}"))?;
    Ok(read > 0 && matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}

/// The full `secrets put <name>` client flow: read the value from THIS
/// process's own stdin (stdin-only intake, module doc) — prompting with
/// echo hidden when stdin is a terminal (P-V4e), reading straight through
/// unchanged when it's piped/redirected (the historical shape) — then
/// [`put`] it over `socket_path`. The value exists only as this function's
/// own local `String`, from the stdin read to the `put()` call(s) — never
/// returned, never logged, never touching argv.
///
/// **P-67:** `force` (the CLI's `--force` flag) rides as `overwrite` on the
/// FIRST attempt — a forced put always succeeds in one round trip, tty or
/// not. Only when `force` is false and the broker refuses with
/// [`PutError::Exists`] does this branch on [`stdin_is_tty`] a second time:
/// a tty gets [`confirm_overwrite`]'s `y/N` prompt and, on yes, a SECOND
/// `put` with the SAME value and `overwrite: true` — the caller is never
/// asked to retype it; a non-tty stdin gets [`non_tty_exists_message`] and
/// aborts. Returns the human-facing success message ("stored" vs.
/// "replaced", so the CLI's own `Outcome` can say which happened) or a
/// value-free error string.
pub fn run_put(secret: &str, socket_path: &Path, force: bool) -> Result<String, String> {
    let value = if stdin_is_tty() {
        read_hidden_line(&format!("value for `{secret}` (input hidden): "))?
    } else {
        use std::io::Read;
        let mut value = String::new();
        std::io::stdin()
            .read_to_string(&mut value)
            .map_err(|e| format!("reading value from stdin: {e}"))?;
        value
    };

    match put(socket_path, secret, &value, force) {
        Ok(true) => Ok(format!("replaced secret `{secret}`'s stored value")),
        Ok(false) => Ok(format!("stored secret `{secret}`")),
        Err(PutError::Other(e)) => Err(e),
        Err(PutError::Exists) => {
            if !stdin_is_tty() {
                return Err(non_tty_exists_message(secret));
            }
            if !confirm_overwrite(secret)? {
                return Err(format!("secret `{secret}` left unchanged"));
            }
            match put(socket_path, secret, &value, true) {
                Ok(true) => Ok(format!("replaced secret `{secret}`'s stored value")),
                Ok(false) => Ok(format!("stored secret `{secret}`")),
                Err(PutError::Other(e)) => Err(e),
                Err(PutError::Exists) => {
                    Err(format!("secret `{secret}`: the broker refused the confirmed overwrite unexpectedly"))
                }
            }
        }
    }
}

/// Spawn `cmd`, `var`=`value` injected, `Stdio::inherit()` throughout
/// (never captured — aoide never holds the child's bytes, so there is
/// nothing here that could redact wrong), and return the CHILD's own exit
/// code — never aoide's own exit-code vocabulary, a wrapped command's exit
/// code is its own signal.
fn spawn_with_secret(cmd: &[String], var: &str, value: &str) -> Result<i32, String> {
    let status = std::process::Command::new(&cmd[0])
        .args(&cmd[1..])
        .env(var, value)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| format!("spawning `{}`: {e}", cmd[0]))?;
    Ok(status.code().unwrap_or(1))
}

/// The full `secrets exec` client flow — parse, resolve over `socket_path`,
/// spawn with the value injected. Returns the process exit code to hand
/// back from `main`: `2` (usage) for a bad invocation, `1` (error) for a
/// denied resolve or a spawn failure, else the CHILD's own exit code.
pub fn run_exec(inv: &Invocation, socket_path: &Path) -> i32 {
    let args = match parse_exec_args(inv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("aoide secrets exec: {e}");
            return 2;
        }
    };
    let value = match resolve(
        socket_path,
        &args.secret,
        &args.consumer,
        args.totp.as_deref(),
        args.cmd.first().map(String::as_str),
        args.reason.as_deref(),
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("aoide secrets exec: {e}");
            return 1;
        }
    };
    match spawn_with_secret(&args.cmd, &args.var, &value) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("aoide secrets exec: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aoide_protocol::Door;
    use std::collections::BTreeMap;

    fn inv(flags: &[(&str, &str)], args: &[&str]) -> Invocation {
        let mut flag_map = BTreeMap::new();
        for (k, v) in flags {
            flag_map.insert(k.to_string(), v.to_string());
        }
        Invocation {
            path: vec!["secrets".to_string(), "exec".to_string()],
            args: args.iter().map(|s| s.to_string()).collect(),
            flags: flag_map,
            door: Door::Cli,
        }
    }

    // ── derive_reason / parse_exec_args's --reason (P3) ──────────────────

    #[test]
    fn derive_reason_joins_a_short_command_verbatim() {
        let cmd = vec!["psql".to_string(), "-U".to_string(), "app".to_string()];
        assert_eq!(derive_reason(&cmd), Some("psql -U app".to_string()));
    }

    #[test]
    fn derive_reason_truncates_a_long_command_to_sixty_chars_with_an_ellipsis() {
        let cmd = vec!["sh".to_string(), "-c".to_string(), "a".repeat(100)];
        let reason = derive_reason(&cmd).unwrap();
        assert_eq!(reason.chars().count(), 60);
        assert!(reason.ends_with('\u{2026}'), "{reason:?}");
        assert!(reason.starts_with("sh -c "), "{reason:?}");
    }

    #[test]
    fn derive_reason_is_none_for_an_empty_command() {
        assert_eq!(derive_reason(&[]), None);
    }

    #[test]
    fn parse_exec_args_derives_reason_from_the_command_when_omitted() {
        let i = inv(&[("as", "m"), ("secret", "db-prod")], &["psql", "-U", "app"]);
        let args = parse_exec_args(&i).unwrap();
        assert_eq!(args.reason.as_deref(), Some("psql -U app"));
    }

    #[test]
    fn parse_exec_args_an_explicit_reason_wins_over_the_derived_one() {
        let i = inv(&[("as", "m"), ("secret", "db-prod"), ("reason", "nightly backup")], &["psql", "-U", "app"]);
        let args = parse_exec_args(&i).unwrap();
        assert_eq!(args.reason.as_deref(), Some("nightly backup"));
    }

    // ── bounded connect (rider task, alongside #75/#81/#82) ─────────────

    fn tmp_socket_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aoide-secrets-client-connect-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A path too long for `sun_path` is a clean, immediate `Err` — never a
    /// panic, and never reached via a raw slice-index that could.
    #[test]
    fn unix_sockaddr_rejects_a_path_too_long_for_sun_path() {
        let long = "/tmp/".to_string() + &"x".repeat(200);
        let err = unix_sockaddr(Path::new(&long)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    /// The ordinary case: a real listener at a real path connects well
    /// within the bound — proves the happy path never pays the poll/
    /// timeout machinery's cost (an immediate `connect()` success returns
    /// straight away, no `poll()` call at all).
    #[test]
    fn connect_bounded_succeeds_against_a_real_listener_fast() {
        let dir = tmp_socket_dir("ok");
        let sock = dir.join("s.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();

        let start = std::time::Instant::now();
        let stream = connect_bounded(&sock, Duration::from_secs(5)).unwrap();
        assert!(start.elapsed() < Duration::from_millis(500), "a live listener must connect near-instantly");
        drop(stream);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A nonexistent path fails FAST with a real `NotFound`-shaped error —
    /// proves `connect_bounded` doesn't secretly block on the negative path
    /// either (the immediate `connect()` syscall itself returns `ENOENT`,
    /// never reaching the `poll()` branch at all).
    #[test]
    fn connect_bounded_fails_fast_against_a_nonexistent_socket() {
        let dir = tmp_socket_dir("dead");
        let dead = dir.join("nothing-here.sock");
        let start = std::time::Instant::now();
        let err = connect_bounded(&dead, Duration::from_secs(5)).unwrap_err();
        assert!(start.elapsed() < Duration::from_millis(500), "a dead path must fail near-instantly, not wait out the bound");
        assert_ne!(err.kind(), io::ErrorKind::TimedOut, "ENOENT is not a timeout");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Hand-rolled listener + a single unaccepted connection, exactly the
    /// reviewer's own reproduction recipe (review-bounce fix, this
    /// commit): `std::os::unix::net::UnixListener::bind` hardcodes a
    /// backlog of 128, far too large to saturate cheaply in a test, so
    /// this builds the listener directly with `libc::listen(fd, 1)` —
    /// the same raw-socket construction `connect_bounded`/`unix_sockaddr`
    /// already use in production code, reused here for the test's own
    /// setup. Returns the listening fd and the one filler fd occupying
    /// the single backlog slot; asserts the backlog is GENUINELY
    /// saturated (a probe connect must observe a real `EAGAIN`) before
    /// handing control to the caller, so this is never a simulated
    /// condition.
    fn saturate_backlog_of_one(sock: &Path) -> (RawFd, Vec<RawFd>) {
        let (addr, addr_len) = unix_sockaddr(sock).unwrap();

        // SAFETY: a fresh listening socket this test exclusively owns.
        let listen_fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        assert!(listen_fd >= 0, "socket: {}", io::Error::last_os_error());
        // SAFETY: `addr`/`addr_len` describe a valid `sockaddr_un` for
        // this exact fd's own address family, matching `connect_bounded`'s
        // own construction of the same struct.
        let bind_rc =
            unsafe { libc::bind(listen_fd, &addr as *const libc::sockaddr_un as *const libc::sockaddr, addr_len) };
        assert_eq!(bind_rc, 0, "bind: {}", io::Error::last_os_error());
        // SAFETY: `listen_fd` is this test's own fd, backlog requested at
        // 1 — but Linux's actual accept-queue capacity for a given
        // `listen()` argument is a kernel implementation detail (commonly
        // rounded up by one, or more, for historical BSD-compat reasons),
        // so this is a REQUEST, not a hard guarantee of exactly one slot.
        let listen_rc = unsafe { libc::listen(listen_fd, 1) };
        assert_eq!(listen_rc, 0, "listen: {}", io::Error::last_os_error());

        // Fill the backlog with unaccepted connections until a connect
        // attempt genuinely observes `EAGAIN` — never assume the queue
        // holds exactly `listen()`'s own argument; PROVE saturation by
        // continuing to fill until the kernel itself refuses one, capped
        // so a kernel that (for whatever reason) never saturates fails
        // the test loudly instead of hanging.
        let mut fillers = Vec::new();
        loop {
            assert!(fillers.len() < 256, "backlog never saturated after 256 connects — test assumption invalid on this kernel");
            // SAFETY: a fresh client-side socket this test exclusively
            // owns, pushed into `fillers` (and closed by the caller) on
            // every path except the terminal EAGAIN below, where it is
            // the rejected attempt itself and closed immediately.
            let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
            assert!(fd >= 0, "socket: {}", io::Error::last_os_error());
            set_fd_nonblocking(fd, true);
            // SAFETY: same address-struct contract as the bind above.
            let rc = unsafe { libc::connect(fd, &addr as *const libc::sockaddr_un as *const libc::sockaddr, addr_len) };
            if rc == 0 {
                fillers.push(fd);
                continue;
            }
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EINPROGRESS) => {
                    fillers.push(fd);
                }
                Some(libc::EAGAIN) => {
                    // SAFETY: this attempt was rejected — never queued,
                    // never handed to anything else.
                    unsafe { libc::close(fd) };
                    break;
                }
                _ => panic!("unexpected connect error while saturating the backlog: {e}"),
            }
        }
        assert!(!fillers.is_empty(), "the backlog accepted zero connections before EAGAIN — test setup invalid");

        (listen_fd, fillers)
    }

    /// **The headline review-bounce proof:** `connect_bounded` must
    /// actually RETRY through a saturated backlog and succeed once a slot
    /// frees, not fail immediately on the first `EAGAIN` the way the
    /// bounced version of this function did. A background thread frees
    /// the one occupied slot (by accepting the filler connection) ~80ms
    /// in; `connect_bounded`'s own retry interval is 15ms, so it must
    /// notice well within its 3s budget — and the elapsed time must be
    /// LONG ENOUGH to prove it actually waited (not a lucky race past a
    /// backlog that was never really full).
    #[test]
    fn connect_bounded_retries_through_a_saturated_backlog_until_a_slot_frees() {
        let dir = tmp_socket_dir("saturated-frees");
        let sock = dir.join("s.sock");
        let (listen_fd, fillers) = saturate_backlog_of_one(&sock);

        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(80));
            // SAFETY: accepting exactly one of the queued connections
            // `saturate_backlog_of_one` created; frees exactly one slot —
            // enough for `connect_bounded`'s own retry to take. The
            // LISTENER itself stays open (closing it would refuse every
            // further connect outright, which is not the condition this
            // test is proving) — closed by the main thread once
            // `connect_bounded` has already succeeded, below.
            let accepted = unsafe { libc::accept(listen_fd, std::ptr::null_mut(), std::ptr::null_mut()) };
            assert!(accepted >= 0, "accept: {}", io::Error::last_os_error());
            // SAFETY: `accepted` was never handed to anything else.
            unsafe { libc::close(accepted) };
        });

        let start = std::time::Instant::now();
        let stream = connect_bounded(&sock, Duration::from_secs(3)).unwrap();
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(60), "should have genuinely waited for the slot to free: {elapsed:?}");
        assert!(elapsed < Duration::from_secs(1), "should succeed well within the 3s bound once the slot frees: {elapsed:?}");

        handle.join().unwrap();
        drop(stream);
        // SAFETY: none of these fds were ever handed to anything else.
        unsafe { libc::close(listen_fd) };
        for fd in fillers {
            unsafe { libc::close(fd) };
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The deadline half of the same proof: when the backlog stays
    /// saturated for good (nothing ever accepts), `connect_bounded`'s
    /// `EAGAIN` retry loop must still respect the overall bound rather
    /// than retrying forever.
    #[test]
    fn connect_bounded_times_out_when_the_backlog_stays_saturated() {
        let dir = tmp_socket_dir("saturated-stuck");
        let sock = dir.join("s.sock");
        let (listen_fd, fillers) = saturate_backlog_of_one(&sock);

        let start = std::time::Instant::now();
        let err = connect_bounded(&sock, Duration::from_millis(200)).unwrap_err();
        let elapsed = start.elapsed();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
        assert!(elapsed < Duration::from_millis(500), "must not overrun the bound by much: {elapsed:?}");

        // SAFETY: none of these fds were ever handed to anything else.
        unsafe { libc::close(listen_fd) };
        for fd in fillers {
            unsafe { libc::close(fd) };
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn default_var_name_uppercases_and_underscores_hyphens() {
        assert_eq!(default_var_name("db-prod"), "DB_PROD");
        assert_eq!(default_var_name("token"), "TOKEN");
        assert_eq!(default_var_name("a-b-c"), "A_B_C");
    }

    #[test]
    fn parses_a_full_invocation() {
        let i = inv(&[("as", "m"), ("secret", "db-prod")], &["psql", "-c", "select 1"]);
        let args = parse_exec_args(&i).unwrap();
        assert_eq!(args.consumer, "m");
        assert_eq!(args.secret, "db-prod");
        assert_eq!(args.var, "DB_PROD");
        assert_eq!(args.totp, None);
        assert_eq!(args.cmd, vec!["psql", "-c", "select 1"]);
    }

    #[test]
    fn explicit_var_name_wins_over_the_derived_default() {
        let i = inv(&[("as", "m"), ("secret", "db-prod:PGPASSWORD")], &["psql"]);
        let args = parse_exec_args(&i).unwrap();
        assert_eq!(args.secret, "db-prod");
        assert_eq!(args.var, "PGPASSWORD");
    }

    #[test]
    fn totp_flag_is_carried_through() {
        let i = inv(&[("as", "m"), ("secret", "t"), ("totp", "123456")], &["cmd"]);
        let args = parse_exec_args(&i).unwrap();
        assert_eq!(args.totp.as_deref(), Some("123456"));
    }

    #[test]
    fn missing_as_is_a_clear_error() {
        let i = inv(&[("secret", "t")], &["cmd"]);
        assert!(parse_exec_args(&i).unwrap_err().contains("--as"));
    }

    #[test]
    fn missing_secret_is_a_clear_error() {
        let i = inv(&[("as", "m")], &["cmd"]);
        assert!(parse_exec_args(&i).unwrap_err().contains("--secret"));
    }

    #[test]
    fn missing_command_is_a_clear_error() {
        let i = inv(&[("as", "m"), ("secret", "t")], &[]);
        assert!(parse_exec_args(&i).unwrap_err().contains("command after"));
    }

    #[test]
    fn invalid_secret_name_is_rejected() {
        let i = inv(&[("as", "m"), ("secret", "Bad Name")], &["cmd"]);
        assert!(parse_exec_args(&i).unwrap_err().contains("invalid secret name"));
    }

    // ── describe_connect_error (pure — injected io::Error, no real socket) ──

    #[test]
    fn permission_denied_teaches_both_the_sg_and_relogin_fixes() {
        let socket = Path::new("/run/aoide-secrets/secrets.sock");
        let err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let msg = describe_connect_error(socket, &err, "aoide secrets put db-prod");
        assert!(msg.contains(&socket.display().to_string()), "{msg}");
        assert!(msg.contains("aoide-secrets-access"), "{msg}");
        assert!(msg.contains("sg aoide-secrets-access -c 'aoide secrets put db-prod'"), "{msg}");
        assert!(msg.to_lowercase().contains("log out"), "{msg}");
    }

    #[test]
    fn not_found_teaches_checking_the_broker_service() {
        let socket = Path::new("/run/aoide-secrets/secrets.sock");
        let err = io::Error::new(io::ErrorKind::NotFound, "no such file or directory");
        let msg = describe_connect_error(socket, &err, "aoide secrets exec --as m --secret t -- true");
        assert!(msg.contains(&socket.display().to_string()), "{msg}");
        assert!(msg.contains("systemctl status aoide-secrets-serve"), "{msg}");
        assert!(msg.contains("AOIDE_SECRETS_SOCKET"), "{msg}");
    }

    #[test]
    fn connection_refused_gets_the_same_not_running_hint_as_not_found() {
        let socket = Path::new("/run/aoide-secrets/secrets.sock");
        let err = io::Error::new(io::ErrorKind::ConnectionRefused, "connection refused");
        let msg = describe_connect_error(socket, &err, "aoide secrets put t");
        assert!(msg.contains("systemctl status aoide-secrets-serve"), "{msg}");
    }

    #[test]
    fn an_unrelated_error_kind_rides_through_unenriched() {
        let socket = Path::new("/run/aoide-secrets/secrets.sock");
        let err = io::Error::new(io::ErrorKind::TimedOut, "timed out");
        let msg = describe_connect_error(socket, &err, "aoide secrets put t");
        assert!(msg.contains(&socket.display().to_string()), "{msg}");
        assert!(msg.contains("timed out"), "{msg}");
        assert!(!msg.contains("aoide-secrets-access"), "{msg}");
        assert!(!msg.contains("systemctl"), "{msg}");
    }

    #[test]
    fn resolve_against_a_dead_socket_is_a_connect_error() {
        let dead = Path::new("/tmp/aoide-secrets-nonexistent-test.sock");
        let err = resolve(dead, "t", "m", None, None, None).unwrap_err();
        assert!(err.contains("connecting"), "{err}");
    }

    #[test]
    fn put_against_a_dead_socket_is_a_connect_error() {
        let dead = Path::new("/tmp/aoide-secrets-nonexistent-put-test.sock");
        let err = put(dead, "t", "irrelevant", false).unwrap_err();
        assert!(matches!(err, PutError::Other(_)), "{err}");
        assert!(err.to_string().contains("connecting"), "{err}");
    }

    // ── P-V4e: `secrets put`'s tty prompt ───────────────────────────────
    //
    // `read_hidden_line`'s own tty path (`aoide_protocol::pick::
    // hidden_input`) is not exercised here — `cargo test`'s own stdin is
    // never a tty. `strip_one_trailing_newline`'s own pure-trim test moved
    // to `aoide_protocol::dialog`'s test module with the function itself
    // (P-P5, F5); what stays here is `stdin_is_tty` reading false (so
    // `run_put` takes the untouched pipe path) under this process's own
    // non-tty stdin, same as every existing `run_put`-adjacent test already
    // implicitly relies on.

    // ── P-67: warn-before-overwrite ─────────────────────────────────────

    #[test]
    fn non_tty_exists_message_teaches_the_force_spelling() {
        let msg = non_tty_exists_message("db-prod");
        assert!(msg.contains("already has a stored value"), "{msg}");
        assert!(msg.contains("--force"), "{msg}");
        assert!(
            msg.contains("printf %s <value> | aoide secrets put db-prod --force"),
            "must spell out the exact fix: {msg}"
        );
    }

    /// End-to-end proof that [`put`] surfaces the wire's `exists` flag as
    /// [`PutError::Exists`] (never inferred by matching `error` prose) and
    /// that `overwrite: true` reports `replaced: true` back — a REAL
    /// broker + socket round trip, same shape as `commands.rs`'s own
    /// `require_totp_on_add_births_a_gated_policy_denied_without_a_code`.
    #[test]
    fn put_reports_exists_then_replaced_true_through_a_real_broker() {
        let home = std::env::temp_dir().join(format!(
            "aoide-secrets-client-put-overwrite-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        crate::store::save_policies(&home, &[crate::policy::Policy::new("t", "file", "k")]).unwrap();

        // A short /tmp-direct socket path — sockaddr_un's ~108-byte
        // sun_path can overflow under a nested tempdir (same SUN_LEN
        // caution `tests/e2e.rs`/`commands.rs`'s own TOTP e2e test document).
        let socket_path = std::path::PathBuf::from(format!(
            "/tmp/aoide-secrets-client-put-overwrite-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));

        let home_for_thread = home.clone();
        let sock_for_thread = socket_path.clone();
        let broker_thread = std::thread::spawn(move || {
            let _ = crate::broker::serve(&home_for_thread, &sock_for_thread);
        });

        let mut connected = false;
        for _ in 0..50 {
            if UnixStream::connect(&socket_path).is_ok() {
                connected = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(connected, "broker did not bind {} in time", socket_path.display());

        // First put: no stored value yet -> `replaced: false`.
        assert_eq!(put(&socket_path, "t", "first-value", false), Ok(false));

        // Second put, no overwrite: the DISTINCT exists refusal.
        assert_eq!(put(&socket_path, "t", "attempted-overwrite", false), Err(PutError::Exists));

        // Third put, overwrite: true -> `replaced: true`.
        assert_eq!(put(&socket_path, "t", "second-value", true), Ok(true));

        drop(broker_thread);
        std::fs::remove_file(&socket_path).ok();
        std::fs::remove_dir_all(&home).ok();
    }

    // ── P-N2: pending/approve/dismiss ───────────────────────────────────

    #[test]
    fn pending_against_a_dead_socket_is_a_connect_error() {
        let dead = Path::new("/tmp/aoide-secrets-nonexistent-pending-test.sock");
        let err = pending(dead).unwrap_err();
        assert!(err.contains("connecting"), "{err}");
    }

    #[test]
    fn approve_against_a_dead_socket_is_a_connect_error() {
        let dead = Path::new("/tmp/aoide-secrets-nonexistent-approve-test.sock");
        let err = approve(dead, "1", "123456").unwrap_err();
        assert!(err.contains("connecting"), "{err}");
    }

    #[test]
    fn dismiss_against_a_dead_socket_is_a_connect_error() {
        let dead = Path::new("/tmp/aoide-secrets-nonexistent-dismiss-test.sock");
        let err = dismiss(dead, "1").unwrap_err();
        assert!(err.contains("connecting"), "{err}");
    }

    /// A real broker + socket round trip through the client wrappers
    /// themselves: `resolve` parks (no code given), `pending` sees the ask
    /// with no value anywhere in it, `approve` releases the value down the
    /// ORIGINAL `resolve` call — never into `approve`'s own `Ok(())` — and
    /// once approved the ask is gone from `pending` again. Same real-broker
    /// shape as `put_reports_exists_then_replaced_true_through_a_real_broker`
    /// (a single `serve` call for the whole test, dropped-not-joined, same
    /// pattern that test already establishes).
    #[test]
    fn pending_approve_round_trips_through_a_real_broker_and_releases_to_the_original_caller() {
        let home = std::env::temp_dir().join(format!(
            "aoide-secrets-client-park-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        let mut p = crate::policy::Policy::new("t", "file", "k");
        p.require_totp = true;
        crate::store::save_policies(&home, &[p]).unwrap();
        let totp_secret = b"a-twenty-byte-totp-s".to_vec();
        crate::store::save_totp_secret(&home, &totp_secret).unwrap();

        let socket_path = std::path::PathBuf::from(format!(
            "/tmp/aoide-secrets-client-park-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));

        let home_for_thread = home.clone();
        let sock_for_thread = socket_path.clone();
        let broker_thread = std::thread::spawn(move || {
            let _ = crate::broker::serve(&home_for_thread, &sock_for_thread);
        });
        let mut connected = false;
        for _ in 0..50 {
            if UnixStream::connect(&socket_path).is_ok() {
                connected = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(connected, "broker did not bind {} in time", socket_path.display());

        // `put` a value first (no TOTP gate on `put`, module doc), so the
        // parked `resolve` below has something real to release.
        assert_eq!(put(&socket_path, "t", "the-real-value", false), Ok(false));
        assert_eq!(pending(&socket_path).unwrap(), Vec::new());

        let sock_for_resolve = socket_path.clone();
        let resolve_thread = std::thread::spawn(move || resolve(&sock_for_resolve, "t", "m", None, None, None));

        let mut ask = None;
        for _ in 0..200 {
            let list = pending(&socket_path).unwrap();
            if let Some(a) = list.into_iter().next() {
                ask = Some(a);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let ask = ask.expect("the resolve did not park in time");
        assert_eq!(ask.secret, "t");
        assert_eq!(ask.consumer, "m");
        // #73: a REAL socket connection's SO_PEERCRED is this same test
        // process's own euid (the resolving thread and this thread are one
        // process) — proves the peer uid survives the full accept ->
        // park -> pending round trip, not just the in-process unit tests.
        assert_eq!(ask.peer_uid, Some(unsafe { libc::geteuid() }));

        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let step = crate::totp::timestep(now);
        let code = crate::totp::format6(crate::totp::hotp(&totp_secret, step, crate::totp::DIGITS));
        approve(&socket_path, &ask.id, &code).unwrap();

        assert_eq!(resolve_thread.join().unwrap(), Ok("the-real-value".to_string()));
        assert_eq!(pending(&socket_path).unwrap(), Vec::new());

        drop(broker_thread);
        std::fs::remove_file(&socket_path).ok();
        std::fs::remove_dir_all(&home).ok();
    }

    // ── P-N2c FIX 1: interim-line framing (`read_final_reply`) ──────────

    #[test]
    fn read_final_reply_skips_interim_lines_and_returns_the_first_real_one() {
        let wire = "{\"interim\":true,\"parked\":true,\"id\":\"ab12-1\",\"timeoutSecs\":300}\n\
                    {\"ok\":true,\"value\":\"the-value\"}\n";
        let mut reader = std::io::Cursor::new(wire.as_bytes());
        let reply = read_final_reply(&mut reader).unwrap();
        assert_eq!(reply["ok"], true);
        assert_eq!(reply["value"], "the-value");
    }

    #[test]
    fn read_final_reply_with_no_interim_line_behaves_exactly_as_before() {
        // Old-broker compat: a reply with zero interim lines (every op
        // besides a parking `resolve`) must round-trip byte-identically.
        let wire = "{\"ok\":false,\"error\":\"secret not found\"}\n";
        let mut reader = std::io::Cursor::new(wire.as_bytes());
        let reply = read_final_reply(&mut reader).unwrap();
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["error"], "secret not found");
    }

    #[test]
    fn read_final_reply_skips_multiple_interim_lines() {
        let wire = "{\"interim\":true,\"parked\":true,\"id\":\"1\",\"timeoutSecs\":1}\n\
                    {\"interim\":true,\"parked\":true,\"id\":\"1\",\"timeoutSecs\":1}\n\
                    {\"ok\":false,\"error\":\"timed out\"}\n";
        let mut reader = std::io::Cursor::new(wire.as_bytes());
        let reply = read_final_reply(&mut reader).unwrap();
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["error"], "timed out");
    }

    #[test]
    fn read_final_reply_on_a_connection_that_closes_after_only_interim_lines_is_a_clear_error() {
        let wire = "{\"interim\":true,\"parked\":true,\"id\":\"1\",\"timeoutSecs\":1}\n";
        let mut reader = std::io::Cursor::new(wire.as_bytes());
        let err = read_final_reply(&mut reader).unwrap_err();
        assert!(err.contains("closed the connection"), "{err}");
    }

    #[test]
    fn resolve_against_a_dead_socket_never_reaches_the_interim_loop_at_all() {
        // Sanity: a dead-socket connect error still short-circuits before
        // `read_final_reply` is ever called — same shape as the existing
        // `resolve_against_a_dead_socket_is_a_connect_error` test, kept
        // here as a reminder that FIX 1's new loop sits strictly AFTER the
        // connect step, never wrapping it.
        let dead = Path::new("/tmp/aoide-secrets-nonexistent-interim-test.sock");
        let err = resolve(dead, "t", "m", None, None, None).unwrap_err();
        assert!(err.contains("connecting"), "{err}");
    }

    #[test]
    fn stdin_is_tty_is_false_under_cargo_test() {
        // `cargo test` never runs with a tty on fd 0 — this is the same
        // guarantee `run_put`'s existing pipe-path callers already lean on
        // implicitly; asserted directly so a sandboxing change that somehow
        // attaches a tty would fail loudly here instead of silently
        // changing `run_put`'s behavior under every other test.
        assert!(!stdin_is_tty());
    }

    // ── resolve_bounded (task #84: bounded, wait:false, no cache) ───────────

    #[test]
    fn resolve_bounded_against_a_dead_socket_is_a_connect_error() {
        let dead = Path::new("/tmp/aoide-secrets-nonexistent-bounded-test.sock");
        let err = resolve_bounded(dead, "t", "a2a-door", Duration::from_secs(2)).unwrap_err();
        assert!(err.contains("connecting"), "{err}");
    }

    /// A real broker + socket round trip proving [`resolve_bounded`] returns
    /// the value on a granted, TOTP-free resolve — the deployed automation-
    /// open happy path task #84's PINNED CONSTRAINTS describe.
    #[test]
    fn resolve_bounded_returns_the_value_on_a_granted_resolve() {
        let home = std::env::temp_dir().join(format!(
            "aoide-secrets-client-bounded-ok-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        crate::store::save_policies(&home, &[crate::policy::Policy::new("t", "file", "k")]).unwrap();

        let socket_path = std::path::PathBuf::from(format!(
            "/tmp/aoide-secrets-client-bounded-ok-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let home_for_thread = home.clone();
        let sock_for_thread = socket_path.clone();
        let broker_thread = std::thread::spawn(move || {
            let _ = crate::broker::serve(&home_for_thread, &sock_for_thread);
        });
        let mut connected = false;
        for _ in 0..50 {
            if UnixStream::connect(&socket_path).is_ok() {
                connected = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(connected, "broker did not bind {} in time", socket_path.display());

        assert_eq!(put(&socket_path, "t", "bounded-value", false), Ok(false));
        assert_eq!(
            resolve_bounded(&socket_path, "t", "a2a-door", Duration::from_secs(2)),
            Ok("bounded-value".to_string())
        );

        drop(broker_thread);
        std::fs::remove_file(&socket_path).ok();
        std::fs::remove_dir_all(&home).ok();
    }

    /// **The PARKING HAZARD test (task #84).** A `requireTotp` secret with
    /// NO code and NO automation-open exemption would, under plain
    /// [`resolve`], PARK — holding the connection open for the full
    /// `AOIDE_SECRETS_PARK_TIMEOUT` (300s default). [`resolve_bounded`]
    /// must never do that: `wait:false` on the wire makes the broker deny
    /// immediately instead of parking at all, so this returns well inside
    /// the bound (asserted against a generous few-second wall-clock budget,
    /// never the full park timeout) with a denial, not a hang.
    #[test]
    fn resolve_bounded_never_parks_on_a_requiretotp_secret_with_no_code() {
        let home = std::env::temp_dir().join(format!(
            "aoide-secrets-client-bounded-parking-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        let mut p = crate::policy::Policy::new("t", "file", "k");
        p.require_totp = true;
        crate::store::save_policies(&home, &[p]).unwrap();
        let totp_secret = b"a-twenty-byte-totp-s".to_vec();
        crate::store::save_totp_secret(&home, &totp_secret).unwrap();

        let socket_path = std::path::PathBuf::from(format!(
            "/tmp/aoide-secrets-client-bounded-parking-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let home_for_thread = home.clone();
        let sock_for_thread = socket_path.clone();
        let broker_thread = std::thread::spawn(move || {
            let _ = crate::broker::serve(&home_for_thread, &sock_for_thread);
        });
        let mut connected = false;
        for _ in 0..50 {
            if UnixStream::connect(&socket_path).is_ok() {
                connected = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(connected, "broker did not bind {} in time", socket_path.display());

        assert_eq!(put(&socket_path, "t", "never-released", false), Ok(false));

        let started = std::time::Instant::now();
        let err = resolve_bounded(&socket_path, "t", "a2a-door", Duration::from_secs(2)).unwrap_err();
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(10),
            "resolve_bounded must never approach the 300s park timeout — took {elapsed:?}"
        );
        assert!(err.contains("totp") || err.contains("TOTP"), "{err}");

        drop(broker_thread);
        std::fs::remove_file(&socket_path).ok();
        std::fs::remove_dir_all(&home).ok();
    }
}
