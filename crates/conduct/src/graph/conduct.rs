//! `aoide conduct` — the PTY-backed, controllable sibling of `graph wrap`: its
//! own PTY + controlling tty, a per-session injection socket, and the raw
//! `poll()` multiplexer that shuttles stdin/stdout/injections. The unsafe libc
//! here is confined to `spawn_on_pty`, the raw-mode guard, the winsize
//! ioctls, and the multiplexer; each is documented where the ordering
//! matters.

use super::doc::restage_graph;
use super::model::{
    canonical_state, load_stage, sessions_path, write_stage, SessionsFile, STAGE_GRAPH_VERSION,
};
use super::session_store::{do_session_end, do_session_start, set_session_log_path};
use super::window::discover_window_address;
use aoide_protocol::Invocation;
use aoide_protocol::output::Outcome;
use aoide_storage::fs::{session_logs_dir, with_stage_lock};
use serde_json::json;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixListener;
#[cfg(test)]
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

/// The command's basename (the agent-name default), e.g. `/usr/bin/claude` →
/// `claude`.
fn command_basename(program: &str) -> String {
    std::path::Path::new(program)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| program.to_string())
}

pub(in crate::graph) fn unix_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The per-session conductor control socket:
/// `$XDG_RUNTIME_DIR/aoide/session-<id>.sock` — the same user-scoped runtime-dir
/// convention as shellbridge's socket (never networked). A missing
/// `XDG_RUNTIME_DIR` falls back to `/run/user/1000` like [`crate::shellbridge`].
/// `pub`, not `pub(crate)` (pre-Phase-3b visibility): this crosses the
/// aoide-conduct → aoide-server crate boundary too, since `aoide-server`'s
/// `a2a` (Phase 4c) resolves a just-spawned conducted session's control-socket
/// path via `aoide_conduct::graph::conduct_socket_path` directly — root no
/// longer re-exports this symbol at all (dropped in Phase 4c as dead once the
/// only caller moved into `aoide-server`).
pub fn conduct_socket_path(id: &str) -> PathBuf {
    let runtime = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/run/user/1000".into());
    PathBuf::from(runtime)
        .join("aoide")
        .join(format!("session-{id}.sock"))
}

// SIGWINCH latch: the handler only flips a flag (async-signal-safe); the poll
// loop services it (re-reading the real tty size and pushing it to the master).
static WINCH: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
extern "C" fn on_winch(_sig: libc::c_int) {
    WINCH.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Install the SIGWINCH handler WITHOUT `SA_RESTART`, so a resize interrupts
/// `poll()` (returns `EINTR`) and the loop can propagate the new size promptly.
fn install_winch_handler() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_winch as *const () as libc::sighandler_t;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGWINCH, &sa, std::ptr::null_mut());
    }
}

/// The current window size of a tty fd, or `None` when it is not a terminal
/// (a pipe / redirected stdin in a test) or reports a zero geometry.
fn tty_winsize(fd: RawFd) -> Option<libc::winsize> {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws as *mut libc::winsize) };
    if rc == 0 && (ws.ws_row != 0 || ws.ws_col != 0) {
        Some(ws)
    } else {
        None
    }
}

/// Push a window size onto the pty master (TIOCSWINSZ → the child sees SIGWINCH).
fn set_winsize(master: RawFd, ws: &libc::winsize) {
    unsafe {
        libc::ioctl(master, libc::TIOCSWINSZ, ws as *const libc::winsize);
    }
}

/// RAII raw-mode guard for the REAL controlling tty. `enter` saves the current
/// termios and switches to raw (so the wrapped TUI gets keystrokes unbuffered,
/// unechoed, and Ctrl-C flows to it as a byte instead of a signal). Drop —
/// which runs on normal return AND on unwind (panic=unwind) — restores it, so no
/// exit path can leave a wedged terminal. When the fd is not a tty (a test / a
/// pipe) the guard is inert: conduct still runs, it just touches no terminal.
struct TtyRaw {
    fd: RawFd,
    saved: libc::termios,
    active: bool,
}
impl TtyRaw {
    fn enter(fd: RawFd) -> Self {
        unsafe {
            let mut saved: libc::termios = std::mem::zeroed();
            if libc::isatty(fd) != 1 || libc::tcgetattr(fd, &mut saved) != 0 {
                return TtyRaw {
                    fd,
                    saved,
                    active: false,
                };
            }
            let mut raw = saved;
            libc::cfmakeraw(&mut raw);
            let _ = libc::tcsetattr(fd, libc::TCSANOW, &raw);
            TtyRaw {
                fd,
                saved,
                active: true,
            }
        }
    }
    fn restore(&mut self) {
        if self.active {
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved);
            }
            self.active = false;
        }
    }
}
impl Drop for TtyRaw {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Open a PTY and spawn `program args` on the SLAVE as a fresh session that owns
/// the slave as its controlling terminal. Returns the (reapable) child plus the
/// MASTER fd (owned, so it closes on every drop path).
///
/// The child's `pre_exec` ordering is load-bearing and each step is a raw libc
/// call (async-signal-safe): `setsid()` starts a new session with NO controlling
/// tty; `ioctl(slave, TIOCSCTTY)` then acquires the slave as this session's ctty
/// (only a session leader without a ctty may do this — hence setsid FIRST); the
/// slave is dup'd over fds 0/1/2 so the child's std streams ARE the pty; and the
/// master + spare slave fd are closed in the child. All of this precedes exec.
fn spawn_on_pty(
    program: &str,
    args: &[String],
    session_id: &str,
    ws: Option<libc::winsize>,
) -> std::io::Result<(std::process::Child, OwnedFd)> {
    use std::os::unix::process::CommandExt;

    let mut master: RawFd = -1;
    let mut slave: RawFd = -1;
    let wsp = ws
        .as_ref()
        .map(|w| w as *const libc::winsize)
        .unwrap_or(std::ptr::null());
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            wsp,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Own the master at once: it is now closed on any early return / on drop.
    let master_owned = unsafe { OwnedFd::from_raw_fd(master) };

    let slave_fd = slave;
    let master_fd = master;
    let mut cmd = std::process::Command::new(program);
    cmd.args(args).env("AOIDE_SESSION_ID", session_id);
    unsafe {
        cmd.pre_exec(move || {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(slave_fd, libc::TIOCSCTTY, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            for target in 0..3 {
                if libc::dup2(slave_fd, target) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            libc::close(master_fd);
            if slave_fd > 2 {
                libc::close(slave_fd);
            }
            Ok(())
        });
    }
    let spawned = cmd.spawn();
    // The parent never speaks on the slave — close it whatever spawn returned.
    unsafe {
        libc::close(slave);
    }
    let child = spawned?;
    Ok((child, master_owned))
}

fn pollfd(fd: RawFd, events: libc::c_short) -> libc::pollfd {
    libc::pollfd {
        fd,
        events,
        revents: 0,
    }
}

/// Write every byte of `data` to `fd`, retrying on `EINTR`. A best-effort mirror
/// helper for the multiplexer (a torn write on abrupt child exit is tolerated).
fn write_all_fd(fd: RawFd, mut data: &[u8]) {
    while !data.is_empty() {
        let n = unsafe { libc::write(fd, data.as_ptr() as *const libc::c_void, data.len()) };
        if n <= 0 {
            let err = std::io::Error::last_os_error();
            if n < 0 && err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        data = &data[n as usize..];
    }
}

/// Where the pty-master's output goes: the real stdout (interactive conduct,
/// unchanged) or an append-only session-log file (headless conduct — no
/// controlling tty to write to). `Stdout` is the ENTIRE interactive path
/// today, byte-identical; `Log` is new for headless mode.
enum OutputSink {
    Stdout,
    Log(std::fs::File),
}
impl OutputSink {
    /// Mirror `bytes` to the sink. The `Stdout` arm is exactly today's
    /// `write_all_fd(stdout_fd, …)` call. The `Log` arm appends (retrying a
    /// short write, same as `write_all_fd`'s own retry loop) and, on a write
    /// error, DEGRADES rather than killing the session — mirroring
    /// `write_all_fd` itself, which just stops mirroring on an unrecoverable
    /// write error instead of tearing down the conducted child.
    fn write(&mut self, bytes: &[u8]) {
        match self {
            OutputSink::Stdout => write_all_fd(libc::STDOUT_FILENO, bytes),
            OutputSink::Log(f) => {
                use std::io::Write as _;
                let mut data = bytes;
                while !data.is_empty() {
                    match f.write(data) {
                        Ok(0) => break,
                        Ok(n) => data = &data[n..],
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
            }
        }
    }
}

/// Read `/proc/<pid>/cwd` — the live working directory (follows the shell's `cd`).
pub(in crate::graph) fn proc_cwd(pid: i32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/cwd"))
        .ok()
        .and_then(|p| p.to_str().map(str::to_string))
}

/// Known interactive text-editor binaries whose activity display should read
/// as "<editor> <file>" (or bare "<editor>" with no file), not the raw
/// invocation. Dotfiles routinely wrap these with startup flags (an alias
/// injecting `--cmd 'lua …'`, a resolved absolute binary path) that make the
/// full cmdline read as noise rather than "what's being edited".
const EDITOR_BASENAMES: &[&str] = &["nvim", "vim", "vi", "nano", "emacs", "hx", "micro"];

/// If `argv[0]`'s basename is a known editor, return a friendly `"<editor>
/// <file>"` (or bare `"<editor>"` with no file argument) — pure and
/// unit-tested. The file is the LAST argument that doesn't look like a flag
/// AND doesn't contain a space: flags precede the file operand in normal
/// usage, so scanning from the end finds the real file even past a `--cmd
/// '…'`-style startup injection (whose value sits earlier in argv, before the
/// file) — and the no-space guard additionally rejects a bare, file-less
/// invocation whose flag VALUE doesn't start with `-` either (e.g. `nvim --cmd
/// 'lua x=1'` with no file): a real single-file operand essentially never
/// contains a space, while an option's value routinely does. `None` for a
/// non-editor binary, so the caller falls back to the generic full-cmdline
/// display.
fn friendly_editor_command(argv: &[String]) -> Option<String> {
    let base = std::path::Path::new(argv.first()?).file_name()?.to_str()?;
    if !EDITOR_BASENAMES.contains(&base) {
        return None;
    }
    let file = argv[1..]
        .iter()
        .rev()
        .find(|a| !a.starts_with('-') && !a.contains(' '));
    Some(match file {
        Some(f) => {
            let name = std::path::Path::new(f)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(f);
            format!("{base} {name}")
        }
        None => base.to_string(),
    })
}

/// The generic (non-editor) command label: `argv` joined into a one-liner, but
/// with `argv[0]` collapsed to its BASENAME first (the rest of argv is left
/// untouched). On NixOS many wrapped packages re-exec with `argv[0]` set to the
/// full resolved `/nix/store/<hash>-<name>/bin/<name>` path (confirmed live:
/// `yazi`) rather than the bare command the user typed, so a raw join would show
/// an ugly store path; collapsing `argv[0]` yields a clean `yazi` while leaving
/// arguments (which may legitimately be paths) intact. `None` for empty argv.
fn generic_command_label(argv: &[String]) -> Option<String> {
    let first = argv.first()?;
    let base = std::path::Path::new(first)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(first.as_str());
    let mut parts: Vec<&str> = Vec::with_capacity(argv.len());
    parts.push(base);
    parts.extend(argv[1..].iter().map(String::as_str));
    let joined = parts.join(" ");
    let joined = joined.trim();
    if joined.is_empty() {
        None
    } else {
        Some(joined.to_string())
    }
}

/// A short one-line label for a process's command: a known editor shows as
/// `"<editor> <file>"` ([`friendly_editor_command`]); anything else shows
/// `/proc/<pid>/cmdline` argv joined with `argv[0]` collapsed to its basename
/// ([`generic_command_label`], e.g. `cargo test`), falling back to `comm`.
/// Clipped to a roster-friendly width. Used as a conducted shell's live
/// `activity`.
fn proc_command(pid: i32) -> Option<String> {
    let clip = |s: &str| -> String {
        let one = s.split_whitespace().collect::<Vec<_>>().join(" ");
        if one.chars().count() <= 48 {
            one
        } else {
            let head: String = one.chars().take(47).collect();
            format!("{head}…")
        }
    };
    if let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) {
        let argv: Vec<String> = raw
            .split(|b| *b == 0)
            .filter(|p| !p.is_empty())
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect();
        if let Some(friendly) = friendly_editor_command(&argv) {
            return Some(clip(&friendly));
        }
        if let Some(label) = generic_command_label(&argv) {
            return Some(clip(&label));
        }
    }
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|c| clip(c.trim()))
        .filter(|c| !c.is_empty())
}

/// Just the process's `comm` (e.g. `bash`) — the label for an idle shell sitting
/// at its bare prompt (no foreground command), so the roster still reads as the
/// shell PROCESS rather than going blank.
fn proc_comm(pid: i32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
}

/// Whether `/proc/<pid>/task/<pid>/children` lists any child pid.
/// `Some(true)` = has children, `Some(false)` = none, `None` = unreadable.
/// A conducting `sudo` at its password prompt has NO children yet (it forks
/// the command/monitor only after auth); once it has forked, auth is done.
fn proc_has_children(pid: i32) -> Option<bool> {
    std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
        .ok()
        .map(|s| !s.trim().is_empty())
}

/// Is a conducted SHELL currently blocked on a `sudo` password prompt? A
/// conducted shell is sudo-blocked iff the `[sudo] password for` prompt was
/// just seen (booster), OR the foreground process IS `sudo` AND it has not yet
/// forked its command child (`Some(false)` children == still in the PAM
/// conversation, i.e. at the prompt). `Some(true)` (command already running,
/// e.g. cached-cred `sudo nixos-rebuild`) and `None` (children unreadable →
/// don't trust the primary, rely on the booster) both DON'T fire the primary.
/// Pure and unit-tested; the real caller passes `proc_comm(fg) == Some("sudo")`,
/// `proc_has_children(fg)`, and the booster's recency check.
///
/// WHY the children gate: `sudo` stays the process-group leader for the WHOLE
/// runtime of `sudo <cmd>` on a PAM system (it forks the command/monitor
/// child; it never execs in place), so `comm(fg) == "sudo"` alone would also
/// be true for a multi-minute `sudo nixos-rebuild switch` running on CACHED
/// credentials — no prompt at all. Gating on "sudo has not yet forked a
/// child" narrows the primary signal to the actual PAM conversation window.
fn sudo_awaiting(fg_is_sudo: bool, fg_has_children: Option<bool>, booster_recent: bool) -> bool {
    booster_recent || (fg_is_sudo && fg_has_children == Some(false))
}

/// Update a conducted session's live shell fields — `cwd`, `activity` (the
/// current foreground command, or cleared), `state` (idle at the prompt,
/// working while a command runs, or forced `awaiting` while blocked on
/// `sudo`), and `needsSudo` — CHANGE-ONLY, under the stage lock, and re-stage
/// graph.json only when it actually wrote. Called ~1 Hz from conduct's PTY
/// tick for SHELL sessions (an agent's state/activity come from hooks, so
/// conduct never drives those). No-op for an unregistered id.
fn do_session_refresh(
    id: &str,
    cwd: Option<&str>,
    activity: Option<&str>,
    state: &str,
    needs_sudo: bool,
) {
    with_stage_lock(|| {
        let mut file: SessionsFile = match load_stage(&sessions_path()) {
            Ok(f) => f,
            Err(_) => return,
        };
        let mut changed = false;
        for s in file.sessions.iter_mut() {
            if s.session_id != id {
                continue;
            }
            if let Some(c) = cwd {
                if s.cwd != c {
                    s.cwd = c.to_string();
                    changed = true;
                }
            }
            let act = activity.filter(|a| !a.is_empty()).map(str::to_string);
            if s.activity != act {
                s.activity = act;
                changed = true;
            }
            let canon = canonical_state(state);
            if s.state != canon {
                s.state = canon.to_string();
                changed = true;
            }
            // Change-only, and cleared to `None` (never written as
            // `Some(false)`) so the key disappears the moment the prompt clears.
            let want = if needs_sudo { Some(true) } else { None };
            if s.needs_sudo != want {
                s.needs_sudo = want;
                changed = true;
            }
        }
        if changed {
            if file.schema_version.is_empty() {
                file.schema_version = STAGE_GRAPH_VERSION.to_string();
            }
            if write_stage(&sessions_path(), &file).is_ok() {
                let _ = restage_graph();
            }
        }
    });
}

/// Which process's cwd a conducted shell should report, given the pty's
/// foreground pgid `fg` and the `shell_pid`, using an injectable `cwd_of`
/// lookup (pure and unit-tested; the real caller passes [`proc_cwd`]). At the
/// bare prompt (`fg <= 0` or `fg == shell_pid`) it's the shell's own cwd. While
/// a foreground command runs it's the FOREGROUND process's OWN cwd — which may
/// navigate independently of the shell (e.g. yazi/ranger's live directory
/// browsing calls `chdir()` on themselves, not the parent shell), so the shell's
/// cwd alone would freeze at launch time and never reflect what the foreground
/// process is actually showing — falling back to the shell's cwd when the
/// foreground process's is unreadable (a permissions edge case, or it just
/// exited in a race).
fn cwd_for(fg: i32, shell_pid: i32, cwd_of: impl Fn(i32) -> Option<String>) -> Option<String> {
    if fg <= 0 || fg == shell_pid {
        cwd_of(shell_pid)
    } else {
        cwd_of(fg).or_else(|| cwd_of(shell_pid))
    }
}

/// Pure resolution of a conducted shell's (state, activity, needs_sudo) from
/// the pty foreground pgid. Injected lookups make it unit-testable. Real caller
/// passes (proc_comm, proc_command, proc_has_children). The shell (spawned
/// under `setsid`) is its own process group leader, so a foreground pgid equal
/// to the shell pid means "at the bare prompt" (idle); anything else is a
/// command running in the foreground (working, its command captured as
/// `activity`). `booster_recent` is the text-scan signal from
/// `conduct_multiplex` (a `[sudo] password for` prompt seen crossing
/// master→stdout within the last ~2s); when [`sudo_awaiting`] is true off
/// either signal, `state` is FORCED to `awaiting` regardless of the
/// idle/working computation above — a sudo prompt needs the user NOW.
fn shell_snapshot(
    fg: i32,
    shell_pid: i32,
    booster_recent: bool,
    comm_of: impl Fn(i32) -> Option<String>,
    command_of: impl Fn(i32) -> Option<String>,
    children_of: impl Fn(i32) -> Option<bool>,
) -> (&'static str, Option<String>, bool) {
    let (mut state, activity) = if fg <= 0 || fg == shell_pid {
        // At the bare prompt: idle, but label the row with the shell PROCESS
        // itself (e.g. `bash`) so the terminal roster is never blank.
        ("idle", comm_of(shell_pid))
    } else {
        // A foreground command is running: its cmdline (e.g. `nvim notes.md`,
        // `cargo test`) — the file being edited / the process at work.
        ("working", command_of(fg))
    };
    let fg_is_sudo = fg > 0 && comm_of(fg).as_deref() == Some("sudo");
    let children = if fg_is_sudo { children_of(fg) } else { None };
    let needs_sudo = sudo_awaiting(fg_is_sudo, children, booster_recent);
    if needs_sudo {
        state = "awaiting";
    }
    (state, activity, needs_sudo)
}

/// One conduct-tick refresh for a SHELL session: read the pty's foreground
/// process group and the live cwd, and push cwd + the current command + the
/// idle/working state via [`shell_snapshot`].
fn conduct_refresh_shell(id: &str, master: RawFd, shell_pid: i32, booster_recent: bool) {
    let fg = unsafe { libc::tcgetpgrp(master) };
    let cwd = cwd_for(fg, shell_pid, proc_cwd);
    let (state, activity, needs_sudo) = shell_snapshot(
        fg,
        shell_pid,
        booster_recent,
        proc_comm,
        proc_command,
        proc_has_children,
    );
    do_session_refresh(id, cwd.as_deref(), activity.as_deref(), state, needs_sudo);
}

/// True iff the `[sudo] password for` prompt appears at the start of a line in
/// `chunk` (buffer start, or right after `\n`/`\r`). The line-start guard keeps
/// `grep '[sudo] password'` / `cat auth.log`-style output from false-triggering,
/// while real sudo prints its prompt at line start. A needle split across two
/// reads is tolerated (missed here, caught next tick by the primary).
fn scan_for_sudo_prompt(chunk: &[u8]) -> bool {
    const NEEDLE: &[u8] = b"[sudo] password for";
    chunk
        .windows(NEEDLE.len())
        .enumerate()
        .any(|(i, w)| w == NEEDLE && (i == 0 || chunk[i - 1] == b'\n' || chunk[i - 1] == b'\r'))
}

/// The single-thread `poll()` multiplexer. Shuttles: real stdin → master (you
/// type normally), master → real stdout (you read normally), and each accepted
/// injection connection → master (INJECTION). A pending SIGWINCH re-sizes the
/// master. Returns the child's real exit code once the master hangs up (the
/// child's slave closed) and the child is reaped.
fn conduct_multiplex(
    master: RawFd,
    listener: Option<&UnixListener>,
    child: &mut std::process::Child,
    id: &str,
    is_shell: bool,
    read_stdin: bool,
    sink: &mut OutputSink,
) -> i32 {
    use std::sync::atomic::Ordering;
    let stdin_fd = libc::STDIN_FILENO;
    let listener_fd = listener.map(|l| l.as_raw_fd());
    let mut conns: Vec<RawFd> = Vec::new();
    // Headless: no controlling tty to read from — never push the stdin
    // pollfd, and start already-EOF so the loop never touches it.
    let mut stdin_eof = !read_stdin;
    let mut buf = [0u8; 8192];

    // Live cwd/command tick for a conducted SHELL. A `tail -f` (or any quiet TUI)
    // never produces I/O, so we can't hang the refresh off output — instead the
    // poll gets a ~1s timeout and the tick fires on the elapsed clock. Agents
    // don't tick (state/activity come from hooks), so they keep the blocking poll.
    let shell_pid = child.id() as i32;
    let poll_timeout: libc::c_int = if is_shell { 1000 } else { -1 };
    let tick_period = std::time::Duration::from_millis(950);
    let mut last_tick = std::time::Instant::now();
    // The sudo-prompt TEXT-SCAN booster: the instant a `[sudo] password for`
    // prompt is seen crossing master→stdout, latch a timestamp so the next
    // tick(s) within `SUDO_BOOSTER_WINDOW` treat the shell as sudo-blocked
    // even if `tcgetpgrp` hasn't caught `sudo` as the foreground pgid yet.
    let mut sudo_prompt_seen_at: Option<std::time::Instant> = None;
    const SUDO_BOOSTER_WINDOW: std::time::Duration = std::time::Duration::from_secs(2);
    if is_shell {
        conduct_refresh_shell(id, master, shell_pid, false); // stamp initial cwd/state now.
    }

    loop {
        // Service a pending resize before blocking again.
        if WINCH.swap(false, Ordering::SeqCst) {
            if let Some(ws) = tty_winsize(stdin_fd) {
                set_winsize(master, &ws);
            }
        }

        let mut fds: Vec<libc::pollfd> = Vec::new();
        if !stdin_eof {
            fds.push(pollfd(stdin_fd, libc::POLLIN));
        }
        fds.push(pollfd(master, libc::POLLIN));
        if let Some(lfd) = listener_fd {
            fds.push(pollfd(lfd, libc::POLLIN));
        }
        for &c in &conns {
            fds.push(pollfd(c, libc::POLLIN));
        }

        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, poll_timeout) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue; // a signal (SIGWINCH) — reloop to service the latch.
            }
            break;
        }
        // Refresh the conducted shell's live cwd/command/state on the ~1s clock
        // (rc==0 is a plain timeout; a busy shell also ticks at most this often).
        if is_shell && last_tick.elapsed() >= tick_period {
            let booster_recent = sudo_prompt_seen_at
                .map(|t| t.elapsed() < SUDO_BOOSTER_WINDOW)
                .unwrap_or(false);
            conduct_refresh_shell(id, master, shell_pid, booster_recent);
            last_tick = std::time::Instant::now();
        }

        let revents = |want: RawFd| -> libc::c_short {
            fds.iter()
                .find(|p| p.fd == want)
                .map(|p| p.revents)
                .unwrap_or(0)
        };

        // master → stdout, and hangup detection (the child's slave closed).
        let mrev = revents(master);
        if mrev & libc::POLLIN != 0 {
            let n =
                unsafe { libc::read(master, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n > 0 {
                let n = n as usize;
                // Booster text-scan: shells only, a cheap byte-substring search
                // (never a String allocation of the whole buffer) over exactly
                // what was just read, gated to a line-start match.
                if is_shell && scan_for_sudo_prompt(&buf[..n]) {
                    sudo_prompt_seen_at = Some(std::time::Instant::now());
                }
                sink.write(&buf[..n]);
            } else {
                break;
            }
        }
        if mrev & (libc::POLLHUP | libc::POLLERR) != 0 {
            let n =
                unsafe { libc::read(master, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n > 0 {
                sink.write(&buf[..n as usize]);
            }
            break;
        }

        // real stdin → master.
        if !stdin_eof {
            let srev = revents(stdin_fd);
            if srev & libc::POLLIN != 0 {
                let n = unsafe {
                    libc::read(stdin_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                };
                if n > 0 {
                    write_all_fd(master, &buf[..n as usize]);
                } else {
                    stdin_eof = true; // our own stdin closed; keep bridging the rest.
                }
            } else if srev & (libc::POLLHUP | libc::POLLERR) != 0 {
                stdin_eof = true;
            }
        }

        // listener → accept new injection connections.
        if let (Some(lfd), Some(l)) = (listener_fd, listener) {
            if revents(lfd) & libc::POLLIN != 0 {
                loop {
                    match l.accept() {
                        Ok((stream, _)) => {
                            let _ = stream.set_nonblocking(true);
                            let fd = stream.as_raw_fd();
                            std::mem::forget(stream); // fd owned raw; closed on drain-EOF below.
                            conns.push(fd);
                        }
                        Err(_) => break, // EAGAIN — no more pending.
                    }
                }
            }
        }

        // injection connections → master.
        let mut still: Vec<RawFd> = Vec::new();
        for &c in &conns {
            let cr = revents(c);
            if cr & libc::POLLIN != 0 {
                let n =
                    unsafe { libc::read(c, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if n > 0 {
                    write_all_fd(master, &buf[..n as usize]);
                    still.push(c);
                } else {
                    unsafe {
                        libc::close(c);
                    } // EOF — this injection is done.
                }
            } else if cr & (libc::POLLHUP | libc::POLLERR) != 0 {
                loop {
                    let n =
                        unsafe { libc::read(c, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                    if n > 0 {
                        write_all_fd(master, &buf[..n as usize]);
                    } else {
                        break;
                    }
                }
                unsafe {
                    libc::close(c);
                }
            } else {
                still.push(c);
            }
        }
        conns = still;
    }

    for c in conns {
        unsafe {
            libc::close(c);
        }
    }
    match child.wait() {
        Ok(st) => st.code().unwrap_or(-1),
        Err(_) => -1,
    }
}

/// `aoide conduct [--agent A] [--parent P] [--id I] -- <command …>` — the
/// PTY-backed, controllable sibling of `graph wrap`. Same registration semantics
/// (spawn FIRST so a failed exec registers no ghost; running → done; exit
/// mirrored, real code in `data.exitCode`; `AOIDE_SESSION_ID` exported) PLUS: its
/// own PTY + controlling tty, a per-session injection socket, the
/// `conductable`/`socket` fields on the record so `graph send` can steer it, and
/// a best-effort `windowAddress` (phase ② discovery) so `graph focus` can jump.
pub fn session_conduct(inv: &Invocation) -> Outcome {
    let cmd = "conduct";
    if inv.args.is_empty() {
        return Outcome::usage(
            cmd,
            "usage: aoide conduct [--agent <name>] [--parent <sessionId>] [--id <id>] -- <command …>",
        );
    }
    let program = inv.args[0].clone();
    let agent = inv
        .flags
        .get("agent")
        .cloned()
        .unwrap_or_else(|| command_basename(&program));
    let id = inv
        .flags
        .get("id")
        .cloned()
        .unwrap_or_else(|| format!("conduct-{}-{}", std::process::id(), unix_ts()));
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    let socket_path = conduct_socket_path(&id);

    // Seed the pty with the real tty's geometry so a TUI opens correctly
    // sized. A headless conduct usually has NO controlling tty (spawned by
    // another process), which would hand openpty a NULL winsize and leave the
    // pty at 0 rows x 0 cols — a geometry full-screen TUIs misrender against
    // or refuse outright. Fall back to a conventional 80x24 there; the
    // interactive no-tty case keeps its historical None so nothing changes.
    let headless = inv.flag_present("headless");
    let ws = tty_winsize(libc::STDIN_FILENO).or(if headless {
        Some(libc::winsize { ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0 })
    } else {
        None
    });

    // Spawn FIRST: a failed exec must register no session (parity with `wrap`).
    let (mut child, master) = match spawn_on_pty(&program, &inv.args[1..], &id, ws) {
        Ok(v) => v,
        Err(e) => return Outcome::error(cmd, format!("failed to conduct `{program}`: {e}")),
    };
    let master_fd = master.as_raw_fd();

    // Bind the per-session injection socket (best-effort: a bind failure leaves
    // the session running but un-injectable — recorded as conductable=false).
    if let Some(parent) = socket_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(&socket_path); // clear a stale socket from a prior crash.
    let listener = UnixListener::bind(&socket_path).ok();
    if let Some(l) = &listener {
        let _ = l.set_nonblocking(true);
    }
    let conductable = listener.is_some();
    let socket_str = socket_path.to_string_lossy().into_owned();

    // Phase ②: best-effort window-address discovery (never fails/slows conduct).
    let window = discover_window_address();

    // Register running + conductable with its socket, so `graph send` resolves it.
    let _ = do_session_start(
        &id,
        Some(&agent),
        cwd.as_deref(),
        window.as_deref(),
        inv.flags.get("parent").map(String::as_str),
        Some(conductable),
        if conductable {
            Some(socket_str.as_str())
        } else {
            None
        },
        None,
        // Record THIS conduct process's pid (not the PTY child's): conduct owns
        // the session lifecycle — the `do_session_end` at the bottom of this fn
        // always resolves the record on any NORMAL exit. Only conduct's own
        // uncatchable death (SUPER+Q SIGKILLs the whole kitty→shell→conduct tree)
        // leaves the record stranded `running`, and then `/proc/<this-pid>`
        // vanishes: the reaper's pid signal. (It is also the pid already embedded
        // in the default `conduct-<pid>-<ts>` id.)
        Some(std::process::id()),
    );

    // `--headless`: no controlling tty at all — the pty's output goes to a
    // per-session log file instead of stdout, and the multiplexer never reads
    // stdin (there is nothing to read it from). Everything else about conduct
    // (registration, injection socket, exit mirroring) is identical. (The
    // flag itself is read above, where the pty winsize fallback needs it.)
    let mut sink = OutputSink::Stdout;
    if headless {
        let _ = std::fs::create_dir_all(session_logs_dir());
        let log_path = session_logs_dir().join(format!("{id}.log"));
        match std::fs::OpenOptions::new().create(true).append(true).open(&log_path) {
            Ok(f) => {
                set_session_log_path(&id, &log_path.to_string_lossy());
                sink = OutputSink::Log(f);
            }
            // A log file that can't be opened (e.g. an unwritable state dir) must
            // not kill the session — degrade to stdout, same posture as the
            // socket-bind best-effort above.
            Err(_) => {}
        }
    }

    // Raw-mode the real tty + arm resize passthrough (interactive only — a
    // headless session has no controlling tty to raw-mode or resize). The
    // TtyRaw guard restores the terminal on EVERY path below — normal return
    // and unwind alike.
    let mut tty = if headless {
        None
    } else {
        install_winch_handler();
        let t = TtyRaw::enter(libc::STDIN_FILENO);
        if let Some(ws) = ws {
            set_winsize(master_fd, &ws);
        }
        Some(t)
    };

    let exit_code = conduct_multiplex(
        master_fd,
        listener.as_ref(),
        &mut child,
        &id,
        agent == "shell",
        !headless,
        &mut sink,
    );

    // Restore tty, unlink socket, resolve the session — whatever happened.
    if let Some(t) = tty.as_mut() {
        t.restore();
    }
    let _ = std::fs::remove_file(&socket_path);
    let _ = do_session_end(&id);

    let changed = vec![format!("session {id}: running → done")];
    let data = json!({
        "sessionId": id,
        "agent": agent,
        "exitCode": exit_code,
        "conductable": conductable,
        "socket": socket_str,
    });
    if exit_code == 0 {
        Outcome::ok(cmd, format!("`{agent}` finished (conducted session `{id}`)"))
            .changed(changed)
            .with_data(data)
    } else {
        Outcome::error(
            cmd,
            format!("`{agent}` exited {exit_code} (conducted session `{id}`)"),
        )
        .changed(changed)
        .with_data(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::session_store::upsert_session;
    use crate::graph::testutil::*;

    #[test]
    fn output_sink_log_appends_bytes_and_they_read_back() {
        let dir = unique_stage("output-sink-log");
        let path = dir.join("s.log");
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        let mut sink = OutputSink::Log(f);
        sink.write(b"hello ");
        sink.write(b"world\n");
        let got = std::fs::read_to_string(&path).unwrap();
        assert_eq!(got, "hello world\n");
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn friendly_editor_command_shows_editor_and_file_by_basename() {
        // A plain file argument, editor resolved to a full store path.
        assert_eq!(
            friendly_editor_command(&argv(&[
                "/etc/profiles/per-user/khoa/bin/nvim",
                "modules/facets/quickshell/qml/TerminalsGadget.qml",
            ])),
            Some("nvim TerminalsGadget.qml".to_string())
        );
        // Bare invocation, no file → just the editor name.
        assert_eq!(
            friendly_editor_command(&argv(&["/run/current-system/sw/bin/nvim"])),
            Some("nvim".to_string())
        );
        // A dotfiles-style startup flag with a value ahead of the real file: the
        // LAST non-flag argument (scanning from the end) is the file, not the
        // flag's value.
        assert_eq!(
            friendly_editor_command(&argv(&[
                "nvim",
                "--cmd",
                "lua vim.g.x=1",
                "notes.md",
            ])),
            Some("nvim notes.md".to_string())
        );
        // A value-taking flag with NO file: the flag's value ("lua vim.g.x=1")
        // contains a space, so it's rejected as a candidate file too — falls
        // through to bare "nvim", not the flag's value misread as a filename.
        assert_eq!(
            friendly_editor_command(&argv(&["nvim", "--cmd", "lua vim.g.x=1"])),
            Some("nvim".to_string())
        );
        // A non-editor binary → None, so the caller falls back to the generic
        // full-cmdline display.
        assert_eq!(
            friendly_editor_command(&argv(&["cargo", "test"])),
            None
        );
        assert_eq!(friendly_editor_command(&argv(&[])), None);
    }
    #[test]
    fn generic_command_label_collapses_argv0_basename_only() {
        // A full nix-store path single-arg command (confirmed live: a wrapped
        // `yazi` re-execs with argv[0] set to its store path) collapses to the
        // bare basename, not the ugly store path.
        assert_eq!(
            generic_command_label(&argv(&[
                "/nix/store/0qviwy1qgq5i5yy947wv4d7656mb56vs-yazi-0.4.2/bin/yazi",
            ])),
            Some("yazi".to_string())
        );
        // A full store path WITH args: argv[0] collapses to its basename, the
        // arguments (which may legitimately be paths) stay intact.
        assert_eq!(
            generic_command_label(&argv(&[
                "/nix/store/hash-ripgrep-14.1.0/bin/rg",
                "pattern",
                "file.rs",
            ])),
            Some("rg pattern file.rs".to_string())
        );
        // A plain bare command (no path) is unaffected.
        assert_eq!(
            generic_command_label(&argv(&["yazi"])),
            Some("yazi".to_string())
        );
        // Args after a bare command are left untouched.
        assert_eq!(
            generic_command_label(&argv(&["cargo", "test"])),
            Some("cargo test".to_string())
        );
        // Empty argv → None (caller falls back to `comm`).
        assert_eq!(generic_command_label(&argv(&[])), None);
    }
    #[test]
    fn sudo_awaiting_gates_the_primary_signal_on_children() {
        // The booster fires regardless of the primary signal's inputs.
        assert!(sudo_awaiting(false, None, true));
        assert!(sudo_awaiting(true, Some(true), true));
        assert!(sudo_awaiting(true, Some(false), true));
        assert!(sudo_awaiting(true, None, true));
        // fg IS sudo, and it has forked NO children yet: still at the PAM
        // prompt — the primary signal fires.
        assert!(sudo_awaiting(true, Some(false), false));
        // fg IS sudo, but it HAS forked a child: auth already succeeded and the
        // command is running (e.g. cached-cred `sudo nixos-rebuild switch` — a
        // multi-minute build with no prompt at all). The primary must NOT fire.
        assert!(!sudo_awaiting(true, Some(true), false));
        // fg IS sudo but children are unreadable: don't trust the primary,
        // fall back to the booster alone (which is false here).
        assert!(!sudo_awaiting(true, None, false));
        // fg is not sudo at all: primary never fires, no booster.
        assert!(!sudo_awaiting(false, None, false));
        assert!(!sudo_awaiting(false, Some(false), false));
        assert!(!sudo_awaiting(false, Some(true), false));
    }
    #[test]
    fn shell_snapshot_idle_at_bare_prompt() {
        // fg == shell_pid: idle, activity from comm_of(shell_pid), no sudo.
        let (state, activity, needs_sudo) = shell_snapshot(
            100,
            100,
            false,
            |_| Some("bash".to_string()),
            |_| panic!("command_of should not be consulted at the bare prompt"),
            |_| panic!("children_of should not be consulted when fg isn't sudo"),
        );
        assert_eq!(state, "idle");
        assert_eq!(activity.as_deref(), Some("bash"));
        assert!(!needs_sudo);
    }
    #[test]
    fn shell_snapshot_working_reads_foreground_command() {
        // fg != shell_pid, and it's not sudo: working, activity from command_of(fg).
        let (state, activity, needs_sudo) = shell_snapshot(
            200,
            100,
            false,
            |_| Some("cargo".to_string()),
            |pid| {
                assert_eq!(pid, 200);
                Some("cargo test".to_string())
            },
            |_| panic!("children_of should not be consulted when fg isn't sudo"),
        );
        assert_eq!(state, "working");
        assert_eq!(activity.as_deref(), Some("cargo test"));
        assert!(!needs_sudo);
    }
    #[test]
    fn shell_snapshot_forces_awaiting_while_sudo_has_no_children() {
        // fg IS sudo, with no children yet (still at the password prompt):
        // state is FORCED to awaiting and needs_sudo is true, regardless of
        // what command_of would have said.
        let (state, activity, needs_sudo) = shell_snapshot(
            300,
            100,
            false,
            |_| Some("sudo".to_string()),
            |_| Some("sudo nixos-rebuild switch".to_string()),
            |pid| {
                assert_eq!(pid, 300);
                Some(false)
            },
        );
        assert_eq!(state, "awaiting");
        assert_eq!(activity.as_deref(), Some("sudo nixos-rebuild switch"));
        assert!(needs_sudo);
    }
    #[test]
    fn shell_snapshot_cached_cred_sudo_does_not_force_awaiting() {
        // fg IS sudo, but it has already forked its command child (cached
        // creds, no prompt): state stays "working" off the normal computation,
        // needs_sudo is false — the F1 fix's whole point.
        let (state, activity, needs_sudo) = shell_snapshot(
            300,
            100,
            false,
            |_| Some("sudo".to_string()),
            |_| Some("sudo nixos-rebuild switch".to_string()),
            |pid| {
                assert_eq!(pid, 300);
                Some(true)
            },
        );
        assert_eq!(state, "working");
        assert_eq!(activity.as_deref(), Some("sudo nixos-rebuild switch"));
        assert!(!needs_sudo);
    }
    #[test]
    fn scan_for_sudo_prompt_requires_line_start() {
        const NEEDLE: &str = "[sudo] password for";
        // At the very start of the buffer: true.
        assert!(scan_for_sudo_prompt(NEEDLE.as_bytes()));
        // Right after a newline: true.
        let after_nl = format!("hello\n{NEEDLE}");
        assert!(scan_for_sudo_prompt(after_nl.as_bytes()));
        // Right after a carriage return (a pty commonly emits \r\n): true.
        let after_cr = format!("hello\r{NEEDLE}");
        assert!(scan_for_sudo_prompt(after_cr.as_bytes()));
        // Mid-line — e.g. a compiler error message or `grep` output quoting the
        // needle — must NOT false-trigger.
        let mid_line = format!("foo.rs:9:{NEEDLE} x");
        assert!(!scan_for_sudo_prompt(mid_line.as_bytes()));
        // No needle at all.
        assert!(!scan_for_sudo_prompt(b"just some ordinary shell output"));
        // Empty / too-short buffers must not panic.
        assert!(!scan_for_sudo_prompt(b""));
        assert!(!scan_for_sudo_prompt(b"[sudo]"));
    }
    #[test]
    fn cwd_for_prefers_foreground_process_then_falls_back_to_shell() {
        const SHELL_PID: i32 = 100;
        const FG_PID: i32 = 200;
        // A foreground command runs and its cwd is readable and DIFFERS from the
        // shell's (yazi navigated elsewhere): the foreground process's own cwd
        // wins, so the widget follows it rather than freezing at launch.
        let lookup = |pid: i32| match pid {
            SHELL_PID => Some("/home/khoa".to_string()),
            FG_PID => Some("/home/khoa/dxflake".to_string()),
            _ => None,
        };
        assert_eq!(
            cwd_for(FG_PID, SHELL_PID, lookup),
            Some("/home/khoa/dxflake".to_string())
        );
        // A foreground command runs but its cwd is unreadable (None — a perms
        // edge case, or it exited in a race): fall back to the shell's cwd.
        let unreadable_fg = |pid: i32| match pid {
            SHELL_PID => Some("/home/khoa".to_string()),
            _ => None,
        };
        assert_eq!(
            cwd_for(FG_PID, SHELL_PID, unreadable_fg),
            Some("/home/khoa".to_string())
        );
        // At the bare prompt (fg == shell_pid, and the fg <= 0 "no fg" case):
        // always the shell's own cwd, never consulting any other pid.
        assert_eq!(
            cwd_for(SHELL_PID, SHELL_PID, lookup),
            Some("/home/khoa".to_string())
        );
        assert_eq!(cwd_for(0, SHELL_PID, lookup), Some("/home/khoa".to_string()));
    }
    #[test]
    fn conduct_injects_socket_bytes_into_the_child() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "XDG_RUNTIME_DIR"]);

        let root = unique_stage("conduct-inject");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root); // socket → <root>/aoide/session-*.sock

        let id = "conduct-test";
        let socket = conduct_socket_path(id);
        let proof = root.join("proof.txt");

        // The child reads ONE line from its (pty) stdin and writes it to a file,
        // then exits — proof the injected bytes reached the child's stdin.
        let script = format!("IFS= read -r line; printf '%s' \"$line\" > {}", proof.display());

        // Inject from a helper thread once the socket appears; `conduct` blocks
        // in THIS thread until the child exits.
        let socket_c = socket.clone();
        let injector = std::thread::spawn(move || {
            for _ in 0..300 {
                if socket_c.exists() {
                    if let Ok(mut s) = UnixStream::connect(&socket_c) {
                        use std::io::Write as _;
                        let _ = s.write_all(b"MARKER-42\n");
                        let _ = s.flush();
                        return;
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        });

        let out = session_conduct(&conduct_invocation(&["sh", "-c", &script], &[("id", id)]));
        injector.join().unwrap();

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["exitCode"], 0);
        assert_eq!(out.data.as_ref().unwrap()["conductable"], true);

        // The child received the injected line on its stdin.
        let got = std::fs::read_to_string(&proof).unwrap_or_default();
        assert_eq!(got, "MARKER-42", "child received the injected bytes");

        // Registered conductable with its socket, then resolved done.
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        let rec = s.sessions.iter().find(|r| r.session_id == id).unwrap();
        assert_eq!(rec.state, "done");
        assert_eq!(rec.conductable, Some(true));
        assert!(rec
            .socket
            .as_deref()
            .unwrap()
            .ends_with("session-conduct-test.sock"));
        // Socket unlinked on exit.
        assert!(!socket.exists(), "the control socket is unlinked on exit");

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn conduct_mirrors_a_nonzero_child_exit() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "XDG_RUNTIME_DIR"]);

        let root = unique_stage("conduct-fail");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);

        let out = session_conduct(&conduct_invocation(
            &["sh", "-c", "exit 7"],
            &[("id", "conduct-fail"), ("agent", "sevens")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert_eq!(out.data.as_ref().unwrap()["exitCode"], 7);

        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        let rec = s.sessions.iter().find(|r| r.session_id == "conduct-fail").unwrap();
        assert_eq!(rec.state, "done");
        assert_eq!(rec.agent, "sevens");

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn conduct_headless_mirrors_pty_output_to_the_log_and_stamps_log_path() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR"]);

        let root = unique_stage("conduct-headless");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("XDG_RUNTIME_DIR", &root);

        let out = session_conduct(&conduct_invocation(
            &["sh", "-c", "echo mark-headless"],
            &[("id", "conduct-headless"), ("headless", "true")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["exitCode"], 0);

        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        let rec = s.sessions.iter().find(|r| r.session_id == "conduct-headless").unwrap();
        assert_eq!(rec.state, "done");
        let log_path = rec.log_path.clone().expect("headless conduct stamps logPath");
        assert!(log_path.ends_with("conduct-headless.log"));
        let logged = std::fs::read_to_string(&log_path).unwrap();
        assert!(logged.contains("mark-headless"), "log contents: {logged:?}");

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn session_refresh_drives_shell_cwd_command_and_state() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("refresh");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let now = "2026-01-01T00:00:00Z";
        let mut sessions = Vec::new();
        upsert_session(
            &mut sessions, "sh", Some("shell"), Some("/w"), None, None, None, None, None,
            Some(std::process::id()), now,
        );
        write_stage(
            &sessions_path(),
            &SessionsFile { schema_version: "0".into(), sessions },
        )
        .unwrap();

        // At the prompt: idle, no activity, cwd tracked.
        do_session_refresh("sh", Some("/proj"), None, "idle", false);
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s.sessions[0].state, "idle");
        assert_eq!(s.sessions[0].cwd, "/proj");
        assert_eq!(s.sessions[0].activity, None);
        assert_eq!(s.sessions[0].needs_sudo, None);

        // A foreground command: working + the command as activity.
        do_session_refresh("sh", Some("/proj"), Some("cargo test"), "working", false);
        let s2: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s2.sessions[0].state, "working");
        assert_eq!(s2.sessions[0].activity.as_deref(), Some("cargo test"));
        assert_eq!(s2.sessions[0].needs_sudo, None);

        // Blocked on sudo: state=awaiting and needsSudo=true, regardless of the
        // `state` string passed in (the caller already resolves the force in
        // `conduct_refresh_shell`, but do_session_refresh itself just persists
        // both fields change-only).
        do_session_refresh("sh", Some("/proj"), Some("sudo"), "awaiting", true);
        let s3: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s3.sessions[0].state, "awaiting");
        assert_eq!(s3.sessions[0].needs_sudo, Some(true));

        // The prompt clears: needs_sudo=false CLEARS the field back to None
        // (never left as Some(false)) — change-only, so the key disappears.
        do_session_refresh("sh", Some("/proj"), None, "idle", false);
        let s4: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s4.sessions[0].needs_sudo, None);
        let raw = std::fs::read_to_string(sessions_path()).unwrap();
        assert!(!raw.contains("needsSudo"), "cleared key must be absent: {raw}");

        // An unknown id is a safe no-op (never panics, never inserts).
        do_session_refresh("nope", Some("/x"), Some("x"), "working", false);
        let s5: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s5.sessions.len(), 1);

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
}
