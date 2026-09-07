//! `aoide conduct` — the PTY-backed, controllable conducted session: its
//! own PTY + controlling tty, a per-session injection socket, and the raw
//! `poll()` multiplexer that shuttles stdin/stdout/injections. The unsafe libc
//! here is confined to `spawn_on_pty`, the raw-mode guard, the winsize
//! ioctls, and the multiplexer; each is documented where the ordering
//! matters.

use super::doc::restage_graph;
use super::model::{
    canonical_state, load_stage, sessions_path, write_stage, RestoreSnapshot, SessionsFile,
    STAGE_GRAPH_VERSION,
};
use super::identity::peer_cred;
use super::session_store::{
    do_session_end, do_session_start, set_session_log_path, stamp_headless, stamp_origin,
    stamp_spawned,
};
use super::window::{discover_window_address, resolve_registration_parent};
use aoide_protocol::Invocation;
use aoide_protocol::output::Outcome;
use aoide_storage::attest::is_node_origin;
use aoide_storage::fs::{session_logs_dir, with_stage_lock};
use serde_json::json;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

/// The command's basename (the agent-name default), e.g. `/usr/bin/claude` →
/// `claude`.
fn command_basename(program: &str) -> String {
    std::path::Path::new(program)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| program.to_string())
}

/// The interactive-shell basenames the P-C5 refresh/capture path (cwd
/// tracking, working/idle state, foreground argv, the restore snapshot, and
/// `typed_capture_active`'s buffer) treats as "this is a shell to watch".
const SHELL_BASENAMES: &[&str] = &["bash", "zsh", "fish", "sh"];

/// Shell-likeness derived from the WRAPPED COMMAND, never the roster display
/// name (P-C5 follow-up, task #100 — the P-C7 soak's live finding: `spawn
/// --agent soak-a -- bash` ran a real interactive shell whose roster record
/// never ticked, because the old gate compared `agent == "shell"` and a
/// caller is free to label a shell anything it likes). `agent` is a label a
/// caller chooses (`--agent <name>`, or the command's own basename by
/// default) — it names WHO is being conducted, not WHAT kind of process it
/// wraps, and the two can disagree on purpose (a soak harness, an
/// experiment, a differently-named shell wrapper). `program` is what
/// actually execs on the pty; only ITS basename can answer "does this have
/// a readline prompt to tick/reconstruct". This covers kitty.nix's own
/// terminal wrapper for free: it always execs the resolved login shell
/// explicitly (`$SHELL`/passwd/`/bin/sh`, `<login_shell> -l`) as the
/// conducted command, so its basename lands in [`SHELL_BASENAMES`] the same
/// way any other bash/zsh/fish/sh invocation does — no separate "bare
/// spawn" case to special-case here.
pub(in crate::graph) fn captures_like_a_shell(program: &str) -> bool {
    SHELL_BASENAMES.contains(&command_basename(program).as_str())
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

/// Where the pty-master's output goes. `Stdout` alone never happens
/// anymore in practice (every conduct opens its log — see
/// [`open_session_log`]) but stays as the pre-open-failure default and the
/// shape a headless-only reader still exercises directly in tests. `Log`
/// is headless conduct: no controlling tty, so the log IS the only sink.
/// `StdoutAndLog` is interactive conduct (task #15, "everything tees"):
/// the real stdout, unchanged, PLUS the same master-read bytes mirrored
/// into the per-session log.
enum OutputSink {
    Stdout,
    Log(std::fs::File),
    StdoutAndLog(std::fs::File),
}
impl OutputSink {
    /// Mirror `bytes` to the sink. The `Stdout` arm is exactly today's
    /// `write_all_fd(stdout_fd, …)` call. The `Log`/`StdoutAndLog` log
    /// write appends (retrying a short write, same as `write_all_fd`'s own
    /// retry loop) and, on a write error, DEGRADES rather than killing the
    /// session — mirroring `write_all_fd` itself, which just stops
    /// mirroring on an unrecoverable write error instead of tearing down
    /// the conducted child. This matters most for `StdoutAndLog`: the
    /// interactive pump is raw-mode and latency-sensitive, so a full disk
    /// or a yanked log file must never stall or kill a live terminal —
    /// only the log side of the tee drops.
    fn write(&mut self, bytes: &[u8]) {
        match self {
            OutputSink::Stdout => write_all_fd(libc::STDOUT_FILENO, bytes),
            OutputSink::Log(f) => Self::write_log(f, bytes),
            OutputSink::StdoutAndLog(f) => {
                write_all_fd(libc::STDOUT_FILENO, bytes);
                Self::write_log(f, bytes);
            }
        }
    }
    fn write_log(f: &mut std::fs::File, bytes: &[u8]) {
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

/// Open (creating if needed) this session's per-session pty log at
/// `state/sessions/<id>.log`, the ONE open+stamp path both the headless and
/// interactive arms of [`session_conduct`] call — never duplicated per
/// path. Private end to end and structurally so, not by umask luck: the
/// directory is force-set to `0700` and the file opened with an explicit
/// `0600` mode via `OpenOptionsExt`, so a permissive umask (e.g. `0000`)
/// can never widen either past what the ruling requires (task #15: local,
/// private, no opt-out flag). Returns `None` on any failure (an unwritable
/// state dir, a permissions call that errors, …) — the caller degrades to
/// `OutputSink::Stdout` on `None`, same best-effort posture as every other
/// side-channel write in this file.
fn open_session_log(id: &str) -> Option<(std::fs::File, PathBuf)> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let dir = session_logs_dir();
    std::fs::create_dir_all(&dir).ok()?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok()?;
    let log_path = dir.join(format!("{id}.log"));
    let f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&log_path)
        .ok()?;
    Some((f, log_path))
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
        let argv = parse_cmdline(&raw);
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

/// Pure NUL-split of a raw `/proc/<pid>/cmdline` buffer into argv — split out
/// of [`proc_command`]/[`proc_argv`] so the split itself is unit-testable
/// against a synthesized buffer without a real `/proc` read. Empty segments
/// (a trailing NUL, or two in a row) are dropped.
fn parse_cmdline(raw: &[u8]) -> Vec<String> {
    raw.split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .collect()
}

/// RAW `argv` off `/proc/<pid>/cmdline` — the actual invocation, uncollapsed
/// and UNCLIPPED, unlike [`proc_command`]'s DISPLAY label (basename-collapsed
/// `argv[0]`, 48-char-truncated). A restore snapshot's `argv` must be an
/// exact re-exec candidate, not a shortened label — reusing `proc_command`
/// here would re-exec the wrong binary or a truncated one. `None` when
/// `/proc/<pid>/cmdline` is unreadable (the process already gone, a
/// permissions edge case) or empty.
pub(in crate::graph) fn proc_argv(pid: i32) -> Option<Vec<String>> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let argv = parse_cmdline(&raw);
    if argv.is_empty() {
        None
    } else {
        Some(argv)
    }
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
/// `sudo`), `needsSudo`, and `restore` (the P-C5 continuous capture snapshot,
/// see [`RestoreSnapshot`]) — CHANGE-ONLY, under the stage lock, and re-stage
/// graph.json only when it actually wrote. Called ~1 Hz from conduct's PTY
/// tick for SHELL sessions (an agent's state/activity come from hooks, so
/// conduct never drives those). No-op for an unregistered id.
fn do_session_refresh(
    id: &str,
    cwd: Option<&str>,
    activity: Option<&str>,
    state: &str,
    needs_sudo: bool,
    restore: RestoreSnapshot,
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
            if s.restore.as_ref() != Some(&restore) {
                s.restore = Some(restore.clone());
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

/// Pure resolution of a conducted shell's P-C5 restore snapshot from the pty
/// foreground pgid — mirrors [`shell_snapshot`]'s shape exactly (injected
/// `argv_of` lookup, pure, unit-tested). `idle` reuses the SAME `fg <= 0 ||
/// fg == shell_pid` predicate `shell_snapshot` computes for `state` — kept as
/// its own field here rather than read back off `state` later, since the
/// reap sweep overwrites `state` to `"done"` before its ledger write.
/// `argv` is `None` while idle (no foreground process to capture) and RAW
/// (uncollapsed, unclipped) `/proc/<fg>/cmdline` otherwise — never
/// `proc_command`'s DISPLAY label, which would re-exec the wrong or a
/// truncated binary. `typed` is gated to `idle` HERE, structurally, rather
/// than trusted to the caller: a shell mid-command has no prompt line to
/// reconstruct, so any `typed` the caller passes while working is dropped.
fn restore_snapshot(
    fg: i32,
    shell_pid: i32,
    cwd: Option<String>,
    typed: Option<String>,
    argv_of: impl Fn(i32) -> Option<Vec<String>>,
) -> RestoreSnapshot {
    let idle = fg <= 0 || fg == shell_pid;
    RestoreSnapshot {
        cwd,
        idle,
        argv: if idle { None } else { argv_of(fg) },
        typed: if idle { typed } else { None },
    }
}

/// One conduct-tick refresh for a SHELL session: read the pty's foreground
/// process group and the live cwd, and push cwd + the current command + the
/// idle/working state via [`shell_snapshot`], plus the P-C5 restore snapshot
/// via [`restore_snapshot`]. `typed` comes from `conduct_multiplex`'s own
/// typed-line buffer (`None` for a headless session, which never reads
/// stdin) — this function has no access to the keystroke stream itself.
fn conduct_refresh_shell(
    id: &str,
    master: RawFd,
    shell_pid: i32,
    booster_recent: bool,
    typed: Option<String>,
) {
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
    let restore = restore_snapshot(fg, shell_pid, cwd.clone(), typed, proc_argv);
    do_session_refresh(id, cwd.as_deref(), activity.as_deref(), state, needs_sudo, restore);
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

/// Cap on the P-C5 typed-line buffer, bytes.
const TYPED_LINE_CAP: usize = 4096;

/// The P-C5 typed-but-unsubmitted prompt-line buffer, reconstructed from the
/// raw keystroke stream written into the pty master — from BOTH real stdin
/// and injection connections (`conduct_multiplex`'s two write sites both
/// `feed` it the same way, since both land in the SAME shell readline
/// buffer). REFUSAL-based, not reconstruction-based: readline editing (arrow
/// keys, `^R` history search, Tab completion, `^U`/`^W` kills) means the
/// keystroke stream is no longer the prompt buffer, so replaying it verbatim
/// would be WRONG, not merely lossy — a silently wrong `typed` puts text the
/// operator never composed one keystroke from running. Any control byte
/// below `0x20` other than the two that SUBMIT the line (`\r`/`\n`), or
/// `0x7f` (DEL), POISONS the buffer for the current line; `\r`/`\n`
/// themselves CLEAR it (submitted) and lift any earlier poison, since the
/// NEXT line starts clean. `typed()` additionally refuses non-UTF-8 and an
/// empty line. Scoped to one CONDUCT process's lifetime — never persisted,
/// never read back after the fact (see the module's own P-C5 note on why a
/// `/proc` snapshot can't recover this).
struct TypedLineBuffer {
    buf: Vec<u8>,
    poisoned: bool,
}
impl TypedLineBuffer {
    fn new() -> Self {
        TypedLineBuffer { buf: Vec::new(), poisoned: false }
    }
    /// Feed bytes written to the master. A line that runs past
    /// `TYPED_LINE_CAP` POISONS rather than truncating: a clipped line is
    /// wrong text, not merely short, and this buffer's whole contract is to
    /// refuse the cases it cannot reconstruct exactly. The buffer stops
    /// growing at the cap either way, so it never grows unbounded, and a
    /// later `\r`/`\n` still clears normally.
    fn feed(&mut self, bytes: &[u8]) {
        for &b in bytes {
            match b {
                b'\r' | b'\n' => {
                    self.buf.clear();
                    self.poisoned = false;
                }
                0x7f => self.poisoned = true,
                b if b < 0x20 => self.poisoned = true,
                _ => {
                    if self.buf.len() < TYPED_LINE_CAP {
                        self.buf.push(b);
                    } else {
                        self.poisoned = true;
                    }
                }
            }
        }
    }
    /// Feed bytes that arrived over an INJECTION connection rather than the
    /// operator's own stdin. They reach the same readline buffer, so the
    /// line stops being reconstructable — but they are not what anyone
    /// TYPED, and `graph send` prefixes a delivered payload with its
    /// provenance (`from <petname> (…tail): `), so replaying them would
    /// preload a line no human composed and that would not even run. The
    /// line is poisoned instead. A `\r`/`\n` still ends it, so an injection
    /// that submits leaves the NEXT line clean rather than poisoning
    /// everything after it.
    fn feed_injected(&mut self, bytes: &[u8]) {
        for &b in bytes {
            match b {
                b'\r' | b'\n' => {
                    self.buf.clear();
                    self.poisoned = false;
                }
                _ => self.poisoned = true,
            }
        }
    }
    /// The current line, or `None` when poisoned, empty (nothing typed since
    /// the last submit), or not valid UTF-8.
    fn typed(&self) -> Option<String> {
        if self.poisoned || self.buf.is_empty() {
            return None;
        }
        std::str::from_utf8(&self.buf).ok().map(str::to_string)
    }
}

/// Whether a P-C5 typed-line buffer should even be instantiated: only an
/// INTERACTIVE shell (`is_shell && read_stdin`) has a real readline prompt to
/// reconstruct. A headless conduct never reads stdin at all
/// (`read_stdin == false`, unconditionally — there is no controlling tty to
/// read from), so it has no typed line, ever; a non-shell (an agent harness)
/// has no shell prompt to begin with. Pure so the gating itself is
/// unit-testable without spawning anything.
fn typed_capture_active(is_shell: bool, read_stdin: bool) -> bool {
    is_shell && read_stdin
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
    // P-C5: the typed-line buffer only exists for an interactive shell — a
    // headless conduct never reads stdin (no prompt line to reconstruct) and
    // an agent harness has no shell prompt at all.
    let mut typed_buf = if typed_capture_active(is_shell, read_stdin) {
        Some(TypedLineBuffer::new())
    } else {
        None
    };
    if is_shell {
        let typed = typed_buf.as_ref().and_then(|b| b.typed());
        conduct_refresh_shell(id, master, shell_pid, false, typed); // stamp initial cwd/state now.
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
            let typed = typed_buf.as_ref().and_then(|b| b.typed());
            conduct_refresh_shell(id, master, shell_pid, booster_recent, typed);
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
                    let n = n as usize;
                    if let Some(tb) = typed_buf.as_mut() {
                        tb.feed(&buf[..n]);
                    }
                    write_all_fd(master, &buf[..n]);
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
                            // LANE IDENTITY P-ID2 (`CONTRACTS.md`'s identity
                            // section; review round 1 MUST-FIX — the FIRST
                            // shape of this check refused any connection
                            // whose ancestry merely CONTAINED this
                            // session's own pid anywhere upstream, which
                            // silently broke the single most common flow:
                            // `session_conduct` registers WITHOUT
                            // detaching, so a legitimate CHILD session's
                            // pid is a genuine OS descendant of its
                            // parent's registered pid, and a child sending
                            // to its own live parent via `aoide send --id
                            // <parent> --yes` was dropped downstream of the
                            // gate with a bare broken pipe `--yes` cannot
                            // route around). Read `SO_PEERCRED` on the
                            // CONNECTING stream and refuse it outright —
                            // never forwarded to `conns`, never touches the
                            // pty — ONLY when the CONNECTOR's OWN nearest
                            // live registered session (`identity::
                            // is_self_originated`'s own doc: the same
                            // nearest-first walk `attested_sender` uses,
                            // without seal verification — a narrow
                            // UX/loop defense, not the security boundary
                            // the raw same-uid socket door already is,
                            // OQ1-A/P-ID3) resolves to THIS session's own
                            // id — true self-injection, never a nested
                            // child whose OWN nearest session is itself.
                            // Both a `peer_cred` failure and an
                            // unresolvable connector fail OPEN (allowed) —
                            // this guard only ever refuses the one narrow,
                            // known shape it exists to catch.
                            let self_injection = peer_cred(&stream)
                                .map(|cred| {
                                    let sessions = load_stage::<SessionsFile>(&sessions_path())
                                        .map(|f| f.sessions)
                                        .unwrap_or_default();
                                    super::identity::is_self_originated(cred.pid, &sessions, id)
                                })
                                .unwrap_or(false);
                            if self_injection {
                                continue; // dropped outright — never accepted into `conns`.
                            }
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
                    let n = n as usize;
                    // Injected bytes reach the same readline buffer, but
                    // they are not what anyone TYPED — and a delivered
                    // payload carries its provenance prefix, so replaying
                    // them would preload a line no human composed.
                    if let Some(tb) = typed_buf.as_mut() {
                        tb.feed_injected(&buf[..n]);
                    }
                    write_all_fd(master, &buf[..n]);
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
                        let n = n as usize;
                        if let Some(tb) = typed_buf.as_mut() {
                            tb.feed_injected(&buf[..n]);
                        }
                        write_all_fd(master, &buf[..n]);
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
/// PTY-backed, controllable conducted session. Registration semantics
/// (spawn FIRST so a failed exec registers no ghost; running → done; exit
/// mirrored, real code in `data.exitCode`; `AOIDE_SESSION_ID` exported) PLUS: its
/// own PTY + controlling tty, a per-session injection socket, the
/// `conductable`/`socket` fields on the record so `graph send` can steer it, and
/// a best-effort `windowAddress` (phase ② discovery) so the focus jump
/// (`focus_session`) can reach it.
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

    // Phase ②: best-effort window-address discovery (never fails/slows
    // conduct) — INTERACTIVE only. `headless` has no controlling tty at all,
    // but its `/proc` ancestry still passes straight through whatever
    // launched it (a shell, an agent, a terminal) — `setsid()` (below)
    // detaches its TTY session, never its OS parent — so an unconditional
    // discovery here found and stamped the ENCLOSING terminal's window onto
    // a headless wrap's own record (task #89, review round 2): a `graph
    // spawn` run from inside an agent's shell tool re-acquired its
    // grandparent terminal's window every time, defeating the windowless-
    // lineage fix below (its whole premise is that a headless wrap's own
    // record NEVER holds a window).
    let window = if headless { None } else { discover_window_address() };

    // Automatic parenting (task #89): explicit `--parent` > this registering
    // process's own `/proc` ancestry matched against a live agent's
    // `hookAncestry` > the ambient `AOIDE_SESSION_ID` env — see
    // `window::resolve_registration_parent`'s own doc for the full
    // reasoning (a nested headless `conduct --headless` launched from
    // inside an agent's shell tool — `graph spawn`'s own re-exec — otherwise
    // registers parentless/sibling instead of as that agent's child).
    let sessions_snapshot = load_stage::<SessionsFile>(&sessions_path())
        .map(|f| f.sessions)
        .unwrap_or_default();
    let parent = resolve_registration_parent(
        inv.flags.get("parent").map(String::as_str),
        &id,
        &sessions_snapshot,
    );

    // Register running + conductable with its socket, so `graph send` resolves it.
    let _ = do_session_start(
        &id,
        Some(&agent),
        cwd.as_deref(),
        window.as_deref(),
        parent.as_deref(),
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
    // Stamp `headless` unconditionally (not only once the log file opens
    // below) — it is a registration fact about THIS wrap's own record, the
    // PERMANENT signal `windowless_by_lineage` and
    // `resolve_pending_session_windows` key off (task #89, review round 2):
    // even if the discovery gate above or the listener skip below somehow
    // missed, this field is what makes a headless wrap's own windowlessness
    // survive a corrupted `windowAddress`.
    if headless {
        stamp_headless(&id);
    }
    // `spawned`, on the same footing and for the same reason: a registration
    // fact about THIS record, stamped here in the child rather than by
    // `spawn` after the fact, because `spawn` returns `registered: false`
    // once its socket wait times out — and a spawn that went that wrong is
    // the one most likely to end up abandoned. Both launch modes reach here;
    // `--windowed` is a spawn no less than the headless default.
    if inv.flag_present("spawned") {
        stamp_spawned(&id);
    }
    // Origin, LOCAL-CLASS ONLY (P-P3, `docs/architecture/PAIRING.md`
    // decision 7; tightened at LANE IDENTITY P-ID0, G16/G5): inherited
    // process env is exactly what a same-uid process can set on ITSELF
    // before invoking `aoide conduct` directly, so a `node:*` shape read
    // here is unauthenticated and must never be trusted — that shape now
    // comes ONLY from `aoide-server::a2a::do_spawn` stamping the record
    // directly at the door where the node name IS authenticated
    // (`stamp_spawn_origin` in `crates/server/src/a2a.rs`), never threaded
    // through this env var. A taught refusal, not a panic: a hostile
    // `AOIDE_SESSION_ORIGIN=node:X` simply fails to stamp.
    if let Ok(origin) = std::env::var("AOIDE_SESSION_ORIGIN") {
        if is_node_origin(&origin) {
            eprintln!(
                "aoide conduct: refusing to stamp origin `{origin}` from AOIDE_SESSION_ORIGIN — a node:* origin may only be stamped by the a2a door itself"
            );
        } else if !origin.is_empty() {
            stamp_origin(&id, &origin);
        }
    }

    // Every conduct-owned pty tees its master-read output to the per-session
    // log (task #15, the "everything tees" ruling — no opt-out, interactive
    // included, not just `--headless`). `--headless` has no controlling tty
    // at all, so the log is the ONLY sink and the multiplexer never reads
    // stdin (there is nothing to read it from); interactive keeps writing
    // to the real stdout exactly as before and additionally mirrors the
    // same bytes into the log. Only the pty's OWN output crosses this tee —
    // what the pty emits, master-read side — never raw typed stdin: a
    // no-echo `sudo` password prompt is never echoed back down the master
    // by anything but the child's own tty, so it never lands in the log
    // either, headless or interactive. (The `headless` flag itself is read
    // above, where the pty winsize fallback needs it.)
    let mut sink = OutputSink::Stdout;
    if let Some((f, log_path)) = open_session_log(&id) {
        set_session_log_path(&id, &log_path.to_string_lossy());
        sink = if headless { OutputSink::Log(f) } else { OutputSink::StdoutAndLog(f) };
    }
    // A log that can't be opened (e.g. an unwritable state dir, or a
    // permissions call that fails) must not kill the session — degrade to
    // `Stdout` alone, same posture as the socket-bind best-effort above.

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
        captures_like_a_shell(&program),
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

    /// LANE IDENTITY P-ID2 test infra: write `payload` to `socket` from a
    /// process that is genuinely NOT a descendant of the calling (test)
    /// process — a plain `fork()`'d child is still this process's own
    /// child, so a double-fork daemonizes it: the middle child exits
    /// immediately, orphaning the grandchild to whatever reaps orphans
    /// (traditionally pid 1, or a sandbox's own subreaper) — either way,
    /// NOT this test process, so `pid_ancestry` walking up from the
    /// grandchild's pid never reaches back here. Everything the grandchild
    /// touches post-fork (`addr`/`payload`) is built BEFORE the fork call;
    /// the grandchild itself only ever calls async-signal-safe raw `libc`
    /// syscalls (`socket`/`connect`/`write`/`close`/`_exit`) — the same
    /// discipline `spawn_on_pty`'s own `pre_exec` closure documents, never
    /// touching Rust's allocator or any lock a sibling test thread might
    /// hold. The grandchild retries its OWN connect in a raw poll loop (no
    /// `std::thread`, no channel) since the socket may not exist yet the
    /// instant this returns.
    fn spawn_unrelated_writer(socket_path: &std::path::Path, payload: &[u8]) {
        use std::os::unix::ffi::OsStrExt;
        let path_bytes = socket_path.as_os_str().as_bytes();
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        assert!(path_bytes.len() < addr.sun_path.len(), "test socket path too long: {socket_path:?}");
        for (slot, byte) in addr.sun_path.iter_mut().zip(path_bytes.iter()) {
            *slot = *byte as libc::c_char;
        }
        let addr_len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
        let payload_owned = payload.to_vec();

        // SAFETY: the middle child only calls `setsid`/`fork`/`_exit`
        // (async-signal-safe); the grandchild only touches the
        // already-built `addr`/`payload_owned` and raw socket syscalls,
        // then `_exit`s — never returns into Rust's normal unwind/cleanup
        // path, never allocates, never touches a lock.
        let pid1 = unsafe { libc::fork() };
        if pid1 == 0 {
            unsafe {
                libc::setsid();
                let pid2 = libc::fork();
                if pid2 == 0 {
                    let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
                    if fd >= 0 {
                        for _ in 0..300 {
                            let rc = libc::connect(
                                fd,
                                &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                                addr_len,
                            );
                            if rc == 0 {
                                libc::write(
                                    fd,
                                    payload_owned.as_ptr() as *const libc::c_void,
                                    payload_owned.len(),
                                );
                                break;
                            }
                            let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 10_000_000 };
                            libc::nanosleep(&mut ts, std::ptr::null_mut());
                        }
                        libc::close(fd);
                    }
                    libc::_exit(0);
                }
                libc::_exit(0); // the middle child exits immediately — orphans the grandchild.
            }
        } else if pid1 > 0 {
            unsafe {
                let mut status: libc::c_int = 0;
                libc::waitpid(pid1, &mut status, 0); // reap the middle child — no zombie left behind.
            }
        }
    }

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
    fn parse_cmdline_splits_on_nul_and_drops_empty_segments() {
        // A synthesized raw `/proc/<pid>/cmdline` buffer: NUL-separated,
        // trailing NUL included (the kernel's real shape).
        let raw = b"nvim\0notes.md\0";
        assert_eq!(parse_cmdline(raw), vec!["nvim".to_string(), "notes.md".to_string()]);
        // Two NULs in a row (an empty argv element) never produces an empty
        // string in the output.
        let raw2 = b"cargo\0\0test\0";
        assert_eq!(parse_cmdline(raw2), vec!["cargo".to_string(), "test".to_string()]);
        assert_eq!(parse_cmdline(b""), Vec::<String>::new());
    }
    #[test]
    fn proc_argv_is_none_for_an_unreadable_pid() {
        // A pid this large cannot exist as a real process on this box — the
        // `/proc/<pid>/cmdline` read fails, and `proc_argv` must degrade to
        // `None` rather than propagate the error. No process spawned.
        assert_eq!(proc_argv(i32::MAX), None);
    }
    #[test]
    fn restore_snapshot_idle_at_prompt_yields_no_argv() {
        const SHELL_PID: i32 = 100;
        let snap = restore_snapshot(
            SHELL_PID,
            SHELL_PID,
            Some("/home/khoa/Aoide".to_string()),
            Some("cargo test".to_string()),
            |_| panic!("argv_of should not be consulted at the bare prompt"),
        );
        assert!(snap.idle);
        assert_eq!(snap.argv, None);
        assert_eq!(snap.cwd.as_deref(), Some("/home/khoa/Aoide"));
        // `typed` passes through unchanged while idle.
        assert_eq!(snap.typed.as_deref(), Some("cargo test"));
    }
    #[test]
    fn restore_snapshot_working_yields_full_uncollapsed_argv_and_drops_typed() {
        const SHELL_PID: i32 = 100;
        const FG_PID: i32 = 200;
        let snap = restore_snapshot(
            FG_PID,
            SHELL_PID,
            Some("/home/khoa/Aoide".to_string()),
            // A stale typed buffer from before the foreground command started
            // — must be dropped, never leak through while a command runs.
            Some("leftover".to_string()),
            |pid| {
                assert_eq!(pid, FG_PID);
                Some(vec!["nvim".to_string(), "--cmd".to_string(), "lua x=1".to_string()])
            },
        );
        assert!(!snap.idle);
        assert_eq!(
            snap.argv,
            Some(vec!["nvim".to_string(), "--cmd".to_string(), "lua x=1".to_string()])
        );
        assert_eq!(snap.typed, None, "a shell mid-command has no prompt line to reconstruct");
    }
    #[test]
    fn typed_capture_active_gates_on_shell_and_stdin() {
        // Only an interactive shell has a real readline prompt to capture.
        assert!(typed_capture_active(true, true));
        // A headless conduct never reads stdin — no typed line, ever, even
        // for a conducted shell.
        assert!(!typed_capture_active(true, false));
        // A non-shell (agent harness) has no shell prompt at all, headless
        // or not.
        assert!(!typed_capture_active(false, true));
        assert!(!typed_capture_active(false, false));
    }
    #[test]
    fn captures_like_a_shell_reads_the_wrapped_argv_never_the_agent_label() {
        // The task #100 defect, table-driven: shell-likeness is a property of
        // WHAT is being conducted (the wrapped command's basename), never of
        // WHO it is labelled as (`--agent <name>`). `spawn --agent soak-a --
        // bash` is a real interactive shell that must tick the same as a
        // plain `bash` conduct — the old `agent == "shell"` gate missed
        // exactly this case.
        let cases: &[(&str, bool)] = &[
            ("bash", true),
            ("zsh", true),
            ("fish", true),
            ("sh", true),
            ("/bin/bash", true),
            ("/usr/bin/zsh", true),
            ("/run/current-system/sw/bin/fish", true),
            ("claude", false),
            ("kimi", false),
            ("pi", false),
            ("cargo", false),
            ("/usr/bin/vim", false),
            // A shell-shaped binary named something else entirely still
            // reads by its OWN basename, not any caller-chosen label — this
            // function never sees `--agent` at all.
            ("bashful", false),
        ];
        for (program, expected) in cases {
            assert_eq!(
                captures_like_a_shell(program),
                *expected,
                "captures_like_a_shell({program:?}) should be {expected}"
            );
        }
    }
    #[test]
    fn typed_line_buffer_accumulates_plain_text() {
        let mut tb = TypedLineBuffer::new();
        tb.feed(b"cargo");
        tb.feed(b" test");
        assert_eq!(tb.typed().as_deref(), Some("cargo test"));
    }
    #[test]
    fn typed_line_buffer_injected_bytes_poison_rather_than_accumulate() {
        // Found in the P-C7 live soak: `graph send` prefixes a delivered
        // payload with its provenance, so an injected line captured as
        // "typed" read `from quiet-birch (…1892): echo hello` — a line no
        // human composed, which would not even run if preloaded. Injection
        // reaches the same readline buffer as stdin, so the line is no
        // longer reconstructable either way. Refuse it.
        let mut tb = TypedLineBuffer::new();
        tb.feed(b"echo ");
        tb.feed_injected(b"from quiet-birch (...1892): hello");
        assert_eq!(tb.typed(), None, "an injected line is never reported as typed");

        // A submitting injection still ends the line, so the NEXT one starts
        // clean rather than inheriting the poison forever.
        tb.feed_injected(b"\n");
        tb.feed(b"mine");
        assert_eq!(tb.typed().as_deref(), Some("mine"));
    }
    #[test]
    fn typed_line_buffer_carriage_return_and_newline_both_clear() {
        let mut tb = TypedLineBuffer::new();
        tb.feed(b"echo hi\r");
        assert_eq!(tb.typed(), None, "a submitted line is empty, not the old text");
        tb.feed(b"next line\n");
        assert_eq!(tb.typed(), None);
        tb.feed(b"third");
        assert_eq!(tb.typed().as_deref(), Some("third"));
    }
    #[test]
    fn typed_line_buffer_escape_byte_poisons_the_line() {
        // An ESC (0x1b) — the lead byte of every arrow-key/cursor escape
        // sequence — means the keystroke stream is no longer the prompt
        // buffer. Refuse, don't guess.
        let mut tb = TypedLineBuffer::new();
        tb.feed(b"echo hi");
        tb.feed(&[0x1b, b'[', b'A']); // an up-arrow sequence.
        assert_eq!(tb.typed(), None);
        // The poison holds even if more plain text follows on the SAME line.
        tb.feed(b"more");
        assert_eq!(tb.typed(), None);
        // Submitting clears the poison — the NEXT line starts clean.
        tb.feed(b"\n");
        tb.feed(b"clean");
        assert_eq!(tb.typed().as_deref(), Some("clean"));
    }
    #[test]
    fn typed_line_buffer_ctrl_u_poisons_the_line() {
        // ^U (0x15) — a readline line-kill — is exactly the "keystroke stream
        // isn't the prompt buffer anymore" case this mechanism exists for.
        let mut tb = TypedLineBuffer::new();
        tb.feed(b"garbage");
        tb.feed(&[0x15]);
        assert_eq!(tb.typed(), None);
    }
    #[test]
    fn typed_line_buffer_del_byte_poisons_the_line() {
        let mut tb = TypedLineBuffer::new();
        tb.feed(b"oops");
        tb.feed(&[0x7f]); // backspace/DEL.
        assert_eq!(tb.typed(), None);
    }
    #[test]
    fn typed_line_buffer_tab_completion_poisons_the_line() {
        let mut tb = TypedLineBuffer::new();
        tb.feed(b"carg");
        tb.feed(&[0x09]); // Tab — completion may rewrite the whole line.
        assert_eq!(tb.typed(), None);
    }
    #[test]
    fn typed_line_buffer_overflow_poisons_rather_than_truncating() {
        let mut tb = TypedLineBuffer::new();
        // Well past TYPED_LINE_CAP — must not panic or grow unbounded, and
        // must refuse: a clipped line is WRONG text, not merely short, and
        // handing back a prefix would be exactly the silent guess this
        // buffer exists to avoid.
        tb.feed(&[b'x'; 5000]);
        assert_eq!(tb.typed(), None, "an overflowed line must never yield a truncated prefix");
        // Submitting clears the poison — the NEXT line starts clean.
        tb.feed(b"\n");
        tb.feed(b"ok");
        assert_eq!(tb.typed().as_deref(), Some("ok"));
    }
    #[test]
    fn typed_line_buffer_invalid_utf8_yields_none() {
        let mut tb = TypedLineBuffer::new();
        tb.feed(&[0xff, 0xfe]); // not valid UTF-8, and not a poisoning byte.
        assert_eq!(tb.typed(), None);
    }
    #[test]
    fn typed_line_buffer_empty_line_yields_none() {
        let tb = TypedLineBuffer::new();
        assert_eq!(tb.typed(), None);
    }
    #[test]
    fn conduct_injects_socket_bytes_into_the_child() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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

        // LANE IDENTITY P-ID2: inject from a DETACHED process (never a
        // same-process thread — since `session_conduct` runs IN this test
        // process, a same-pid connection would now be correctly refused as
        // a self-injection, `spawn_unrelated_writer`'s own doc) — this is
        // exactly the "some other, unrelated sender" shape the accept
        // loop's peercred check must still let through. `conduct` blocks in
        // THIS thread until the wrapped child exits.
        spawn_unrelated_writer(&socket, b"MARKER-42\n");

        let out = session_conduct(&conduct_invocation(&["sh", "-c", &script], &[("id", id)]));

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
    /// LANE IDENTITY P-ID2's own integration test: the accept loop reads a
    /// REAL `SO_PEERCRED` off a REAL connecting process and refuses it when
    /// that process's `/proc` ancestry roots back to THIS session's own
    /// pid — a plain `fork()`'d DIRECT CHILD of the test process is exactly
    /// that shape here, since `session_conduct` also runs IN this test
    /// process (module doc's own note on why `spawn_unrelated_writer`
    /// double-forks instead, for the OPPOSITE case). The wrapped child
    /// races a backgrounded `cat` against a bounded `sleep` (no `timeout`
    /// binary dependency — plain POSIX job control) so the test terminates
    /// whether or not anything ever arrives on stdin; the proof file staying
    /// EMPTY is the refusal, not a hang.
    #[test]
    fn accept_refuses_a_connection_from_within_its_own_session_subtree() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "XDG_RUNTIME_DIR"]);

        let root = unique_stage("conduct-self-refuse");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);

        let id = "conduct-self-refuse-test";
        let socket = conduct_socket_path(id);
        let proof = root.join("proof.txt");
        let script = format!(
            "cat > {p} & CP=$!; sleep 1; kill $CP 2>/dev/null; wait $CP 2>/dev/null; true",
            p = proof.display()
        );

        // A DIRECT CHILD of this test process — genuinely "within its own
        // session subtree" from the accept loop's own perspective, since
        // `std::process::id()` there IS this test process's real pid.
        let path_bytes: Vec<u8> = {
            use std::os::unix::ffi::OsStrExt;
            socket.as_os_str().as_bytes().to_vec()
        };
        assert!(path_bytes.len() < 100, "test socket path too long for sockaddr_un: {socket:?}");
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // SAFETY: only raw, async-signal-safe syscalls post-fork — same
            // discipline `spawn_unrelated_writer` documents. `path_bytes`
            // was built and owned BEFORE the fork call.
            unsafe {
                let mut addr: libc::sockaddr_un = std::mem::zeroed();
                addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
                for (slot, byte) in addr.sun_path.iter_mut().zip(path_bytes.iter()) {
                    *slot = *byte as libc::c_char;
                }
                let addr_len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
                let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
                if fd >= 0 {
                    for _ in 0..300 {
                        let rc = libc::connect(
                            fd,
                            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                            addr_len,
                        );
                        if rc == 0 {
                            let payload = b"SELF-INJECTED\n";
                            libc::write(fd, payload.as_ptr() as *const libc::c_void, payload.len());
                            break;
                        }
                        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 10_000_000 };
                        libc::nanosleep(&mut ts, std::ptr::null_mut());
                    }
                    libc::close(fd);
                }
                libc::_exit(0);
            }
        }

        let _out = session_conduct(&conduct_invocation(&["sh", "-c", &script], &[("id", id)]));
        if pid > 0 {
            unsafe {
                let mut status: libc::c_int = 0;
                libc::waitpid(pid, &mut status, 0); // reap — no zombie left behind.
            }
        }

        let got = std::fs::read_to_string(&proof).unwrap_or_default();
        assert!(got.is_empty(), "a connection from within the session's own subtree must never reach the pty: got {got:?}");

        let _ = std::fs::remove_dir_all(&root);
    }
    /// The MUST-FIX itself (LANE IDENTITY P-ID2, review round 1): a
    /// DISTINCT, legitimately-registered CHILD session — a REAL OS
    /// descendant of the target, exactly the shape `session_conduct`'s own
    /// non-detaching registration produces for a nested `conduct` — must
    /// be DELIVERED, not refused. The earlier (buggy) shape of this guard
    /// refused ANY connection whose ancestry merely contained the target's
    /// pid, which silently broke this exact, single most common flow: a
    /// child sending to its own live parent via `aoide send --id <parent>
    /// --yes`. Here a single `fork()`'d DIRECT CHILD stands in for that
    /// child session — registered with its OWN session id and its OWN
    /// (real, live) pid BEFORE it connects, so `identity::
    /// is_self_originated`'s nearest-first resolution finds ITS OWN
    /// session first, never the target's, even though the target genuinely
    /// sits one level up in its real `/proc` ancestry.
    #[test]
    fn accept_delivers_from_a_distinct_child_session_that_is_a_real_os_descendant() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "XDG_RUNTIME_DIR"]);

        let root = unique_stage("conduct-child-delivers");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);

        let target_id = "conduct-child-delivers-target";
        let socket = conduct_socket_path(target_id);
        let proof = root.join("proof.txt");
        // Same shape as `conduct_injects_socket_bytes_into_the_child`: read
        // ONE line off stdin and prove it arrived.
        let script = format!("IFS= read -r line; printf '%s' \"$line\" > {}", proof.display());

        let path_bytes: Vec<u8> = {
            use std::os::unix::ffi::OsStrExt;
            socket.as_os_str().as_bytes().to_vec()
        };
        assert!(path_bytes.len() < 100, "test socket path too long for sockaddr_un: {socket:?}");
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // SAFETY: only raw, async-signal-safe syscalls post-fork — same
            // discipline `spawn_unrelated_writer` documents. `path_bytes`
            // was built and owned BEFORE the fork call.
            unsafe {
                let mut addr: libc::sockaddr_un = std::mem::zeroed();
                addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
                for (slot, byte) in addr.sun_path.iter_mut().zip(path_bytes.iter()) {
                    *slot = *byte as libc::c_char;
                }
                let addr_len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
                let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
                if fd >= 0 {
                    for _ in 0..300 {
                        let rc = libc::connect(
                            fd,
                            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                            addr_len,
                        );
                        if rc == 0 {
                            let payload = b"FROM-CHILD-SESSION\n";
                            libc::write(fd, payload.as_ptr() as *const libc::c_void, payload.len());
                            break;
                        }
                        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 10_000_000 };
                        libc::nanosleep(&mut ts, std::ptr::null_mut());
                    }
                    libc::close(fd);
                }
                libc::_exit(0);
            }
        }

        // Still the (original) parent test process: register the FORKED
        // CHILD's real pid as its OWN, distinct session — BEFORE the
        // target's accept loop ever processes a connection, so there is no
        // race against the retry-connecting grandchild above.
        if pid > 0 {
            crate::graph::session_store::do_session_start(
                "conduct-child-delivers-child",
                Some("claude"),
                Some("/w"),
                None,
                Some(target_id),
                None,
                None,
                None,
                Some(pid as u32),
            );
        }

        let out = session_conduct(&conduct_invocation(&["sh", "-c", &script], &[("id", target_id)]));
        if pid > 0 {
            unsafe {
                let mut status: libc::c_int = 0;
                libc::waitpid(pid, &mut status, 0); // reap — no zombie left behind.
            }
        }

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let got = std::fs::read_to_string(&proof).unwrap_or_default();
        assert_eq!(
            got, "FROM-CHILD-SESSION",
            "a distinct, legitimately-registered child session must be delivered, not refused"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn conduct_mirrors_a_nonzero_child_exit() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
    /// Task #103's underlying defect, at the layer that already gets it
    /// right: `spawn_on_pty`'s `cmd.spawn()` fails SYNCHRONOUSLY the instant
    /// the configured program isn't found (ENOENT) — no fork, no exec, no
    /// child ever runs — and `session_conduct`'s "spawn FIRST" ordering
    /// (its own doc comment, above) means that failure is caught before
    /// `do_session_start` ever writes a record. This is the sync half of
    /// #103's fix: this crate already registers no ghost for a missing
    /// binary; the a2a door's OWN bounded liveness check (`aoide-server`'s
    /// `do_spawn`/`poll_bounded_exit`) is what closes the remaining gap,
    /// where the door acked `submitted` before this synchronous failure —
    /// running one process removed, as a detached child — was ever visible
    /// to it.
    #[test]
    fn conduct_of_a_nonexistent_binary_registers_no_session_at_all() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "XDG_RUNTIME_DIR"]);

        let root = unique_stage("conduct-missing-bin");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);

        let missing = "/definitely/does/not/exist/aoide-test-nonexistent-agent-xyz";
        let out = session_conduct(&conduct_invocation(
            &[missing],
            &[("id", "conduct-missing-bin")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Error, "msg: {}", out.message);
        assert!(
            out.message.contains("failed to conduct"),
            "taught refusal naming the failed exec: {}",
            out.message
        );

        // A missing stage file is `SessionsFile::default()` (empty) per
        // `load_stage`'s own contract — either shape (file absent, or
        // present but empty) proves the same thing: no phantom entry, not
        // even a transient one that later needs the reaper.
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert!(
            s.sessions.iter().all(|r| r.session_id != "conduct-missing-bin"),
            "a failed exec must register no ghost session — found one: {:?}",
            s.sessions.iter().find(|r| r.session_id == "conduct-missing-bin")
        );

        let _ = std::fs::remove_dir_all(&root);
    }
    /// The interactive twin of the test above (task #15, "everything
    /// tees" — no `--headless` flag here at all): an ordinary conducted
    /// session mirrors its pty output into the SAME per-session log a
    /// headless session always has, IN ADDITION to stdout, and stamps
    /// `logPath` exactly the same way.
    #[test]
    fn conduct_interactive_also_mirrors_pty_output_to_the_log_and_stamps_log_path() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR"]);

        let root = unique_stage("conduct-interactive-tee");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("XDG_RUNTIME_DIR", &root);

        let out = session_conduct(&conduct_invocation(
            &["sh", "-c", "echo mark-interactive"],
            &[("id", "conduct-interactive-tee")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["exitCode"], 0);

        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        let rec = s.sessions.iter().find(|r| r.session_id == "conduct-interactive-tee").unwrap();
        assert_eq!(rec.state, "done");
        let log_path = rec.log_path.clone().expect("interactive conduct also stamps logPath");
        assert!(log_path.ends_with("conduct-interactive-tee.log"));
        let logged = std::fs::read_to_string(&log_path).unwrap();
        assert!(logged.contains("mark-interactive"), "log contents: {logged:?}");

        let _ = std::fs::remove_dir_all(&root);
    }
    /// Structural, not umask luck (task #15): the log lands `0600` and its
    /// `state/sessions/` parent `0700`, regardless of whatever umask the
    /// test process happens to run under.
    #[test]
    fn session_log_and_its_directory_are_created_with_private_permissions() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR"]);

        let root = unique_stage("conduct-log-perms");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("XDG_RUNTIME_DIR", &root);

        let out = session_conduct(&conduct_invocation(
            &["sh", "-c", "echo mark-perms"],
            &[("id", "conduct-log-perms"), ("headless", "true")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);

        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        let rec = s.sessions.iter().find(|r| r.session_id == "conduct-log-perms").unwrap();
        let log_path = rec.log_path.clone().expect("logPath must be stamped");

        use std::os::unix::fs::PermissionsExt;
        let file_mode = std::fs::metadata(&log_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "log file mode: {file_mode:o}");
        let dir_mode =
            std::fs::metadata(session_logs_dir()).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "sessions dir mode: {dir_mode:o}");

        let _ = std::fs::remove_dir_all(&root);
    }
    /// The task #100 defect, end to end: `spawn --agent soak-a -- bash` (the
    /// P-C7 soak's live shape) conducts a REAL shell under a caller-chosen
    /// agent label that is not the literal string `"shell"`. Under the old
    /// `agent == "shell"` gate this session's roster record never ticked at
    /// all — `restore` stayed `None` forever, so a later `resurrect` had
    /// nothing beyond a default cwd. The gate now reads the wrapped
    /// command's own basename, so this session gets captured regardless of
    /// what it is labelled.
    #[test]
    fn a_shell_conducted_under_a_non_shell_agent_label_still_gets_captured() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR"]);

        let root = unique_stage("conduct-non-shell-label");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("XDG_RUNTIME_DIR", &root);

        let out = session_conduct(&conduct_invocation(
            &["sh", "-c", "sleep 1"],
            &[("id", "conduct-non-shell-label"), ("agent", "soak-a")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);

        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        let rec = s.sessions.iter().find(|r| r.session_id == "conduct-non-shell-label").unwrap();
        assert_eq!(rec.agent, "soak-a", "the display label stays whatever the caller chose");
        assert!(
            rec.restore.is_some(),
            "a real shell must be captured regardless of its agent label — restore was never populated"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn conduct_headless_mirrors_pty_output_to_the_log_and_stamps_log_path() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
    /// Review round 2 of task #89: `--headless` registration must stamp the
    /// PERMANENT `headless` marker AND never call window discovery at all.
    /// The discovery GATE itself (`if headless { None } else {
    /// discover_window_address() }`) can't be distinguished from "discovery
    /// ran and simply found nothing" in this test environment (no
    /// `HYPRLAND_INSTANCE_SIGNATURE` — `discover_window_address()` would
    /// return `None` either way, gated or not), so this pins the one thing
    /// that IS honestly observable without a live compositor: the stamped
    /// `headless` flag, which is what makes the wrap's windowlessness
    /// permanent regardless of what any discovery path does or doesn't find.
    #[test]
    fn headless_conduct_registration_stamps_the_permanent_headless_marker() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR"]);

        let root = unique_stage("conduct-headless-marker");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("XDG_RUNTIME_DIR", &root);

        let out = session_conduct(&conduct_invocation(
            &["sh", "-c", "sleep 1"],
            &[("id", "conduct-headless-marker"), ("headless", "true")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);

        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        let rec = s
            .sessions
            .iter()
            .find(|r| r.session_id == "conduct-headless-marker")
            .unwrap();
        assert!(rec.headless, "a --headless registration must stamp headless=true");
        assert_eq!(
            rec.window_address, "",
            "off-Hyprland (no HYPRLAND_INSTANCE_SIGNATURE) this holds even ungated — the marker \
             is the permanent, gate-independent signal windowless_by_lineage actually keys off"
        );

        // An INTERACTIVE (non-headless) registration never stamps the marker.
        let out2 = session_conduct(&conduct_invocation(
            &["sh", "-c", "true"],
            &[("id", "conduct-interactive-marker")],
        ));
        assert_eq!(out2.status, aoide_protocol::output::Status::Ok, "msg: {}", out2.message);
        let s2: SessionsFile = load_stage(&sessions_path()).unwrap();
        let rec2 = s2
            .sessions
            .iter()
            .find(|r| r.session_id == "conduct-interactive-marker")
            .unwrap();
        assert!(!rec2.headless, "an interactive registration must never stamp headless=true");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn conduct_registration_refuses_a_node_origin_from_the_env_var() {
        // LANE IDENTITY P-ID0 (G16/G5): `AOIDE_SESSION_ORIGIN` is inherited
        // process env — a same-uid process can set it on ITSELF before
        // invoking `aoide conduct` directly, so a `node:*` shape read here
        // must never be trusted. `session_conduct` now refuses exactly this
        // shape rather than stamping it; a genuine node origin is stamped
        // by `aoide-server::a2a::do_spawn` calling `stamp_origin` directly
        // on the record (proven in that crate's own test, which this crate
        // cannot see).
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_SESSION_ORIGIN"]);

        let root = unique_stage("conduct-origin-marker");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("XDG_RUNTIME_DIR", &root);

        std::env::set_var("AOIDE_SESSION_ORIGIN", "node:yomi-strix");
        let out = session_conduct(&conduct_invocation(
            &["sh", "-c", "true"],
            &[("id", "conduct-origin-node")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        let rec = s.sessions.iter().find(|r| r.session_id == "conduct-origin-node").unwrap();
        assert_eq!(
            rec.origin, None,
            "a node:* shape read off inherited env must be refused, never stamped"
        );

        // A non-node env value is local-class and still stamps — the
        // refusal is specific to the `node:` shape, not to the env read
        // entirely.
        std::env::set_var("AOIDE_SESSION_ORIGIN", "local");
        let out_local = session_conduct(&conduct_invocation(
            &["sh", "-c", "true"],
            &[("id", "conduct-origin-local-class")],
        ));
        assert_eq!(out_local.status, aoide_protocol::output::Status::Ok, "msg: {}", out_local.message);
        let s_local: SessionsFile = load_stage(&sessions_path()).unwrap();
        let rec_local =
            s_local.sessions.iter().find(|r| r.session_id == "conduct-origin-local-class").unwrap();
        assert_eq!(rec_local.origin.as_deref(), Some("local"));

        // No env var set at all — a plain local registration never gets one.
        std::env::remove_var("AOIDE_SESSION_ORIGIN");
        let out2 = session_conduct(&conduct_invocation(
            &["sh", "-c", "true"],
            &[("id", "conduct-origin-local")],
        ));
        assert_eq!(out2.status, aoide_protocol::output::Status::Ok, "msg: {}", out2.message);
        let s2: SessionsFile = load_stage(&sessions_path()).unwrap();
        let rec2 = s2.sessions.iter().find(|r| r.session_id == "conduct-origin-local").unwrap();
        assert_eq!(rec2.origin, None, "a locally-launched conduct never stamps an origin");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn session_refresh_drives_shell_cwd_command_and_state() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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

        let idle_restore = RestoreSnapshot { cwd: Some("/proj".into()), idle: true, argv: None, typed: None };
        let working_restore = RestoreSnapshot {
            cwd: Some("/proj".into()),
            idle: false,
            argv: Some(vec!["cargo".into(), "test".into()]),
            typed: None,
        };

        // At the prompt: idle, no activity, cwd tracked.
        do_session_refresh("sh", Some("/proj"), None, "idle", false, idle_restore.clone());
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s.sessions[0].state, "idle");
        assert_eq!(s.sessions[0].cwd, "/proj");
        assert_eq!(s.sessions[0].activity, None);
        assert_eq!(s.sessions[0].needs_sudo, None);
        assert_eq!(s.sessions[0].restore, Some(idle_restore.clone()));

        // A foreground command: working + the command as activity, and the
        // restore snapshot's raw argv persists change-only alongside it.
        do_session_refresh(
            "sh", Some("/proj"), Some("cargo test"), "working", false, working_restore.clone(),
        );
        let s2: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s2.sessions[0].state, "working");
        assert_eq!(s2.sessions[0].activity.as_deref(), Some("cargo test"));
        assert_eq!(s2.sessions[0].needs_sudo, None);
        assert_eq!(s2.sessions[0].restore, Some(working_restore));

        // Blocked on sudo: state=awaiting and needsSudo=true, regardless of the
        // `state` string passed in (the caller already resolves the force in
        // `conduct_refresh_shell`, but do_session_refresh itself just persists
        // both fields change-only).
        do_session_refresh("sh", Some("/proj"), Some("sudo"), "awaiting", true, idle_restore.clone());
        let s3: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s3.sessions[0].state, "awaiting");
        assert_eq!(s3.sessions[0].needs_sudo, Some(true));

        // The prompt clears: needs_sudo=false CLEARS the field back to None
        // (never left as Some(false)) — change-only, so the key disappears.
        do_session_refresh("sh", Some("/proj"), None, "idle", false, idle_restore.clone());
        let s4: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s4.sessions[0].needs_sudo, None);
        let raw = std::fs::read_to_string(sessions_path()).unwrap();
        assert!(!raw.contains("needsSudo"), "cleared key must be absent: {raw}");

        // An unknown id is a safe no-op (never panics, never inserts).
        do_session_refresh("nope", Some("/x"), Some("x"), "working", false, idle_restore);
        let s5: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s5.sessions.len(), 1);

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
}
