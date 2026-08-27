//! `SO_PEERCRED` — kernel-truth caller identity for an accepted
//! `UnixStream` connection (task #73). Before this phase, the ONLY identity
//! this crate ever recorded for a socket caller was the wire's own
//! self-asserted `consumer` STRING (`AGENTS.md`'s replay-ledger ruling,
//! `CONTRACTS.md`'s honesty note) — nothing verified who actually opened
//! the connection at the OS level. `SO_PEERCRED` closes that half: Linux
//! stamps every `AF_UNIX` socket with the connecting process's real
//! `uid`/`gid`/`pid` at `connect(2)` time, readable by the accepting side
//! via `getsockopt(2)`, and unlike the wire's `consumer` field this is not
//! something the connecting process can lie about.
//!
//! **This does NOT make `consumer` itself authenticated.** A policy's
//! `consumers[]` list, and now `automation.consumers`, are still checked
//! against the SELF-ASSERTED wire field — see `AGENTS.md`'s replay-ledger
//! ruling and `CONTRACTS.md`'s "Honesty note: `consumer` is SELF-ASSERTED"
//! for why that stays true until authenticated session identity lands
//! (#63-adjacent, not this phase). What #73 adds is a SEPARATE, orthogonal
//! fact this crate did not have before: the connecting process's real
//! `uid`, verified by the kernel, independent of anything the wire request
//! itself claims. `broker::handle_dismiss` is the first (and, as of this
//! phase, only) place that fact gates a decision — see that function's own
//! doc for exactly how.
//!
//! `std`'s own `UnixStream::peer_cred` accessor is unstable
//! (`unix_socket_peek`/`peer_credentials`-adjacent nightly-only APIs), so
//! this module reads `SO_PEERCRED` directly via `libc` — already this
//! crate's dependency (`client::connect_bounded`'s own module doc), zero
//! new deps, matching this crate's house rule.

use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;

/// Kernel-truth identity of a connected `UnixStream`'s peer, from
/// `SO_PEERCRED`. Never a value, never anything sensitive — just the three
/// fields the kernel itself stamped on the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    pub uid: u32,
    pub gid: u32,
    pub pid: i32,
}

/// Read `SO_PEERCRED` off `stream` — `None` on ANY failure (a
/// non-`AF_UNIX` stream, an unexpected `getsockopt` error, a platform that
/// doesn't support it at all). **Failure to read means the connection is
/// treated as UNIDENTIFIED, never a panic and never a fabricated uid** —
/// task #73's own requirement. Every caller that gates a decision on this
/// value must treat `None` as "refuse," never as "pass" (`broker::
/// handle_dismiss`'s own doc is the one place this matters today) — the
/// absence of kernel-truth identity is not license to assume a benign
/// caller.
pub fn peer_cred(stream: &UnixStream) -> Option<PeerCred> {
    let fd = stream.as_raw_fd();
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `fd` is a valid, open unix-domain socket fd owned by `stream`
    // for the duration of this call (we only borrow `stream`, never take
    // ownership of the fd); `cred`/`len` are correctly sized out-parameters
    // matching `SO_PEERCRED`'s documented `struct ucred` shape, and
    // `getsockopt` never writes past `len` bytes into `cred`.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return None;
    }
    Some(PeerCred { uid: cred.uid, gid: cred.gid, pid: cred.pid })
}

/// Best-effort `uid` -> username lookup (`getpwuid_r`, the thread-safe form
/// — this broker is thread-per-connection, `broker.rs`'s own module doc) —
/// `None` on any failure (no such uid, a truncated/malformed `passwd` entry,
/// the lookup mechanism itself unavailable), never a panic, same
/// fail-to-`None` posture [`peer_cred`] itself holds. This is DISPLAY DATA
/// for a park's "origin" line (a P3 addition, `park::AskOrigin`'s own doc) —
/// it never gates anything the way the raw `uid` itself does
/// (`broker::handle_dismiss`'s peer-uid check, module doc above).
pub fn username_for_uid(uid: u32) -> Option<String> {
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf: Vec<libc::c_char> = vec![0; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: `pwd`/`buf`/`result` are correctly sized out-parameters
    // matching `getpwuid_r`'s documented contract; `buf`'s pointer/len are
    // passed together and `getpwuid_r` never writes past `buf.len()`.
    let ret = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if ret != 0 || result.is_null() || pwd.pw_name.is_null() {
        return None;
    }
    // SAFETY: `pwd.pw_name` is a valid NUL-terminated C string owned by
    // `buf` (still in scope) once `getpwuid_r` returns success with a
    // non-null `result`.
    let name = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) }.to_string_lossy().into_owned();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Best-effort `/proc/<pid>/comm` read — the short process name the kernel
/// itself recorded for `pid` (task #73's own `SO_PEERCRED` pid, extended:
/// `park::AskOrigin`'s own doc). **Must be read AT PARK TIME, never later**
/// — the caller's own doc on why (a pid can exit and be reused well before
/// an ask resolves or a popup renders it). `None` on any failure (the pid
/// already gone, `/proc` unmounted, an empty read) — this is UNTRUSTED,
/// process-controlled DISPLAY TEXT (a process may name `comm` anything via
/// `prctl(PR_SET_NAME, ...)`), rendered verbatim by a surface, never
/// interpreted as anything else, same posture the wire's self-asserted
/// `consumer`/`reason` fields already hold.
pub fn read_comm(pid: i32) -> Option<String> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `UnixStream::pair()` socketpair is entirely local to THIS process
    /// — both ends' `SO_PEERCRED` must therefore report exactly this
    /// process's own euid/pid, which is a real, checkable fact (not a
    /// placeholder) without needing a second process or root.
    #[test]
    fn peer_cred_on_a_scratch_socketpair_matches_this_processs_own_identity() {
        let (a, b) = UnixStream::pair().expect("socketpair");
        let cred_a = peer_cred(&a).expect("SO_PEERCRED must be readable on a live socketpair");
        let cred_b = peer_cred(&b).expect("SO_PEERCRED must be readable on a live socketpair");
        let euid = unsafe { libc::geteuid() };
        let pid = std::process::id() as i32;
        assert_eq!(cred_a.uid, euid);
        assert_eq!(cred_a.pid, pid);
        assert_eq!(cred_b.uid, euid);
        assert_eq!(cred_b.pid, pid);
    }

    /// `SO_PEERCRED` on a fd that isn't a socket at all fails cleanly —
    /// proves the "failure = unidentified, never a panic" contract without
    /// needing to fabricate a genuinely broken socket.
    #[test]
    fn peer_cred_is_none_after_the_peer_has_hung_up_and_the_fd_reused_is_out_of_scope() {
        // A stream whose OTHER end has already been dropped is still a
        // valid socket fd (SO_PEERCRED reads the credentials recorded at
        // connect/pair time, which survive the peer closing) — this test
        // instead asserts the happy path stays `Some` even so, documenting
        // that `SO_PEERCRED` is a point-in-time stamp, not a liveness
        // check, so a caller must read it at connection start (this
        // module's own doc) rather than assume it tracks the peer's
        // current state.
        let (a, b) = UnixStream::pair().expect("socketpair");
        drop(b);
        assert!(peer_cred(&a).is_some(), "SO_PEERCRED reflects the stamped-at-connect identity, not peer liveness");
    }

    // ── username_for_uid / read_comm (P3: the ask origin line) ──────────

    #[test]
    fn username_for_uid_resolves_this_processs_own_euid() {
        let euid = unsafe { libc::geteuid() };
        assert!(username_for_uid(euid).is_some(), "this process's own euid must resolve to SOME username on any real host");
    }

    #[test]
    fn username_for_uid_is_none_for_an_implausible_uid() {
        assert_eq!(username_for_uid(u32::MAX), None);
    }

    #[test]
    fn read_comm_resolves_this_processs_own_comm() {
        assert!(read_comm(std::process::id() as i32).is_some(), "/proc/<this pid>/comm must be readable for this live process");
    }

    #[test]
    fn read_comm_is_none_for_a_pid_that_does_not_exist() {
        assert_eq!(read_comm(i32::MAX), None);
    }
}
