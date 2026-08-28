//! LANE IDENTITY P-ID2 (`docs/architecture/CONTRACTS.md`'s identity
//! section; plan file "LANE IDENTITY (#63)"'s thesis) — the kernel-truth
//! primitives the send gate and the per-session control socket both build
//! on: `SO_PEERCRED` for a connecting `UnixStream` peer, and
//! [`attested_sender`], the pure decision function that walks a pid's real
//! `/proc` ancestry to find the (verified) sealed session it is running
//! under.
//!
//! **Why `attested_sender` runs in the SENDER's own process, not at the
//! target's accept().** A pid cannot lie to itself about its own real pid
//! (`getpid()` is a kernel fact no userspace trick can override) — walking
//! `pid_ancestry(std::process::id())` in `aoide send`'s OWN process is
//! exactly as trustworthy as a peercred read of that SAME process's pid
//! from the OTHER end of a socket would be, since both observe the
//! identical real kernel ancestry of the identical real process. The
//! per-session control socket (`graph/conduct.rs`) carries raw injected
//! BYTES with no envelope — `--yes`/autogate are argv-only signals the
//! wire never carries — so the receiving accept loop has no way to tell an
//! explicitly-approved send from an ordinary one; moving the FULL gate
//! decision onto the accept side would require inventing a wire protocol,
//! which this phase does not do (scope fence: only the per-session socket
//! + the send gate). `SO_PEERCRED` earns its keep at the accept side for a
//! DIFFERENT, narrower property instead: [`peer_cred`] backs
//! `conduct.rs`'s own self-injection refusal (a connecting pid that is a
//! descendant of the socket's OWN session gets dropped, unconditionally,
//! un-bypassably — the replacement for the old client-side `is_self_send`
//! guard, which only ever guarded well-behaved callers of `aoide send`).

use super::model::{canonical_state, SessionRecord};
use super::window::{pid_ancestry, pid_starttime};
use aoide_storage::sealed_id::{verify_seal, SealedIdentity};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;

/// Kernel-truth identity of a connected `UnixStream`'s peer, from
/// `SO_PEERCRED` — mirrors `aoide_secrets::peercred::PeerCred` exactly
/// (task brief: a small local reimplementation is fine here, `libc`
/// already this crate's dependency for the PTY/signal code in
/// `conduct.rs`; adding a cross-crate edge onto `aoide-secrets` for one
/// struct+fn would invert nothing architecturally but buys nothing either).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::graph) struct PeerCred {
    pub uid: u32,
    pub pid: i32,
}

/// Read `SO_PEERCRED` off `stream` — `None` on ANY failure (a non-`AF_UNIX`
/// stream, an unexpected `getsockopt` error). Same fail-to-`None`, never-a-
/// panic, never-a-fabricated-identity contract `aoide_secrets::peercred::
/// peer_cred` documents for its own callers.
pub(in crate::graph) fn peer_cred(stream: &UnixStream) -> Option<PeerCred> {
    let fd = stream.as_raw_fd();
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `fd` is a valid, open unix-domain socket fd owned by `stream`
    // for the duration of this call (borrowed, never taken); `cred`/`len`
    // are correctly sized out-parameters matching `SO_PEERCRED`'s
    // documented `struct ucred` shape, and `getsockopt` never writes past
    // `len` bytes into `cred`.
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
    Some(PeerCred { uid: cred.uid, pid: cred.pid })
}

/// Reconstruct the exact `SealedIdentity` `rec.seal` was signed over and
/// check it against `pubkey_hex` (LANE IDENTITY P-ID2). Fail-closed on
/// every incomplete/unrevalidatable shape, never treated as "verified":
/// no `pid` (never conductable), no `seal`/`sealedIssuedAt` (never
/// sealed), or a live `/proc/<pid>/stat` read that comes back absent OR
/// exactly `0` — a `0` starttime is `mint_seal`'s own documented degrade
/// for a pid that had ALREADY vanished at mint time (`CONTRACTS.md`'s
/// identity section: "no live process ever reports starttime 0"), so a
/// FRESH read landing on `0` here can only mean the pid still doesn't
/// exist, never a legitimate match. `pid`/`sessionId`/`originClass` come
/// straight off the record; `pidStarttime` is RE-DERIVED fresh (never
/// trusted from a stored value — this is the pid-reuse defense: a stale
/// mint-time value simply fails to match a live process's real starttime).
pub(in crate::graph) fn verify_seal_over(rec: &SessionRecord, pubkey_hex: &str) -> bool {
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

/// The kernel-attested sender resolution (LANE IDENTITY P-ID2, module
/// doc): walk `start_pid`'s real `/proc` ancestry (self-first, nearest
/// ancestor first — the SAME tie-break `window::ancestry_parent` already
/// uses for its own, differently-purposed walk) and return the `sessionId`
/// of the FIRST live session whose `pid` matches an ancestor AND whose
/// seal `verify`s. A same-uid attacker cannot forge this: it cannot alter
/// its own real kernel ancestry, and a `verify` that checks a genuine
/// daemon signature cannot be satisfied by hand-editing `sessions.json`
/// alone (a forged record can claim any `pid`/`parentSessionId` it likes,
/// but not a signature over them from a key it never held).
///
/// `verify` is injected (never hard-codes a pubkey lookup here) so this
/// stays a PURE, exhaustively table-testable function — the real call
/// site supplies a closure that fetches the daemon's live public key
/// (`aoide_client::daemon::daemon_seal_pubkey_hex`) and delegates to
/// [`verify_seal_over`]; a test supplies a fixed key or a canned bool.
/// `None` when no ancestor resolves — an "unidentified" caller, which
/// every gate caller must treat as fail-closed (pending), never as a
/// benign default.
pub(in crate::graph) fn attested_sender(
    start_pid: i32,
    sessions: &[SessionRecord],
    verify: impl Fn(&SessionRecord) -> bool,
) -> Option<String> {
    for pid in pid_ancestry(start_pid) {
        if let Some(rec) = sessions.iter().find(|s| {
            s.pid == Some(pid as u32) && canonical_state(&s.state) != "done" && verify(s)
        }) {
            return Some(rec.session_id.clone());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use aoide_storage::identity;

    fn sealed_record(session_id: &str, pid: i32, origin: Option<&str>, kp: &identity::Keypair) -> SessionRecord {
        let starttime = pid_starttime(pid).expect("test pids must be real, live pids");
        let issued_at = 1_700_000_000;
        let sid = SealedIdentity {
            session_id: session_id.to_string(),
            pid,
            pid_starttime: starttime,
            origin_class: origin.unwrap_or("").to_string(),
            issued_at,
        };
        let seal = aoide_storage::sealed_id::mint_seal(kp, &sid);
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

    // ── verify_seal_over ──────────────────────────────────────────────────

    #[test]
    fn verify_seal_over_accepts_a_genuine_seal_for_a_real_live_pid() {
        let kp = identity::mint_ephemeral().unwrap();
        let me = std::process::id() as i32;
        let rec = sealed_record("s1", me, Some("local"), &kp);
        assert!(verify_seal_over(&rec, &kp.info().pubkey_hex));
    }

    #[test]
    fn verify_seal_over_rejects_a_wrong_pubkey() {
        let kp = identity::mint_ephemeral().unwrap();
        let other = identity::mint_ephemeral().unwrap();
        let me = std::process::id() as i32;
        let rec = sealed_record("s1", me, Some("local"), &kp);
        assert!(!verify_seal_over(&rec, &other.info().pubkey_hex));
    }

    #[test]
    fn verify_seal_over_rejects_a_missing_seal() {
        let kp = identity::mint_ephemeral().unwrap();
        let rec = SessionRecord {
            session_id: "s1".to_string(),
            pid: Some(std::process::id()),
            ..Default::default()
        };
        assert!(!verify_seal_over(&rec, &kp.info().pubkey_hex));
    }

    #[test]
    fn verify_seal_over_rejects_a_missing_sealed_issued_at() {
        let kp = identity::mint_ephemeral().unwrap();
        let mut rec = sealed_record("s1", std::process::id() as i32, Some("local"), &kp);
        rec.sealed_issued_at = None; // seal present, its issued_at "lost" — un-reconstructable.
        assert!(!verify_seal_over(&rec, &kp.info().pubkey_hex));
    }

    #[test]
    fn verify_seal_over_rejects_a_tampered_seal_string() {
        let kp = identity::mint_ephemeral().unwrap();
        let mut rec = sealed_record("s1", std::process::id() as i32, Some("local"), &kp);
        rec.seal = Some("deadbeef".to_string());
        assert!(!verify_seal_over(&rec, &kp.info().pubkey_hex));
    }

    #[test]
    fn verify_seal_over_rejects_a_pid_that_does_not_exist() {
        let kp = identity::mint_ephemeral().unwrap();
        // Sealed over a plausible pid we do NOT control — cannot mint a
        // real starttime for it, so build the record directly instead.
        let rec = SessionRecord {
            session_id: "s1".to_string(),
            pid: Some(2_000_000_000), // window.rs's own "no such pid" fixture value.
            origin: Some("local".to_string()),
            seal: Some("whatever".to_string()),
            sealed_issued_at: Some(1_700_000_000),
            ..Default::default()
        };
        assert!(!verify_seal_over(&rec, &kp.info().pubkey_hex));
    }

    /// A record whose `pidStarttime` was minted as the degraded `0` (a pid
    /// that had already vanished at mint time) can NEVER verify against a
    /// fresh read — `CONTRACTS.md`'s "un-revalidatable" rule. Simulated
    /// directly since a genuine mint-time `0` requires a pid to vanish
    /// mid-mint; `verify_seal_over` itself always re-derives starttime
    /// fresh, so it never even reaches the stored value — this test pins
    /// that a live pid whose FRESH read is unreadable is ALSO refused.
    #[test]
    fn verify_seal_over_rejects_when_the_live_starttime_read_is_unreadable() {
        let kp = identity::mint_ephemeral().unwrap();
        let rec = SessionRecord {
            session_id: "s-vanished".to_string(),
            pid: Some(2_000_000_000),
            origin: Some("local".to_string()),
            seal: Some(aoide_storage::sealed_id::mint_seal(
                &kp,
                &SealedIdentity {
                    session_id: "s-vanished".to_string(),
                    pid: 2_000_000_000,
                    pid_starttime: 0,
                    origin_class: "local".to_string(),
                    issued_at: 1_700_000_000,
                },
            )),
            sealed_issued_at: Some(1_700_000_000),
            ..Default::default()
        };
        assert!(!verify_seal_over(&rec, &kp.info().pubkey_hex));
    }

    // ── attested_sender ───────────────────────────────────────────────────

    #[test]
    fn attested_sender_finds_a_verified_self_ancestor() {
        let kp = identity::mint_ephemeral().unwrap();
        let me = std::process::id() as i32;
        let sessions = vec![sealed_record("orch", me, Some("local"), &kp)];
        let pubkey = kp.info().pubkey_hex;
        let found = attested_sender(me, &sessions, |rec| verify_seal_over(rec, &pubkey));
        assert_eq!(found, Some("orch".to_string()));
    }

    #[test]
    fn attested_sender_is_none_when_verify_always_fails() {
        let kp = identity::mint_ephemeral().unwrap();
        let me = std::process::id() as i32;
        let sessions = vec![sealed_record("orch", me, Some("local"), &kp)];
        let found = attested_sender(me, &sessions, |_rec| false);
        assert_eq!(found, None, "an unverifiable candidate must never resolve to a sender");
    }

    #[test]
    fn attested_sender_is_none_for_an_empty_roster() {
        let me = std::process::id() as i32;
        assert_eq!(attested_sender(me, &[], |_| true), None);
    }

    #[test]
    fn attested_sender_skips_a_done_session_even_if_verify_would_pass() {
        let me = std::process::id() as i32;
        let sessions = vec![SessionRecord {
            session_id: "dead-orch".to_string(),
            state: "done".to_string(),
            pid: Some(me as u32),
            ..Default::default()
        }];
        assert_eq!(attested_sender(me, &sessions, |_| true), None);
    }

    #[test]
    fn attested_sender_ignores_a_record_whose_pid_is_not_in_the_ancestry() {
        let me = std::process::id() as i32;
        let sessions = vec![SessionRecord {
            session_id: "unrelated".to_string(),
            state: "idle".to_string(),
            pid: Some(999_999), // not an ancestor of `me`.
            ..Default::default()
        }];
        assert_eq!(attested_sender(me, &sessions, |_| true), None);
    }

    // ── peer_cred ────────────────────────────────────────────────────────

    /// A `UnixStream::pair()` socketpair is entirely local to THIS process
    /// — both ends' `SO_PEERCRED` must report exactly this process's own
    /// euid/pid, a real checkable fact (mirrors `aoide_secrets::peercred`'s
    /// own test of the same shape, proving the local reimplementation here
    /// behaves identically).
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
}
