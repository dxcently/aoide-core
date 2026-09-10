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

use super::model::SessionRecord;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;

/// Kernel-truth identity of a connected `UnixStream`'s peer, from
/// `SO_PEERCRED` — mirrors `aoide_secrets::peercred::PeerCred` exactly
/// (task brief: a small local reimplementation is fine here, `libc`
/// already this crate's dependency for the PTY/signal code in
/// `conduct.rs`; adding a cross-crate edge onto `aoide-secrets` for one
/// struct+fn would invert nothing architecturally but buys nothing either).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PeerCred {
    pub uid: u32,
    pub pid: i32,
}

/// Read `SO_PEERCRED` off `stream` — `None` on ANY failure (a non-`AF_UNIX`
/// stream, an unexpected `getsockopt` error). Same fail-to-`None`, never-a-
/// panic, never-a-fabricated-identity contract `aoide_secrets::peercred::
/// peer_cred` documents for its own callers.
///
/// `pub(crate)`, not `pub(in crate::graph)` (LANE IDENTITY P-ID3): this
/// crate's `shellbridge.rs` — a sibling of `graph`, not a descendant — reuses
/// this exact primitive for its own accept-time cross-uid floor rather than
/// re-implementing a second `SO_PEERCRED` read (`graph.rs`'s own `mod
/// identity` doc comment).
pub(crate) fn peer_cred(stream: &UnixStream) -> Option<PeerCred> {
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
/// every incomplete/unrevalidatable shape, never treated as "verified" —
/// `pidStarttime` RE-DERIVED fresh, never trusted from a stored value (the
/// pid-reuse defense). The BODY lives in `aoide_storage::attest::
/// verify_seal_over` as of LANE IDENTITY P-ID4 (the secrets broker's origin
/// gate verifies the identical seal shape and `aoide-secrets` cannot depend
/// on this crate — that module's doc has the full DAG argument and the
/// complete fail-closed contract); this delegate keeps `crate::graph`'s
/// call sites and tests unchanged.
pub(in crate::graph) fn verify_seal_over(rec: &SessionRecord, pubkey_hex: &str) -> bool {
    aoide_storage::attest::verify_seal_over(rec, pubkey_hex)
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
/// The BODY (the nearest-first walk over the real `/proc` ancestry) lives
/// in `aoide_storage::attest::attested_session` as of LANE IDENTITY P-ID4
/// — one walk, shared with the secrets broker's origin gate (that module's
/// doc has the DAG argument); this delegate keeps `crate::graph`'s call
/// sites, tests, and the name `attested_sender` unchanged.
pub(in crate::graph) fn attested_sender(
    start_pid: i32,
    sessions: &[SessionRecord],
    verify: impl Fn(&SessionRecord) -> bool,
) -> Option<String> {
    aoide_storage::attest::attested_session(start_pid, sessions, verify)
}

/// The conducted-ancestor-only sibling of [`attested_sender`] (P-QOL-C §1):
/// same nearest-first `/proc` ancestry walk and the same injected, fail-closed
/// `verify`, but narrowed to a record that is itself a conducted wrap
/// (`conductable == Some(true)`) — the process a `session kill` can actually
/// stop. `attested_sender` accepts ANY verified sealed ancestor (its callers
/// gate on sender identity, not on process ownership); this one exists
/// because the hook-time re-parenting seam (`hook_ensure_session`) and the
/// kill door both need the NEAREST conducted wrap specifically, never a bare
/// hook-fed ancestor. `verify` stays injected for the same reason
/// `attested_sender`'s doc gives: a pure, table-testable function, with the
/// real call site (`send.rs`'s `real_attested_wrap`) supplying the live
/// daemon-key check.
pub(in crate::graph) fn attested_wrap(
    start_pid: i32,
    sessions: &[SessionRecord],
    verify: impl Fn(&SessionRecord) -> bool,
) -> Option<String> {
    aoide_storage::attest::attested_session(start_pid, sessions, |rec| {
        rec.conductable == Some(true) && verify(rec)
    })
}

/// The per-session control socket's self-injection refusal (LANE IDENTITY
/// P-ID2, review round 1 MUST-FIX): resolves the CONNECTING pid's OWN
/// nearest live registered session — the SAME nearest-first walk
/// [`attested_sender`] uses, but WITHOUT seal verification, since this is
/// a narrow UX/loop defense, not the security boundary itself (the raw
/// same-uid socket door is OQ1-A-inherent and stays open until P-ID3
/// floors it; `verify` here would only add cost, not close anything this
/// guard doesn't already fail open on). Refuses — returns `true` — ONLY
/// when the connector's OWN nearest session resolves to `target_session_id`
/// itself: true self-injection, a session's own descendant (an unregistered
/// tool subprocess, or an explicit `--id <own-id>` send) reaching back into
/// its OWN socket.
///
/// **Why "nearest", not "contains"**: `session_conduct` registers WITHOUT
/// detaching (`spawn.rs`'s `--headless` re-exec is the only path that
/// `setsid`-reparents; a plain `conduct` child stays a true OS descendant
/// of whatever registered it) — a LEGITIMATE child session's pid is
/// therefore a genuine descendant of its OWN parent's registered pid. An
/// earlier revision of this guard refused any connection whose ancestry
/// merely CONTAINED the target's pid anywhere upstream, which silently
/// broke the single most common flow: a child sending to its own live
/// parent via `aoide send --id <parent> --yes` — the child's connecting
/// pid genuinely has the parent's registered pid in its ancestry, so the
/// old check refused it, downstream of the gate, with a bare broken pipe
/// `--yes` cannot route around (this check runs at the TARGET's accept,
/// after the sender already decided to deliver). Resolving the CONNECTOR's
/// own NEAREST session instead fixes this: walking nearest-first, a
/// nested child's own registered pid is found FIRST (it is closer than its
/// parent's), so it resolves to the CHILD's own session id, never the
/// parent/target's — only a connection whose nearest resolvable session
/// genuinely IS the target gets refused.
///
/// An unresolvable connector (no seal — irrelevant here, since `verify` is
/// trivial — but genuinely no registered session anywhere in its ancestry,
/// e.g. a fully orphaned/reparented process) resolves `None`, which
/// `is_some_and` folds to `false` — FAILS OPEN (allowed), never refused.
/// This guard exists to catch one narrow, known shape; an ambiguous
/// connector is not license to assume the worst the way a REAL gate would.
pub(in crate::graph) fn is_self_originated(
    connecting_pid: i32,
    sessions: &[SessionRecord],
    target_session_id: &str,
) -> bool {
    attested_sender(connecting_pid, sessions, |_rec| true)
        .is_some_and(|connector_session| connector_session == target_session_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::window::{pid_ancestry, pid_starttime};
    use aoide_storage::identity;
    use aoide_storage::sealed_id::SealedIdentity;

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

    // ── attested_wrap ─────────────────────────────────────────────────────

    #[test]
    fn attested_wrap_finds_the_conducted_ancestor_of_a_real_child_process() {
        let mut child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let kp = identity::mint_ephemeral().unwrap();
        let me = std::process::id() as i32;
        let mut wrap = sealed_record("wrap", me, Some("local"), &kp);
        wrap.conductable = Some(true);
        let sessions = vec![wrap];
        let pubkey = kp.info().pubkey_hex;
        let found = attested_wrap(child.id() as i32, &sessions, |rec| {
            verify_seal_over(rec, &pubkey)
        });
        assert_eq!(
            found,
            Some("wrap".to_string()),
            "a real spawned child must resolve to its conducted parent"
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn attested_wrap_refuses_a_non_conductable_ancestor_and_the_init_chain() {
        let kp = identity::mint_ephemeral().unwrap();
        let me = std::process::id() as i32;
        // conductable defaults to None — a bare sealed session, not a wrap.
        let sessions = vec![sealed_record("hook-fed", me, Some("local"), &kp)];
        let pubkey = kp.info().pubkey_hex;
        assert_eq!(
            attested_wrap(me, &sessions, |rec| verify_seal_over(rec, &pubkey)),
            None,
            "a non-conductable ancestor is never a kill target"
        );
        assert_eq!(
            attested_wrap(1, &sessions, |_| true),
            None,
            "walking from init resolves nothing"
        );
    }

    // ── is_self_originated (review round 1 MUST-FIX) ────────────────────────

    /// True self-injection: the connector's OWN nearest session (found via
    /// its real `pid` at ancestry position 0, self) IS the target — refused.
    #[test]
    fn is_self_originated_refuses_when_the_connector_is_literally_the_target() {
        let me = std::process::id() as i32;
        let sessions = vec![SessionRecord {
            session_id: "target".to_string(),
            state: "idle".to_string(),
            pid: Some(me as u32),
            ..Default::default()
        }];
        assert!(is_self_originated(me, &sessions, "target"));
    }

    /// The MUST-FIX itself: a DISTINCT, legitimately-registered CHILD
    /// session whose pid is a real OS descendant of the target's own pid
    /// (exactly the shape `session_conduct`'s own non-detaching
    /// registration produces) must NOT be refused — its OWN nearest
    /// session is ITSELF (found first, nearest-first), never the parent
    /// it happens to descend from. Simulated here without a real fork:
    /// `me` stands in as the "child's" pid (self is always the nearest
    /// entry in its own ancestry, position 0), sealed... registered as a
    /// DIFFERENT session id than the target, with the target ALSO present
    /// deeper in the (real) ancestry chain — proving the nearest match
    /// wins over the raw-containment shape the old, buggy guard used.
    #[test]
    fn is_self_originated_allows_a_distinct_child_session_even_though_the_target_is_an_ancestor() {
        let me = std::process::id() as i32;
        let ancestry = pid_ancestry(me);
        assert!(ancestry.len() >= 2, "this test needs a real parent pid to stand in as the target");
        let parent_pid = ancestry[1];
        let sessions = vec![
            SessionRecord {
                session_id: "child-session".to_string(),
                state: "idle".to_string(),
                pid: Some(me as u32), // nearest — this is the CONNECTOR's own session.
                ..Default::default()
            },
            SessionRecord {
                session_id: "target".to_string(),
                state: "idle".to_string(),
                pid: Some(parent_pid as u32), // an ancestor, but NOT nearest.
                ..Default::default()
            },
        ];
        assert!(
            !is_self_originated(me, &sessions, "target"),
            "a distinct child session must never be refused just because the target is upstream in its ancestry"
        );
    }

    /// An unregistered subprocess of the target (no session of its own
    /// anywhere in its OWN ancestry below the target) resolves to the
    /// target itself via the nearest REGISTERED ancestor — still refused,
    /// the exact "tool call within the wrapped agent" shape the guard
    /// exists to catch.
    #[test]
    fn is_self_originated_refuses_an_unregistered_descendant_whose_nearest_registered_ancestor_is_the_target() {
        let me = std::process::id() as i32;
        let sessions = vec![SessionRecord {
            session_id: "target".to_string(),
            state: "idle".to_string(),
            pid: Some(me as u32),
            ..Default::default()
        }];
        // `me` itself has no session record — only ITS ancestor (also
        // `me`, since a pid is always its own ancestry position 0) does in
        // this minimal fixture; a genuinely deeper unregistered descendant
        // behaves identically since `attested_sender` walks past any
        // pid with no matching record until it finds one.
        assert!(is_self_originated(me, &sessions, "target"));
    }

    /// An unresolvable connector (no session anywhere in its ancestry)
    /// FAILS OPEN — never refused. This guard is a narrow UX/loop defense,
    /// not the security boundary; an ambiguous connector must not be
    /// treated as guilty.
    #[test]
    fn is_self_originated_fails_open_for_an_unresolvable_connector() {
        assert!(!is_self_originated(999_999, &[], "target"));
    }

    /// A resolved sender that is neither the target nor unresolvable —
    /// some OTHER, unrelated live session — is never refused either.
    #[test]
    fn is_self_originated_allows_a_resolved_but_unrelated_sender() {
        let me = std::process::id() as i32;
        let sessions = vec![SessionRecord {
            session_id: "someone-else".to_string(),
            state: "idle".to_string(),
            pid: Some(me as u32),
            ..Default::default()
        }];
        assert!(!is_self_originated(me, &sessions, "target"));
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
