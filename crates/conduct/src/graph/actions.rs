//! Local session management for terminal and widget callers.
use super::common::{require_flag, stage_error};
use super::doc::restage_graph;
use super::model::{
    canonical_state, load_stage, projects_path, sessions_path, write_stage, ProjectsFile,
    SessionRecord, SessionsFile,
};
use aoide_protocol::{output::Outcome, Door, Invocation};
use aoide_storage::fs::with_stage_lock;
use serde_json::json;
use std::collections::HashSet;

fn local_daemon(inv: &Invocation) -> Option<Outcome> {
    match inv.door {
        Door::Daemon => None,
        Door::Cli => Some(
            aoide_client::daemon::daemon_dispatch(inv).unwrap_or_else(|| {
                Outcome::error(
                    inv.dotted(),
                    "aoided must be running for session management",
                )
            }),
        ),
        _ => Some(Outcome::error(
            inv.dotted(),
            "session management is local-only",
        )),
    }
}

pub fn session_project(inv: &Invocation) -> Outcome {
    if let Some(out) = local_daemon(inv) {
        return out;
    }
    let id = match require_flag(inv, "id") {
        Ok(id) => id,
        Err(out) => return out,
    };
    let project = inv.flags.get("project").map(String::as_str);
    if inv.flag_present("clear") == project.is_some() {
        return Outcome::usage(
            "session.project",
            "use exactly one of --project NAME or --clear",
        );
    }
    assign_project(&id, project)
}

pub(super) fn assign_project(id: &str, project: Option<&str>) -> Outcome {
    with_stage_lock(|| {
        let projects: ProjectsFile = match load_stage(&projects_path()) {
            Ok(v) => v,
            Err(e) => return stage_error("session.project", e),
        };
        if project.is_some_and(|name| !projects.projects.iter().any(|p| p.name == name)) {
            return Outcome::error("session.project", "project is not registered");
        }
        let mut sessions: SessionsFile = match load_stage(&sessions_path()) {
            Ok(v) => v,
            Err(e) => return stage_error("session.project", e),
        };
        let Some(rec) = sessions.sessions.iter_mut().find(|s| s.session_id == id) else {
            return Outcome::error("session.project", "session is not registered locally");
        };
        rec.project = project.map(str::to_owned);
        if let Err(e) = write_stage(&sessions_path(), &sessions) {
            return stage_error("session.project", e);
        }
        if let Err(e) = restage_graph() {
            return stage_error("session.project", e);
        }
        Outcome::ok("session.project", "session project updated")
            .with_data(json!({"sessionId":id,"project":project}))
    })
}

/// The refusal message a stalled or unresolvable walk returns — VERBATIM
/// what this function always returned before the walk existed, so a caller
/// (and every existing test) that only ever saw the direct-record shape sees
/// the identical string for the identical class of refusal.
const NO_DEDICATED_PROCESS: &str =
    "no dedicated conducted process; refusing to terminate a shared app or unverified harness";

/// Resolve `id` to the record whose process a kill actually stops (P-QOL-C
/// §2): `id` itself when it's already a conducted wrap with a dedicated pid
/// (today's shape, unchanged), else the nearest `parentSessionId` ancestor
/// that is. The desktop menu and the CLI both pass whatever card the user
/// clicked — a native hook-fed record, never necessarily a wrap — so this is
/// what makes "Kill process" resolve at all (`§0`'s whole problem statement).
///
/// Returns the target record plus the walked CHAIN (`id` first, the target
/// last) so the shared-pid check below can exclude every hop the walk
/// legitimately passed through — a wrap and its own hook-fed descendants
/// sharing one process's pid is the EXPECTED shape, never a collision.
///
/// The walk is ≤32 hops and cycle-guarded with a `seen` set — the same
/// guard [`super::session_store::lineage_of`] applies to its own ancestor
/// half (`session_store.rs`). `lineage_of` itself doesn't fit here: it
/// returns an unordered `HashSet` mixing ancestors with descendants, and
/// this needs an ORDERED, ancestors-only chain — hence the small local loop
/// rather than reusing it.
///
/// The seal is deliberately NOT checked here — [`terminate_verified`]
/// re-verifies it fresh against the resolved target, and a stale seal must
/// surface ITS OWN "session process identity is stale or unsealed" message,
/// never get pre-empted by a misleading ancestry refusal from this walk.
fn kill_target<'a>(
    id: &str,
    sessions: &'a [SessionRecord],
) -> Result<(&'a SessionRecord, Vec<String>), &'static str> {
    let rec = sessions
        .iter()
        .find(|s| s.session_id == id)
        .ok_or("session is not registered locally")?;
    if canonical_state(&rec.state) == "done" {
        return Err("session has already ended");
    }
    let is_wrap = |s: &SessionRecord| {
        s.conductable == Some(true)
            && s.pid.is_some_and(|pid| pid > 1 && pid != std::process::id())
    };
    let mut chain = vec![rec.session_id.clone()];
    let mut seen: HashSet<String> = [rec.session_id.clone()].into_iter().collect();
    let mut current = rec;
    while !is_wrap(current) {
        let parent_id = current.parent_session_id.as_deref().ok_or(NO_DEDICATED_PROCESS)?;
        if chain.len() >= 32 || !seen.insert(parent_id.to_string()) {
            return Err(NO_DEDICATED_PROCESS);
        }
        current = sessions
            .iter()
            .find(|s| s.session_id == parent_id)
            .ok_or(NO_DEDICATED_PROCESS)?;
        chain.push(parent_id.to_string());
    }
    let target = current;
    if sessions.iter().any(|s| {
        !chain.contains(&s.session_id)
            && s.pid == target.pid
            && canonical_state(&s.state) != "done"
    }) {
        return Err("process is shared by multiple sessions");
    }
    Ok((target, chain))
}

pub fn session_kill(inv: &Invocation) -> Outcome {
    if let Some(out) = local_daemon(inv) {
        return out;
    }
    let id = match require_flag(inv, "id") {
        Ok(id) => id,
        Err(out) => return out,
    };
    with_stage_lock(|| {
        let sessions: SessionsFile = match load_stage(&sessions_path()) {
            Ok(v) => v,
            Err(e) => return stage_error("session.kill", e),
        };
        let (target, _chain) = match kill_target(&id, &sessions.sessions) {
            Ok(v) => v,
            Err(e) => return Outcome::error("session.kill", e),
        };
        match terminate_verified(target) {
            Ok(()) => {
                let message = if target.session_id == id {
                    "termination requested; exit is not yet confirmed".to_string()
                } else {
                    format!(
                        "terminating {} (the terminal that hosts {id}); exit is not yet confirmed",
                        target.session_id
                    )
                };
                Outcome::ok("session.kill", message).with_data(json!({
                    "sessionId": id,
                    "target": target.session_id,
                    "pid": target.pid,
                    "signal": "SIGTERM",
                }))
            }
            Err(e) => Outcome::error("session.kill", e),
        }
    })
}

#[cfg(target_os = "linux")]
fn terminate_verified(rec: &SessionRecord) -> Result<(), String> {
    let key =
        aoide_storage::attest::daemon_seal_pubkey_hex().ok_or("daemon identity unavailable")?;
    terminate_with_key(rec, &key)
}

#[cfg(target_os = "linux")]
fn terminate_with_key(rec: &SessionRecord, key: &str) -> Result<(), String> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let pid = rec.pid.ok_or("session has no process")?;
    // Pin the process before seal verification so PID reuse cannot redirect the signal.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(format!(
            "cannot pin session process: {}",
            std::io::Error::last_os_error()
        ));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    if !aoide_storage::attest::verify_seal_over(rec, key) {
        return Err("session process identity is stale or unsealed".into());
    }
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            libc::SIGTERM,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result < 0 {
        return Err(format!(
            "cannot signal session process: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn terminate_verified(_: &SessionRecord) -> Result<(), String> {
    Err("verified process termination requires Linux pidfds".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rec(id: &str) -> SessionRecord {
        SessionRecord {
            session_id: id.into(),
            pid: Some(99999),
            conductable: Some(true),
            state: "idle".into(),
            ..Default::default()
        }
    }
    #[test]
    fn kill_target_refuses_shared_desktop_and_done() {
        let mut a = rec("a");
        assert!(kill_target("a", &[a.clone(), rec("b")]).is_err());
        a.conductable = None;
        assert!(kill_target("a", &[a.clone()]).is_err());
        a.conductable = Some(true);
        a.state = "done".into();
        assert!(kill_target("a", &[a]).is_err());
    }
    #[test]
    fn kill_target_resolves_a_hook_child_to_its_conducted_wrap() {
        let w = rec("w"); // conducted wrap: conductable, dedicated pid.
        let mut c = rec("c");
        c.conductable = None;
        c.pid = None;
        c.parent_session_id = Some("w".into());
        let sessions = [c, w];
        let (target, chain) = kill_target("c", &sessions)
            .expect("a hook child must resolve to its conducted wrap");
        assert_eq!(target.session_id, "w");
        assert_eq!(chain, vec!["c".to_string(), "w".to_string()]);
    }
    #[test]
    fn kill_target_refuses_a_shared_record_with_no_conductable_ancestor() {
        // A desktop record: a pid, no parent, never conducted — refused
        // outright, no walk to attempt.
        let mut desktop = rec("d");
        desktop.conductable = None;
        assert_eq!(kill_target("d", &[desktop]).unwrap_err(), NO_DEDICATED_PROCESS);

        // A two-hop chain, neither hop conductable — the walk runs out of
        // ancestors without ever finding a wrap.
        let mut c1 = rec("c1");
        c1.conductable = None;
        c1.pid = None;
        c1.parent_session_id = Some("c2".into());
        let mut c2 = rec("c2");
        c2.conductable = None;
        c2.pid = None;
        assert_eq!(
            kill_target("c1", &[c1, c2]).unwrap_err(),
            NO_DEDICATED_PROCESS
        );
    }
    #[test]
    fn kill_target_excludes_the_walked_chain_from_the_shared_process_check() {
        let w = rec("w"); // wrap, pid 99999.
        let mut c = rec("c");
        c.conductable = None;
        c.parent_session_id = Some("w".into());
        // `c` carries the SAME pid as the wrap it walks to — a chain member
        // sharing the target's pid is the EXPECTED shape, not a collision.
        let two = [c.clone(), w.clone()];
        let (target, _chain) = kill_target("c", &two)
            .expect("a chain member sharing the target's pid must not trip the shared check");
        assert_eq!(target.session_id, "w");

        // An UNRELATED live record on that same pid is the real collision.
        let mut d = rec("d");
        d.conductable = None;
        let three = [c, w, d];
        assert_eq!(
            kill_target("c", &three).unwrap_err(),
            "process is shared by multiple sessions"
        );
    }
    #[test]
    fn kill_target_stops_at_a_parent_cycle() {
        let mut a = rec("a");
        a.conductable = None;
        a.pid = None;
        a.parent_session_id = Some("b".into());
        let mut b = rec("b");
        b.conductable = None;
        b.pid = None;
        b.parent_session_id = Some("a".into());
        assert_eq!(kill_target("a", &[a, b]).unwrap_err(), NO_DEDICATED_PROCESS);
    }
    #[test]
    fn kill_target_selects_a_wrap_with_a_stale_seal() {
        // The walk must not pre-filter on seal validity — that refusal is
        // `terminate_verified`'s job alone (already pinned by
        // `verified_termination_rejects_stale_seal_and_stops_only_child`).
        let mut w = rec("w");
        w.seal = Some("stale-or-forged".into());
        w.sealed_issued_at = Some(1);
        let sessions = vec![w];
        let (target, chain) = kill_target("w", &sessions)
            .expect("kill_target never checks the seal — only terminate_verified does");
        assert_eq!(target.session_id, "w");
        assert_eq!(chain, vec!["w".to_string()]);
    }
    #[test]
    fn explicit_project_beats_cwd_and_clear_restores_it() {
        let projects = vec![
            super::super::model::Project {
                name: "a".into(),
                path: "/a".into(),
                roots: Vec::new(),
                auto_resume: false,
            },
            super::super::model::Project {
                name: "b".into(),
                path: "/b".into(),
                roots: Vec::new(),
                auto_resume: false,
            },
        ];
        let mut a = rec("a");
        a.cwd = "/a/work".into();
        a.project = Some("b".into());
        assert_eq!(super::super::model::project_for(&a, &projects), Some(1));
        a.project = None;
        assert_eq!(super::super::model::project_for(&a, &projects), Some(0));
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn verified_termination_rejects_stale_seal_and_stops_only_child() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let key = aoide_storage::identity::mint_ephemeral().unwrap();
        let mut record = rec("disposable");
        record.pid = Some(child.id());
        record.sealed_issued_at = Some(123);
        let mut identity = aoide_storage::sealed_id::SealedIdentity {
            session_id: record.session_id.clone(),
            pid: child.id() as i32,
            pid_starttime: 1,
            origin_class: String::new(),
            issued_at: 123,
        };
        record.seal = Some(aoide_storage::sealed_id::mint_seal(&key, &identity));
        let stale = terminate_with_key(&record, &key.info().pubkey_hex);
        let still_alive = child.try_wait().unwrap().is_none();
        identity.pid_starttime = aoide_storage::attest::pid_starttime(child.id() as i32).unwrap();
        record.seal = Some(aoide_storage::sealed_id::mint_seal(&key, &identity));
        let live = terminate_with_key(&record, &key.info().pubkey_hex);
        if live.is_err() {
            let _ = child.kill();
        }
        let status = child.wait().unwrap();
        assert!(stale.is_err());
        assert!(still_alive);
        assert!(live.is_ok(), "{live:?}");
        assert!(!status.success());
    }

    #[test]
    fn project_assignment_validates_before_write_and_clear_preserves_cwd() {
        let _lock = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, _root) = aoide_test_support::isolated_mail_root("session-project");
        let mut record = rec("one");
        record.cwd = "/original".into();
        write_stage(
            &sessions_path(),
            &SessionsFile {
                sessions: vec![record],
                ..Default::default()
            },
        )
        .unwrap();
        write_stage(
            &projects_path(),
            &ProjectsFile {
                projects: vec![super::super::model::Project {
                    name: "chosen".into(),
                    path: "/elsewhere".into(),
                    roots: Vec::new(),
                    auto_resume: false,
                }],
                ..Default::default()
            },
        )
        .unwrap();
        let before = std::fs::read(sessions_path()).unwrap();
        assert_eq!(
            assign_project("one", Some("missing")).status,
            aoide_protocol::output::Status::Error
        );
        assert_eq!(std::fs::read(sessions_path()).unwrap(), before);
        assert_eq!(
            assign_project("one", Some("chosen")).status,
            aoide_protocol::output::Status::Ok
        );
        let file: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(file.sessions[0].project.as_deref(), Some("chosen"));
        assert_eq!(file.sessions[0].cwd, "/original");
        assert_eq!(
            assign_project("one", None).status,
            aoide_protocol::output::Status::Ok
        );
        let file: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(file.sessions[0].project, None);
        assert_eq!(file.sessions[0].cwd, "/original");
    }
}
