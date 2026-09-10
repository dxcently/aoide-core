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

fn kill_target<'a>(
    id: &str,
    sessions: &'a [SessionRecord],
) -> Result<&'a SessionRecord, &'static str> {
    let rec = sessions
        .iter()
        .find(|s| s.session_id == id)
        .ok_or("session is not registered locally")?;
    if canonical_state(&rec.state) == "done" {
        return Err("session has already ended");
    }
    if rec.conductable != Some(true) {
        return Err("no dedicated conducted process; refusing to terminate a shared app or unverified harness");
    }
    let pid = rec
        .pid
        .filter(|pid| *pid > 1 && *pid != std::process::id())
        .ok_or("no eligible session process")?;
    if sessions
        .iter()
        .any(|s| s.session_id != id && s.pid == Some(pid) && canonical_state(&s.state) != "done")
    {
        return Err("process is shared by multiple sessions");
    }
    Ok(rec)
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
        let rec = match kill_target(&id, &sessions.sessions) {
            Ok(v) => v,
            Err(e) => return Outcome::error("session.kill", e),
        };
        match terminate_verified(rec) {
            Ok(()) => Outcome::ok(
                "session.kill",
                "termination requested; exit is not yet confirmed",
            )
            .with_data(json!({"sessionId":id,"pid":rec.pid,"signal":"SIGTERM"})),
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
