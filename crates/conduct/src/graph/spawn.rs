//! `graph spawn` — the DETACHED verb that starts a headless conducted agent
//! (P2 of the conducted-agents plan; P1 landed `conduct --headless`,
//! a044bae). Unlike `graph wrap`/`conduct`, which block the calling process
//! until the wrapped agent exits, `spawn` re-execs THIS SAME binary as
//! `conduct --headless … -- <command …>` (the same `std::env::current_exe()`
//! self-re-exec idiom `server/src/a2a.rs`'s `do_spawn` and `shellbridge.rs`
//! use), detaches it into its own session (`setsid`, stdio nulled) so it
//! OUTLIVES this call, waits briefly for it to register its control socket,
//! and returns immediately either way. An optional `--prompt` is then
//! injected through the ONE gated injection door (`graph send`, re-driven the
//! same way `graph/pending.rs::pending_approve` re-drives an approved entry)
//! — never a direct socket write.
//!
//! `--parent`, when given, passes straight through as `conduct`'s own
//! `--parent` flag (`session_conduct` already reads `inv.flags.get("parent")`
//! and threads it into `do_session_start` — no re-implementation needed
//! here, unlike `graph wrap`, which registers the session itself in-process).

use super::conduct::{conduct_socket_path, unix_ts};
use super::model::{load_stage, sessions_path, SessionsFile};
use super::send::session_send;
use aoide_protocol::output::{Outcome, Status};
use aoide_protocol::Invocation;
use serde_json::json;
use std::collections::BTreeMap;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// How long `spawn` waits for the just-launched headless child to bind its
/// control socket before giving up and returning `registered: false` anyway.
/// The spawn itself has already succeeded (the process is running, detached,
/// and will keep running) — this is only a best-effort "did it get far
/// enough to be steerable yet" check, never a blocking guarantee.
const REGISTRATION_BUDGET: Duration = Duration::from_millis(3000);
const REGISTRATION_POLL: Duration = Duration::from_millis(25);

/// The command's basename — the agent-name default. Mirrors
/// `conduct.rs::command_basename` / `session_store.rs::session_wrap`'s own
/// copy: each `graph` verb that spawns a labelled agent keeps its own small
/// copy of this one-liner rather than sharing it across modules.
fn command_basename(program: &str) -> String {
    std::path::Path::new(program)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| program.to_string())
}

/// Resolve the binary to re-exec as the headless conducted child.
///
/// In production this is always the running `aoide` binary itself — `graph
/// spawn` only ever executes AS that binary's own dispatch, so
/// `current_exe()` is correct live, exactly like `server/src/a2a.rs`'s
/// `do_spawn`. Under `cargo test -p aoide-conduct`, though, `current_exe()`
/// resolves to the unit-test harness binary, which has NO CLI dispatcher at
/// all (confirmed: it exits 101 "Unrecognized option: 'headless'" on this
/// module's own argv) — so the module's own end-to-end test points this at
/// the real, already-built sibling `aoide` binary via
/// `AOIDE_CONDUCT_SPAWN_EXE`, a test-only escape hatch that is
/// `cfg(test)`-gated so it can never exist as a live override in the shipped
/// binary.
fn spawn_exe() -> std::io::Result<PathBuf> {
    #[cfg(test)]
    if let Some(over) = std::env::var_os("AOIDE_CONDUCT_SPAWN_EXE") {
        return Ok(PathBuf::from(over));
    }
    std::env::current_exe()
}

/// Poll for a LIVE control socket at `path`, every [`REGISTRATION_POLL`],
/// until `budget` elapses. Returns whether one answered.
///
/// A successful `UnixStream::connect` — not bare existence — is the signal,
/// for the same reason `reap::sweep_orphan_sockets` and the a2a door's
/// `spawn_inject_prompt` both insist on it: a SIGKILLed conduct leaves its
/// socket FILE behind until the reaper sweeps it (~12s), so an existence
/// check against a reused `--id` can see the corpse of the PREVIOUS session
/// and report the new one registered before it has even forked.
fn wait_for(path: &std::path::Path, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(REGISTRATION_POLL);
    }
}

/// `aoide graph spawn [--agent <name>] [--parent <sessionId>] [--id <id>]
/// [--prompt <text>] -- <command …>` — spawn `<command>` as a headless
/// conducted session that OUTLIVES this call, wait briefly for it to
/// register, and return `{ sessionId, agent, socket, logPath, registered,
/// prompt }`.
///
/// Ordering mirrors `conduct`/`wrap`: the re-exec'd `conduct --headless`
/// child spawns its own command FIRST and only registers on success, so a
/// bad `<command>` never leaves a ghost session — the control socket simply
/// never appears here and `registered` comes back `false`.
pub fn session_spawn(inv: &Invocation) -> Outcome {
    let cmd = "graph.spawn";
    if inv.args.is_empty() {
        return Outcome::usage(
            cmd,
            "usage: aoide graph spawn [--agent <name>] [--parent <sessionId>] [--id <id>] [--prompt <text>] -- <command …>",
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
        .unwrap_or_else(|| format!("spawn-{}-{}", std::process::id(), unix_ts()));

    let exe = match spawn_exe() {
        Ok(e) => e,
        Err(e) => {
            return Outcome::error(cmd, format!("resolving the aoide binary to re-exec: {e}"))
                .with_data(json!({ "reason": "exe-unresolvable", "sessionId": id }));
        }
    };

    let mut args: Vec<String> = vec![
        "conduct".to_string(),
        "--headless".to_string(),
        "--agent".to_string(),
        agent.clone(),
        "--id".to_string(),
        id.clone(),
    ];
    if let Some(parent) = inv.flags.get("parent") {
        args.push("--parent".to_string());
        args.push(parent.clone());
    }
    args.push("--".to_string());
    args.extend(inv.args.iter().cloned());

    let mut command = std::process::Command::new(&exe);
    command
        .args(&args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // SAFETY: `setsid()` is async-signal-safe and the only call made in this
    // pre_exec hook (same discipline as `graph/conduct.rs::spawn_on_pty`'s and
    // `server/src/a2a.rs::do_spawn`'s pre_exec) — it detaches the child into
    // its own session so it survives THIS call's own process lifetime. A
    // failure here (already a session leader — vanishingly unlikely for a
    // freshly-forked child) is not fatal to the spawn; the child would just
    // inherit our process group instead.
    unsafe {
        command.pre_exec(|| {
            let _ = libc::setsid();
            Ok(())
        });
    }

    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            return Outcome::error(cmd, format!("failed to spawn headless `{program}`: {e}"))
                .with_data(json!({ "reason": "spawn-failed", "sessionId": id }));
        }
    };

    // `setsid()` above detaches the child into its own session so it outlives
    // THIS call, but a new session does NOT reparent it — this process is
    // still its parent and still owes it a `wait()`, or the kernel keeps its
    // exit status around as a zombie for as long as THIS process lives. A
    // short-lived CLI invocation of `graph spawn` exits right after returning
    // below, at which point the (still-running) child reparents to
    // init/a subreaper and gets collected there regardless of whether this
    // thread ever ran — but a caller that stays up far longer (an
    // orchestrator driving `graph spawn` the same way `server/src/a2a.rs`'s
    // `do_spawn` drives `conduct`) would otherwise leak one zombie per spawn
    // for as long as it kept running. Parking the wait on its own thread is
    // correct — and cheap — either way, so it is unconditional here rather
    // than only for the long-lived caller.
    std::thread::spawn(move || {
        let _ = child.wait();
    });

    // Registration wait: poll for the control socket the headless child binds
    // once `session_conduct` reaches that point.
    let socket_path = conduct_socket_path(&id);
    let registered = wait_for(&socket_path, REGISTRATION_BUDGET);

    let (socket, log_path) = if registered {
        load_stage::<SessionsFile>(&sessions_path())
            .ok()
            .and_then(|f| f.sessions.into_iter().find(|s| s.session_id == id))
            .map(|r| (r.socket, r.log_path))
            .unwrap_or((None, None))
    } else {
        (None, None)
    };

    // `--prompt`: only after registration succeeded, through the one gated
    // injection door (`session_send`, `--yes --submit`, in-process) — the
    // exact re-drive shape `graph/pending.rs::pending_approve` uses to replay
    // an approved held entry. Never a direct write to the socket.
    let prompt_flag = inv.flags.get("prompt").cloned();
    let prompt_result = match &prompt_flag {
        None => "none".to_string(),
        Some(_) if !registered => "skipped-unregistered".to_string(),
        Some(text) => {
            let mut flags = BTreeMap::new();
            flags.insert("id".to_string(), id.clone());
            flags.insert("yes".to_string(), "true".to_string());
            flags.insert("submit".to_string(), "true".to_string());
            let inner = session_send(&Invocation {
                path: vec!["graph".to_string(), "send".to_string()],
                args: vec![text.clone()],
                flags,
                door: inv.door,
            });
            if inner.status == Status::Ok {
                "delivered".to_string()
            } else {
                format!("failed: {}", inner.message)
            }
        }
    };

    let mut changed = vec![format!(
        "session {id}: spawned headless{}",
        if registered { ", registered" } else { " (not yet registered)" }
    )];
    if prompt_result == "delivered" {
        changed.push(format!("session {id}: prompt injected"));
    }

    let data = json!({
        "sessionId": id,
        "agent": agent,
        "socket": socket,
        "logPath": log_path,
        "registered": registered,
        "prompt": prompt_result,
    });

    Outcome::ok(
        cmd,
        format!(
            "`{agent}` spawned headless (session `{id}`){}",
            if registered { "" } else { " — not yet registered" }
        ),
    )
    .changed(changed)
    .with_data(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::model::SessionsFile;
    use crate::graph::testutil::*;

    /// Locate the real, already-built `aoide` binary as `current_exe()`'s
    /// sibling in the shared `target/<profile>/` dir (`current_exe()` under
    /// `cargo test` resolves to `target/<profile>/deps/aoide_conduct-<hash>`
    /// — the profile dir's PARENT of `deps/` is where cargo also drops the
    /// workspace's own `[[bin]]` outputs). Panics with a clear message rather
    /// than silently no-op-ing if it isn't there — the box this ships on has
    /// already built it (P1 landed and tested against this same binary).
    fn built_aoide_bin() -> std::path::PathBuf {
        let test_exe = std::env::current_exe().expect("current_exe resolves under cargo test");
        let profile_dir = test_exe
            .parent() // .../target/<profile>/deps
            .and_then(|p| p.parent()) // .../target/<profile>
            .expect("test exe has a target/<profile>/deps parent");
        let bin = profile_dir.join("aoide");
        assert!(
            bin.exists(),
            "expected a pre-built `aoide` binary at {bin:?} — run `cargo build --bin aoide` first"
        );
        bin
    }

    #[test]
    fn spawn_registers_a_detached_headless_child_and_mirrors_its_log() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_CONDUCT_SPAWN_EXE",
        ]);

        let root = unique_stage("spawn-e2e");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_CONDUCT_SPAWN_EXE", built_aoide_bin());

        let id = "spawn-ok";
        let out = session_spawn(&spawn_invocation(
            &["sh", "-c", "echo spawn-mark; sleep 1"],
            &[("id", id)],
        ));

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.as_ref().unwrap();
        assert_eq!(data["sessionId"], id);
        assert_eq!(data["registered"], true, "data: {data}");
        let socket = data["socket"].as_str().expect("socket present once registered");
        assert!(socket.ends_with(&format!("session-{id}.sock")));
        let log_path = data["logPath"].as_str().expect("logPath present once registered");
        assert!(log_path.ends_with(&format!("{id}.log")));

        // The record itself is registered too, independent of the outcome's
        // own echo of it.
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        let rec = s.sessions.iter().find(|r| r.session_id == id).expect("session registered");
        assert_eq!(rec.conductable, Some(true));

        // Wait out the child's own `sleep 1` (it outlives this call — the
        // whole point of `spawn` — so its `done` transition is not
        // synchronous with the outcome above) and confirm the log mirrors
        // its output.
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(4000);
        let mut logged = String::new();
        while std::time::Instant::now() < deadline {
            logged = std::fs::read_to_string(log_path).unwrap_or_default();
            if logged.contains("spawn-mark") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(logged.contains("spawn-mark"), "log contents: {logged:?}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn spawn_of_a_nonexistent_binary_registers_no_ghost_session() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_CONDUCT_SPAWN_EXE",
        ]);

        let root = unique_stage("spawn-badexec");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_CONDUCT_SPAWN_EXE", built_aoide_bin());

        let id = "spawn-badexec";
        // The wrapped command itself doesn't exist — the re-exec'd `conduct
        // --headless` fails its OWN spawn and registers nothing (parity with
        // `conduct`/`wrap`'s "spawn first" rule), so the socket never
        // appears and `spawn` honestly times out unregistered.
        let out = session_spawn(&spawn_invocation(
            &["/no/such/binary-aoide-spawn-test"],
            &[("id", id)],
        ));

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.as_ref().unwrap();
        assert_eq!(data["registered"], false, "data: {data}");
        assert!(data["socket"].is_null());
        assert!(data["logPath"].is_null());

        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert!(
            !s.sessions.iter().any(|r| r.session_id == id),
            "a failed exec must not leave a ghost session record"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn spawn_without_a_command_is_a_usage_error() {
        let out = session_spawn(&spawn_invocation(&[], &[]));
        assert_eq!(out.status, aoide_protocol::output::Status::Usage);
    }

    #[test]
    fn prompt_is_skipped_honestly_when_registration_never_happens() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_CONDUCT_SPAWN_EXE",
        ]);

        let root = unique_stage("spawn-prompt-skip");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_CONDUCT_SPAWN_EXE", built_aoide_bin());

        let id = "spawn-prompt-skip";
        let out = session_spawn(&spawn_invocation(
            &["/no/such/binary-aoide-spawn-test"],
            &[("id", id), ("prompt", "hello")],
        ));
        assert_eq!(out.data.as_ref().unwrap()["prompt"], "skipped-unregistered");

        let _ = std::fs::remove_dir_all(&root);
    }
}
