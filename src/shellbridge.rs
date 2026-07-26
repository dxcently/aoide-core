//! shellbridge — the session/hook state bridge (concepts/shellbridge).
//!
//! Registers agent sessions + window addresses and records Claude Code hook
//! phases, publishing them to `song/stage/` for Quickshell to read. Writes are
//! atomic (write-temp-then-rename) so a hot-reload never sees a torn file
//! (CONTRACTS.md §4 discipline).
//!
//! Skeleton: the process wires the real paths + atomic writer and seeds empty
//! stage files, proving the socket-path and stage-file contracts. The live
//! socket accept loop is future work.

use crate::daemon;
use serde_json::json;
use std::io::Write;
use std::path::PathBuf;

/// The shellbridge socket path — **contract**: never computed independently.
/// `$XDG_RUNTIME_DIR/aoide/shellbridge.sock`.
pub fn socket_path() -> PathBuf {
    let runtime = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/run/user/1000".into());
    PathBuf::from(runtime).join("aoide").join("shellbridge.sock")
}

/// The live-state stage directory: `~/Aoide/song/stage/`.
pub fn stage_dir() -> PathBuf {
    daemon::aoide_home().join("Aoide").join("song").join("stage")
}

/// Atomic write-temp-then-rename into a file within a directory.
pub fn atomic_write(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!(
        "tmp.{}",
        std::process::id()
    ));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(contents.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// Run the shellbridge skeleton: publish empty `sessions.json`/`hooks.json`
/// stage files (with their v0 shapes) atomically, and return a status document.
pub fn run() -> serde_json::Value {
    let sock = socket_path();
    let stage = stage_dir();

    // Seed the two stage files with their documented shapes (empty registries).
    let sessions = json!({
        "schemaVersion": "0",
        // records: { sessionId, agent, windowAddress, cwd, state, startedAt,
        //            parentSessionId? (optional spawned-by edge, `aoide graph link`) }
        "sessions": []
    });
    let hooks = json!({
        "schemaVersion": "0",
        // records: { sessionId, phase, updatedAt }
        "hooks": []
    });

    let mut wrote: Vec<String> = Vec::new();
    let s_path = stage.join("sessions.json");
    let h_path = stage.join("hooks.json");
    if atomic_write(&s_path, &serde_json::to_string_pretty(&sessions).unwrap()).is_ok() {
        wrote.push(s_path.to_string_lossy().into_owned());
    }
    if atomic_write(&h_path, &serde_json::to_string_pretty(&hooks).unwrap()).is_ok() {
        wrote.push(h_path.to_string_lossy().into_owned());
    }

    let _ = daemon::audit(
        &daemon::default_audit_log(),
        daemon::Door::Daemon,
        daemon::EventClass::Audit,
        "shellbridge",
        "started",
        "shellbridge skeleton online; stage files seeded",
    );

    json!({
        "process": "shellbridge",
        "state": "skeleton",
        "socket": sock.to_string_lossy(),
        "stageDir": stage.to_string_lossy(),
        "wrote": wrote,
        "stageFiles": {
            "sessions.json": ["sessionId", "agent", "windowAddress", "cwd", "state", "startedAt", "parentSessionId?"],
            "hooks.json": ["sessionId", "phase", "updatedAt"],
            // Written by `aoide graph`, read by Quickshell (CONTRACTS.md §4):
            "projects.json": ["name", "path"],
            "graph.json": ["nodes", "edges"]
        },
        "atomicWrites": true
    })
}
