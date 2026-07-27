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
    PathBuf::from(runtime)
        .join("aoide")
        .join("shellbridge.sock")
}

/// The live-state stage directory: `~/Aoide/song/stage/`.
///
/// **Contract seam (CONTRACTS.md §4):** the systemd unit
/// (`modules/nucleus/shellbridge.nix`) sets `AOIDE_STAGE_DIR=%h/Aoide/song/stage`
/// on the service — that env var wins when set to an absolute path, so the
/// daemon and the CLI door always agree on where the stage tree lives. The
/// fallback below derives the same `~/Aoide/song/stage` from `aoide_home()`,
/// so on the default layout the two paths coincide; the override only matters
/// when the unit relocates the stage (or a test/smoke run points elsewhere).
/// A relative or empty value is ignored (we never resolve a runtime path
/// against an arbitrary cwd). Every stage reader/writer routes through here.
pub fn stage_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("AOIDE_STAGE_DIR") {
        let p = PathBuf::from(&dir);
        if p.is_absolute() {
            return p;
        }
    }
    daemon::aoide_home()
        .join("Aoide")
        .join("song")
        .join("stage")
}

/// Atomic write-temp-then-rename into a file within a directory.
pub fn atomic_write(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
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

// ── Tests (the AOIDE_STAGE_DIR precedence seam; CONTRACTS.md §4) ─────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // `stage_dir()` reads process-global env; serialise these cases so they
    // never race each other (or any other env-touching test in the crate).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn stage_dir_honors_absolute_env_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();

        std::env::set_var("AOIDE_STAGE_DIR", "/tmp/aoide-test-stage");
        assert_eq!(stage_dir(), PathBuf::from("/tmp/aoide-test-stage"));

        // Empty and relative values are ignored — we fall back, never resolve a
        // runtime path against an arbitrary cwd.
        std::env::set_var("AOIDE_STAGE_DIR", "");
        assert!(stage_dir().is_absolute());
        assert!(stage_dir().ends_with("Aoide/song/stage"));
        std::env::set_var("AOIDE_STAGE_DIR", "relative/stage");
        assert!(stage_dir().ends_with("Aoide/song/stage"));

        // Absent → the aoide_home()-derived fallback.
        std::env::remove_var("AOIDE_STAGE_DIR");
        assert!(stage_dir().ends_with("Aoide/song/stage"));

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }
}
